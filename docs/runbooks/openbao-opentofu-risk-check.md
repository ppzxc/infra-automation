# OpenBao OpenTofu 호환 위험 확인 결과

> Spec #511 / Ticket-6(#517), #505 열린 위험 2번. 운영 런북 `openbao-operations`(#512)가 병합되면 이 파일의 "확인 결과" 절을 그 런북으로 합치고 이 파일은 지운다. 공개 저장소라 주소·토큰·CIDR은 적지 않는다. 운영자 값은 비공개 노트에 둔다.

## 1. 확인 환경

- 실서버가 아니라 **로컬 dev OpenBao 컨테이너**(`openbao/openbao` 이미지, 서버 2.7.2, `server -dev`)에서 했다. 네임스페이스 `infra`는 `bao namespace create infra`로 만들었다.
- OpenTofu 1.13.9(`ghcr.io/opentofu/opentofu` 이미지), provider `hashicorp/vault` 5.13.0, state는 로컬 파일(S3 backend 대신) + `TF_ENCRYPTION`의 pbkdf2.
- `runner_cidrs`는 루프백 대역으로 두어 AppRole CIDR 바인딩이 실제로 로그인 경로를 통과하는지 봤다.
- 순서: 루트 토큰으로 bootstrap apply, 이어서 `applier` AppRole(secret_id 1회용)로 로그인해 plan·apply를 다시 했다.

## 2. 확인 결과

| 위험 | 결과 |
|---|---|
| 자식 토큰 발급 | provider 기본(`skip_child_token = false`)이면 `applier` 토큰으로 `POST auth/token/create`가 403이라 plan이 `failed to create limited child token`으로 실패한다. 서버가 거부하는 것이 아니라 **applier 정책에 그 경로가 없어서**다. `skip_child_token = true`로 두면 plan·apply 모두 통과한다. 코드는 `true`로 고정했다 |
| 버전 문자열 파싱 | 서버 2.7.2에서 provider가 버전 문자열을 파싱하다 실패하지 않았다(`skip_get_vault_version` 없이 plan·apply 통과). 다만 **실서버의 패키지 빌드 문자열로는 확인하지 못했다.** 첫 실제 `plan`에서 이 오류가 나면 provider의 `skip_get_vault_version = true`를 켠다 |
| 네임스페이스 인자 | provider `namespace = "infra"`(`X-Vault-Namespace` 헤더)로 마운트·정책·AppRole·userpass 생성과 읽기가 모두 통과했다. 같은 헤더로 userpass·AppRole 로그인과 정책 거부(`secrets/`·`auth/token/create` 403)도 확인했다 |

추가로 확인한 것:

- `vault_generic_endpoint`로 userpass 사용자를 `password_hash`(bcrypt, `$2a$`) 없이 만들면 `must provide either password or password_hash`로 거부된다. 그래서 코드는 평문 비밀번호 대신 해시를 받는다(평문이 state에 남지 않게 한다).
- state 파일의 `key_provider.pbkdf2.main` 메타만 보이고 passphrase 문자열은 state에 없다. `TF_ENCRYPTION` 없이 plan하면 실패한다(enforced).
- `applier` 정책에 `auth/approle/role/+/secret-id` 등을 `deny`로 두면 `applier` 토큰의 secret_id 발급이 403이고 `tofu plan`은 `No changes`다(role 리소스는 `role-id`만 읽는다).
- `applier` 토큰으로 `secrets/`에 KV를 쓰려 하면 403이다. 정책 조회·변경은 통과한다.

## 3. 확인하지 못한 것 (운영자 확인 필요)

- 실서버 버전·패키지 빌드에서의 버전 문자열 파싱(위 표).
- `infra` 네임스페이스 생성을 `vault_namespace` 리소스로 해 보지 않았다. bootstrap은 `bao namespace create infra`(`admin`)로 한다.
- 실서버 `plan`에서 `operator` 정책이 아직 없어도 사용자 선언은 통과하지만(정책 이름만 참조), 로그인 후 권한은 #518 이후에 확인한다.
- S3 backend(RustFS)에서 `init`·`use_lockfile`(조건부 쓰기 지원 여부)·암호화 state 왕복. 로컬 backend로만 확인했다. RustFS는 `skip_s3_checksum`·`use_path_style`이 필요할 수 있다(`versions.tf`에 켰다). 첫 `init` 때 확인한다.
- 이 확인은 사람이 손으로 한 것이 아니라 에이전트가 로컬 컨테이너에서 실행했다. 전환 동결 창의 확인 목록에서 운영자가 실서버로 다시 확인한다.

## 4. 재현

```bash
docker run -d --name bao-dev --network host -e BAO_DEV_ROOT_TOKEN_ID=<임시값> \
  -e BAO_DEV_LISTEN_ADDRESS=127.0.0.1:18200 openbao/openbao:latest server -dev
docker exec -e BAO_ADDR=http://127.0.0.1:18200 -e BAO_TOKEN=<임시값> bao-dev bao namespace create infra
# tofu/openbao를 복사해 backend "s3" 블록을 backend "local"로 바꾼 뒤
# VAULT_ADDR, VAULT_TOKEN, TF_VAR_runner_cidrs, TF_ENCRYPTION을 주고 init/plan/apply
docker rm -f bao-dev
```
