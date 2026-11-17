# OpenBao 구성 OpenTofu (`tofu/openbao`)

> Spec #511 / Ticket-6(#517). `infra` 네임스페이스의 마운트·정책·AppRole·userpass를 코드로 관리한다. 이 문서는 코드와 Semaphore 템플릿 정의까지다. 실제 `apply`와 첫 bootstrap은 운영자 작업이다. 저장소가 공개라서 주소·CIDR·계정·키 값은 여기에 쓰지 않는다(운영자 로컬 비공개 노트).

## 1. 구성

| 파일 | 내용 |
|---|---|
| `tofu/openbao/versions.tf` | OpenTofu·`hashicorp/vault` provider 버전 고정(`= x.y.z`), S3 backend, `pbkdf2` state·plan 암호화 |
| `tofu/openbao/provider.tf` | provider. 네임스페이스 `infra`, 자식 토큰 끔(`skip_child_token`) |
| `tofu/openbao/mounts.tf` | KV v2 마운트 `inventory/`·`secrets/` |
| `tofu/openbao/auth.tf` | userpass·approle 마운트, 운영자 사용자 |
| `tofu/openbao/applier.tf`, `policies/applier.hcl` | `applier` 정책·AppRole |
| `tofu/openbao/.terraform.lock.hcl` | provider 해시 고정(올릴 때 `tofu init -upgrade`로 갱신해 함께 커밋) |

작업 계열별 정책·AppRole 9개와 `operator`·`agent_session` 정책은 #518이 같은 디렉터리에 더한다.

## 2. 입력 값(저장소에 쓰지 않는다)

모두 Semaphore Environment(`applier` 전용, 비밀은 Secret 칸)로 넣는다.

| 이름 | 종류 | 내용 |
|---|---|---|
| `VAULT_ADDR` | env | OpenBao 주소 |
| `VAULT_TOKEN` | secret | 적용할 때마다 운영자가 직접 넣는다: 1회용 secret_id를 발급하고 `applier`로 로그인해 얻은 30분 토큰을 이 Environment 비밀에 붙여 넣는다(절차는 `openbao-operations`, #512). 토큰은 갱신하지 않으므로 plan, 사람의 확인, apply가 **30분 안에** 끝나야 한다. 넘기면 secret_id 발급부터 다시 한다. provider의 `auth_login`은 쓰지 않는다. `secret_id_num_uses = 1`이라 plan과 apply가 각각 새로 로그인해야 해서 두 번째가 실패한다 |
| `AWS_ENDPOINT_URL_S3` | env | state 저장소(RustFS) 주소 |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | secret | state 버킷 전용 키 |
| `TF_ENCRYPTION` | secret | pbkdf2 passphrase(3절) |
| `TF_VAR_runner_cidrs` | env | Semaphore 러너 CIDR 목록. JSON 배열 문자열, 예 `["<러너 CIDR>"]`. 기본값 없음 |
| `TF_VAR_operator_password_hashes` | secret | `{"<사용자>":"<bcrypt 해시>"}`. 해시는 `htpasswd -niBC 10 x \| cut -d: -f2 \| sed 's/^\$2y/$2a/'`로 만든다(비밀번호는 표준 입력 프롬프트로 입력, 명령행 인자 금지). 평문 비밀번호는 넣지 않는다 |

## 3. state·plan 암호화(pbkdf2)

state는 S3 호환 저장소의 `opentofu-state/openbao/terraform.tfstate`에 둔다. 암호화 블록은 변수를 받지 못하므로 passphrase는 `TF_ENCRYPTION` 환경변수로 `key_provider`만 채우고, 코드는 `method`·`enforced = true`만 가진다. 환경변수가 없으면 평문으로 쓰지 않고 실패한다.

```text
TF_ENCRYPTION=key_provider "pbkdf2" "main" { passphrase = "<16자 이상 임의 문자열>" }
```

- `openbao` key provider는 쓰지 않는다. OpenBao가 고장 나면 고칠 state를 못 여는 순환 의존이 생긴다.
- passphrase는 Semaphore 비밀과 운영자 비밀번호 관리자의 오프라인 사본에만 둔다. OpenBao에는 두지 않는다. 잃으면 state를 못 열어 `import`로 복구해야 한다.
- state·plan에는 `vault_generic_endpoint`의 `data_json`(bcrypt 해시)이 남는다. 그래서 암호화가 필수다. 로컬에서 plan 파일을 만들면 평문 노출을 막기 위해 같은 `TF_ENCRYPTION`을 쓴다.
- 기본 암호화 속성: pbkdf2 반복 600000회(OpenTofu 기본), aes_gcm.

## 4. applier

- 정책(`policies/applier.hcl`)은 `sys/policies/acl/*`, `auth/approle/role/*`, `sys/mounts/*`, `sys/auth/*`만 다룬다. 운영자 사용자 선언에 `auth/userpass/users/*`가 하나 더 필요하다(정책 연결·해시만). KV 데이터 경로(`inventory/`, `secrets/`)와 `auth/token/create`는 없다. 다른 AppRole의 `secret-id` 발급 경로는 `deny`로 막아 admin 런북으로만 발급하게 한다.
- state 잠금: backend에 `use_lockfile = true`(S3 조건부 쓰기)를 켰다. RustFS가 조건부 쓰기를 지원하는지는 첫 `init`·`plan`에서 확인해야 하며 아직 미확인이다. 지원하지 않으면 실패하므로 그때 이 옵션 처리를 정한다. 동시에 두 번 돌리지 않는다.
- 한계: 이 토큰이 KV를 직접 읽지는 못하지만 사실상 관리자 권한이다(#505). 자기 정책(`sys/policies/acl/*`)도 고칠 수 있어 `applier` 정책에 KV 경로를 더하면 즉시 읽을 수 있다. 정책을 직접 쓰고 userpass 사용자(해시)를 만들 수 있어 그 정책·사용자로 로그인하면 KV에 닿을 수 있다. 그래서 수명을 짧게 하고 CIDR로 묶고 Auto Approve를 끄며, 정책 변경은 PR 리뷰와 plan 확인을 거친다. 정책·role 목록 변경은 Periodic Check가 OpenTofu 밖 변경으로 잡는다.
- AppRole: `secret_id_ttl` 1일, `secret_id_num_uses` 1, `secret_id_bound_cidrs`·`token_bound_cidrs`는 `runner_cidrs`, 토큰 TTL 30분·최대 1시간.
- `secret_id`는 OpenTofu로 만들지 않는다(state에 남는다). 적용할 때마다 `bao` CLI response-wrapping으로 수동 발급한다(절차는 운영 런북 `openbao-operations`, #512).
- 첫 bootstrap: 네임스페이스 `infra` 생성과 `applier` 정책·AppRole 첫 생성만 루트 `admin`으로 한 번 한다. 이후는 `applier`로 한다. (`tofu apply`를 `admin` 토큰으로 처음 한 번 돌리는 방식이 가장 단순하다. 그때도 `skip_child_token`이 켜져 있다.)

## 5. Semaphore 템플릿 정의

| 항목 | 값 |
|---|---|
| 이름 | `OpenBao — OpenTofu` |
| 앱 | OpenTofu |
| 저장소 | 이 저장소(기본 브랜치) |
| Sub-directory path | `tofu/openbao` |
| Environment | OpenTofu 전용 Environment 하나(2절의 값). 다른 템플릿과 공유하지 않는다 |
| Auto Approve | **끔**. 템플릿에서도, 실행 때 토글도 켜지 않는다 |
| Allow destroy | 끔 |
| 실행 | 항상 `Plan`으로 먼저 돌려 diff를 사람이 확인한 뒤 같은 템플릿을 Plan 없이 실행해 승인한다. 토큰 수명(30분) 안에 끝낸다 |
| 스케줄 | 없음(수동만) |

Semaphore는 실행마다 `init`을 자동으로 한다. 내장 HTTP backend는 Pro라서 쓰지 않고 S3 backend를 쓴다.

## 6. 로컬·CI 검증

```bash
cd tofu/openbao
tofu fmt -check -recursive
tofu init -backend=false
tofu validate
```

CI(`.github/workflows/tests.yml`의 `tofu` 잡)가 같은 세 명령을 돈다. 운영 서버에는 닿지 않는다. 정적 구조 검사는 `tests/test_openbao_tofu.py`다. 실서버 허용·거부 시험은 전환 동결 창의 확인 목록에서 한다.

위험 확인(자식 토큰·버전 문자열·네임스페이스) 결과는 [openbao-opentofu-risk-check.md](runbooks/openbao-opentofu-risk-check.md)에 있다.
