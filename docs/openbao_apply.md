# OpenBao 정책·AppRole 적용 도구 (`scripts/openbao_apply.py`)

> Spec #511, #505의 도구 선택을 대체한다(OpenTofu에서 Python 스크립트로, [ADR-0014](adr/0014-openbao-storage-structure-and-access-policy.md) 개정 줄). `infra` 네임스페이스의 마운트·정책·AppRole·userpass를 코드(`openbao/`)로 선언하고 이 스크립트가 서버를 코드에 맞춘다. 저장소가 공개라서 주소·CIDR·계정·키 값은 여기에 쓰지 않는다(운영자 로컬 비공개 노트).

## 1. 구성

| 파일 | 내용 |
|---|---|
| `openbao/roles.yml` | 선언 원본. 마운트(`inventory/`·`secrets/` KV v2), 인증 마운트(userpass·approle), 운영자 정책 연결, `applier` AppRole, 계열별 AppRole(정책 목록·`token_max_ttl`·`secret_id_ttl`). 관리 대상 AppRole 목록은 이 파일의 `families` 키에서 파생한다 |
| `openbao/policies/*.hcl` | 정책 본문 원본(정책 이름 = 파일명에서 `.hcl`을 뺀 것). `applier.hcl`이 적용 도구용 정책이다 |
| `scripts/openbao_apply.py` | `plan`·`apply` |
| `scripts/openbao_code.py` | 위 선언을 읽는 공용 로더(Periodic Check도 같이 쓴다) |

계열별 정책 목록은 `host_audit`까지 풀어서 쓴다(계산하지 않는다). `provision ∪ host_agents ∪ 자기 경로`와 어긋나면 `tests/test_openbao_policies.py`가 실패한다.

## 2. 사용법

저장소 루트에서 Python 3과 PyYAML가 있는 곳(운영자 작업 환경)에서 돌린다. 서버에는 `openbao/`만 있으면 된다.

```bash
python3 scripts/openbao_apply.py plan                       # 차이만 보고(쓰기 없음). 차이가 있으면 종료 코드 2
python3 scripts/openbao_apply.py apply                      # 차이만 쓴다
python3 scripts/openbao_apply.py apply --rotate-operators   # 운영자 비밀번호 해시도 모두 다시 쓴다
python3 scripts/openbao_apply.py --code-dir <디렉터리> plan  # 선언 디렉터리 지정(기본: openbao)
```

출력은 `종류<TAB>이름<TAB>동작`뿐이고 값(CIDR·해시·토큰·정책 본문)은 내지 않는다. 종료 코드는 0(정상, plan은 차이 없음), 1(서버·실행 오류, HTTP 상태만 출력), 2(plan에 차이 있음, 또는 입력·사용법 오류)다.

- `plan`은 서버를 읽기만 한다. 정책 본문, AppRole 설정 키(`token_policies`·`secret_id_ttl`·`secret_id_num_uses`·`token_ttl`·`token_max_ttl`·`secret_id_bound_cidrs`·`token_bound_cidrs`), 마운트·인증 마운트 존재, 운영자 사용자 존재와 연결 정책을 코드와 비교한다. AppRole 차이는 다른 설정 키의 이름만 보인다.
- `apply`는 그 차이만 쓴다. 두 번째 `apply`는 변경이 0이고, 이어서 `plan`하면 차이가 없다.
- KV 마운트는 없을 때만 만들고 삭제하거나 tune하지 않는다. 마운트를 지우면 안의 데이터가 모두 사라진다. 예외로 AppRole 인증 마운트의 `max_lease_ttl`은 `roles.yml` 값보다 낮으면 올린다(기본 32일이 role의 180일 `secret_id_ttl`을 깎기 때문이다). 서버 값이 더 크면 건드리지 않는다.
- 코드에 없는 정책·AppRole은 지우지 않고 `코드에 없음(삭제하지 않는다)`으로 보고만 한다. 지우는 일은 사람이 `admin`으로 한다([런북 7절](runbooks/openbao-operations.md)). 같은 항목을 Periodic Check가 `not_in_code`로 알린다.
- `secret_id`는 만들지 않는다. 수동 response-wrapping 런북으로 발급한다(4절).

## 3. 입력 값(저장소에 쓰지 않는다)

모두 환경변수다. 비밀은 셸 이력에 남지 않게 프롬프트로 입력한다.

| 이름 | 내용 |
|---|---|
| `VAULT_ADDR` | OpenBao 주소(필수). 네임스페이스는 `roles.yml`의 `infra`로 고정이다 |
| `VAULT_ROLE_ID`, `VAULT_SECRET_ID` | `applier` AppRole 로그인. 로그인으로 받은 토큰을 그대로 쓴다 |
| `VAULT_TOKEN` | bootstrap용 토큰(위 AppRole 변수가 없을 때만). 5절 참고 |
| `OPENBAO_RUNNER_CIDRS` | Semaphore 러너 출발지 CIDR 쉼표 목록. `applier`와 계열 AppRole의 `secret_id_bound_cidrs`·`token_bound_cidrs`. 비어 있으면 거부 |
| `OPENBAO_AGENT_SESSION_CIDRS` | `agent_session` AppRole의 출발지 CIDR 쉼표 목록. 비어 있으면 거부 |
| `OPENBAO_OPERATOR_PASSWORD_HASHES` | 선택. `{"<사용자>":"<bcrypt 해시>"}` JSON 맵. 비어 있으면 운영자 사용자는 다루지 않는다. bcrypt 형식이 아닌 값(평문 비밀번호)은 쓰기 전에 거부한다 |

운영자 비밀번호 해시는 서버 값과 비교하지 않는다. 운영자가 서버에서 바꾼 비밀번호를 드리프트로 보지 않는다. 해시는 사용자가 없거나 연결 정책이 다를 때, 또는 `apply --rotate-operators`일 때만 쓴다. 더 단순하게 하려고 "해시는 명시 옵션으로만 덮어쓴다"로 정했다.

해시는 비밀번호를 표준 입력 프롬프트로 입력해 만든다(명령행 인자 금지). 평문 비밀번호는 환경변수에 넣지 않는다.

```bash
htpasswd -niBC 10 x | cut -d: -f2 | sed 's/^\$2y/$2a/'
```

## 4. applier

- 정책(`policies/applier.hcl`)은 `sys/policies/acl/*`, `auth/approle/role/*`, `sys/mounts/*`, `sys/auth/*`와 운영자 사용자 선언용 `auth/userpass/users/*`만 다룬다. KV 데이터 경로(`inventory/`, `secrets/`)와 `auth/token/create`는 없다. 그래서 스크립트는 자식 토큰을 만들지 않고 AppRole 로그인 토큰을 그대로 쓴다. 다른 AppRole의 `secret-id` 발급 경로는 `deny`로 막아 admin 런북으로만 발급하게 한다.
- 한계: 이 토큰이 KV를 직접 읽지는 못하지만 사실상 관리자 권한이다(#505). 자기 정책(`sys/policies/acl/*`)도 고칠 수 있어 `applier` 정책에 KV 경로를 더하면 즉시 읽을 수 있다. 정책을 직접 쓰고 userpass 사용자(해시)를 만들 수 있어 그 정책·사용자로 로그인하면 KV에 닿을 수 있다. 그래서 수명을 짧게 하고 CIDR로 묶으며, 정책 변경은 PR 리뷰와 `plan` 확인을 거쳐 사람이 승인한다. 정책·role 목록 변경은 Periodic Check가 코드 밖 변경으로 잡는다. `secret-id` deny는 보안 경계가 아니라 가드레일이다: `bind_secret_id`와 CIDR을 바꾸거나 role-id를 읽는 경로와 정책 수정으로 우회할 수 있다. 더 좁히려면 정책 쓰기와 AppRole 변경을 분리한 별도 토큰이 필요하다(사용자 결정).
- AppRole: `secret_id_ttl` 1일, `secret_id_num_uses` 1, `secret_id_bound_cidrs`·`token_bound_cidrs`는 러너 CIDR, 토큰 TTL 30분·최대 1시간.
- `secret_id`는 이 스크립트가 만들지 않는다. 적용할 때마다 `bao` CLI response-wrapping으로 수동 발급한다(절차는 [운영 런북 2절](runbooks/openbao-operations.md)).

## 5. 적용 절차와 bootstrap

`secret_id_num_uses`가 1이라 AppRole 변수로 `plan`과 `apply`를 따로 돌리면 두 번째 로그인이 실패한다. 둘 중 하나를 쓴다.

1. **토큰 한 번 받기(권장)**: `secret_id`를 발급해 `applier`로 한 번 로그인하고 받은 30분 토큰을 `VAULT_TOKEN`에 넣어 `plan`, 사람의 확인, `apply`, 다시 `plan`을 **30분 안에** 끝낸다. 넘기면 `secret_id` 발급부터 다시 한다. 토큰은 갱신하지 않는다.
2. **한 번에 apply**: `VAULT_ROLE_ID`·`VAULT_SECRET_ID`로 `apply`만 돈다. `apply`도 바뀐 항목을 출력하므로 확인은 그 출력과 Git diff로 한다.

첫 bootstrap(`infra` 네임스페이스 생성은 이미 돼 있다고 본다)은 루트 `admin` 토큰으로 `VAULT_TOKEN`을 주고 `apply`를 한 번 돈다. `applier` 정책과 AppRole, 마운트, 나머지가 한 번에 만들어진다. 이후는 `applier`로 한다. 그 뒤 `plan`이 차이 없음(종료 코드 0)이어야 한다.

적용 뒤 정책이 바뀐 계열의 대표 실행을 한 번 돌려 허용과 거부(범위 밖 경로 403)를 확인한다.

**새 계열 AppRole을 추가한 경우**(예: `ledger`, Spec #630): `apply`는 정책과 AppRole 정의만 만든다. `secret_id` 발급([운영 런북 2절](runbooks/openbao-operations.md))과 Semaphore Environment(`VAULT_ADDR`·`VAULT_ROLE_ID`·`VAULT_SECRET_ID`) 등록은 운영자 단계이고 이 도구가 하지 않는다. 비밀 값 문서 적재도 운영자가 `operator`로 한다. `ledger`에는 서버 접속용 `connect`가 아직 없고 수집 템플릿(#645)의 별도 PR에서 더한다.

## 6. 검증

CI는 `pytest tests/`의 `tests/test_openbao_apply.py`(선언 코드 정적 검사와 공용 가짜 OpenBao 통합 검사: 멱등, `plan` 종료 코드, 값 비노출, 삭제·tune·`secret_id` 발급 없음), `tests/test_openbao_policies.py`(계열 × 경로 매트릭스), `tests/test_openbao_docs_check.py`(Periodic Check)가 돈다. 실서버 허용·거부 시험은 전환 동결 창의 확인 목록에서 한다.
