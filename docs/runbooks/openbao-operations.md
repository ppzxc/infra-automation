# OpenBao 운영 런북 (Spec #511 / Ticket-1)

새 OpenBao 구조([ADR-0014](../adr/0014-openbao-storage-structure-and-access-policy.md))를 운영하며 반복하는 절차다. secret_id 발급과 교체, 정책 적용(`openbao_apply.py`), `operator` 사용자 추가, 비상용 `admin` 사용을 다룬다. 일회성 전환은 [openbao-cutover](openbao-cutover.md)에 있다.

공개 저장소이므로 주소·CIDR·계정 이름·시각은 이 문서에 쓰지 않는다. 값은 운영자 로컬 비공개 경로(`~/.local/share/infra-automation/openbao-restructure/`)에 두고 이슈에는 통과 여부만 적는다. 명령에는 값 대신 자리표시(`<...>`)를 쓴다.

## 1. 전제와 도구

| 항목 | 내용 |
|---|---|
| 네임스페이스 | `infra`. 모든 명령에 네임스페이스를 지정한다(`bao` CLI의 `-namespace=infra`) |
| 마운트 | `inventory/`(비밀 아님), `secrets/`(비밀) |
| AppRole | 계열별: `provision`·`host_agents`·`backup_maintenance`·`openobserve_config`·`host_audit`·`network_backup`·`github_webhook_watch`, 그리고 `periodic_check`·`agent_session`·`applier` |
| secret_id 수명 | Semaphore 계열 AppRole(7개)과 `periodic_check`: 180일(단 이 AppRole은 만료되면 알림을 보낼 검사 자체가 멈추므로 알림 대상이 아니고 §3 4번으로 따로 챙긴다). `applier`: 1일(적용할 때마다 발급). `agent_session`: 24시간. 30일 전 만료 알림은 Semaphore 계열 AppRole 7개가 대상이다. `applier`·`agent_session`은 만료가 짧아 알림 없이 필요할 때 새로 발급한다 |
| 정책·AppRole 원본 | `openbao/roles.yml`과 `openbao/policies/*.hcl`. 손으로 바꾸지 않는다(바꾸면 Periodic Check가 코드 밖 객체(`not_in_code`)로 잡는다) |
| 비밀을 쓰는 곳 | secret_id는 Semaphore Environment(`VAULT_ROLE_ID`·`VAULT_SECRET_ID`)에만 둔다. Git·이슈·채팅에 붙이지 않는다 |

## 2. secret_id 발급과 교체

Semaphore용 AppRole의 `secret_id`는 TTL이 180일이고 러너 CIDR에 묶여 있다. `openbao_apply.py`는 secret_id를 만들지 않으므로 response-wrapping으로 수동 발급한다. 래핑 토큰은 한 번만 풀 수 있어 전달 중에 가로채이면 발급자가 알아챈다.

1. 교체할 계열과 Environment를 정한다(계열 하나당 Environment 하나). 만료가 가까운 것은 Periodic Check 알림으로 알고, 폐기할 옛 accessor는 `bao list -namespace=infra auth/approle/role/<계열>/secret-id`로 목록을 보고 `bao write -namespace=infra auth/approle/role/<계열>/secret-id-accessor/lookup secret_id_accessor=<accessor>`로 만료 시각을 확인해 고른다.
2. `operator`에는 `sys/`와 AppRole 권한이 없으므로 `admin`(§7)으로 래핑해 발급한다. 사유를 비공개 노트에 적는다.

   ```bash
   bao write -namespace=infra -wrap-ttl=5m -f auth/approle/role/<계열>/secret-id
   ```

3. 출력의 래핑 토큰을 한 번만 풀어 secret_id를 얻고, 곧바로 Semaphore Environment의 `VAULT_SECRET_ID`를 갱신한다. 셸 이력에 값이 남지 않게 한다(프롬프트로 입력하고 인자·환경변수에 값을 쓰지 않는다).

   ```bash
   read -rs BAO_TOKEN && export BAO_TOKEN   # 래핑 토큰을 프롬프트로 입력(인자·이력에 남기지 않는다)
   bao unwrap -namespace=infra
   unset BAO_TOKEN
   ```

4. 해당 계열 템플릿을 한 번 실행해 로그인되는지 확인한다(읽기 전용 실행이나 `--check`).
5. 확인이 끝나면 옛 secret_id를 accessor로 폐기한다.

   ```bash
   bao write -namespace=infra auth/approle/role/<계열>/secret-id-accessor/destroy secret_id_accessor=<accessor>
   ```

6. 비공개 노트의 만료 일정에 새 만료일을 적는다.

교체 주기는 180일이다. 새 secret_id를 먼저 발급하고 Environment를 갱신한 뒤에 옛 것을 폐기하므로 작업이 끊기는 구간이 없다.

## 3. 만료 알림 대응

Periodic Check가 secret_id 만료 30일 전에 `alert/notify`로 알림을 보낸다. 알림에는 AppRole 이름과 규칙 이름만 있고 값은 없다.

1. 알림이 가리키는 AppRole의 계열을 확인한다.
2. 30일 안에 §2 절차로 교체한다. 만료되면 그 계열 템플릿이 로그인에 실패해 멈춘다.
3. 교체 뒤 다음 Periodic Check가 통과하는지 확인한다. 알림이 계속되면 폐기하지 않은 옛 secret_id의 accessor가 남았는지 본다.
4. `periodic_check` AppRole 자신의 secret_id도 같은 주기로 교체한다. 만료되면 알림 자체가 오지 않으므로 비공개 노트의 일정으로 따로 챙긴다.

## 4. 정책 적용(`openbao_apply.py`)

정책·AppRole·마운트·userpass 변경은 모두 선언 코드(`openbao/`)로 하고 `scripts/openbao_apply.py`로 적용한다([openbao_apply.md](../openbao_apply.md)).

1. 변경을 PR로 올린다. CI는 `pytest`의 `tests/test_openbao_apply.py`·`tests/test_openbao_policies.py`가 정적 검사와 가짜 OpenBao 통합 검사를 한다(실서버 허용·거부 시험은 하지 않는다).
2. 병합 뒤 운영자 작업 환경에서 `applier`로 적용한다. `applier`의 secret_id는 짧게(1일, 1회용) 두므로 적용할 때마다 §2와 같은 방식으로 수동 발급한다. 로그인해 받은 30분 토큰을 `VAULT_TOKEN`에 넣고(또는 `VAULT_ROLE_ID`·`VAULT_SECRET_ID`로 `apply`만) 아래 순서로 한다.

   ```bash
   python3 scripts/openbao_apply.py plan    # 차이만 본다. 의도하지 않은 변경이 있으면 중단한다(종료 코드 2는 차이 있음)
   python3 scripts/openbao_apply.py apply   # 차이만 쓴다
   python3 scripts/openbao_apply.py plan    # 다시 plan하면 변경이 없다(종료 코드 0)
   ```

3. `applier`는 정책·role·마운트·auth만 다루고 KV 데이터는 읽지 못한다. `applier` 정책에는 `auth/token/create`가 없어야 하고, 스크립트는 자식 토큰을 만들지 않고 AppRole 로그인 토큰을 그대로 쓴다.
4. 적용 뒤 정책이 바뀐 계열의 대표 실행을 한 번 돌려 허용과 거부(범위 밖 경로 403)를 확인한다.
5. 코드 밖에서 만든 정책·role·마운트는 `plan`이 `코드에 없음`으로 보고만 하고 `apply`도 지우지 않는다. Periodic Check가 `not_in_code`로 알리면 코드로 편입하거나 `admin`(§7)으로 지운다. KV 마운트는 지우거나 tune하지 않는다(AppRole 인증 마운트의 `max_lease_ttl`만 올린다).

러너·에이전트 세션 CIDR(`OPENBAO_RUNNER_CIDRS`·`OPENBAO_AGENT_SESSION_CIDRS`)과 운영자 해시는 환경변수로 넣고 저장소에 쓰지 않는다.

## 5. 운영자 비밀번호 해시 만들기

`OPENBAO_OPERATOR_PASSWORD_HASHES`의 값은 bcrypt 해시다. 평문 비밀번호는 넣지 않는다(스크립트가 거부한다). 비밀번호는 프롬프트로 입력하고 명령행 인자에 쓰지 않는다.

```bash
htpasswd -niBC 10 x | cut -d: -f2 | sed 's/^\$2y/$2a/'
```

해시는 서버 값과 비교하지 않는다. 운영자가 서버에서 바꾼 비밀번호는 `plan` 차이가 아니고, 해시를 다시 쓰려면 `apply --rotate-operators`를 쓴다.

## 6. operator 사용자 추가

`operator`는 `infra` 안 userpass 사용자다. 전체 읽기(list 포함)와 create/update만 있고 delete·destroy·`sys/`는 없다.

1. 사람의 이름과 bcrypt 해시(§5)를 `OPENBAO_OPERATOR_PASSWORD_HASHES` 맵에 더해 §4 절차로 적용한다(사용자 목록의 원본은 저장소가 아니라 이 환경변수다. `operator` 정책 연결은 `openbao/roles.yml`).
2. 적용 뒤 본인이 초기 비밀번호를 정하고 바꾼다. 비밀번호는 비밀번호 관리자에만 둔다.
3. 로그인해 `inventory/`와 `secrets/`를 읽을 수 있고 삭제가 403으로 거부되는지 확인한다.
4. 사람이 나가면 같은 방식으로 사용자 항목을 지우고, 그 사람의 `inventory/operators/<사람>` 공개키 문서는 폐기 키로 옮긴다.

문서를 등록·수정할 때는 `operator` 토큰으로 `openbao_docs`의 `put`을 쓴다(정책으로 강제되지 않는 운영 규칙).

## 7. 비상용 admin 사용

`admin`은 루트 네임스페이스의 비상용 신분이다. 삭제, 영구 삭제(destroy), 정책 수동 변경이 필요할 때만 쓴다. `admin` 자격은 운영자 비밀번호 관리자의 오프라인 사본에 보관하고 OpenBao·Semaphore가 고장 난 때에도 이 경로로 꺼낸다. 허용되는 정기 용도는 `applier`·`agent_session` secret_id 발급(§2, §4)이고, 그 밖에는 삭제·영구 삭제·정책 수동 변경이다. 쓰기 전에 사유를 비공개 노트에 적고, 일이 끝나면 토큰을 폐기한다.

### 7.1 참조 중인 Credential 삭제

Credential을 지우면 그것을 가리키는 Endpoint의 접속이 깨진다. 삭제 전에 다음을 확인한다.

1. 지울 Credential의 경로와 이름을 적는다(`secrets/assets/<관리번호>/credentials/<이름>`).
2. 참조를 찾는다. Endpoint의 `credential`·`become.credential`, Asset 문서 `access`의 `admin_credentials`·`bootstrap_credential`, 경유(`via`)로 이 Asset의 Endpoint를 쓰는 다른 Asset을 모두 확인한다. 도구가 있으면 `openbao_docs check`가 깨진 참조를 알려 준다.
3. 참조가 남아 있으면 먼저 참조하는 문서를 `operator`로 고쳐 다른 Credential을 가리키게 한다. 참조가 하나라도 남으면 지우지 않는다.
4. 소프트 삭제(최신 버전 삭제)를 먼저 한다. 영구 삭제(destroy)는 소프트 삭제 뒤 Periodic Check가 통과하고 접속 작업이 정상임을 확인한 다음에만 한다.
5. 삭제 뒤 `openbao_docs check`로 전체를 대조하고, 해당 Asset을 쓰는 계열의 대표 실행을 한 번 돌린다.

### 7.2 정책 수동 변경

정책은 `openbao/`의 선언 코드가 원본이다. 장애 때문에 `admin`으로 손으로 바꿨다면 같은 변경을 바로 코드로 옮기는 PR을 내서 `plan`이 차이 없음이 되게 한다. 그렇지 않으면 다음 `apply`가 코드대로 되돌리고, 코드에 없는 객체는 Periodic Check가 `not_in_code`로 계속 알린다.

## 8. applier가 지켜야 할 제약

`applier`는 사실상 관리자 권한이지만 다음 제약 위에서 동작해야 한다(로컬 dev 서버로 확인한 사실, #517).

- **자식 토큰 없이 동작한다**: `applier` 정책에는 `auth/token/create`가 없어서 자식 토큰 발급이 403이다. 그래서 스크립트는 자식 토큰을 만들지 않고 AppRole 로그인으로 받은 토큰을 그대로 쓴다. 정책에 그 경로를 더하지 않는다.
- **네임스페이스는 헤더로 준다**: 모든 호출에 `X-Vault-Namespace: infra`를 붙이면 마운트·정책·AppRole·userpass 생성과 읽기, AppRole·userpass 로그인, 정책 거부(`secrets/`·`auth/token/create` 403)가 모두 통과한다.
- **운영자 사용자는 해시로만 만든다**: userpass 사용자를 `password_hash`(bcrypt, `$2a$`) 없이 만들면 `must provide either password or password_hash`로 거부된다. 그래서 스크립트는 평문 비밀번호 대신 해시만 받는다.
- **`secret-id` deny는 가드레일이다**: `auth/approle/role/+/secret-id` 등을 `deny`로 두면 `applier` 토큰의 secret_id 발급이 403이다. 보안 경계는 아니다([openbao_apply.md](../openbao_apply.md) 4절).
- **KV는 쓰지 못한다**: `applier` 토큰으로 `secrets/`에 KV를 쓰려 하면 403이다. 정책 조회·변경은 통과한다.

실서버 확인은 전환 동결 창의 확인 목록에서 운영자가 한다.

## 9. 실패한 실행 뒤 남은 임시 키

접속 해석 뒤 플레이에서 호스트가 실패하면 컨트롤러 임시 디렉터리에 복호화한 키 파일(`*_bao_{admin,boot,hop}_key`, `*_bao_*_key.askpass`)이 다음 실행 때까지 남을 수 있다. 파일은 `0600`이고 다음 `resolve_connection`이 12시간 지난 것을 지운다. 실패한 실행 뒤에는 컨트롤러에서 이 이름의 파일이 남아 있는지 보고, 있으면 지운다.
