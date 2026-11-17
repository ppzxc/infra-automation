# OpenBao 운영 런북 (Spec #511 / Ticket-1)

새 OpenBao 구조([ADR-0014](../adr/0014-openbao-storage-structure-and-access-policy.md))를 운영하며 반복하는 절차다. secret_id 발급과 교체, OpenTofu 적용, `operator` 사용자 추가, 비상용 `admin` 사용을 다룬다. 일회성 전환은 [openbao-cutover](openbao-cutover.md)에 있다.

공개 저장소이므로 주소·CIDR·계정 이름·시각은 이 문서에 쓰지 않는다. 값은 운영자 로컬 비공개 경로(`~/.local/share/infra-automation/openbao-restructure/`)에 두고 이슈에는 통과 여부만 적는다. 명령에는 값 대신 자리표시(`<...>`)를 쓴다.

## 1. 전제와 도구

| 항목 | 내용 |
|---|---|
| 네임스페이스 | `infra`. 모든 명령에 네임스페이스를 지정한다(`bao` CLI의 `-namespace=infra`) |
| 마운트 | `inventory/`(비밀 아님), `secrets/`(비밀) |
| AppRole | 계열별: `provision`·`host_agents`·`backup_maintenance`·`openobserve_config`·`host_audit`·`network_backup`·`github_webhook_watch`, 그리고 `periodic_check`·`agent_session`·`applier` |
| 정책·AppRole 원본 | OpenTofu 코드와 정책 HCL. 손으로 바꾸지 않는다(바꾸면 Periodic Check가 OpenTofu 밖 객체로 잡는다) |
| 비밀을 쓰는 곳 | secret_id는 Semaphore Environment(`VAULT_ROLE_ID`·`VAULT_SECRET_ID`)에만 둔다. Git·이슈·채팅에 붙이지 않는다 |

## 2. secret_id 발급과 교체

Semaphore용 AppRole의 `secret_id`는 TTL이 180일이고 러너 CIDR에 묶여 있다. OpenTofu로 발급하면 state에 남으므로 response-wrapping으로 수동 발급한다. 래핑 토큰은 한 번만 풀 수 있어 전달 중에 가로채이면 발급자가 알아챈다.

1. 교체할 계열과 Environment를 정한다(계열 하나당 Environment 하나). 만료가 가까운 순서는 Periodic Check 알림이나 `bao read -namespace=infra auth/approle/role/<계열>/secret-id-accessor` 목록으로 확인한다.
2. `operator`에는 `sys/`와 AppRole 권한이 없으므로 `admin`(§7)으로 래핑해 발급한다. 사유를 비공개 노트에 적는다.

   ```bash
   bao write -namespace=infra -wrap-ttl=5m -f auth/approle/role/<계열>/secret-id
   ```

3. 출력의 래핑 토큰을 한 번만 풀어 secret_id를 얻고, 곧바로 Semaphore Environment의 `VAULT_SECRET_ID`를 갱신한다. 셸 이력에 값이 남지 않게 한다(프롬프트로 입력하고 인자·환경변수에 값을 쓰지 않는다).

   ```bash
   bao unwrap -namespace=infra <wrapping_token>
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

## 4. OpenTofu 적용

정책·AppRole·마운트·userpass 변경은 모두 OpenTofu 코드로 한다.

1. 변경을 PR로 올린다. CI는 `tofu fmt`·`tofu validate`만 한다(실서버 허용·거부 시험은 하지 않는다).
2. 병합 뒤 Semaphore의 OpenTofu 템플릿을 **Auto Approve 없이** 실행해 plan을 사람이 확인한다. 의도하지 않은 destroy가 있으면 중단한다.
3. 적용은 `applier` AppRole로 한다. applier는 정책·role·마운트·auth만 다루고 KV 데이터는 읽지 못한다. `applier`의 secret_id는 짧게(1일) 두므로 적용할 때마다 §2와 같은 방식으로 수동 발급해 그 템플릿의 Environment에 넣는다.
4. 적용 뒤 정책이 바뀐 계열의 대표 실행을 한 번 돌려 허용과 거부(범위 밖 경로 403)를 확인한다.
5. OpenTofu 밖에서 만든 정책·role·마운트는 `plan`에 보이지 않는다. Periodic Check가 이를 탐지하면 코드로 편입하거나(`import`) 지운다.

러너 CIDR 등 환경 값은 `TF_VAR_*`로 Semaphore에서 넣고 저장소에 쓰지 않는다.

첫 OpenTofu 준비 때는 OpenBao 호환 위험 세 가지를 dev 서버로 손으로 확인하고 결과를 이 절에 적는다. 자식 토큰 발급 거부 가능성(거부되면 `skip_child_token`), 패키지 빌드에 따른 버전 문자열 파싱(문제면 `skip_get_vault_version`), 네임스페이스 인자다. provider 버전은 고정한다.

## 5. state passphrase 보관

state와 plan은 `pbkdf2`로 암호화한다. passphrase를 잃으면 state를 열 수 없고 `import`로 복구해야 한다.

| 보관 위치 | 용도 |
|---|---|
| Semaphore 비밀(OpenTofu 템플릿의 Environment) | 적용할 때 쓰는 정본 |
| 운영자 비밀번호 관리자의 오프라인 사본 | Semaphore가 고장 났을 때 state를 열기 위한 사본 |

OpenBao에는 두지 않는다. OpenBao가 고장 났을 때 고칠 state를 열 수 없는 순환 의존이 생기기 때문이다. passphrase를 바꿀 때는 두 곳을 함께 바꾸고, 바꾸기 전 state 사본을 비공개 경로에 남긴다.

## 6. operator 사용자 추가

`operator`는 `infra` 안 userpass 사용자다. 전체 읽기와 create/update만 있고 delete·destroy·`sys/`는 없다.

1. OpenTofu 코드의 운영자 사용자 목록에 사람을 추가하는 PR을 낸다(§4 절차로 적용).
2. 적용 뒤 본인이 초기 비밀번호를 정하고 바꾼다. 비밀번호는 비밀번호 관리자에만 둔다.
3. 로그인해 `inventory/`와 `secrets/`를 읽을 수 있고 삭제가 403으로 거부되는지 확인한다.
4. 사람이 나가면 같은 방식으로 사용자 항목을 지우고, 그 사람의 `inventory/operators/<사람>` 공개키 문서는 폐기 키로 옮긴다.

문서를 등록·수정할 때는 `operator` 토큰으로 `openbao_docs`의 `put`을 쓴다(정책으로 강제되지 않는 운영 규칙).

## 7. 비상용 admin 사용

`admin`은 루트 네임스페이스의 비상용 신분이다. 삭제, 영구 삭제(destroy), 정책 수동 변경이 필요할 때만 쓴다. 쓰기 전에 사유를 비공개 노트에 적고, 일이 끝나면 토큰을 폐기한다.

### 7.1 참조 중인 Credential 삭제

Credential을 지우면 그것을 가리키는 Endpoint의 접속이 깨진다. 삭제 전에 다음을 확인한다.

1. 지울 Credential의 경로와 이름을 적는다(`secrets/assets/<관리번호>/credentials/<이름>`).
2. 참조를 찾는다. Endpoint의 `credential`·`become.credential`, Asset 문서 `access`의 `admin_credentials`·`bootstrap_credential`, 경유(`via`)로 이 Asset의 Endpoint를 쓰는 다른 Asset을 모두 확인한다. 도구가 있으면 `openbao_docs check`가 깨진 참조를 알려 준다.
3. 참조가 남아 있으면 먼저 참조하는 문서를 `operator`로 고쳐 다른 Credential을 가리키게 한다. 참조가 하나라도 남으면 지우지 않는다.
4. 소프트 삭제(최신 버전 삭제)를 먼저 한다. 영구 삭제(destroy)는 소프트 삭제 뒤 Periodic Check가 통과하고 접속 작업이 정상임을 확인한 다음에만 한다.
5. 삭제 뒤 `openbao_docs check`로 전체를 대조하고, 해당 Asset을 쓰는 계열의 대표 실행을 한 번 돌린다.

### 7.2 정책 수동 변경

정책은 OpenTofu 코드가 원본이다. 장애 때문에 `admin`으로 손으로 바꿨다면 같은 변경을 바로 코드로 옮기는 PR을 내서 `plan`이 차이 없음이 되게 한다. 그렇지 않으면 Periodic Check가 OpenTofu 밖 객체로 계속 알린다.
