# 이 저장소에서 계정을 이미 관측·관리하는 코드

[#622](https://github.com/ppzxc/infra-automation/issues/622) 조사 결과다. 상위 지도는 [#618](https://github.com/ppzxc/infra-automation/issues/618)(Host Account 원장, idc-access)이다.
2026-11-20에 `origin/main` `204ebe8`을 기준으로 읽었다. 이 문서의 줄 번호는 모두 그 커밋 기준이다.
근거는 이 저장소의 코드·스키마·ADR·`CONTEXT.md`뿐이다. OpenBao와 서버에는 조회하지 않았다. 인벤토리 데이터에 있는 호스트 이름·주소·계정 이름은 적지 않았고, 코드에 들어 있는 계정 이름은 변수 이름으로만 쓴다.

## 요약

- **관측은 Host Audit Asset Inventory 한 곳에만 있다.** raw POSIX sh 프로브 한 번으로 `/etc/passwd`, `/etc/shadow`(상태 단어만), wheel·sudo·admin 그룹, sudoers, lastlog를 읽는다. CentOS 6/7, Raw Provisioning Path 호스트, 에이전트만 설치된 호스트를 모두 같은 경로로 수집한다. 다만 #618이 정한 관측 항목 중 **보조 그룹 전체, 만료, `authorized_keys` 지문은 수집하지 않는다.** 기준선 비교도 **이름 단위의 추가·삭제만** 본다. 대상은 로그인 가능 계정과 특수권한 계정뿐이며, **월 1회 정기 실행끼리만** 비교한다.
- **관리는 `common` 롤 `accounts` 한 경로다.** 운영에서 `accounts`는 OpenBao Asset 문서의 `access.admin_credentials`에서 만들어진다. 그래서 실제로 만들어지는 계정은 **`tier: admin`뿐**이다(문서가 설명하는 3계층 admin/operator/user는 쓰이지 않는다). 공개키는 `inventory/operators/<계정 이름>`에서 읽는다. 시스템 계정은 롤 기본값에 하드코딩돼 있다(`docker_engine`의 `docker_svc_user`, `monitoring`의 `otelcol_user`).
- **`docker_operators`는 죽은 변수다.** 정의(`roles/docker_engine/defaults/main.yml:21`)와 ADR-0002 설명만 있고 아무 태스크도 읽지 않는다.
- **"선언된 계정" 목록을 읽는 소비자가 이미 셋 있다.** Host Audit 특수권한 허용 목록, Log Review 1부 1번 허용 계정, `security` 롤 `authorized_keys` 감시 대상이다. 원장이 생기면 셋 다 원장을 읽어야 한다.
- **확인된 결함 후보:** #578 뒤로 Host Audit 실행에서는 `accounts`가 비어, 특수권한 허용 목록에 관리 계정이 들어가지 않는다. 그래서 sudo 권한이 있는 관리 계정이 모두 '선언 외'로 나올 수 있다(아래 1.4).
- **ADR·용어 충돌:** `CONTEXT.md` Operator 정의("Not an account on an Asset")는 이미 코드와 어긋난다. 코드는 Operator 문서를 계정 이름으로 찾는다. ADR-0009 Considered Options의 "Git에 계정을 남기지 않는다"와 "CMDB 기각", ADR-0014의 소유 대상 목록에 Host Account가 없는 점도 원장이 대체하거나 고쳐야 할 조항이다(아래 3절).

---

## 1. 관측: Host Audit Asset Inventory

### 1.1 수집(호스트 쪽)

| 항목 | 출처 | 근거 |
|---|---|---|
| 실행 방식 | `ansible.builtin.raw`로 `sh -c <inventory_probe.sh>`를 실행한다. `become: true`, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` | `roles/host_audit/tasks/inventory.yml:12-20` |
| 이름·UID·GID·셸 | `awk -F: '{print "passwd=" $1 "|" $3 "|" $4 "|" $7}' /etc/passwd`. 홈 디렉터리와 GECOS는 버린다 | `roles/host_audit/files/inventory_probe.sh:77` |
| 비밀번호 상태 | `/etc/shadow` 2번째 필드만 `set`/`locked`/`empty`로 줄인다. `!`와 `*`로 시작하면 모두 `locked`(즉 `!!`, `*`도 locked). 해시는 호스트를 떠나지 않는다. 읽지 못하면 `shadow_unreadable=1` | `inventory_probe.sh:4-5`, `:78-82` |
| 만료·비밀번호 나이 | **수집 안 함.** shadow 3~8번째 필드(마지막 변경, 최소·최대, 경고, 비활성, 만료일)는 읽지 않는다 | `inventory_probe.sh:79` |
| 그룹 | **`wheel`·`sudo`·`admin` 세 그룹의 구성원만** 읽는다. 보조 그룹 전체와 `docker`·`disk`·`shadow`는 읽지 않는다 | `inventory_probe.sh:83`, `filter_plugins/host_audit_inventory.py:53` |
| sudoers | `/etc/sudoers`와 `/etc/sudoers.d/*`에서 주석·`Defaults`·빈 줄을 뺀 규칙 줄을 읽는다 | `inventory_probe.sh:84-88` |
| 마지막 로그인 | `lastlog`(없으면 `lastlog2`) 전체와 `-t 90` | `inventory_probe.sh:89-99` |
| `authorized_keys` | **수집 안 함** | 프로브 전체(120줄)에 없음 |
| 계정 원천 | `/etc/passwd` 파일만 읽는다. `getent`를 쓰지 않으므로 NSS/SSSD/LDAP 계정은 보이지 않는다 | `inventory_probe.sh:77` |

대상 호스트는 `host_audit_scope_pattern: "servers:loadbalancers:overseer:!host_audit_excluded"`다(`roles/host_audit/defaults/main.yml:14`). Host Agents Exclusion 호스트와 CentOS 6/7 호스트도 포함되고 `host_audit_excluded` 그룹만 빠진다(`docs/host_audit.md:15`). raw 조회라 CentOS 6~Rocky 10, Ubuntu가 같은 경로다(`docs/host_audit.md:16`, `:127` AUD-100). Raw Provisioning Path라서 따로 다루는 분기는 없다. ADR-0009 §4가 Raw Provisioning Path를 점검불가로 두는 대상은 **Configuration Drift**뿐이다(`docs/adr/0009-host-audit-read-only-inspection.md:13`).

### 1.2 해석(러너 쪽)

- `_accounts()`는 사용자마다 `name, uid, gid, shell, login, password, last_login, recent_login`을 만든다(`filter_plugins/host_audit_inventory.py:207-243`). `login`은 셸 이름이 `nologin|false|sync|shutdown|halt`가 아니면 참이다(`:52`, `:232`).
- **특수권한 근거**는 uid 0, `wheel`·`sudo`·`admin` 구성원, sudoers 규칙 대상이다. 규칙에 `NOPASSWD`가 있으면 표시한다(`:244-273`). `User_Alias`·`Runas_Alias`·`#include`·`@include` 줄은 건너뛴다(`:261-262`). 그래서 별칭과 include 파일 안의 권한은 펼쳐지지 않는다(`docs/host_audit.md:166`).
- 보고서 행(`_account_rows`)은 **로그인 가능 계정과 특수권한 계정만** 남긴다. 로그인할 수 없고 특수권한도 없는 계정(시스템 계정)은 버려진다(`:468-475`). sudoers 대상 중 `/etc/passwd`에 없는 이름도 행으로 남긴다(`:495-503`).
- '장기 미사용'은 로그인 가능 계정 중 `lastlog -t 90`에 없는 계정이다. 점검 계정과 uid 0은 제외한다(`:480-483`, `docs/host_audit.md:167`).

### 1.3 기준선 비교(Audit Baseline)

- 계정 발견의 정체는 `account:<이름>`과 `privileged:<이름>`이다(`filter_plugins/host_audit_baseline.py:216-237`). 비교 키는 (호스트, 섹션, id)다(`:17`).
- Asset Inventory 항목은 판정이 아니라 **변경**이라 `신규`와 `삭제` 두 가지뿐이다(`:22-24`, `:470-484`). **같은 이름의 UID·셸·비밀번호 상태·그룹이 바뀐 것은 드러나지 않는다.** `privileged:` id의 label에는 근거가 붙지만 id 자체는 이름뿐이다(`:226-227`).
- Host Audit에 새로 들어온 호스트의 계정은 신규로 세지 않는다(`:475`).
- 기준선은 **직전 정기(scheduled) 실행**이다. 수시 실행은 기준선이 되지 않는다(`:1-8`, ADR-0009 §5). 정기 실행은 Semaphore `Host Audit — Monthly`로 **월 1회**다(`docs/semaphore-setup.md:15`).
- 산출물(호스트별 JSON 포함)은 RustFS **GOVERNANCE 3년 잠금 버킷**에 올라간다(`docs/host_audit.md:455-475`, ADR-0009 §6). 올린 뒤에는 지울 수 없다.

### 1.4 특수권한 허용 목록과 #578의 부작용

- 허용 목록은 `host_audit_privileged_allowlist(accounts, openbao_ssh_allowed_principals, host_audit_privileged_extra)`에 root를 더한 것이다(`roles/host_audit/tasks/inventory.yml:39-40`, `filter_plugins/host_audit_inventory.py:637-653`, `:470`). `accounts` 중 sudo 권한 계정만 고른다.
- #578(`d1c0e87`) 뒤로 `playbooks/host_audit.yml:34`는 `connection_needs_accounts: false`를 넘긴다. 그러면 `admin_accounts`가 `[]`이고(`lookup_plugins/openbao_connection.py:219`), `resolve_connection.yml:204-213`이 `accounts`를 빈 목록(+삭제 대상 absent 항목)으로 덮어쓴다.
- `openbao_ssh_allowed_principals`는 `access_security` 롤 기본값이다(`roles/access_security/defaults/main.yml:17-19`). Host Audit 플레이는 이 롤을 싣지 않으므로 `| default([])`로 빈 목록이 된다. 저장소의 `group_vars`에도 정의가 없다.
- **추론:** Semaphore가 `host_audit_privileged_extra` 등을 실행 변수로 넘기지 않는다면, #578 이후 정기 실행에서는 sudo 권한이 있는 관리 계정이 모두 '선언 외'로 표시된다. 서버 실행 결과로는 확인하지 않았다. Log Review 1부 1번은 `accounts`가 아니라 `_normalized_admin_users`(`admin_users`)를 같이 읽으므로 영향이 없다(`roles/host_audit/tasks/log_review.yml:150-168`).

### 1.5 같은 데이터를 쓰는 다른 Host Audit 항목

- **KISA-2026 U-01~U-13(계정 관리)**: `roles/host_audit/files/kisa/U-01.sh`~`U-13.sh`, 카탈로그 `filter_plugins/host_audit_kisa_items.yml`. 특히 **U-07(불필요한 계정 제거)**과 **U-08(관리자 그룹 최소 계정)**은 "불필요"를 판단할 근거가 없어 **점검불가(수동)**로 두고 목록만 증적으로 낸다(`kisa/U-07.sh:1-3`, `kisa/U-08.sh:1-4`).
- **Log Review 1부 1번(허가되지 않은 계정 로그인)**의 허용 계정 집합은 `_allowed()`가 만든다(`filter_plugins/host_audit_log_review_accounts.py:172-190`). 집합은 선언 관리 계정, bootstrap 계정, root다. 에이전트만 설치된 호스트는 **Asset Inventory가 관측한 계정 목록 자체를 허용 목록으로 쓴다**(`:178-182`, `:193-224`). 관측과 허용 기준이 같은 출처라서 순환한다.

---

## 2. 관리(쓰기)와 계정 관련 설정

### 2.1 `common` 롤 `accounts`

- 롤 기본값에는 admin 계정 한 개가 하드코딩돼 있다(`roles/common/defaults/main.yml:10-16`, `keys: []`). 운영 실행에서는 `resolve_connection.yml`이 `set_fact accounts`로 이 값을 덮는다(`playbooks/common/resolve_connection.yml:204-213`).
- 모듈 경로 태스크(`roles/common/tasks/main.yml`):
  - `COMMON-012`(:146) 기본 그룹을 만든다.
  - `COMMON-013`(:159) `ansible.builtin.user`로 계정을 만든다. 보조 그룹은 admin이면 `wheel`/`sudo`에 `item.groups`를 더한다. `state: absent`면 `remove: true`로 홈까지 지운다.
  - `COMMON-014`(:186) `/etc/sudoers.d/90-<이름>`에 `NOPASSWD:ALL`을 쓴다.
  - `COMMON-015`(:203)는 키를 배포하고, `COMMON-022`(:232)는 `revoked_keys`를 회수하며, `COMMON-023`(:247)은 삭제한 계정의 sudoers를 지운다.
  - **`authorized_key`는 `exclusive`를 쓰지 않으므로 선언에 없는 키는 그대로 남는다.**
- Raw Provisioning Path의 같은 짝은 `COMMON-027`~`COMMON-033`이다(`roles/common/tasks/main.yml:414-530`). `filter_plugins/raw_provisioning.py:282-301`의 `groupadd`/`useradd`/`usermod`/`userdel`을 쓴다. raw 태스크는 `--check`에서 건너뛴다(ADR-0005).
- `docs/common.md:16`, `:54`는 admin/operator/user 3계층과 `docker`·`dockermgmt` 보조 그룹을 설명한다. 하지만 아래 2.2대로 운영 경로가 만드는 항목은 언제나 `tier: admin`이다.

### 2.2 `accounts`의 출처: `admin_accounts`와 OpenBao

- `admin_accounts()`(`lookup_plugins/openbao_connection.py:171-194`)는 Asset 문서 `access.admin_credentials`의 Credential마다 `username`을 계정 이름으로 쓴다. 항목은 항상 `{"tier": "admin", "shell": "/bin/bash", ...}`이다(:192-193).
  - Endpoint 기본 Credential이 `identity: automation`이면 그 계정의 키는 **Automation Identity** `secrets/automation/ssh`의 `public_key` 하나다(:184-188).
  - 그 밖에는 `inventory/operators/<username>`의 `public_keys`·`revoked_keys`다(:189-191).
- 읽는 문서 패턴은 `ADMIN_ACCOUNTS_READS = ("inventory/assets/+", "inventory/operators/+")`이다(:51).
- `host_connections()`는 `with_accounts=False`면 이 목록을 만들지 않는다. 다만 `admin_names`(관리 계정 이름)는 항상 돌려준다(:197-222).
- **삭제 경로:** Asset 문서 `access.removed_accounts`와 실행 변수 `target_removed_users`의 합집합이 `state: absent` 항목이 된다(`resolve_connection.yml:128-168`, `:204-213`). ISMS 2.5.1 증적은 debug로 남긴다(:181-189).
- **자기 차단 방지가 이미 하나 있다.** 접속 계정, bootstrap 계정, 이번 실행에서 선언한 관리 계정을 지우려 하면 `[REMOVED-USER-CONFLICT]`로 실패한다(`resolve_connection.yml:192-202`).
- Host Agents(`playbooks/host_agents.yml:31`)와 Host Audit(`playbooks/host_audit.yml:34`)은 `connection_needs_accounts: false`다(`docs/openbao_integration.md:83`).

### 2.3 OpenBao 스키마

| 문서 | 내용 | 근거 |
|---|---|---|
| `inventory/operators/+` | `public_keys`(필수, 1개 이상)와 `revoked_keys`가 전부다. `additionalProperties: false`라서 이름·소속·만료·GWS 식별자를 둘 자리가 없다. 제목은 `<사람>`이지만 실제 키(문서 이름)는 계정 이름이다 | `schemas/openbao/inventory/operator.schema.json:1-28`, `schemas/openbao/index.yml:6`, `docs/openbao_integration.md:31`, `:71` |
| `inventory/assets/+` → `access` | `admin_credentials`(Credential 이름 목록), `bootstrap_credential`, `removed_accounts`(계정 이름 목록), `python_interpreter` | `schemas/openbao/inventory/asset.schema.json:58-87` |
| `secrets/assets/+/credentials/+` | `type`·`username`·비밀. 계정 이름(`username`)이 Credential 안에 있다 | `schemas/openbao/secrets/credential.schema.json` |
| `secrets/automation/ssh` | Automation Identity: `private_key`(필수), `public_key`, `passphrase` | `schemas/openbao/secrets/automation_ssh.schema.json` |

#578 이슈 본문은 `inventory/operators/`에 문서가 하나뿐이라서 그 밖의 관리 계정(사람이 아닌 계정 포함)을 참조하는 호스트 30대가 실패했다고 적었다. 사람(Operator)과 계정(Credential `username`)이 같은 이름 공간에 섞여 있다는 직접 증거다.

### 2.4 `docker_engine`

- `docker_operators: ["{{ admin_user | default(<개인 계정>) }}"]`(`roles/docker_engine/defaults/main.yml:21-22`)를 **읽는 태스크가 없다**(저장소 전체 grep 결과 정의와 ADR-0002 설명뿐이다). ADR-0002는 "`docker_operators`에 등록하면 그룹·심볼릭 링크가 구성된다"고 적었지만(`docs/adr/0002-docker-account-directory-permissions.md:37`) 실제 태스크는 `accounts`를 돈다.
  - `DOC-013`(docker 그룹, `roles/docker_engine/tasks/main.yml:163`)
  - `DOC-019`(dockermgmt·docker, :250)
  - `DOC-020`(홈 심볼릭 링크, :267)
  - 조건은 `item.docker | default(tier in [admin, operator])`다.
- 서비스 계정: `DOC-014`는 `dockermgmt` 그룹(GID 2000)을 만들고(:181), `DOC-015`는 `docker_svc_user`(UID `docker_svc_uid`=2000, `/sbin/nologin`, system)를 만든다(:188). 문서와 코드가 다르다. ADR-0002 표는 이 계정을 UID 998로 적었다(`0002...md:31`).
- CentOS 6은 `ansible_distribution_major_version >= 7` 조건으로 빠진다.

### 2.5 `monitoring`

- `MON-001`/`MON-002`는 `otelcol_group`과 `otelcol_user`를 만든다(`roles/monitoring/tasks/main.yml:71`, `:89`, 기본값 `roles/monitoring/defaults/main.yml:6-7`). system, `/sbin/nologin`, 보조 그룹 `adm`/`systemd-journal`에 docker 소켓 그룹이 있으면 그것도 더한다.
- `MON-014`/`MON-015`는 레거시 `node_exporter` 사용자와 그룹을 지운다(:53, :61).
- 레거시(CentOS 6/7 raw) 경로는 컬렉터를 root로 실행하고 계정을 만들지 않는다(`roles/monitoring/tasks/legacy.yml:7`).

### 2.6 `access_security`(OpenBao SSH CA principals)

- `ACC-006`은 `accounts` 중 admin 또는 sudo 계정마다 `/etc/ssh/auth_principals/<이름>`을 쓴다. 내용은 `openbao_ssh_allowed_principals`이고 기본값은 `admin`과 `admin_user`다(`roles/access_security/tasks/main.yml:55-73`, `defaults/main.yml:17-19`). CA 공개키가 비어 있으면 아무것도 하지 않고, CentOS 6은 제외한다. 이 값은 Host Audit 허용 목록에도 들어간다(1.4).

### 2.7 `security` 롤: `authorized_keys` 감시(내용 감사는 아님)

- `security` 롤은 `authorized_keys`의 **내용을 감사하지 않는다.** auditd watch(`-p wa -k ssh_keys`)만 건다.
- 대상은 root와 `audit_ssh_key_accounts`, 즉 `accounts` 중 키가 있고 absent가 아닌 계정이다(`roles/security/defaults/main.yml:121-134`). **원장 밖 계정의 `authorized_keys`는 감시하지 않는다.**
- 홈은 `getent passwd`로 찾는다(`roles/security/tasks/main.yml:154-172` SEC-092/093, 모듈 경로 SEC-090/091 :1039-1050).
- 같은 템플릿이 `/etc/passwd`·`shadow`·`group`·`gshadow`(`-k identity`)와 `sudoers`(`-k sudo_config`)를 감시한다(`roles/security/templates/audit.rules.j2:26-37`, `:54-58`).
- 이 규칙은 `security` 롤을 적용한 호스트에만 있다. 에이전트만 설치된 호스트에서 auditd 기록이 수집되는지는 이 조사에서 확인하지 않았다.

### 2.8 OpenObserve 계정 변경 알림(이벤트, 상태 아님)

| 알림 | 무엇을 | 근거 |
|---|---|---|
| `infra-account-change`(P2) | auditd `ADD_USER`·`DEL_USER`·`USER_MGMT`·`USER_CHAUTHTOK`·`ACCT_LOCK` 등. 특권 그룹(`o2c_privileged_groups: wheel, sudo, docker, root, disk, shadow`) 변경은 따로 표시한다 | `roles/openobserve_config/defaults/main.yml:186-188`, `:710-737` |
| `infra-audit-watch-change` | 계정 도구를 거치지 않은 직접 수정(`identity`·`sudo_config`·`ssh_keys` 감시 키). 계정 도구 목록(`o2c_audit_account_tools`)은 중복을 막으려고 뺀다 | `:380-392`, `:931-940` |
| `infra-audit-watch-provisioning`(P3) | 프로비저닝 접속 계정(`audit_provisioning_accounts`, OpenBao `inventory/config/openobserve_config`)의 정상 변경 후보 | `:413-420`, `:1008` |
| `infra-sudo-risky-command` | `userdel` 포함 위험 sudo 명령 | `:198`, `:738` |
| `infra-ssh-login-new-user` | 지난 N일 동안 성공 기록이 없던 사용자의 SSH 로그인 | `:856` |

이 알림들은 **변경 이벤트**를 본다. 원장과 비교해 "있어야 할 계정이 없다", "없어야 할 계정이 있다"를 판정하는 **상태 비교**는 없다. 특권 그룹 정의도 서로 다르다. OpenObserve는 6개 그룹(docker·disk·shadow 포함)을 보고 Host Audit은 3개(wheel·sudo·admin)를 본다.

---

## 3. 원장과 부딪히거나 대체가 필요한 조항

### 3.1 ADR-0009(Host Audit)

| 조항 | 내용 | 원장과의 관계 |
|---|---|---|
| §1(`0009:10`) | 읽기 전용 = 계정을 포함한 관리 상태 불변. 로그인 흔적은 허용 | 관측 단계와 **충돌하지 않는다.** #618 첫 단계(서버 변경 없음)와 같은 정의다. ADR-0016과 #589도 이 정의를 그대로 가져갔다 |
| §5(`0009:14`) | Audit Baseline = 직전 **정기** 실행 | Account Drift를 "직전 실행 대비 변화만 알람"(#618의 ADR-0016 선례)으로 만들려면 월 1회 주기와 기준선 규칙이 맞지 않는다. 새 개념으로 분리해야 한다 |
| §6(`0009:15`) | 보관은 RustFS 3년 잠금 버킷. Host Audit은 조치를 추적하지 않는다 | 계정↔직원 매핑을 Host Audit 산출물에 넣으면 3년 동안 지울 수 없다 |
| Considered Options, CMDB(`0009:22`) | "월간 보고서가 실사 내역이므로 CMDB 제품은 불필요" | 원장은 계정 범위의 CMDB 역할을 한다. 이 기각 이유를 계정에는 적용하지 않는다고 적어야 한다 |
| Considered Options, Git 보관(`0009:23`) | "**Git에는 계정·포트·취약점이 남는다**"는 이유로 결과를 Git에 두지 않는다 | `idc-access`(비공개 Git)에 계정을 두는 결정과 정면으로 부딪힌다. ADR-0016이 방화벽에 대해 "비공개 저장소라서 둔다"로 푼 선례가 있다 |
| Consequences(`0009:30`) | 점검 계정은 Deploy와 같은 관리 계정이고, 최소 권한 감사 전용 계정은 후속 작업이다 | automation 종류 Host Account를 원장에 올릴 때 이 계정이 점검·배포를 겸한다는 사실이 드러난다. 장기 미사용 판정 제외 규칙(`host_audit_inventory.py:480`)도 이 계정 기준이다 |
| 2026-11-19 개정(`0009:43`) | 스위치는 Asset Inventory를 하지 않는다 | #618 범위(리눅스만)와 같다. 충돌 없음 |

### 3.2 ADR-0014(OpenBao 구조)

| 조항 | 내용 | 원장과의 관계 |
|---|---|---|
| 결정 2(`0014:15`) | 소유 대상은 Asset, Service, **Operator**, Automation Identity | Host Account(그리고 Employee·Access Grant)가 소유 대상에 없다. 원장이 정본이 되면 "Operator의 공개키 정본은 OpenBao `inventory/operators/`"가 원장으로 옮겨 간다(**부분 대체**). 시크릿만 OpenBao에 남는다는 #618 정본 규칙과 맞추려면 비밀이 아닌 공개키가 `inventory/`에 남는 이유도 다시 적어야 한다 |
| 결정 3(`0014:16`) | 스키마 강제, `additionalProperties: false`, 등록 도구로만 쓴다 | `operator.schema.json`에는 소속·만료·GWS 식별자를 넣을 수 없다. 원장 쪽으로 옮기거나 스키마를 바꿔야 한다 |
| 결정 6(`0014:19`) | 사람은 OpenBao `operator`(userpass)와 `admin`으로 나눈다 | 같은 단어 "operator"가 OpenBao 사용자 역할로도 쓰인다. 새 용어가 이것과 섞이지 않게 해야 한다 |
| Consequences(`0014:36`) | 새 Asset 유형은 Endpoint·Credential만 더해 받는다 | 계정 정보가 Credential `username`과 `access.admin_credentials`/`removed_accounts`에 흩어진다. 원장의 Access Grant와 두 정본이 된다 |
| `docs/openbao_integration.md:31`, `:71`, `:84` | Operator 공개키 위치, 관리 계정은 `common` 롤이 만든다, `removed_accounts`가 삭제 입력이다 | #618이 이미 부분 대체 대상으로 적은 서술이다. `removed_accounts`·`target_removed_users`(삭제 입력)도 원장 PR 흐름과 겹친다 |

### 3.3 `CONTEXT.md`

| 용어 | 현재 정의 | 쟁점 |
|---|---|---|
| Operator(`CONTEXT.md:83-85`) | "A person ... holding personal SSH public keys ... **Not an account on an Asset**" | 코드는 이미 Operator 문서를 **계정 이름**으로 찾는다(2.3). Employee(GWS 신원)와 Host Account(person)로 나누면 이 정의를 고치거나 대체해야 한다 |
| Credential(`:71-73`) | `_Avoid_: account (when the secret is meant)` | 새 용어 Host Account는 비밀이 아니라 계정을 가리키므로 이 금지어와 충돌하지 않는다. 다만 Credential `username`과 Host Account 이름이 어느 쪽이 정본인지 정해야 한다 |
| Automation Identity(`:75-77`) | 여러 Asset에 공개키가 깔린 자동화 키 쌍. 어느 Asset의 Credential도 아니고 Operator 키도 아니다 | #618의 `automation` 종류 Host Account는 이 키를 받는 **계정**이다. Identity(키)와 Account(계정)를 구분해 적어야 한다 |
| Asset Inventory(`:55-57`) | 계정과 특수권한자를 포함한 호스트 기록이고 Host Audit이 만든다 | Account Drift의 관측 원천 후보다. 정의를 바꿀 필요는 없지만 원장과의 관계(관측 vs 정본)를 적어야 한다 |
| Configuration Drift(`:107-109`) / Audit Baseline(`:111-113`) | 전자는 Git 선언 대비 check 모드 차이이고 Raw Provisioning Path에서는 볼 수 없다. 후자는 "직전 정기 실행 대비 Asset Inventory 변경(새 계정·포트·특수권한자)" | Account Drift는 둘 다와 다르다(원장 대비, check 모드 불필요). Audit Baseline의 "새 계정" 변경과 Account Drift를 구분하는 문장이 필요하다. Firewall Drift(`:199-201`)가 같은 구분의 선례다 |

### 3.4 그 밖의 ADR

- **ADR-0002**(`docs/adr/0002-docker-account-directory-permissions.md:25-37`): 서비스 계정, 운영자 계정, `docker_operators` 등록 절차를 정한다. 원장이 `service`·`person` 계정을 관리하면 이 표와 절차(이미 코드와 다름)를 대체하게 된다.
- **ADR-0005**(Raw Provisioning Path): 계정 쓰기(COMMON-027~033)가 이 경로에 있다. #618의 "적용 단계"가 CentOS 6/7을 다룰 때 출발점이다.

---

## 4. Account Drift 관측: Host Audit 수집 재사용과 새 읽기 전용 수집기의 근거

판단은 하지 않고 근거만 나열한다.

### 4.1 재사용 쪽 근거

- 프로브가 이미 전체 대상(에이전트만 설치된 호스트, CentOS 6/7, Raw Provisioning Path 포함)에서 raw·읽기 전용으로 돈다. 읽기 전용 검증 장치(pytest의 `check_mode: false` 조회 전용 검사, molecule 실행 전후 체크섬 `VERIFY-AUD-010`)도 있다(`docs/host_audit.md:32`, ADR-0009 §1).
- 이름·UID·GID·셸·비밀번호 상태(set/locked/empty)·sudo 근거·NOPASSWD·마지막 로그인을 이미 정규화한다(`host_audit_inventory.py:207-280`). #618 관측 항목 중 절반가량이 있다.
- 비밀번호 해시를 호스트에서 상태 단어로 줄이는 규약이 이미 있다(`inventory_probe.sh:4-5`). #618의 "설정됨/없음/잠김"과 같은 모양이다.
- 접속 해석(`resolve_connection`), 동시 접속 제한, 수집 실패를 점검불가로 남기는 규칙, 메일·RustFS 경로를 그대로 쓸 수 있다.
- 원장을 첫 초안으로 만들 데이터(관측 → 초안, 드리프트 0에서 시작)는 정기 실행마다 호스트별 JSON(`hosts/<Inventory Hostname>.json`)으로 이미 보관된다(`docs/host_audit.md:37`, `:470`).
- KISA U-07·U-08이 원장을 읽으면 점검불가(수동)에서 자동 판정으로 바꿀 여지가 생긴다(1.5).

### 4.2 새 수집기 쪽 근거

- **필드 공백:** 보조 그룹 전체, shadow 만료·나이, `authorized_keys` 지문, 홈 디렉터리, NSS 계정이 없다(1.1). 추가하려면 `inventory_probe.sh`(Host Audit 증적 프로브)를 바꿔야 한다. 그러면 호스트별 JSON `schema_version`(기준선 비교 호환, `docs/host_audit.md:165`, `:449`)과 3년 보관 증적의 모양이 함께 바뀐다.
- **필터링:** 보고서 행과 기준선은 로그인 불가·비특권 계정을 버린다(`host_audit_inventory.py:473-474`). #618은 "전체 관측, 시스템 계정은 개수만"을 요구한다. 원본 `users`는 JSON에 남지만 비교 경로는 쓰지 않는다.
- **비교 의미:** 기준선은 이름 단위 신규·삭제뿐이고 속성 변화는 보지 않는다(1.3). Account Drift는 원장 대비이지 직전 실행 대비가 아니다.
- **주기와 실행 단위:** Host Audit 정기 실행은 월 1회다. Package Vulnerability(Trivy)·KISA·Drift 하위 실행·보고서까지 한 덩어리라 실행이 무겁다(러너 메모리 1024M 이상, `docs/semaphore-setup.md:36`). 계정만 자주 보려고 전체를 돌릴 수는 없다. 다만 `--tags`나 별도 템플릿으로 inventory 단계만 떼어 낼 수 있는지는 확인하지 않았다.
- **보관 제약:** 산출물은 3년 잠금 버킷에 간다(ADR-0009 §6). 원장·직원 매핑과 섞이면 지울 수 없다. ADR-0009 Considered Options는 Git 보관을 계정 이름 때문에 기각했다(`0009:23`).
- **선례:** 방화벽은 Host Audit에 붙이지 않고 별도 읽기 전용 수집기(플레이북, "판단하지 않는다")를 두되, **읽기 전용 정의만 Host Audit과 같게** 했다(#589 본문 "모듈 구성 1. 수집기", ADR-0016 Consequences `0016:34`). 드리프트는 check 모드가 아니라 수집 상태 비교로 판정하고 알람은 직전 실행 대비 변화만 보낸다(`0016:15`, `0016:24`).
- **허용 목록 경로 결함:** 지금 특수권한 '선언 외' 판정은 #578 이후 선언 출처를 잃었을 가능성이 있다(1.4). 재사용하면 이 판정을 원장 기준으로 다시 짜야 한다.
- **CentOS 6 지문 계산:** CentOS 6의 OpenSSH는 `ssh-keygen -l`이 MD5만 낼 수 있다(확인 안 함). 호스트에서 공개키 본문을 받아 러너에서 SHA256 지문을 계산하는 방법이 대안이 될 수 있다(검증 안 함). 어느 쪽이든 프로브에 새 읽기가 필요하다.

### 4.3 중립 근거(어느 쪽이든 필요)

- 원장 소비자 세 곳(Host Audit 허용 목록, Log Review 1부 1번 허용 계정, `security` 롤 `audit_ssh_key_accounts`)은 수집 방식과 무관하게 원장을 읽도록 바꿔야 한다.
- 특권 그룹 정의가 Host Audit(3개)과 OpenObserve 알림(6개) 사이에서 다르다(2.8). 원장이 sudo·특권 그룹을 정의하면 둘 다 맞춰야 한다.
- 정기 태스크의 호스트 목록은 Semaphore static 인벤토리를 따른다(`docs/semaphore-setup.md:90`, `:104`). 이 함정은 수집 방식과 무관하다.

---

## 5. 불확실한 점

1. **1.4의 '선언 외' 오표시**는 코드 경로로 추론한 것이다. Semaphore Environment나 템플릿이 `host_audit_privileged_extra`나 `openbao_ssh_allowed_principals`를 실행 변수로 넘기는지는 확인하지 않았다. #578 이후 정기 실행 보고서로 확인해야 한다.
2. 에이전트만 설치된 호스트에서 auditd 계정 변경 기록이 OpenObserve로 오는지(2.7, 2.8)는 이 조사 범위 밖이다.
3. Host Audit의 inventory 단계만 따로 돌릴 수 있는지(태그·별도 템플릿)는 확인하지 않았다.
4. CentOS 6 `ssh-keygen`의 지문 형식은 확인하지 않았다.
5. `/etc/passwd` 밖(NSS/SSSD/LDAP) 계정이 있는 호스트가 실제로 있는지는 서버를 보지 않아 모른다.
