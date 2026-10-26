# FortiGate Configuration Backup Role Task Specification

`fortigate_backup` 역할은 포티게이트 방화벽(IDC HA 클러스터와 사무실 장비)의 전체 설정을 Semaphore 예약 작업으로 받아 보관하고 보관 주기를 넘긴 파일을 정리한다. `cisco_backup`과 같은 구조이며 설계 배경은 [#282](https://github.com/ppzxc/infra-automation/issues/282), 구현 티켓은 #284다. 공개 저장소라 IP·포트·토큰·장비 상세는 적지 않는다(비공개 자료와 런북에서 관리).

---

## 1. 개요 및 구현 기능 (What)

- **접속 대상 단위 수집**: HA 관리 인터페이스가 없어 멤버별 직접 접속은 불가능하다. 백업 대상은 **접속 대상**(IDC 클러스터 1, 사무실 1)이며 인벤토리 호스트 하나가 대상 하나다. 대상은 `ansible_host`로 접속해 REST API(`/api/v2/monitor/system/config/backup`, 범위 `global`)로 전체 설정을 받는다. IDC 클러스터는 현재 active 멤버가 응답한다.
- **응답 멤버 식별**: 같은 접속으로 `/api/v2/monitor/system/status`를 먼저 조회해 실제 응답한 멤버(기본 hostname, 변수로 serial)를 파일명의 `<멤버>` 자리에 쓴다. 장애 전환으로 응답 멤버가 바뀌면 같은 대상인데 파일명의 멤버가 달라진다(4절).
- **인증**: `Authorization: Bearer <토큰>` 헤더. 토큰을 URL(`access_token`)에 넣지 않는다 — 최근 FortiOS는 기본으로 URL 토큰을 거부하고 이후 버전은 제거했으며, 헤더 방식이 대상 장비 버전 모두에서 공식 방식이다(Fortinet 관리 가이드 "Using APIs", 커뮤니티 기술 문서). 장비 모델·버전은 비공개 자료에 둔다.
- **무결성 검증**: HTTP 200이 아니거나 본문이 비었거나 FortiOS 설정 헤더(`#config-version=`)로 시작하지 않으면 저장하지 않고 호스트를 실패 처리한다. 기존 정상 백업은 건드리지 않는다.
- **권한**: 디렉터리 `0700`, 파일 `0600`. 설정에는 VPN 사전 공유 키와 관리자 해시가 들어 있다.
- **보관 주기**: `fortigate_backup_retention_days`(기본 90일)를 넘은 같은 대상(`<장비>_*`, 멤버 무관)의 파일을 백업 성공 직후 삭제한다. 변경 알림 전송이 실패해도 정리는 건너뛰지 않는다(호스트는 알림 실패로 실패 처리). 백업이 실패하면 정리도 하지 않는다.
- **접속 정보(OpenBao KV)**: 같은 KV에 스위치 시크릿과 같은 키 이름으로 `ansible_host`(주소), `ansible_port`(포트, 문자열), `fqdn`(도메인)을 둘 수 있다. 접속 대상은 `fqdn`이 있으면 `fqdn`(인증서 이름 검증), 없으면 주소다. 주소는 인벤토리의 `ansible_host`(호스트명과 다를 때)가 KV보다 우선이라 Semaphore 인벤토리에는 호스트명만 있어도 동작한다. 포트는 KV `ansible_port`, 없으면 `fortigate_backup_api_port`(기본 443)다. KV에 접속 키가 없으면 기존처럼 인벤토리 `ansible_host`를 쓴다. 주소·포트 값은 로그에 남기지 않는다(관련 태스크 `no_log`, 실패 메시지에도 값 없음).
- **시크릿**: 읽기 전용 API 토큰은 Git에 없다. Semaphore Environment(`fortigate_api_token`)로 호스트별 주입하거나 OpenBao KV `<mount>/fortigate/<인벤토리 호스트명>`의 `api_token`에서 읽는다(AppRole 또는 `VAULT_TOKEN`, `cisco_backup`·`backup`과 같은 환경변수). 토큰·응답 본문을 다루는 태스크는 `no_log`다.

---

## 2. 왜 구현해야 하는가? (Why)

1. 장비 교체·설정 실수 시 최신 설정으로 복구해야 한다(ISMS 2.9.3 백업 및 복구관리, 변경관리 증적).
2. 직전 백업과 비교해 승인 없는 변경을 감지하고 알린다(7절, #286).
3. 백업 계정이 탈취돼도 피해가 작아야 한다: 읽기 전용 프로파일, 접속 허용 출발지는 Semaphore만.

---

## 3. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `FGBK-001` | `Assert the backup target identity` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (장비·멤버 이름은 영문·숫자·하이픈만, 보관 일수 1 이상, 멤버 출처는 hostname/serial) |
| `FGBK-002` | `Log in to OpenBao with AppRole when no API token or Vault token is given` | `ansible.builtin.uri` | Controller / Localhost | POST `auth/approle/login`, `no_log`, Vault 토큰이 없고 AppRole 자격이 있을 때만 |
| `FGBK-003` | `Fetch the API token and connection info from OpenBao KV when OpenBao access is given` | `ansible.builtin.uri` | Controller / Localhost | GET(200 또는 404), `no_log`, OpenBao 인증이 있을 때만 (404면 인벤토리·Environment 값으로 계속) |
| `FGBK-004` | `Resolve and assert the read-only API token and the connection target` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용, `no_log` (토큰 없음·접속 주소 없음·포트가 숫자가 아님이면 장비를 호출하기 전에 실패, 값은 로그에 없음) |
| `FGBK-005` | `Ensure local backup destination directory exists (0700)` | `ansible.builtin.file` | Controller / Localhost | 디렉터리 상태 및 권한(`0700`) 일치 시 `ok` |
| `FGBK-006` | `Query the system status through the same connection to identify the responding member` | `ansible.builtin.uri` | Controller / Localhost | GET `system/status`, `changed_when: false`, `no_log`, 인증서 기본 검증 |
| `FGBK-007` | `Verify the status response names the responding member` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (200 + 응답 멤버 hostname/serial 확인, 위반 시 장비 설정을 받기 전에 실패) |
| `FGBK-008` | `Derive the responding member and the backup file name` | `ansible.builtin.set_fact` | Controller / Localhost | 순수 함수 (`<장비>_<멤버>_YYYYMMDDTHHMMSS.conf`, 멤버는 `[A-Za-z0-9-]` 외 문자를 `-`로 치환) |
| `FGBK-009` | `Download the full configuration from the target's management address` | `ansible.builtin.uri` | Controller / Localhost | GET `config/backup?scope=global`, `changed_when: false`, `no_log`, 인증서 기본 검증 |
| `FGBK-010` | `Verify the response is a non-empty FortiOS configuration` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (200 + 비어 있지 않음 + `#config-version=` 시작, 위반 시 저장 전에 실패) |
| `FGBK-011` | `Save the configuration to the backup destination (0600)` | `ansible.builtin.copy` | Controller / Localhost | 원자적 쓰기, `0600`, `no_log`, 같은 이름이 있으면 덮어쓰지 않음 |
| `FGBK-012` | `Find backup files of this target older than the retention period` | `ansible.builtin.find` | Controller / Localhost | 읽기 전용 (`<장비>_*.conf`, 수정 시각 기준) |
| `FGBK-013` | `Delete the expired backup files of this target` | `ansible.builtin.file` | Controller / Localhost | `state: absent` |
| `FGBK-014` | `Find the backup files of this target to locate the previous backup` | `ansible.builtin.find` | Controller / Localhost | 읽기 전용 (`<장비>_*.conf`) |
| `FGBK-015` | `Pick the previous backup of the same target (member may differ)` | `ansible.builtin.set_fact` | Controller / Localhost | 순수 함수 (마지막 `_` 뒤 시각 기준 직전 파일, 멤버 무관, 없으면 빈 값) |
| `FGBK-016` | `Read the previous backup for comparison` | `ansible.builtin.slurp` | Controller / Localhost | 읽기 전용, `no_log`, 직전 백업이 있을 때만 |
| `FGBK-017` | `Compare with the previous backup and keep only section and item names` | `ansible.builtin.set_fact` | Controller / Localhost | 순수 함수, `no_log`, `#` 헤더 줄 제외, 값은 결과에 넣지 않음 |
| `FGBK-018` | `Report the changed sections (names only, no values)` | `ansible.builtin.debug` | Controller / Localhost | 읽기 전용, 변경이 있을 때만 |
| `FGBK-019` | `Assert the alert webhook is configured when a change is detected` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (변경이 있는데 webhook이 없으면 실패) |
| `FGBK-020` | `Send the configuration change alert once` | `ansible.builtin.uri` | Controller / Localhost | POST, `no_log`, 변경이 있을 때만(변경이 없거나 첫 백업이면 건너뜀) |
| `FGBK-021` | `Assert the alert was delivered` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (전송 실패 시 호스트 실패) |

테스트는 [tests/test_fortigate_backup.py](../tests/test_fortigate_backup.py)다. 구조·3-Way 추적성은 정적으로, 동작(대상별 저장·응답 멤버 파일명·장애 전환 시 멤버 변경·`0600`, 상태·설정 응답이 비정상이거나 비면 저장 안 함과 실패, 보관 일수 정리, 토큰 비노출, 설정 변경 알림·첫 백업·멤버 전환·비밀 비노출)은 장비를 로컬 HTTP 서버(장비와 알림 수신기)로 모사해 역할을 실제 실행해 검증한다. 장비에는 닿지 않는다.

`molecule/*/verify.yml`은 두지 않는다. 역할이 컨트롤러(localhost)에서 REST API만 호출하고 대상 호스트에 상태를 만들지 않아 컨테이너 수렴 검증의 이득이 없고, `cisco_backup`과 같이 로컬 HTTP 서버로 장비를 모사한 pytest 실행 시험이 같은 방식으로 동작을 검증한다(3-Way 추적성의 검증 쪽은 이 pytest다).

---

## 4. 백업 파일 이름과 디렉터리 구조 (후속 티켓 #286 계약)

```text
<fortigate_backup_dir>/                      # 기본 <저장소>/backups/fortigate, 0700
  <장비>_<멤버>_YYYYMMDDTHHMMSS.conf         # 0600, 평문 FortiOS 설정 전체
```

- 평면 구조(하위 디렉터리 없음). `<장비>`는 **접속 대상**(인벤토리 호스트명 = 관리번호, 예: IDC 클러스터는 `ns0380`, 사무실은 `ns0399`)이고 `<멤버>`는 그때 실제로 응답한 장비의 hostname(또는 serial)이다. 둘 다 `[A-Za-z0-9-]+`로 밑줄이 없어 파일명은 `_`로 정확히 세 부분(장비·멤버·시각)으로 나뉜다.
- 시각은 컨트롤러 로컬 시간이고 문자열 정렬이 곧 시간 순서다.
- **#286의 비교 기준은 접속 대상 단위다.** 같은 `<장비>_` 접두사 파일 중 현재(가장 큰 이름)의 **바로 앞 시각 파일이 직전 백업**이며, 멤버가 같을 필요가 없다. 파일명으로 정렬할 때는 `<장비>_` 뒤의 멤버가 아니라 **마지막 `_` 뒤의 시각**을 키로 써야 한다(멤버 이름이 정렬에 섞이면 안 된다).
- **장애 전환**: active가 바뀌면 같은 대상인데 멤버 자리가 달라진 파일이 나온다(예: `ns0380_fw-a_…` 다음 `ns0380_fw-b_…`). 이 경우 설정 차이는 설정 변경이 아니라 멤버 고유 설정(hostname, HA 우선순위, 관리 인터페이스)에서 나올 수 있으므로 #286은 멤버가 바뀐 비교임을 알림에 표시하고 멤버 고유 줄을 변경으로 오탐하지 않게 다뤄야 한다.
- 백업이 실패하면 파일이 생기지 않으므로 "파일이 있다 = 유효한 설정"이다.
- 헤더 `#config-version=` 줄에 장비 버전·빌드 정보가 있어 펌웨어 업데이트만으로도 달라질 수 있다. `#`로 시작하는 헤더 줄은 비교에서 제외한다(7절).

### 알려진 한계

- **secondary 고유 설정은 백업되지 않는다.** 클러스터 주소로는 active 멤버만 응답하므로 secondary의 고유 설정(hostname, HA 우선순위, 관리 인터페이스 등)은 평상시 백업에 들어오지 않는다. HA 구성 멤버 간 공통 설정은 동기화되어 active 백업에 모두 들어 있다. secondary 교체 시 고유 설정은 공통 설정 복원 뒤 수동으로 다시 넣어야 하며, 장애 전환이 한 번 일어나면 그때 반대 멤버의 설정이 처음 백업된다.
- 상태 조회와 설정 조회는 별도 호출이라 그 사이에 전환이 일어나면 파일명 멤버가 실제와 다를 수 있다(드묾, 수초 간격).
- HA 관리 인터페이스가 생기면 멤버별 직접 접속으로 바꿀 수 있다(그때는 대상을 멤버별로 늘리고 같은 파일 규칙을 유지한다).

---

## 5. 원격 보관과 암호화 결정 (#284에서 확정)

설정 파일에는 VPN 사전 공유 키와 관리자 해시가 들어 있어 원격 보관 시 암호화가 필요하다.

| 결정 | 내용 | 근거 |
|---|---|---|
| 원격 보관 | 이 역할은 RustFS에 직접 올리지 않는다. 백업 디렉터리를 Semaphore 호스트의 호스트 에이전트 백업([backup.md](backup.md), restic → RustFS)의 `backup_extra_paths`에 넣어 소산한다. | 호스트 에이전트가 이미 일일 스냅샷·무결성 검사·유지보수·`backup_logs` 증적을 제공한다. 같은 일을 하는 업로드 경로와 RustFS 키를 하나 더 두면 중복이고 시크릿 표면만 늘어난다. |
| 전송·저장 암호화 | restic의 저장소 암호화(저장소 비밀번호 기반, 클라이언트 측)를 그대로 쓴다. 로컬 파일은 `0700/0600`만으로 보호하고 별도 파일 암호화를 하지 않는다. | RustFS에는 암호화된 데이터만 간다. 로컬 암호화는 키 관리를 하나 더 만들고, 변경 감지(#286)가 평문 비교를 해야 해 복잡도만 늘린다. |
| 보관 기간 | 로컬은 90일(변수). 원격 스냅샷은 restic 보존(daily 7 / weekly 4 / monthly 12)을 따른다. | 로컬 정리는 원격 스냅샷 이력을 지우지 않는다. 오래된 설정이 최대 12개월 원격에 남는 것은 restic 키 통제(호스트별 백업 키, 삭제 불가)로 감수한다. |

운영자는 백업 디렉터리가 호스트 에이전트의 백업 대상 경로인지 확인해야 한다(Semaphore가 컨테이너면 호스트 경로로 마운트되어 있어야 한다).

---

## 6. 플레이북 실행 및 Semaphore UI 연동

```bash
./docker-run.sh playbooks/backup_fortigate.yml
./docker-run.sh playbooks/backup_fortigate.yml --limit <인벤토리 호스트명>
```

1. **인벤토리**: 그룹 `fortigate_firewalls`에 접속 대상마다 호스트 하나(호스트명은 관리번호, 파일명의 `<장비>`). 호스트 변수는 `ansible_host`(IDC는 클러스터 주소)가 있으면 그것을 쓰고, 없으면 OpenBao KV의 접속 키를 쓴다(1절). 대상 목록: IDC 클러스터(`ns0380`; 쌍의 다른 멤버 `ns0381`은 대상이 아니다), 사무실 `ns0399`. 예시는 `inventory/hosts.yml.example`. Semaphore 인벤토리는 정적이므로 저장소 `group_vars`가 아니라 Semaphore 인벤토리에 직접 넣는다.
2. **Task Template**: Playbook `playbooks/backup_fortigate.yml`. Environment에 `VAULT_ADDR`와 AppRole(`VAULT_ROLE_ID`/`VAULT_SECRET_ID`)을 주입하거나 호스트별 `fortigate_api_token`을 Secret으로 주입한다.
3. **OpenBao KV**: `fortigate/<인벤토리 호스트명>`에 `api_token` 하나(접두사는 `OPENBAO_FORTIGATE_PREFIX`).
4. **예약**: 매일 03:30(`30 3 * * *`). 실패한 멤버가 있으면 Semaphore 실행이 실패로 끝나 기존 알림 채널로 전달된다.
5. **인증서**: 기본은 인증서 검증을 한다. 장비가 사설 인증서면 컨트롤러가 그 CA를 신뢰하게 하고, 검증을 끄는 `fortigate_backup_validate_certs: false`는 마지막 수단이다.

---

## 7. 설정 변경 감지와 알림 (#286)

백업을 저장한 직후(보관 정리 전) 같은 접속 대상의 **직전 백업**과 비교해 달라졌을 때만 알린다.

- **직전 백업**: 같은 `<장비>_` 파일 중 현재 바로 앞 시각의 파일이다. 정렬 키는 마지막 `_` 뒤 시각이고 멤버는 같지 않아도 된다(4절 계약). 없으면(첫 백업, 직전 파일이 보관 정리로 없어진 경우) 비교·알림 없이 정상 종료한다.
- **비교에서 제외**: `#`로 시작하는 헤더 줄(`#config-version`의 빌드·사용자·시각 등 매번 바뀌는 값). 이 줄만 다르면 알림이 없다. 줄은 섹션·항목(`config`/`edit`) 단위로 파싱하고 따옴표 안의 여러 줄 값(인증서)은 한 값으로 본다.
- **멤버가 바뀐 비교**: 장애 전환으로 직전 백업과 응답 멤버가 다르면 멤버 고유 설정(`config system global`의 `hostname`, `config system ha`의 `priority`)은 변경으로 세지 않고, 알림에 멤버 변경 비교임을 적는다.
- **반복 알림 금지(멱등)**: 비교는 항상 "직전 백업 대 이번 백업"이므로 같은 변경은 변경이 처음 보인 실행에서만 한 번 알린다. 다음 실행은 변경 후 상태끼리 비교해 조용하다.
- **비밀 비노출**: 알림과 로그에는 섹션·항목 이름과 바뀐 설정 키 이름만 나온다(예: `config system admin > edit "admin" (변경: password)`). 값(VPN 사전 공유 키, 관리자 해시, 인증서)은 어느 곳에도 쓰지 않으며, 설정을 다루는 태스크는 `no_log`다. 항목은 기본 20개까지 보이고 나머지는 건수로 줄인다.
- **통지 형식**: 기존 알림 형식(등급 P2, 무슨 일, 왜 중요, 대상, 조치, 런북)을 따라 네이버웍스 webhook으로 직접 보낸다. 런북은 [alerts.md](runbooks/alerts.md#fortigate-config-change)다.
- **설정**: `fortigate_backup_alert_webhook_url`(필수, 변경이 있을 때만 필요), `fortigate_backup_alert_webhook_token`, `fortigate_backup_alert_webhook_auth_header`(기본 `X-NANOIT-ACCESS`)를 Semaphore Environment로 주입한다. OpenBao `agents/openobserve`의 `alert_webhook_*`와 같은 값이다. 저장소에는 두지 않는다.
- **알림 실패**: webhook이 없거나 전송이 실패하면(3회 시도) 호스트를 `FORTIGATE-ALERT`로 실패 처리하고 변경 항목 이름을 로그에 남긴다. 백업은 이미 저장돼 같은 변경을 다시 알리지 않으므로 이때는 사람이 변경 항목을 확인해야 한다.
- **한계**: 값이 바뀐 사실만 알리고 무엇으로 바뀌었는지는 보여 주지 않는다(원본은 백업 파일 `diff`로 사람이 확인). 설정 키 이름이 같은 값 변경은 키 이름만 나온다.

---

## 8. 장비 쪽 준비 (사람이 수행)

API 계정 생성은 자동화하지 않는다. 최소 권한 관리자 프로파일과 REST API 관리자를 대상마다(IDC 쌍은 HA 동기화로 한 번) 만들고, 접속 허용 출발지(trusted host)를 Semaphore로 제한하고, 토큰을 위 경로로 주입한다. **주의: `config/backup` API는 완전 읽기 전용 프로파일로는 거부될 수 있다.** 벤더 연동 문서 중에는 백업을 위해 시스템 관련 접근 그룹에 쓰기 권한이 필요하다고 한 것이 있어(FortiOS 버전별로 다름) 대상 장비 버전에서 실제로 백업과 `system/status`가 되는 가장 낮은 권한 프로파일을 사람이 확인해 정한다. 이 프로파일은 trusted host로 Semaphore 출발지만 허용해 위험을 줄인다. 상세 명령과 체크리스트는 FortiOS 버전에 따라 달라 로컬 비공개 자료에서 관리한다(공개 저장소 원칙).

**실측 결과(IDC 장비 1대)**: 시스템 그룹을 사용자 정의로 두고 설정 항목은 읽기·쓰기, 유지보수 항목은 읽기로 올려도 `config/backup`은 403(본문에 오류 코드 없음)이었고, 시스템 그룹 전체를 읽기·쓰기로 올리자 성공했다. `system/status`는 더 낮은 권한에서도 성공했다. 따라서 백업 계정의 프로파일은 쓰기 권한을 갖는다. 이 위험은 trusted host를 Semaphore 한 곳으로 제한하고, 토큰을 OpenBao에만 두고, 이 계정의 관리자 로그인 이력을 `security_logs`로 감시하는 것으로 줄인다. 프로파일 이름과 설명에 읽기 전용이 아님을 적는다. 사무실 장비는 같은 확인을 따로 해야 한다.
