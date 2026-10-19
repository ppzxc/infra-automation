# OpenObserve Config Role Task Specification

> **상태: 구현됨.** `openobserve_config` 역할은 [ADR-0008](adr/0008-log-structuring-edge-envelope-central-semantics.md)에 따라 OpenObserve의 VRL ingest function, 파이프라인, 통지 대상(webhook), 알림 규칙을 이 저장소의 정의로 관리하고 OpenObserve API로 반영합니다. 호스트에는 접속하지 않는 **컨트롤러 전용** 역할이며 `playbooks/openobserve_config.yml`이 유일한 진입점입니다.

---

## 1. 개요 (What)

- **VRL ingest function `security_semantics`** (`roles/openobserve_config/files/vrl/security_semantics.vrl`): `security_logs`의 sshd·sudo·su 메시지를 해석해 필드를 **추가**합니다. 원문 `body`와 기존 필드는 바꾸지 않으며, 해석할 수 없는 레코드는 그대로 통과합니다. 필드는 OTel semantic conventions를 따르고 OpenObserve가 점을 밑줄로 저장하므로 아래 이름으로 보입니다.

  | 필드 | 의미 |
  |---|---|
  | `user_name` (`user.name`) | sshd 로그인 대상 사용자 / sudo를 실행한 사용자 |
  | `source_address`, `source_port` (`source.address`, `source.port`) | sshd 원격 주소·포트 (`Invalid user` 줄에 포트가 없으면 `source_port` 없음) |
  | `event_action` | `ssh_login`, `sudo` 또는 `su` |
  | `event_outcome` | `success` 또는 `failure` |
  | `event_reason` | 실패 사유: `failed password`, `invalid user`, `NOT in sudoers`, `authentication failure` |
  | `user_effective_name`, `process_command_line` | sudo 대상 사용자(`USER=`)와 실행 명령(`COMMAND=`) — sudo 성공은 알림 없이 이 필드로 감사 기록만 남김 |

  입력 필드는 엣지(#91)가 만든 `process_executable_name`(= `sshd`/`sudo`)와 원문 `body`입니다. 엣지와 필드 계약이 바뀌면 같은 PR(또는 연속 PR)에서 함께 고칩니다.
- **파이프라인** `security_semantics`: `security_logs` 실시간 소스 → 함수(`after_flatten: true`) → `security_logs`.
- **통지 대상**: webhook 하나(`infra-automation-webhook`) — 네이버웍스 봇 text API(`{"content": {"type": "text", "text": ...}}`)로 보내는 본문 템플릿과 `Content-Type: application/json` 헤더. 등급별 분리는 범위 밖입니다.
- **알림 메시지**: 행동 가능한 형식 — 심각도(🔴P1·🟠P2·🟡P3)와 제목, 무슨 일, 왜 중요, 대상(알림별 `row_template`), 조치, [런북](runbooks/alerts.md) 링크, 로그 보기 링크, 발생 구간. 알림별 문구는 `o2c_alerts`의 `severity`·`title`·`what`·`why`·`action`·`runbook`(`context_attributes`로 전달)에 둔다.
- **알림 규칙 7종(8개 정의)**: 모두 위 대상으로 보냅니다.

  | 이름 | 조건 |
  |---|---|
  | `infra-ssh-login-failures-per-source` | `source_address`별 5분 10회 이상 sshd 로그인 실패 |
  | `infra-ssh-login-failures-per-host` | 호스트별 5분 50회 이상 sshd 로그인 실패 |
  | `infra-root-login-success` | 정상 출발지 목록 밖의 root SSH 로그인 성공 1건부터 (P1, Event Alert). Semaphore·사무실 종류 출발지는 제외 |
  | `infra-root-login-office-daily` | 사무실 종류 출발지의 root SSH 로그인 성공, 하루 1번 요약 (P3, period·silence 1440) |
  | `infra-sudo-escalation-failure` | sudo/su `authentication failure`/`NOT in sudoers` 1건부터 (`event_action IN (sudo, su)`, 성공은 알리지 않음) |
  | `infra-oom-kill` (P2) | `system_logs`의 `Killed process`·`Kill process`·`invoked oom-killer`를 대소문자 무시(`lower(body)`)로 매칭. 행에 호스트·종료된 프로세스명 |
  | `infra-disk-fs-errors` (P1) | `system_logs`의 `I/O error`, `EXT4-fs error`, `XFS ... Corruption`, `blk_update_request`, `Buffer I/O error` (대소문자 무시, severity가 아닌 패턴 기반). 옛 `infra-kernel-disk-errors`를 대체하며 서버에서 삭제된다 |
  | `infra-app-log-errors` (P2) | `app_logs`의 `severity`가 error 이상(`error`·`err`·`severe`·`fatal`·`critical`·`panic`·`dpanic`, 대소문자 무시)인 줄을 호스트·컨테이너별로 5분 1건부터(Event Alert). 레벨은 수집기가 JSON `level`·`log.level`, valkey 레벨 문자에서 올린 값이며 키워드 추정은 없다. WARN은 알리지 않는다 (Spec #236) |
  | `infra-log-parse-errors-security-logs` / `-system-logs` | `log.parse_error=true` 비율이 10% 이상(최소 20줄, 30분 창) |

  - **Silent Host 2개 정의 (Spec #184 / Ticket-4, `stream_type: metrics`)**: `infra-silent-host-p2`(수집 로스터 호스트의 `system_memory_usage`가 15분 없음, 3시간 미만 — P2, 재통지 1440분)와 `infra-silent-host-p1`(3시간 없음 — P1, 재통지 60분). 둘 다 조회 구간 180분이며, P2 SQL은 "구간에는 있었지만 최근 15분은 없음"만 잡아 같은 호스트에 P1과 동시에 오지 않는다. SQL은 로스터 호스트마다 `SELECT '<호스트>' AS host_name, count(*) … HAVING count(*) < 1` 가지를 `UNION ALL`로 이은 형태다(인라인 `VALUES`/`unnest` JOIN은 이 버전에서 틀린 결과를 내므로 쓰지 않는다). P1 문구는 "약 5시간이 지나면 이 구간 로그는 OpenObserve로 복구되지 않음"을 안내한다 — OpenObserve `ZO_INGEST_ALLOWED_UPTO` 기본값 5시간(공식 문서)이며 `o2c_ingest_allowed_hours`로 표현하고 서버 값을 바꾸면 함께 고친다. **5시간은 공식 문서 기본값일 뿐 ns0332 서버의 실제 값은 확인하지 못했다 — 운영 반영 때 ns0332의 `ZO_INGEST_ALLOWED_UPTO`를 확인하고 다르면 `o2c_ingest_allowed_hours`를 맞춘다.** 로스터는 실행 시 인벤토리 그룹에서 만든다(아래 "로스터와 계획 정지 예외").

  - **서버 응답 없음 `infra-unreachable-host` (Spec #184 / Ticket-6, ADR-0010, `stream_type: metrics`)**: `tcpcheck_status`(otelcol `tcp_check` 수신기의 `tcpcheck.status`, 접속 성공 1/실패 0)가 5분 조회 구간 최댓값 0이면 발화하는 P1 State Alert(재통지 60분). 행은 대상 `tcpcheck_endpoint`(`<주소>:<포트>`)와 검사한 호스트(`host_name`). 수집은 Host Agents가 검사하는 쪽 호스트(`host_agents_o2_health_checker`, ns0266) 수집기에만 붙인다(`roles/monitoring`, 대상은 `servers` 전체 + 각 호스트 `ansible_port`). Silent Host SQL에서 이 알림 대상 호스트를 빼는 서브쿼리는 실서버 검증 전이라 적용하지 않았고, 서버가 다운되면 두 알림이 함께 울린다(Silent Host 조치 첫 줄이 "같은 호스트의 서버 응답 없음 알림이 있으면 그쪽이 원인"으로 안내).
  - **백업 알림 4개 정의 (Spec #184 / Ticket-5, `backup_logs`)**: `infra-backup-failure`(`job=backup`, `success=false`)·`infra-integrity-check-failure`(`job=maintenance`, `command=check`, `success=false`)는 P2 Event Alert(period·silence 5분). `infra-backup-missing`(수집 로스터 호스트의 마지막 성공 `job=backup` > 26h, period 1560분)·`infra-maintenance-missing`(유지보수 로스터, Backup Only 포함, 마지막 `command=check` > 8일, period 11520분)은 P2 State Alert(frequency 60분, silence 1440분)이며 로스터 호스트마다 `SELECT '<호스트>' AS host … HAVING count(*) < 1` 가지를 `UNION ALL`로 잇는다(`o2c_missing_sql`). `backup_logs`의 호스트 식별은 `host` 필드이며, 검증 픽스처는 `host_field: host`로 합성 레코드를 `host`에 넣고 `row_key: host`로 결과를 읽는다. 백업 누락 조치 첫 줄은 "같은 호스트의 Silent Host 알림이 있는지 먼저 확인"이다.

  - **앱 텔레메트리 무소식 `infra-app-telemetry-silent` (Spec #253 / Ticket-8, ADR-0012, `stream_type: metrics`)**: OpenBao `hosts/<host>/agents`의 `otel_app_telemetry`가 켜진 호스트에서 funa JVM 메트릭(`jvm_memory_used`의 `service_name = 'funa'`)이 15분(조회 구간) 없으면 발화하는 P2 State Alert(frequency 5분, 재통지 1440분)다. Silent Host와 같은 방식으로 로스터 호스트마다 `SELECT '<호스트>' AS host_name … WHERE host_name = '<호스트>' AND service_name = 'funa' HAVING count(*) < 1` 가지를 `UNION ALL`로 잇는다(`o2c_missing_sql`). `jvm_memory_used`는 모든 JVM이 공유하는 스트림이라 `service_name`으로 좁힌다. **로스터는 스위치가 켜진 호스트에서만 만든다**: 수집 로스터 호스트마다 `O2C-004`가 `hosts/<host>/agents`를 읽고(스위치는 인벤토리가 아니라 OpenBao에만 있다) boolean `true`인 호스트만 `O2C-005`가 남긴 뒤 Silent Host와 같은 계획 정지 예외를 뺀다. 스위치가 꺼졌거나 키가 없는 호스트, 수집 로스터 밖(Exclusion·Backup Only) 호스트는 들어가지 않는다. 켠 호스트가 없으면 절대 발화하지 않는 가지 하나만 남는다. **스위치를 바꾸면 `OpenObserve — Config`를 다시 실행해야 로스터가 따라온다**(호스트 편입·폐기와 같다). 롤아웃 순서상 스위치를 켜기 전에 이 알림이 먼저 반영되어도 켠 호스트가 없으므로 오발화하지 않는다.
  - **`app_traces` 보존 기간 (Spec #253 / Ticket-8)**: 트레이스 스트림 `app_traces`(`o2c_traces_stream`)가 서버에 **이미 있을 때만** 보존 기간을 30일(`o2c_traces_retention_days`)로 맞춘다(`PUT /api/<org>/streams/app_traces/settings?type=traces`, 본문 `{"data_retention": 30}`). 스트림은 첫 span이 들어와야 생기므로 없으면 계획에서 건너뛰고 실패하지 않는다(`GET /api/<org>/streams?type=traces`로 존재와 현재 값을 읽는다). 이미 30이면 쓰기가 없어 두 번째 실행은 `changed=0`이다. 다른 트레이스 스트림은 건드리지 않는다. 계획·반영은 기존 `O2C-012`·`O2C-020` 경로를 쓴다. 보존 기간은 서버 전역 `ZO_COMPACT_DATA_RETENTION_DAYS`(0보다 커야 함)가 켜져 있어야 적용된다. 스트림이 생긴 뒤 Config를 한 번 더 실행해야 30일이 반영된다.
  - **운영 규칙: org당 트레이스 스트림은 `app_traces` 하나만 둔다 (Spec #253 / Ticket-8)**: OpenObserve 로그 화면의 View Trace는 org의 트레이스 스트림 중 **이름순 첫 번째**를 기본으로 고른다(`docs/research/openobserve-view-trace-stream.md`, #251). 트레이스 스트림이 둘 이상이면 기본 선택이 `app_traces`가 아닐 수 있어 로그에서 트레이스로 가는 길이 흔들린다. 그래서 다른 이름의 트레이스 스트림을 만들지 않는다(수집기는 `stream-name: app_traces` 헤더로 한 스트림에만 보낸다). 다른 이름의 트레이스 스트림이 생기면 지우거나 `app_traces`로 합친다.

  - **리소스 알림 6개 정의 (Spec #184 / Ticket-3, `stream_type: metrics`)**: `infra-disk-usage-p2/-p1`(`system_filesystem_usage`), `infra-inode-usage-p2/-p1`(`system_filesystem_inodes_usage`), `infra-memory-usage-p2/-p1`(`system_memory_usage`). 알림 정의의 `stream_type`(생략하면 `logs`)이 알림 생성 요청에 그대로 들어간다. 사용률은 `_timestamp`별로 묶은 뒤 구간 최솟값(디스크·inode 15분, 메모리 10분)이 P2 90%~95% 미만 / P1 95% 이상일 때 발화하고 State Alert로 P1 60분·P2 1440분 후 재통지한다. 메모리는 `used` ÷ (`slab_unreclaimable`을 뺀 state 합). 제외 파일시스템 유형(`o2c_resource_excluded_fstypes`)과 임계값(`o2c_resource_p2_threshold`, `o2c_resource_p1_threshold`)은 Git 기본값이고, OpenBao의 호스트·마운트 예외와 임계값 덮어쓰기는 SQL로 만들어 반영한다(`o2c_resource_sql` 필터). 검증 단계는 메트릭 알림도 `logs` 유형의 검증 스트림에 합성 지표 레코드(`ts`로 스크레이프 시각 지정)를 넣어 SQL 논리만 확인한다.

  임계값은 `roles/openobserve_config/defaults/main.yml`의 `o2c_*` 변수입니다. 파싱 실패율 알림의 기본값(10%, 최소 20줄, 30분 창)도 `o2c_parse_error_percent`, `o2c_parse_error_min_lines`, `o2c_parse_error_window_minutes`로 조정합니다(SSH 실패는 `o2c_ssh_fail_per_source_threshold`, `o2c_ssh_fail_per_host_threshold`, `o2c_ssh_fail_window_minutes`).

  - **`Invalid user X from ...` 줄**: sshd는 같은 시도에 대해 `Failed password for invalid user X`도 남깁니다. 실패가 두 번 집계되지 않도록 `Invalid user` 줄은 `event_reason=invalid user`와 주소·사용자만 붙이고 `event_outcome`은 붙이지 않습니다(알림은 `event_outcome='failure'`만 셉니다). 비밀번호 시도 없이 끝나는 사용자 열거는 `Failed password` 줄이 없어 실패로 집계되지 않으며, 필요하면 `event_reason='invalid user'` 조건의 별도 알림을 추가합니다.
  - **파싱 실패율의 한계**: 분모는 스트림·호스트의 전체 줄 수입니다. `otel_log_formats`에 없는 경로(사용자 추가 경로, 표에서 뺀 `sudo.log`/`boot.log`/`firewalld`)의 줄도 분모에 들어가 비율이 희석될 수 있습니다. 이런 경로는 파서를 적용하지 않아 `log.parse_error` 자체가 붙지 않으므로 오탐은 없지만, 해당 줄이 많은 호스트는 실제 실패율보다 낮게 보입니다. 이 변경 이전 레코드는 새 필드가 null이라 조건에서 빠집니다. 수집기는 파싱한 줄마다 `log.parse_error`를 `true`/`false`로 명시합니다. 이 필드가 스트림에 한 번도 들어오지 않으면 OpenObserve가 `unknown field`로 알림 쿼리를 거부합니다(알림 상태 "오류").

  - **로스터와 계획 정지 예외 (Spec #184 / Ticket-4)**: `OpenObserve — Config`는 localhost에서 돌지만 인벤토리의 그룹을 읽는다(`servers` 인벤토리 필요). 수집 로스터 = `servers` − Host Agents Exclusion(`host_agents_excluded`) − Host Agents Backup Only(`host_agents_backup_only`)이고 ns0266·ns0332를 포함한다. 유지보수 로스터 = `servers` − Host Agents Exclusion이다. 호스트 이름은 인벤토리 호스트명(관리번호)이며 수집기가 보내는 `host_name`과 같다. 호스트 편입·폐기 뒤에는 Config를 다시 실행해야 한다. 계획 정지 예외(OpenBao `silent_host_exceptions: [{host, expires: YYYY-MM-DD}]`)는 만료일이 필수이고, 만료일이 지난 항목은 로스터 생성 때 무시되어 해제를 잊어도 감시가 돌아온다. 검증 단계는 모든 케이스의 가짜 호스트를 로스터에 넣어 "데이터가 없으면 발화하고, 있으면 발화하지 않는지"를 확인한다.

---

## 2. 시크릿과 입력

모두 OpenBao `agents/openobserve`(또는 Extra variables)에서 받으며 Git에는 두지 않습니다. 모든 API 태스크는 `no_log`이고 출력에는 객체 이름만 나옵니다.

| 키 | 설명 |
|---|---|
| `o2_endpoint`, `o2_org`, `o2_ca_file` | 호스트 에이전트와 같은 연결 값 |
| `api_user`, `api_password` | 설정 API(함수·파이프라인·알림)를 쓸 수 있는 OpenObserve 계정 (수집 토큰과 별개) |
| `alert_webhook_url` | 통지 webhook URL |
| `normal_sources` | (선택) root 로그인 정상 출발지 `[{address: <IP>, kind: semaphore\|office}]`. Semaphore는 어느 root 알림에도 걸리지 않고 office(사무실·S2S)는 P3 하루 요약에만, 그 밖은 P1. SSH 실패 급증 알림에는 적용하지 않음. 주소는 IP 문자·종류를 검증하며 출력하지 않음 |
| `alert_resource_exclusions`, `alert_resource_thresholds` | (선택, 비어 있어도 동작) 리소스 알림의 호스트·마운트 예외 `[{host, mount?, metric?}]`와 임계값 덮어쓰기 `[{host, mount?, metric?, p2?, p1?}]` (`metric`: disk·inode·memory) |
| `silent_host_exceptions` | (선택) Silent Host 계획 정지 예외 `[{host: <인벤토리 호스트명>, expires: YYYY-MM-DD, reason?}]`. 만료일 필수(없거나 형식이 틀리면 요청 전에 실패), 만료일이 지난 항목은 무시 |
| `alert_webhook_token`, `alert_webhook_auth_header` | (선택) 인증 토큰과 헤더 이름(기본 `Authorization`, 네이버웍스 봇은 `X-NANOIT-ACCESS`) |

---

## 3. 실행

```bash
ansible-playbook -i inventory/hosts.yml playbooks/openobserve_config.yml --check   # 변경 예정 목록만 출력, 쓰기 요청 0건
ansible-playbook -i inventory/hosts.yml playbooks/openobserve_config.yml
```

GET으로 현재 상태와 비교해 **차이가 있는 객체만** POST(생성)/PUT(수정)합니다. 의존 순서는 템플릿 → 통지 대상 → 함수 → 파이프라인 → 알림입니다.

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `O2C-000` | `Log in to OpenBao with AppRole for the OpenObserve configuration KV` | `ansible.builtin.uri` | Controller | 읽기 전용 (토큰 발급만, `changed_when: false`, `check_mode: false`, `no_log`. `VAULT_ROLE_ID`/`VAULT_SECRET_ID`가 없으면 건너뛰고 `VAULT_TOKEN`을 쓴다) |
| `O2C-001` | `Fetch OpenObserve configuration KV from OpenBao (agents/openobserve)` | `ansible.builtin.uri` | Controller | 읽기 전용 (GET, `check_mode: false`, `no_log`) |
| `O2C-002` | `Resolve and assert the OpenObserve inputs (endpoint, API account, webhook URL)` | `ansible.builtin.assert` | Controller | 읽기 전용 (필수 입력이 없으면 요청 전에 실패, `no_log`) |
| `O2C-003` | `Derive the desired OpenObserve objects from the repository definitions` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_desired`: 템플릿·대상·함수·파이프라인·알림) |
| `O2C-004` | `Read the otel_app_telemetry switch of every collect-roster host from OpenBao (hosts/<host>/agents)` | `o2c_http` | Controller | 읽기 전용 (수집 로스터 호스트마다 병렬 GET, 200·404만 허용하고 그 밖은 실패, `changed_when: false`, `check_mode: false`, `no_log`. 테스트 픽스처 `o2c_app_telemetry_kv_fixture`가 있거나 토큰이 없으면 건너뜀) |
| `O2C-005` | `Keep the hosts with the otel_app_telemetry switch on (the roster of the app telemetry silent alert)` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_app_telemetry_roster`: `otel_app_telemetry`가 boolean `true`인 호스트 이름만 남김, KV 본문은 팩트로 두지 않음, `no_log`) |
| `O2C-010` | `Read the current OpenObserve state (templates, destinations, functions, pipelines, alerts)` | `o2c_http` | Controller | 읽기 전용 (GET, `changed_when: false`, `check_mode: false`) |
| `O2C-011` | `Read each existing alert (the list view carries no query or trigger settings)` | `o2c_http` | Controller | 읽기 전용 (GET, `changed_when: false`, `check_mode: false`) |
| `O2C-012` | `Plan the writes needed (only objects that differ)` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_plan`: 원하는 상태 ⊆ 현재 상태이면 쓰기 없음) |
| `O2C-013` | `Show the planned changes (names only, never bodies)` | `ansible.builtin.debug` | Controller | 읽기 전용 (check 모드 포함 항상 출력, 본문 미출력) |
| `O2C-014` | `Seed the empty self-test stream with one past record before its alert is created` | `ansible.builtin.uri` | Controller | 자가 시험 알림을 새로 만들 때만 검증 전용 스트림에 조회 구간보다 오래된(기본 1시간 전) 레코드 1건을 넣어 스트림을 만든다 — 통지 없음 (`changed_when: false`, check 모드 제외, `no_log`) |
| `O2C-020` | `Apply the planned changes to OpenObserve (POST create / PUT update / DELETE stale infra- alerts)` | `o2c_http` | Controller | 계획된 차이만 전송 — 저장소 정의에 없는 `infra-` 접두어 알림은 DELETE, 접두어 밖 알림은 건드리지 않음 (`changed_when: true`, check 모드 제외, `no_log`) |

### 알림 검증 단계 (Spec #184 / Ticket-1)

> **`o2c_http` 모듈** (`roles/openobserve_config/library/o2c_http.py`, Issue #207): 위 표에서 `ansible.builtin.uri`를 `loop`로 돌리던 태스크를 요청 목록을 한 번의 모듈 실행으로 보내게 바꿨다. `uri` loop는 항목마다 모듈 프로세스를 새로 띄워(약 0.4초) 알림 수에 비례해 느렸다(상태 조회·상세 조회·검증이 합쳐 약 50초). 결과는 `uri` loop의 `results`(`item`·`status`·`json`)와 같은 모양이라 필터·검증 태스크는 그대로다. 읽기·검색·검증 레코드 주입(`parallel: true`)은 동시에 보내고, 쓰기(`O2C-020`)는 계획된 순서(템플릿→대상→함수→파이프라인→알림)대로 하나씩 보내며 앞 요청이 실패하면 멈춘다. check 모드에서는 GET만 보낸다. 헤더(Authorization)는 `no_log`로 가려지고 실패 메시지에는 요청 이름과 상태만 나온다. `O2C-033`의 재시도는 항목별에서 전체 검색 재전송으로 바뀌었다(불일치가 남은 알림이 없을 때까지 `o2c_verify_retries`×`o2c_verify_delay`). 모듈이 role 전용이라 FQCN이 없다.

반영(`O2C-020`) 직후 매번 실행한다. check 모드에서는 요청을 보내지 않는다. 운영 스트림·운영 알림·통지 대상은 건드리지 않는다.

- **① SQL 논리**: `files/alert_fixtures.yml`의 합성 레코드(알림마다 "발화해야 하는" 케이스와 "발화하면 안 되는" 케이스)를 검증 전용 스트림(`<운영 스트림><o2c_verify_stream_suffix>`, 기본 `_alert_verify`)에 넣고, 알림 SQL의 스트림명만 바꿔 검색 API로 실행해 기대와 비교한다. 케이스 호스트에 실행 ID가 붙어 이전 실행 데이터와 섞이지 않는다. 불일치하면 알림·케이스 이름을 출력하고 실패한다. `known_failure`(선택)가 붙은 케이스는 경고만 한다. 현재 이 표시가 붙은 케이스는 없다.
- **② 평가 오류**: `GET /api/v2/<org>/alerts/history`에서 관리 대상 알림의 가장 최근 평가가 `error`이면 실패한다.
- 합성 레코드 주입은 OpenBao `agents/openobserve`의 `controller_ingest_token`(컨트롤러 전용)으로 인증한다. 새 알림은 픽스처가 없으면 검증이 실패한다.

| ID | Task | Module | Target | Notes |
|---|---|---|---|---|
| `O2C-030` | `Plan the alert verification (synthetic records and rewritten searches)` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_verify_plan`), check 모드 제외, `no_log` |
| `O2C-031` | `Assert the controller ingest token exists (needed to inject the synthetic records)` | `ansible.builtin.assert` | Controller | 토큰이 없으면 주입 전에 실패 |
| `O2C-032` | `Inject the synthetic records into the verification streams` | `o2c_http` | Controller | 검증 스트림에만 POST (`changed_when: false`, `no_log`) |
| `O2C-033` | `Run each alert SQL against its verification stream and compare with the expected rows` | `o2c_http` | Controller | 검색 POST, 수집 지연을 위해 재시도 (`no_log`) |
| `O2C-034` | `Fail when an alert did not fire (or fired) as the fixtures expect` | `ansible.builtin.debug` | Controller | 불일치 시 알림·케이스 이름과 함께 실패 |
| `O2C-035` | `Read the recent alert evaluation history` | `ansible.builtin.uri` | Controller | 읽기 전용 (GET, `no_log`) |
| `O2C-036` | `Fail when the latest evaluation of a managed alert ended in error` | `ansible.builtin.assert` | Controller | 평가 오류가 있으면 실패 |
| `O2C-037` | `Inject one self-test record so the standing self-test alert notifies (only with o2c_verify_notify=true)` | `ansible.builtin.uri` | Controller | 검증 전용 스트림에만 POST (`changed_when: false`, `no_log`), `o2c_verify_notify`가 참일 때만, check 모드 제외 |

### 통지 경로 자가 시험 (Spec #184 / Ticket-2)

- 상설 알림 `infra-alert-selftest`가 검증 전용 스트림(`alert_selftest<o2c_verify_stream_suffix>`)을 본다. Config가 멱등하게 관리하며 운영 스트림은 보지 않는다.
- 기본 실행에서는 레코드가 없어 통지가 가지 않는다. `-e o2c_verify_notify=true`로 실행하면 레코드 1건(`O2C-037`)을 넣어 템플릿·destination·webhook까지 실제로 통지하며, 메시지 첫 줄은 `🧪 [TEST] 알림 통지 경로 시험 (실제 장애 아님)`이다. check 모드에서는 넣지 않는다.
- 알림은 조회 구간 5분·silence 5분이라 레코드 1건당 통지는 1회다. 반영 직후가 아니라 다음 평가(최대 1분 뒤)에 통지가 도착한다.
