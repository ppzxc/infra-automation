# OpenObserve Config Role Task Specification

> **상태: 구현됨.** `openobserve_config` 역할은 [ADR-0008](adr/0008-log-structuring-edge-envelope-central-semantics.md)에 따라 OpenObserve의 VRL ingest function, 파이프라인, 통지 대상(webhook), 알림 규칙을 이 저장소의 정의로 관리하고 OpenObserve API로 반영합니다. 호스트에는 접속하지 않는 **컨트롤러 전용** 역할이며 `playbooks/openobserve_config.yml`이 유일한 진입점입니다.

---

## 1. 개요 (What)

- **VRL ingest function `security_semantics`** (`roles/openobserve_config/files/vrl/security_semantics.vrl`): `security_logs`의 sshd·sudo 메시지를 해석해 필드를 **추가**합니다. 원문 `body`와 기존 필드는 바꾸지 않으며, 해석할 수 없는 레코드는 그대로 통과합니다. 필드는 OTel semantic conventions를 따르고 OpenObserve가 점을 밑줄로 저장하므로 아래 이름으로 보입니다.

  | 필드 | 의미 |
  |---|---|
  | `user_name` (`user.name`) | sshd 로그인 대상 사용자 / sudo를 실행한 사용자 |
  | `source_address`, `source_port` (`source.address`, `source.port`) | sshd 원격 주소·포트 (`Invalid user` 줄에 포트가 없으면 `source_port` 없음) |
  | `event_action` | `ssh_login` 또는 `sudo` |
  | `event_outcome` | `success` 또는 `failure` |
  | `event_reason` | 실패 사유: `failed password`, `invalid user`, `NOT in sudoers`, `authentication failure` |
  | `user_effective_name`, `process_command_line` | sudo 대상 사용자(`USER=`)와 실행 명령(`COMMAND=`) — sudo 성공은 알림 없이 이 필드로 감사 기록만 남김 |

  입력 필드는 엣지(#91)가 만든 `process_executable_name`(= `sshd`/`sudo`)와 원문 `body`입니다. 엣지와 필드 계약이 바뀌면 같은 PR(또는 연속 PR)에서 함께 고칩니다.
- **파이프라인** `security_semantics`: `security_logs` 실시간 소스 → 함수(`after_flatten: true`) → `security_logs`.
- **통지 대상**: 범용 webhook 하나(`infra-automation-webhook`)와 JSON 본문 템플릿. 등급별 분리는 범위 밖입니다.
- **알림 규칙 6종(7개 정의)**: 모두 위 대상으로 보냅니다.

  | 이름 | 조건 |
  |---|---|
  | `infra-ssh-login-failures-per-source` | `source_address`별 5분 10회 이상 sshd 로그인 실패 |
  | `infra-ssh-login-failures-per-host` | 호스트별 5분 50회 이상 sshd 로그인 실패 |
  | `infra-root-login-success` | root SSH 로그인 성공 1건부터 |
  | `infra-sudo-escalation-failure` | sudo `authentication failure`/`NOT in sudoers` 1건부터 (성공은 알리지 않음) |
  | `infra-kernel-disk-errors` | `system_logs`의 `Out of memory: Killed process`, `I/O error`, `EXT4-fs error`, `XFS ... Corruption` (severity가 아닌 패턴 기반) |
  | `infra-log-parse-errors-security-logs` / `-system-logs` | `log.parse_error=true` 비율이 10% 이상(최소 20줄, 30분 창) |

  임계값은 `roles/openobserve_config/defaults/main.yml`의 `o2c_*` 변수입니다. 이 변경 이전 레코드는 새 필드가 null이라 조건에서 빠집니다.

---

## 2. 시크릿과 입력

모두 OpenBao `agents/openobserve`(또는 Extra variables)에서 받으며 Git에는 두지 않습니다. 모든 API 태스크는 `no_log`이고 출력에는 객체 이름만 나옵니다.

| 키 | 설명 |
|---|---|
| `o2_endpoint`, `o2_org`, `o2_ca_file` | 호스트 에이전트와 같은 연결 값 |
| `api_user`, `api_password` | 설정 API(함수·파이프라인·알림)를 쓸 수 있는 OpenObserve 계정 (수집 토큰과 별개) |
| `alert_webhook_url` | 통지 webhook URL |
| `alert_webhook_token`, `alert_webhook_auth_header` | (선택) 인증 토큰과 헤더 이름(기본 `Authorization`) |

---

## 3. 실행

```bash
ansible-playbook playbooks/openobserve_config.yml --check   # 변경 예정 목록만 출력, 쓰기 요청 0건
ansible-playbook playbooks/openobserve_config.yml
```

GET으로 현재 상태와 비교해 **차이가 있는 객체만** POST(생성)/PUT(수정)합니다. 의존 순서는 템플릿 → 통지 대상 → 함수 → 파이프라인 → 알림입니다.

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `O2C-001` | `Fetch OpenObserve configuration KV from OpenBao (agents/openobserve)` | `ansible.builtin.uri` | Controller | 읽기 전용 (GET, `check_mode: false`, `no_log`) |
| `O2C-002` | `Resolve and assert the OpenObserve inputs (endpoint, API account, webhook URL)` | `ansible.builtin.assert` | Controller | 읽기 전용 (필수 입력이 없으면 요청 전에 실패, `no_log`) |
| `O2C-003` | `Derive the desired OpenObserve objects from the repository definitions` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_desired`: 템플릿·대상·함수·파이프라인·알림) |
| `O2C-010` | `Read the current OpenObserve state (templates, destinations, functions, pipelines, alerts)` | `ansible.builtin.uri` | Controller | 읽기 전용 (GET, `changed_when: false`, `check_mode: false`) |
| `O2C-011` | `Read each existing alert (the list view carries no query or trigger settings)` | `ansible.builtin.uri` | Controller | 읽기 전용 (GET, `changed_when: false`, `check_mode: false`) |
| `O2C-012` | `Plan the writes needed (only objects that differ)` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`o2c_plan`: 원하는 상태 ⊆ 현재 상태이면 쓰기 없음) |
| `O2C-013` | `Show the planned changes (names only, never bodies)` | `ansible.builtin.debug` | Controller | 읽기 전용 (check 모드 포함 항상 출력, 본문 미출력) |
| `O2C-020` | `Apply the planned changes to OpenObserve (POST create / PUT update)` | `ansible.builtin.uri` | Controller | 계획된 차이만 전송 (`changed_when: true`, check 모드 제외, `no_log`) |
