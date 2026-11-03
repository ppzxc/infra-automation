# GitHub Webhook Watch Role Task Specification

`github_webhook_watch` 역할은 Semaphore 정기 작업(컨트롤러 전용)으로 GitHub 조직 웹훅의 존재·활성·구독 이벤트를 의도값과 비교하고, 최근 실패한 전달을 재전송하며, 결과를 하트비트 레코드로 OpenObserve에 남긴다. 설계 배경은 Spec [#399](https://github.com/ppzxc/infra-automation/issues/399), 구현 티켓은 #404(Ticket-5)다. 공개 저장소라 조직명·URL·주소·토큰은 적지 않는다(값은 OpenBao에만 둔다).

---

## 1. 개요 및 구현 기능 (What)

- **왜 필요한가**: GitHub은 실패한 웹훅 전달을 자동으로 재전송하지 않는다. 수신기가 내려가 있던 동안의 이벤트는 이 작업이 재전송해야만 복구된다. 훅이 삭제되거나 꺼지거나 구독 이벤트가 줄어드는 변조도 이 작업이 발견한다.
- **훅 비교**: 조직 웹훅 목록(`GET /orgs/{org}/hooks`)에서 수신 URL(`config.url`)이 의도값(`hook_url`)과 같은 훅을 찾는다. 결과 `hook_status`는 `ok`, `missing`(훅 없음), `inactive`(비활성), `events_mismatch`(구독 이벤트가 의도와 다름, 순서 무관) 중 하나이고 여러 문제가 겹치면 `hook_problems`에 모두 담긴다. API 호출 자체가 실패하면 `unknown`이다. 훅 상태 문제는 실행을 실패시키지 않고 하트비트에 상태로 남긴다(알림은 Ticket-6).
- **재전송**: 전달 목록(`GET .../deliveries`, 커서 페이지)에서 **재전송 가능 기간 안(기본 72시간 = 3일)** 의 실패한 전달만 `POST .../deliveries/{id}/attempts`로 재전송한다. 실패는 상태 코드가 200~399가 아닌 전달(시간 초과 0 포함)이다. 같은 전달(guid)에 성공 시도가 있으면 이미 복구된 것이고, 재전송 시도(`redelivery`)가 이미 있으면 다시 보내지 않는다. 재전송했는데 다시 실패한 전달은 `failed_count`로 센다.
- **재전송 가능 기간과 점검 주기**: 공식 문서는 최근 3일의 전달만 재전송할 수 있다고 한다(Ticket-1). 점검 주기는 6시간(`gww_check_interval_hours`)이고 GWW-001이 주기 < 기간을 검사해 어기면 GitHub을 호출하기 전에 실패한다. 기간을 막 넘긴 실패(기간 ~ 기간+주기)는 `expired_count`로 한 번 센다.
- **하트비트 레코드**: 매 실행마다 보안 로그 스트림에 `service_name=github-webhook-watch`, `record_type=heartbeat` 레코드 한 건을 남긴다. 필드 계약(Ticket-6 알림의 입력):

  | 필드 | 의미 |
  |---|---|
  | `checked_at` | 확인 시각(UTC, `YYYY-MM-DDTHH:MM:SSZ`) |
  | `result` | `ok` 또는 `error` |
  | `error` | 비면 정상. `credential_missing`, `api_unreachable`, `api_http_<상태 코드>` 중 하나(고정 코드만, 자격·URL 없음) |
  | `hook_status` | `ok` / `missing` / `inactive` / `events_mismatch` / `unknown` |
  | `hook_problems` | 문제 목록(쉼표 구분) |
  | `redelivered_count` | 이번 실행에서 재전송한 건수 |
  | `failed_count` | 복구되지 않은 실패 건수(재전송 요청 실패, 재전송 뒤 재실패) |
  | `expired_count` | 재전송 가능 기간을 넘긴 실패 건수 |
  | `interval_hours` | 점검 주기(침묵 알림 임계 계산용) |

- **오류 표면화**: GitHub API가 실패하거나(상태 코드 오류, 연결 불가) 자격이 없으면 먼저 `result=error`와 오류 코드를 하트비트에 남기고, 마지막 태스크(GWW-010)가 실행을 실패시킨다. 하트비트를 남길 OpenObserve 연결이 없거나 수집이 실패하면 실행이 실패한다.
- **check 모드**: 재전송하지 않고(`would_redeliver_count`만 계산해 출력) 하트비트도 쓰지 않는다. 읽기 요청만 보낸다.
- **자격 최소화**: GitHub 자격은 조직 권한 **Webhooks**(읽기와 재전송을 위한 쓰기)만 가진 세분화 토큰 또는 GitHub App이고 만료일을 둔다. 읽기와 재전송 권한은 분리할 수 없다(Ticket-1). 값은 OpenBao KV `agents/github-webhook-watch`에만 둔다. 이 값을 다루는 태스크는 모두 `no_log`이고 실패 메시지·하트비트에는 값이 없다.

---

## 2. OpenBao 입력

KV `agents/github-webhook-watch`(호스트 네임스페이스, 다른 컨트롤러 역할과 같은 AppRole·환경변수). Extra variables(`-e gww_...`)가 KV보다 우선한다.

| 키 | 용도 |
|---|---|
| `github_token` | 조직 Webhooks 권한 토큰(만료일 있음) |
| `github_org` | 조직 이름 |
| `hook_url` | 의도한 웹훅 수신 URL(훅을 찾는 기준) |
| `o2_endpoint`, `o2_org`, `o2_ingest_user`, `o2_ingest_password` | 하트비트를 남길 OpenObserve 연결 |
| `github_api_url`(선택) | 기본 공개 API 주소 |
| `expected_events`(선택) | 의도한 구독 이벤트 목록(기본은 Ticket-1에서 확정한 13개) |

---

## 3. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `GWW-001` | `Assert the check interval is shorter than the redelivery window` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (주기 < 재전송 가능 기간, 양의 정수) |
| `GWW-002` | `Log in to OpenBao with AppRole when no Vault token is given` | `ansible.builtin.uri` | Controller / Localhost | POST `auth/approle/login`, `no_log`, check 모드에서도 실행, Vault 토큰이 없고 AppRole 자격이 있을 때만 |
| `GWW-003` | `Fetch the webhook check inputs from OpenBao KV when OpenBao access is given` | `ansible.builtin.uri` | Controller / Localhost | GET, `no_log`, OpenBao 인증이 있을 때만 |
| `GWW-004` | `Keep the OpenBao KV values as a fact that never reaches the fact cache` | `ansible.builtin.set_fact` | Controller / Localhost | 순수 함수, `no_log`, `cacheable: false` |
| `GWW-005` | `Assert the heartbeat destination inputs exist before calling GitHub` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용, `no_log` (하트비트를 남길 수 없으면 점검 전에 실패) |
| `GWW-006` | `Compare the organization webhook and redeliver recently failed deliveries` | `gww_check` | Controller / Localhost | 훅 비교는 읽기 전용, 재전송은 같은 전달을 다시 보내지 않아 멱등, check 모드는 재전송 없음, `no_log` |
| `GWW-007` | `Build the heartbeat record (codes and counts only, no credentials or URLs)` | `ansible.builtin.set_fact` | Controller / Localhost | 순수 함수, `no_log`, `cacheable: false` |
| `GWW-008` | `Send the heartbeat record to OpenObserve` | `ansible.builtin.uri` | Controller / Localhost | POST `_json`, `no_log`, 재시도 2회, check 모드에서는 건너뜀 |
| `GWW-009` | `Report the check result (status and counts only)` | `ansible.builtin.debug` | Controller / Localhost | 읽기 전용 (상태와 건수만 출력) |
| `GWW-010` | `Fail the run when the GitHub API failed or the credential is missing` | `ansible.builtin.assert` | Controller / Localhost | 읽기 전용 (오류 코드가 있으면 하트비트를 남긴 뒤 실패) |

---

## 4. Semaphore 템플릿 등록 방법

실제 등록은 서버에서 사람이 하며 Ticket-8의 범위다. 이 절은 방법만 설명한다.

1. Semaphore 프로젝트에서 새 Task Template을 만든다. 이름은 `GitHub Webhook Watch`.
2. Playbook은 `playbooks/github_webhook_watch.yml`, Inventory는 `localhost`가 들어 있는 인벤토리(컨트롤러 전용이라 호스트에는 접속하지 않는다), Repository는 이 저장소의 기본 브랜치.
3. Environment(시크릿 변수)에는 OpenBao 접속(`VAULT_ADDR`, AppRole `VAULT_ROLE_ID`/`VAULT_SECRET_ID`, 네임스페이스)만 둔다. GitHub 토큰·URL은 OpenBao KV `agents/github-webhook-watch`에 둔다. 이 AppRole은 해당 KV 읽기 권한이 필요하다.
4. 예약(Schedule)은 6시간마다 `0 */6 * * *`(cron, 서버 시간대 기준)이다. 재전송 가능 기간이 3일이므로 주기를 하루 이상으로 늘리지 않는다. 주기를 바꾸면 `gww_check_interval_hours`도 맞춘다(하트비트 침묵 알림 임계가 이 값을 쓴다).
5. 처음 등록할 때는 `--check`(Semaphore의 Dry Run)로 한 번 돌려 훅 상태와 재전송 예정 건수가 기대와 같은지 본 뒤 일반 실행으로 바꾼다.
6. 실패 알림: 실행이 실패하면 Semaphore가 실패로 표시하고 하트비트에는 `result=error`가 남는다.

---

## 5. 점검 절차

- 실행 결과의 `[GWW-RESULT]` 줄에서 훅 상태와 건수를 본다(자격·URL은 출력되지 않는다).
- `failed_count`나 `expired_count`가 0이 아니면 수신기 쪽 장애 기간을 확인하고, 기간을 넘긴 실패는 복구할 수 없으므로 월간 감사 로그 내보내기로 보완한다.
- 자격 만료 전에 OpenBao의 `github_token`을 교체한다(만료일은 비공개 노트에 기록).
