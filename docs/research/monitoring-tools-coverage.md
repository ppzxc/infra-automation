# Uptime Kuma·LibreNMS 감시 범위와 OpenObserve 알림의 겹침·공백

- 질문: [#163](https://github.com/ppzxc/infra-automation/issues/163), 상위 map [#162](https://github.com/ppzxc/infra-automation/issues/162) (OpenObserve 알림 보강)
- 조사일: 2026-10-13
- 방법: 두 시스템의 **읽기 전용 API(GET)** 만 호출했습니다. 설정은 하나도 바꾸지 않았습니다. 접속 정보는 저장소 루트 `.env`(커밋되지 않음)의 `UPTIME_KUMA_*`, `LIBRENMS_*`입니다.
- 공개 저장소이므로 URL, 내부 도메인, IP는 적지 않았습니다. 호스트는 인벤토리 호스트명(관리번호)으로만 적습니다.

## 핵심 답변

1. **`servers` 인벤토리 27대 중 서버 다운(ping/SSH)을 감시받는 호스트는 0대입니다.** Uptime Kuma에는 ping·TCP(22) 모니터가 하나도 없고, LibreNMS에는 서버가 한 대도 등록되어 있지 않습니다.
2. **Uptime Kuma**(v2.5.0)는 활성 모니터 16개로 **funa 서비스(ns0325·ns0327·ns0338)** 만 봅니다. 앱 헬스 JSON, Valkey(master/replica), keepalived push, Caddy `/healthz`, 대표 URL입니다. 세 호스트가 통째로 죽으면 이 모니터들이 DOWN이 되므로 **사실상 간접적인 호스트 다운 신호**는 있습니다. 나머지 24대는 아무것도 보지 않습니다.
3. **LibreNMS**(26.7.0)는 **Cisco 스위치 12대**만 SNMP로 봅니다. 규칙은 기본 두 개(장비 down, 포트 down)뿐이고 **두 규칙 모두 Alert Operation이 없어 통지를 보내지 않습니다.** 공식 문서상 operation이 없는 규칙은 알림을 띄우기만 하고 통지는 하지 않습니다. 게다가 포트 down 규칙은 12대 전부에서 열린 상태(관리상 up인데 링크 down인 포트 269개)라 지금 그대로 통지를 켜면 잡음입니다.
4. **통지 경로**: OpenObserve는 webhook → 네이버웍스입니다(저장소 정의). Uptime Kuma는 API 키로 통지 설정을 읽을 수 없어 **확인하지 못했습니다**(아래 "확인 못 한 것"). LibreNMS는 위와 같이 **통지 없음**입니다.
5. 따라서 map #162의 역할 분담 원칙("Uptime Kuma = 서비스·포트·ping 도달성")은 **원칙일 뿐 현재 구현되어 있지 않습니다.** 서버 다운·Silent Host는 지금 어느 도구도 잡지 않습니다.

## Uptime Kuma

### 접근 방법과 한계

- Uptime Kuma의 API 키는 **Prometheus `/metrics` 엔드포인트 전용**입니다. HTTP Basic Auth의 비밀번호 자리에 키를 넣습니다. 모니터 목록·통지 설정·편집은 Socket.io(사용자 로그인 필요)로만 됩니다.
  - 출처: uptime-kuma-wiki [Prometheus-API-Keys](https://github.com/louislam/uptime-kuma-wiki/blob/master/Prometheus-API-Keys.md), [Internal-API](https://github.com/louislam/uptime-kuma-wiki/blob/master/Internal-API.md) ("Metrics endpoints support HTTP Basic Auth using either a generated API key...", 모니터·통지는 Socket.io 이벤트)
- `GET /metrics` → 200. `app_version` = 2.5.0.
- `/metrics`에는 **실행 중인 모니터만** 나옵니다. 모니터를 멈추면 `stop()`에서 `this.prometheus?.remove()`로 시계열을 지웁니다([server/model/monitor.js](https://github.com/louislam/uptime-kuma/blob/master/server/model/monitor.js), `async stop()`). 모니터 ID가 1~33 중 16개만 보이므로 **일시정지·삭제된 모니터가 있을 수 있고, 그 내용은 이 방법으로 알 수 없습니다.**
- 모니터 라벨에 있는 것은 이름·유형·URL·호스트·포트뿐입니다. **검사 주기, 재시도 횟수, 연결된 통지(notification)는 `/metrics`에 없습니다.**

### 활성 모니터 (16개, 모두 현재 UP)

| 호스트 | 모니터 | 유형 | 무엇을 보나 |
|---|---|---|---|
| ns0325 | app | `json-query` | 내부 주소의 앱 헬스 엔드포인트(HTTP, 8091) JSON 값 |
| ns0325 | valkey-master / valkey-replica | `redis` | Valkey 6379 / 26379 연결 |
| ns0325 | keepalived | `push` | keepalived가 주기적으로 push (끊기면 DOWN) |
| ns0325 | caddy | `http` | 공개 FQDN `/healthz` (TLS 인증서 지표 포함) |
| ns0327 | app, valkey-master, valkey-replica, keepalived, caddy | 위와 같음 | 위와 같음 |
| ns0338 | app, valkey-master, valkey-replica, keepalived, caddy | 위와 같음 | 위와 같음 |
| (서비스) | funa 대표 URL | `http` | 공개 서비스 URL의 `/docs` |

유형별: `json-query` 3, `redis` 6, `push` 3, `http` 4. **`ping`, `port`(TCP) 유형은 0개**입니다.

참고로 세 호스트의 `valkey-master` 모니터는 모두 **같은 한 주소**(공유 VIP로 보임)의 6379를 봅니다. 따라서 master 모니터는 호스트별 감시가 아닙니다. `valkey-replica` 모니터의 26379는 Valkey/Redis Sentinel 기본 포트이며, 호스트마다 다른 주소를 봅니다(ns0327의 것만 master와 같은 주소). 호스트별 생존 신호로 쓸 수 있는 것은 app(`json-query`), caddy(`http`), keepalived(`push`) 세 가지입니다.

## LibreNMS

모든 호출은 `X-Auth-Token` 헤더로 `GET /api/v0/...`만 했습니다.

| 호출 | 결과 |
|---|---|
| `system` | 200. 버전 26.7.0 |
| `devices` | 200. **12대, 전부 Cisco(`ios` 11, `iosxe` 1), `type=network`, 전부 up**, disable_notify 0 |
| `services` | 200. 서비스 체크 0개 |
| `devicegroups` | "No device groups found" |
| `rules` | 200. 2개 (아래) |
| `alerts` | 200. 열린 알림 12건, 전부 "Port status up/down" |
| `ports` | 516개 중 관리상 up이면서 링크 down인 포트 269개(장비당 13~49개) |
| 통지 수단(transport) 목록 | API 라우트 없음(404). 규칙의 operation으로 판단 |

등록 장비는 스위치 관리번호 ns0065, ns0250, ns0263, ns0278, ns0279, ns0281, ns0282, ns0304, ns0305, ns0341, ns0347, ns0348입니다. **`servers` 인벤토리 호스트는 하나도 없습니다.**

### 알림 규칙

| ID | 이름 | 조건 | 심각도 | 대상 | 통지 |
|---|---|---|---|---|---|
| 1 | Devices up/down | `macros.device_down = 1` (status 0, disabled·ignore 아님) | warning | 전체 장비 | **없음** (`alert_operation_id: null`, `operations: []`) |
| 2 | Port status up/down | `macros.port_down = 1` (ifOperStatus down, ifAdminStatus ≠ down) | warning | 전체 장비 | **없음** (같음) |

- 공식 문서: "An alert rule without an operation still raises an alert. It sends no notification." — [doc/Alerting/Operations.md](https://github.com/librenms/librenms/blob/master/doc/Alerting/Operations.md). API 문서도 `alert_operation_id`를 `null`로 두면 "suppress notifications for this rule"이라고 적습니다 — [doc/API/Alerts.md](https://github.com/librenms/librenms/blob/master/doc/API/Alerts.md).
- 규칙 2는 2026-08-10부터 12대 모두에서 열려 있습니다. 미사용 포트를 ignore 처리하지 않은 결과로 보이며, 통지를 붙이려면 먼저 포트 정리가 필요합니다.

## `servers` 인벤토리 호스트별 감시 현황

"서버 다운"은 ping 또는 SSH(TCP 22) 도달성 감시를 뜻합니다. OpenObserve 열은 기존 7개 로그 알림이 해당 호스트 로그로 발화할 수 있는지입니다(Host Agents가 로그를 보내는 호스트만 해당).

| 호스트 | 그룹 | Uptime Kuma | LibreNMS | 서버 다운 감시 | OpenObserve 로그 알림 |
|---|---|---|---|---|---|
| ns0217, ns0235, ns0237, ns0266, ns0272, ns0273, ns0287, ns0288, ns0290, ns0291, ns0292, ns0293, ns0294, ns0296, ns0297, ns0298, ns0299, ns0329, ns0334, ns0340 (20대) | 일반 | 없음 | 없음 | **없음** | 있음 (로그 기반 7종)* |
| ns0270 | host_agents_backup_only | 없음 | 없음 | **없음** | 없음 (백업만, 로그 수집 안 함) |
| ns0325, ns0327, ns0338 | host_agents_backup_only | 서비스 5종씩 | 없음 | **간접만** (app·caddy·keepalived가 함께 DOWN이면 추정 가능) | 없음 (백업만) |
| ns0229, ns0246, ns0331 | host_agents_excluded | 없음 | 없음 | **없음** | 없음 (에이전트 미설치) |

\* 로그 알림은 로그가 실제로 들어오는 동안에만 발화할 수 있습니다. [#161](https://github.com/ppzxc/infra-automation/issues/161)의 CentOS 6 9대처럼 수집이 조용히 멈춘 호스트는 이 열의 "있음"에도 불구하고 **현재 어느 도구에도 잡히지 않습니다.**

주의: ns0331는 OpenObserve 자신입니다. ns0331가 죽으면 OpenObserve 알림 전체가 멈추는데, 이를 바깥에서 보는 감시도 현재 없습니다.

## OpenObserve 알림과의 겹침·공백

OpenObserve 기존 알림 7개(`roles/openobserve_config/defaults/main.yml`의 `o2c_alerts`): SSH 실패 급증(출발지별·호스트별), root 원격 로그인 성공, sudo 실패, 커널·디스크 오류, 로그 해석 실패율(보안·시스템) 2개. 모두 로그 기반이고 통지는 webhook → 네이버웍스입니다.

| 감시 영역 | OpenObserve (현재) | Uptime Kuma (현재) | LibreNMS (현재) | 판정 |
|---|---|---|---|---|
| 서버 다운 (ping/SSH 도달성) | 없음 | 없음 (ns0325·0327·0338은 서비스 경유 간접) | 없음 (서버 미등록) | **공백** — 27대 전부 |
| Silent Host (로그 수집 중단) | 없음 | 없음 | 없음 | **공백** — #161 사고 유형 |
| 리소스 고갈 (디스크·메모리·CPU) | 없음 (메트릭 알림 없음) | 없음 | 없음 (서버 미등록) | **공백** — 예: ns0334 `/` 99.2% |
| 백업 실패·누락 | 없음 | 없음 | 없음 | **공백** — 예: ns0294 backup 실패 |
| maintenance 작업 실패 | 없음 | 없음 | 없음 | **공백** — 예: ns0270 |
| 서비스·포트 헬스 (앱, Valkey, Caddy, keepalived) | 없음 | funa 3대만 | 없음 | Uptime Kuma 단독 (통지 경로 미확인) |
| TLS 인증서 만료 | 없음 | funa Caddy·대표 URL (`monitor_cert_days_remaining`) | 없음 | Uptime Kuma 단독 |
| 네트워크 장비 up/down | 없음 | 없음 | 스위치 12대, **통지 없음** | 감지만 있고 통지 공백 |
| 스위치 포트 up/down | 없음 | 없음 | 스위치 12대, 통지 없음, 상시 발화 중 | 잡음 상태 |
| SSH 무차별 대입, root 로그인, sudo 실패 | 있음 (4종) | 없음 | 없음 | OpenObserve 단독, 겹침 없음 |
| 커널·디스크 오류 로그 | 있음 | 없음 | 없음 | OpenObserve 단독 |
| 로그 해석 실패율 | 있음 (2종) | 없음 | 없음 | OpenObserve 단독 |
| OpenObserve(ns0331) 자체 생존 | 해당 없음 (자기 감시 불가) | 없음 | 없음 | **공백** |

**겹침은 없습니다.** 세 도구가 보는 영역이 서로 닿지 않고, 공백은 map #162가 범위로 잡은 Silent Host·리소스 고갈·백업 실패/누락에 서버 다운과 ns0331 자체 생존이 더해진 형태입니다.

## 확인 못 한 것

- **Uptime Kuma 통지 대상**: API 키로는 `/metrics`만 읽을 수 있어 어떤 통지(네이버웍스, 메일 등)가 어느 모니터에 붙어 있는지 알 수 없습니다. 확인하려면 웹 UI(설정 → 알림)나 로그인 세션 기반 Socket.io 조회가 필요합니다.
- **Uptime Kuma 일시정지·삭제 모니터**: ID 1~33 중 17개가 `/metrics`에 없습니다. 멈춘 ping 모니터가 있는지는 UI로 확인해야 합니다.
- **Uptime Kuma 검사 주기·재시도**: `/metrics`에 없습니다.
- **LibreNMS 통지 수단(transport) 설정 자체**: 목록 API가 없습니다. 다만 두 규칙 모두 operation이 없으므로 transport가 있더라도 이 규칙들로는 통지되지 않습니다.
