# Cisco Catalyst 스위치 장애 알림 기준과 적용

- 조사일: 2026-11-13
- 범위: Catalyst 2960 / 3750 / 3850, Telegraf SNMP 60초 폴링, OpenObserve PromQL
- 원칙: 장애 증상과 업무 영향에 직접 연결되는 상태만 통지하고, 계획된 종료·미사용 포트·짧은 부하는 억제한다.

## 업계 기준에서 채택한 점

공통적으로 쓰이는 방법은 **인터페이스 관리 상태와 동작 상태를 분리**하고, 관리자가 활성화한 포트(`ifAdminStatus=up`)의 실제 링크 상태(`ifOperStatus`)를 감시하는 것이다. Cisco의 SNMP 가이드는 두 IF-MIB 값을 함께 확인하고, 링크 상태 전이에는 표준 `linkUp`/`linkDown` 알림을 설명한다. 이 구성은 Trap을 수집하지 않으므로 같은 IF-MIB 상태를 60초 SNMP 폴링으로 판단한다. [Cisco: Monitoring Interface Status and Link Notifications](https://www.cisco.com/c/en/us/td/docs/routers/7300/technical_references/7301_mib_guides/7301_mib_specs_guide_v3/7301mib3_1/7301appa.html)

LibreNMS의 규칙 예시는 포트의 `ifOperStatus`와 장비·포트 용도를 조건으로 삼고, software loopback 및 사용자 클라이언트 포트를 제외하는 식으로 범위를 조정한다. 따라서 전체 포트가 down이라는 이유만으로 알리지 않고, 이 저장소의 기존 Watched Port 표기(`ifAlias`가 `Core:` 또는 `Transit:`)가 있는 물리 Ethernet과 Port-channel만 링크 장애·플랩 경보 대상으로 삼는다. [LibreNMS: Alert Rules](https://docs.librenms.org/Alerting/Rules/), [LibreNMS: Alert Entities](https://docs.librenms.org/Alerting/Entities/)

Prometheus 권고는 증상 중심의 조치 가능한 경보, 짧은 순간값 대신 지속 조건(`for`)을 사용해 한 번의 평가 이상 지속되는지 확인하는 것이다. OpenObserve의 `pending_period_sec`가 PromQL 규칙에 이 지속 조건을 구현한다. Counter는 원시 누적값을 비교하지 않고 `rate()`/`increase()`로 변화량을 계산해야 재부팅에 따른 카운터 감소를 보정할 수 있다. [Prometheus: Alerting Rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/), [Prometheus: Query Functions](https://prometheus.io/docs/prometheus/latest/querying/functions/), [OpenObserve: PromQL pending duration implementation](https://github.com/openobserve/openobserve/blob/main/src/config/src/meta/alerts/prom_rule.rs)

## 채택한 경보

| 알림 | 조건 | 등급·지속 | 근거와 범위 |
|---|---|---|---|
| `infra-switch-snmp-unreachable` | 스위치 uptime 성공 표본이 3분 없음 | P1 | `cisco_snmp_targets` 인벤토리의 명시 대상만 감시. 관리망·자격 증명·Telegraf 경로 장애 탐지 |
| `infra-switch-interface-down` | Watched Port 중 `ifAdminStatus=up`이고 `ifOperStatus!=up` | P1, 2분 지속 | 핵심 링크 단절. 60초 폴링 2회 이상을 요구해 순간 상태 변화를 억제 |
| `infra-switch-interface-flapping` | 같은 포트의 oper 상태가 10분에 3회 이상 변화 | P2 | 반복 단절은 별도 장애 증상. SNMP `changes()`로 syslog 누락과 무관하게 감지 |
| `infra-switch-cpu-high` | 5분 평균 CPU ≥90% | P2, 10분 지속 | Cisco CPU OID의 완화된 5분 평균과 지속 조건으로 순간 부하 억제 |
| `infra-switch-memory-pool-high` | Processor 풀 used/(used+free) ≥90% | P2, 10분 지속 | 절대 byte 수가 아닌 모델별 풀 용량 비율을 사용 |
| `infra-switch-interface-in-errors` | Watched Port의 inErrors가 5분에 30 이상 증가 | P2, 10분 지속 | 패킷 수집 제외 조건 때문에 오류율 대신 수신 오류 건수 증가량 사용. 임계값은 2주 운영 관찰로 조정 |
| `infra-switch-interface-out-errors` | Watched Port의 outErrors가 5분에 30 이상 증가 | P2, 10분 지속 | 송신 방향도 별도 규칙으로 감시해 양방향 오류를 모두 보존 |

## 의도적으로 제외한 신호

- **포트가 up으로 복구됨**: 별도 호출 경보를 만들지 않는다. `ifOperStatus=up`으로 장애 상태가 해소되며, down 알림을 재통지·복구 알림에 사용한다.
- **admin down**: 계획된 shutdown이다. 운영자 실수를 찾는 변경 감사는 설정 변경 로그에서 본다.
- **미사용 포트 down**: 정상 상태이며 Watched Port가 아니다.
- **모든 포트의 패킷/트래픽·VLAN·MAC/ARP 테이블·Trap**: 현 수집 요구사항에서 제외됐다.
- **절대 CPU·메모리 임계의 출처 주장**: 90%는 여러 모니터링 기준에서 흔한 출발점이지 Catalyst 전 모델의 벤더 보증 한계가 아니다. 운영 경보 강도는 실제 baseline에 맞춰 조정한다.
- **상태 없는 OID 지원 여부**: 현재 모델 walk 검증을 통과한 IF-MIB, CISCO-PROCESS-MIB, CISCO-MEMORY-POOL-MIB 값만 사용한다.

## 운영 조건과 한계

1. SNMP 무응답 로스터(`cisco_snmp_targets`)에는 Telegraf에 설정했고 실제 장애 감시가 필요한 장비를 둔다. 표본이 없어도 의도된 대상이면 포함해 P1을 받는다. 기본 `cisco_switches` 전체를 무조건 넣지 않아 수집 대상이 아닌 장비의 오탐을 피한다.
2. 링크 다운·플랩은 `ifAlias`에 `Core:` 또는 `Transit:`가 지정된 행만 감시한다. 중복 집계를 피하기 위해 알림은 물리 Ethernet(`ifType=6`)과 논리 Port-channel(`ifType=53`)만 허용한다. Port-channel과 구성원 포트를 모두 Watched Port로 표시하면 같은 장애가 두 행으로 잡힐 수 있으므로 대시보드와 라벨링에서 한 계층만 선택한다.
3. 폴링 주기는 60초다. 따라서 링크 상태 경보의 관측 지연은 보통 최대 한 폴링 주기이며, SNMP 수집기·장비가 동시에 멈추면 포트 상태 경보 대신 수집 대상별 도달성 감시가 필요하다.
4. 오류 30건/5분은 표준 보편 임계가 아니라 패킷 카운터를 추가 수집하지 않는 조건의 운영 시작값이다. Cisco 포트별 CRC/input error 기준 및 실제 트래픽 패턴을 2주간 검토하고 장비·포트별 예외가 필요하면 별도 명세로 관리한다.
5. OpenObserve PromQL 수식은 렌더링과 문법 검증 대상이다. 실제 장비 레코드가 들어온 후 포트 라벨, OID fallback 장비, 상태 enum, 재부팅 뒤 rate 계산, 통지 행을 확인해야 적용 결과가 검증된다.
