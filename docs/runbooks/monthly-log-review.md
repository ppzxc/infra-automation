# 월간 로그 점검 런북

> 운영자가 매달 한 번 따라 하는 로그 점검 절차와 기록 양식이다(ISMS 정기 점검 증적, Spec #322 / Ticket-11, #333). 공개 저장소라 IP·계정·포트·장비 식별자와 실제 점검 결과는 적지 않는다. **실제 점검 기록은 비공개 노트에 둔다.** 이 문서에는 절차·쿼리·양식·관찰 목록만 있다.

## 점검 개요

- **주기**: 매달 1회. 점검 기간은 직전 한 달(OpenObserve 화면의 시간 범위를 "지난 30일"로 둔다). 로그 보존은 서버 전역 365일이라 한 달 전 로그는 모두 남아 있다.
- **담당과 기록 위치**: 점검자와 기록을 둘 비공개 노트의 위치는 운영에서 정한다. 이 문서는 어느 쪽이든 같은 양식으로 쓰도록 양식만 둔다.
- **쓰는 화면**: OpenObserve 로그 화면(스트림을 고르고 SQL 모드로 쿼리), OpenObserve 알림 화면의 이력, Semaphore 작업 이력, 월간 Host Audit 보고서 메일.
- **원칙**: 읽기만 한다. 점검 중 발견한 이상은 조치 전에 기록하고, 이슈에는 요약만 적는다(공개 저장소라 IP·포트·방화벽·SSH 약점 같은 상세는 비공개 노트에).

## 월간 점검 절차

쿼리의 출발지·호스트 이름은 결과에서 읽는다. "정상 출발지 목록"과 "수집 대상 호스트 목록"은 비공개 자료에 있다. 각 단계마다 결과를 아래 기록 양식에 한 줄씩 적는다.

1. **수집이 끊긴 호스트 찾기 (`system_logs`)**: 호스트마다 지난 한 달 레코드가 있는지 본다. 수집 대상 호스트 목록과 대조해 빠진 호스트가 있으면 기록한다. 평소보다 건수가 크게 적은 호스트도 기록한다.

   ```sql
   SELECT host_name, count(*) AS records FROM "system_logs" GROUP BY host_name ORDER BY records
   ```

2. **SSH 로그인 실패 상위 출발지 (`security_logs`)**: 상위 출발지가 알려진 스캐너·내부 점검 도구인지 본다. 새로 올라온 출발지와 한 호스트에 몰린 시도를 기록한다.

   ```sql
   SELECT source_address, count(*) AS failures FROM "security_logs"
   WHERE event_action = 'ssh_login' AND event_outcome = 'failure'
   GROUP BY source_address ORDER BY failures DESC LIMIT 20
   ```

3. **SSH 로그인 성공 (`security_logs`)**: 계정·출발지 조합이 정상 출발지 목록에 있는지 대조한다. root 성공과 목록에 없는 출발지의 성공은 모두 기록하고 사유를 확인한다.

   ```sql
   SELECT host_name, user_name, source_address, count(*) AS logins FROM "security_logs"
   WHERE event_action = 'ssh_login' AND event_outcome = 'success'
   GROUP BY host_name, user_name, source_address ORDER BY logins DESC LIMIT 50
   ```

4. **권한 상승 실패와 계정 변경 (`security_logs`)**: sudo 실패가 특정 계정에 몰리는지, 계정 추가·삭제·변경이 작업 일정과 맞는지 본다. 일정에 없는 변경은 기록한다.

   ```sql
   SELECT host_name, user_name, count(*) AS failures FROM "security_logs"
   WHERE event_action = 'sudo' AND event_outcome = 'failure'
   GROUP BY host_name, user_name ORDER BY failures DESC LIMIT 20
   ```

   ```sql
   SELECT host_name, count(*) AS changes FROM "security_logs"
   WHERE body LIKE '%type=ADD_USER%' OR body LIKE '%type=DEL_USER%' OR body LIKE '%type=USER_MGMT%'
   GROUP BY host_name ORDER BY changes DESC
   ```

5. **방화벽 로그 (`security_logs`, `service_name = 'fortigate-syslog'`)**: 장비마다 유형별 건수를 보고, 관리자 로그인 실패·설정 변경·중대 탐지가 있었는지 본다. 장비 이름 하나가 한 달 내내 안 보이면 수신 중단이다([방화벽 로그 런북](fortigate-syslog.md) 3절).

   ```sql
   SELECT device_name, fortigate_log_type, fortigate_log_subtype, count(*) AS records FROM "security_logs"
   WHERE service_name = 'fortigate-syslog'
   GROUP BY device_name, fortigate_log_type, fortigate_log_subtype ORDER BY records DESC
   ```

6. **스위치 로그 (`system_logs`, `service_name = 'switch-syslog'`)**: 메시지 코드별 건수로 설정 변경·로그인 실패·MAC 플랩이 있었는지 본다. 새로 많아진 코드는 잡음 목록에 넣을지 알림에 넣을지 판단해 기록한다([스위치 로그 런북](switch-syslog.md), [알림 런북](alerts.md)).

   ```sql
   SELECT event_name, count(*) AS records FROM "system_logs"
   WHERE service_name = 'switch-syslog' GROUP BY event_name ORDER BY records DESC LIMIT 20
   ```

7. **백업 결과 (`backup_logs`)**: 실패한 백업과, 한 달 안에 성공 기록이 없는 호스트를 본다. 유지보수(`job = 'maintenance'`) 실패와 무결성 검사 실패도 함께 본다.

   ```sql
   SELECT host, job, command, count(*) AS failures FROM "backup_logs"
   WHERE success = false GROUP BY host, job, command ORDER BY failures DESC
   ```

8. **하드웨어·시각 동기 점검 (`host_status_logs`)**: RAID 이상 판독과 시각 동기가 어긋난 호스트를 본다. 같은 호스트에서 반복되면 알림이 닫혔는지, 조치 일정이 있는지 기록한다.

   ```sql
   SELECT host_name, kind, hw_name, raw_state, count(*) AS readings FROM "host_status_logs"
   WHERE kind IN ('controller', 'logical_drive', 'physical_drive', 'cache_battery') AND hw_state <> 'ok'
   GROUP BY host_name, kind, hw_name, raw_state ORDER BY readings DESC
   ```

   ```sql
   SELECT host_name, sync_status, count(*) AS readings FROM "host_status_logs"
   WHERE kind = 'time_sync' AND sync_status <> 'synced'
   GROUP BY host_name, sync_status ORDER BY readings DESC
   ```

9. **알림 이력**: OpenObserve 알림 화면에서 지난 한 달 발생한 알림을 이름별로 센다. 같은 알림이 같은 호스트에서 반복되면 원인이 풀렸는지, 조건을 조정할지 기록한다. 조치 없이 닫힌 알림이 있으면 사유를 기록한다([알림 런북](alerts.md)).
10. **월간 Host Audit 보고서**: 보고서 메일이 도착했는지, 지난달보다 나빠진 항목이 있는지 본다. 보고서가 오지 않았으면 Semaphore 작업 이력에서 월간 Host Audit 실행 결과를 확인한다.
11. **수집량과 보존**: 스트림별 일일 수집량이 지난달과 크게 다르지 않은지 본다(관찰 목록의 로그량 재측정과 같은 화면). 보존 기간이 서버 전역 값(365일)에서 바뀌지 않았는지 확인한다.
12. **기록과 후속**: 점검 기록 양식을 채워 비공개 노트에 둔다. 조치가 필요한 항목은 이슈로 만들되 본문에는 요약만 적고 상세는 비공개 노트에 둔다.

## 점검 기록 양식

비공개 노트에 이 표를 복사해 매달 새로 채운다. 이 문서(공개 저장소)에는 채운 기록을 올리지 않는다.

```text
월간 로그 점검 기록
- 점검 기간: YYYY-MM-DD ~ YYYY-MM-DD
- 점검일:
- 점검자:

| 단계 | 점검 항목 | 결과(정상 / 이상 / 확인 필요) | 근거(쿼리·화면, 건수) | 조치(이슈 번호·담당·기한) |
|---|---|---|---|---|
| 1 | 수집이 끊긴 호스트 | | | |
| 2 | SSH 로그인 실패 상위 출발지 | | | |
| 3 | SSH 로그인 성공(root·목록 밖 출발지) | | | |
| 4 | 권한 상승 실패·계정 변경 | | | |
| 5 | 방화벽 로그 | | | |
| 6 | 스위치 로그 | | | |
| 7 | 백업 결과 | | | |
| 8 | 하드웨어·시각 동기 | | | |
| 9 | 알림 이력 | | | |
| 10 | 월간 Host Audit 보고서 | | | |
| 11 | 수집량·보존 | | | |

- 종합 의견:
- 다음 점검에서 추적할 항목:
- 관찰 목록 갱신(새로 도착한 로그 종류, 로그량 재측정 결과):
- 검토자 확인(서명·일자):
```

## 관찰 목록

아직 한 번도 실로그로 확인하지 못한 로그 종류와 정책 정리 뒤 재측정 항목이다. 이슈로 추적하지 않고 이 목록에서 월간 점검 때 확인한다. 해당 로그가 처음 도착한 달에 필드 추출과 알림이 의도대로인지 확인하고, 확인되면 항목을 지우거나 "확인됨(날짜)"로 바꾼다.

| 항목 | 언제 확인하나 | 무엇을 확인하나 |
|---|---|---|
| 방화벽 HA 상태 변경 | HA 장애 전환(시험 포함)이 처음 있었을 때 | 실제 전환 줄에서 장비·유형·동작 필드가 채워지고 HA 전환 알림이 한 번만 울리는지. 정보성 동기화 로그에는 울리지 않아야 한다([알림 런북](alerts.md)). 새 primary 이름으로 로그가 이어지는지 |
| SSL VPN 로그인·실패 | SSL VPN 사용자 로그인이 처음 기록됐을 때 | 사용자·출발지·동작 필드가 채워지는지. 이 신호는 현재 알림이 없으므로 필요하면 알림이 쓸 수집 필드를 정리한다 |
| 장비가 만든 웹 필터·앱 제어 줄 | 방화벽이 웹 필터·앱 제어 로그를 처음 낼 때 | 유형·하위 유형이 구분되고 허용 트래픽처럼 건수가 폭증하지 않는지. 건수가 많으면 장비 쪽 로그 거름 기준([방화벽 로그 런북](fortigate-syslog.md) 2절)을 다시 본다 |
| IPv6 | IPv6 주소가 든 로그가 처음 도착했을 때 | 출발지 필드가 IPv6 형식에서도 추출되는지, 정상 출발지 대조·알림 SQL이 깨지지 않는지 |
| 로그량 재측정 | 방화벽 정책별 로그 설정을 정리한 뒤 장기 세션이 닫히고 한 달 지났을 때 | 스트림별 분당·일일 수집량을 정리 전과 비교해 정책 정리 효과를 확인하고, 보존 용량 계획에 반영한다 |

```sql
SELECT date_format(_timestamp, '%Y-%m-%d', '+09:00') AS day, count(*) AS records FROM "security_logs"
WHERE service_name = 'fortigate-syslog' GROUP BY day ORDER BY day
```
