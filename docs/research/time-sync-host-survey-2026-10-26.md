# 서버 시각 동기 현황 조사 (2026-10-26)

> Spec #322 / Ticket-14(#336) 구현 중 읽기 전용으로 확인한 호스트의 시각 동기 방식이다. 공개 저장소라 호스트 이름·주소·계정은 적지 않고 대수와 OS 계열만 적는다. 호스트별 값은 비공개 노트에 둔다. 이 조사는 서버를 바꾸지 않았다(조회 명령만 실행).

## 조사 범위와 방법

| 계열 | 조사 대수 | 확인한 것 |
|---|---|---|
| CentOS 6.9 | 12대 | `ntpq -pn`, `ntpstat`로 ntpd 응답 여부 |
| CentOS 6.9 | 그중 2대 | 서비스 등록(`chkconfig`), ntpd 프로세스 수, `/etc/crontab`의 시각 맞춤 항목, 시계 오차(이 PC와 비교) |
| CentOS 7.9 | 4대 | `chronyc tracking`, `chronyc sources`, `timedatectl` |
| Rocky 9.8 | 1대 | `chronyc tracking`, `timedatectl` |

모든 명령은 `LC_ALL=C`로 실행했고 조회 전용이다. 수집기(`host-agents-time-sync.sh`)도 같은 방식으로 CentOS 6·7 호스트에서 한 번씩 실행해 JSON 한 줄이 나오는 것을 확인했다(호스트에 설치하지 않고 표준 입력으로 실행).

## 결과

### CentOS 6 (12대 모두 같음)

- ntpd가 떠 있지 않다. `ntpq`는 `Connection refused`, `ntpstat`은 `Unable to talk to NTP daemon`(종료 코드 2)을 낸다.
- 설정을 확인한 2대: `ntpd`와 `ntpdate`가 모든 런레벨에서 꺼져 있고 ntpd 프로세스는 0개다. ntp 패키지(4.2.6p5)는 설치돼 있다.
- 대신 `/etc/crontab`의 `rdate -s <공용 시간 서버> && /sbin/clock -w`가 **하루 한 번(02:00)** 시각을 맞춘다(분 단위 줄은 주석 처리돼 있다).
- 조사 시점의 시계 오차는 두 대 모두 이 PC와 1초 이내였다.
- 결론: 상시 동기가 아니라 하루 한 번 맞추는 방식이다. 하루 중 시계가 서서히 틀어질 수 있고, 수집기는 그 오차를 잴 수 없다.

### CentOS 7 (4대), Rocky 9 (1대)

- chrony가 동작하며 동기돼 있다(조사한 호스트의 시스템 시각 오차는 모두 0.1ms 미만, stratum 3, 시간원 4~7개).
- `timedatectl`의 동기 라벨이 OS마다 다르다: CentOS 7은 `NTP synchronized:`, Rocky 9은 `System clock synchronized:`. 호스트 로캘이 한국어인 호스트에서는 라벨이 한글로 나온다(수집기가 `LC_ALL=C`로 고정하는 이유).

## 수집기에 미치는 영향

- chrony 호스트: 동기 여부와 부호 있는 오차(ms)가 기록되어 오차 알림이 동작한다.
- CentOS 6: ntpd가 답하지 않으므로 `sync_status=unsynced`, message `ntpq not answering (daemon not running?)`로 기록된다. 35분 넘게 이어지므로 `infra-time-unsynced`(P2) 대상이다. 적용하면 CentOS 6 호스트 전체가 이 알림을 받는다.
- 정상 동작하는 ntpd의 출력은 조사 대상에서 얻지 못했다. 그래서 `tests/fixtures/time_sync/ntpq_p_*.txt`는 도구 문서 형식으로 만든 모의다(해당 폴더 README 참고).

## 열린 결정 (이 조사에서 정하지 않음)

1. CentOS 6의 ntpd를 켜 상시 동기로 바꿀지(호스트 변경이라 승인·작업 창이 필요하다).
2. 하루 한 번 맞추는 방식을 받아들이고 `infra-time-unsynced`를 운영 결정으로 닫을지, 이 계열에서 알림을 빼는 예외를 둘지.
3. 시각 동기 수집기 배포 방식(서버 변경 범위와 otelcol 재시작 시점)은 #336 후속에서 정한다.

결정과 날짜는 비공개 노트에 남기고, 이 문서에는 결과만 갱신한다.
