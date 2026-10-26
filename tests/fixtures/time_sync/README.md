# 시각 동기 수집기 픽스처 (Spec #322 / Ticket-14, #336)

2026-10-26에 운영 서버에서 읽기 전용으로 받은 실제 출력(`LC_ALL=C`)에서 Reference ID·피어 주소를 문서용 대역(192.0.2.0/24)으로 바꾼 것:

- `chronyc_tracking_rocky9_synced.txt`, `timedatectl_rocky9_synced.txt` — Rocky 9.8, chrony 4.8
- `chronyc_tracking_el7_synced.txt`, `timedatectl_el7_synced.txt` — CentOS 7.9, chrony 3.4
- `ntpq_el6_daemon_down.txt` — CentOS 6.9, ntp 4.2.6p5, ntpd가 꺼진 상태(`ntpq: read: Connection refused`, `ntpstat` 종료 코드 2). 조사한 CentOS 6 호스트는 모두 ntpd를 끄고 cron의 `rdate`로 하루 한 번 맞춘다.

운영 서버에서 받지 못해 도구 문서의 출력 형식대로 만든 것(실제 캡처가 아님):

- `chronyc_tracking_rocky9_offset_2s.txt` — 실제 출력에서 `System time` 줄만 2.35초로 바꿈
- `chronyc_tracking_not_synchronised.txt` — chrony의 `Leap status : Not synchronised` 형식
- `ntpq_p_*.txt` — ntpq -pn 형식(offset 열은 밀리초). CentOS 6에는 ntpd가 켜진 호스트가 없어 실제 출력을 받지 못했다
- `timedatectl_unsynced.txt` — `NTP synchronized: no`
