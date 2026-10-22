---
status: accepted
date: 2026-10-13
---

# 10. 서버 다운 감시: Uptime Kuma가 아니라 중앙 otelcol `tcpcheck` + OpenObserve 알림

조사해 보니 `servers` 호스트 가운데 ping/SSH 다운 감시를 받는 서버가 한 대도 없었다([#163](https://github.com/ppzxc/infra-automation/issues/163)). 그래서 Semaphore 호스트(ns0266)의 otelcol에 `tcpcheck` 수신기를 붙여 인벤토리 `servers` 전체(Host Agents Backup Only 포함)의 SSH 포트를 60초마다 검사하고, 그 결과를 OpenObserve 메트릭으로 보내 알림을 판정하기로 한다. `tcpcheck.status = 0`이 5분 연속이면 **Unreachable Host** P1 알림을 보낸다. 서버 방화벽이 이미 Semaphore 출발지에 SSH를 열어 두었으므로 새로 열 포트는 없다. 이렇게 하면 알림이 OpenObserve 한 곳에 모이고, "서버가 죽었다"(Unreachable Host)와 "수집기만 멈췄다"(Silent Host)를 구분할 수 있다([#174](https://github.com/ppzxc/infra-automation/issues/174)).

## Considered Options

- **Uptime Kuma ping/TCP 모니터**: 역할로만 보면 가장 자연스럽다. 그러나 공식 쓰기 REST API가 없어 설정은 Socket.IO 내부 API로만 바꿀 수 있다. Ansible 컬렉션과 `uptime-kuma-api`는 1.x까지만 지원하고, as-code로 관리할 수 있는 유일한 길(`breml/terraform-provider-uptimekuma`, 2.5.0+)은 저장소에 Terraform을 새로 들여와야 한다. 게다가 Uptime Kuma는 감시 대상인 ns0270 위에서 돌고, ns0270 출발지는 서버 SSH 방화벽에 열려 있지 않을 가능성이 높다.
- **LibreNMS ping 장비 등록**: API로 관리할 수는 있다. 하지만 서버 알림이 OpenObserve와 LibreNMS 두 곳으로 갈라지고, 통지 경로를 따로 연결해야 한다.
- **Silent Host 알림이 서버 다운까지 겸함**: 로그를 보내지 않는 Backup Only 호스트를 잡지 못하고, 서버 다운과 수집기 중단을 구분하지 못한다.
- **otelcol `icmpcheck`(ping)**: development 단계이고 contrib 배포판에 들어 있지 않다. `tcpcheck`는 contrib에 포함돼 있다(alpha).

## Consequences

- 검사하는 쪽 ns0266이 죽으면 `tcpcheck` 메트릭 전체가 끊긴다. ns0266 자신은 Silent Host 로스터로 잡는다.
- OpenObserve(ns0331)는 자기가 죽은 것을 알릴 수 없다. 그래서 ns0266의 systemd 타이머가 5분마다 OpenObserve 헬스 엔드포인트를 확인하고, 실패하면 네이버웍스 webhook으로 직접 통지한다. ns0266과 ns0331가 동시에 죽는 경우는 감수한다.
- SSH 포트에 접속이 된다고 OS가 건강하다는 뜻은 아니다. 이 알림은 도달성만 본다.
- Uptime Kuma는 funa 서비스 감시만 맡고, LibreNMS는 네트워크 장비만 맡는다.
