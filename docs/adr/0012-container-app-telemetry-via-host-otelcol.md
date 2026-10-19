---
status: accepted
date: 2026-10-19
---

# 12. 컨테이너 앱 텔레메트리는 노드 otelcol의 OTLP HTTP 수신기로 받는다

FUNA Cluster의 Caddy와 funa가 내는 **Business Telemetry**(트레이스와 앱 메트릭)를 각 노드의 Host Agents otelcol이 받아 OpenObserve로 보낸다([#239](https://github.com/ppzxc/infra-automation/issues/239), [#246](https://github.com/ppzxc/infra-automation/issues/246)). 수신기는 OTLP **HTTP만** 열고 모든 주소(`0.0.0.0`)에 바인드한다. 컨테이너는 compose의 `extra_hosts: host.docker.internal:host-gateway`로 호스트를 찾고, 수신기 주소를 compose에 상수로 적는다. 켜는 스위치는 OpenBao `hosts/<host>/agents`의 boolean `otel_app_telemetry`다(`otel_docker_metrics`, `otel_container_logs`와 같은 방식). 이번에 켜는 곳은 FUNA Cluster뿐이지만 어느 Docker 앱 호스트에도 같은 스위치로 켠다.

10-01까지는 노드마다 손으로 설치한 별도 수집기가 같은 일을 했다. 수집처가 바뀌자 알림 없이 끊겨 2주 넘게 데이터가 버려졌다([#240](https://github.com/ppzxc/infra-automation/issues/240)). 저장소가 관리하는 Host Agents 하나로 모으는 것이 이 결정의 출발점이다.

## 파이프라인

- **traces**: OTLP 수신 → `memory_limiter` → `resource/host` → `batch` → 트레이스 전용 `otlphttp` exporter. `stream-name` 헤더로 스트림 `app_traces`를 지정한다. 헤더가 없으면 OpenObserve는 `default` 스트림에 넣는다([#242](https://github.com/ppzxc/infra-automation/issues/242)).
- **metrics**: OTLP 수신 → 같은 처리 → 기존 `otlphttp/metrics`.
- **logs**: OTLP로 받지 않는다. 앱 로그는 지금처럼 컨테이너 로그(`filelog/containers`)로만 받는다. 둘 다 받으면 중복된다.
- `resource/host`가 호스트 Resource Attribute를 덮어쓴다. 앱이 보내는 호스트명은 컨테이너 hostname이라 믿을 수 없다. `service.name`은 보낸 쪽 값(`caddy`, `funa`)을 그대로 둔다.
- 트레이스와 앱 메트릭의 전송 큐는 **메모리 큐**다. 로그만 디스크 영속 큐를 쓴다.

## Considered Options

- **루프백(127.0.0.1) 바인드**: bridge 네트워크의 컨테이너에게 127.0.0.1은 자기 자신이라 닿지 않는다. 지금 Caddy의 trace export가 1분마다 실패하는 원인이 바로 이것이다.
- **docker0 주소에만 바인드**: 노출 면은 가장 작다. 대신 docker가 뜨지 않아 그 주소가 없으면 otelcol 전체가 기동하지 못하고 로그 수집까지 함께 죽는다. docker 장애가 로그 장애로 번지는 위험이 `0.0.0.0`의 추가 노출보다 크다고 봤다. `0.0.0.0`의 외부 접근은 firewalld가 막는다. public 존은 기본 거부이고, trusted 존 출발지는 이미 모든 포트에 닿는다.
- **docker 네트워크 안의 수집용 컨테이너(gateway collector)**: 서브넷이 노드마다 달라도 영향이 없다. 대신 수집 경로에 관리할 구성 요소가 하나 더 생긴다.
- **gRPC도 연다**: Caddy와 Java agent의 기본 프로토콜은 `http/protobuf`라 gRPC를 쓸 곳이 없다. 열지 않으면 포트가 하나로 줄고, 노드에 깔린 netdata otel 플러그인의 gRPC 기본 포트와도 겹치지 않는다.
- **수신기 주소를 OpenBao `clusters/funa`로 렌더링**: `cluster.env` 값은 `/etc/profile.d`로 호스트 셸에도 export된다. 그러면 호스트에서 풀리지 않는 `host.docker.internal` 주소가 표준 변수 이름으로 셸에 퍼진다. 이 값은 노드마다 같은 상수라 compose에 직접 적는다.
- **트레이스 영속 큐**: OpenObserve는 5시간보다 오래된 span을 조용히 버린다. 영속 큐에 오래 쌓인 트레이스는 결국 버려지는 데다, 로그 큐와 디스크를 다툰다. 트레이스는 감사 증적이 아니라 진단용이다.

## Consequences

- otelcol을 재시작하거나 수집처가 길게 장애가 나면 그 사이 트레이스와 앱 메트릭은 잃는다.
- `roles/common`이 `/etc/environment`와 `/etc/profile.d/98-node-env.sh`에 넣던 `OTEL_EXPORTER_OTLP_ENDPOINT`(루프백 gRPC)를 없앤다. 쓰는 프로세스가 없고, HTTP 전용 수신기와 맞지 않는 주소를 알려 줄 뿐이다.
- 각 노드에 남은 옛 docker 수집기 compose와 이미지는 롤아웃할 때 삭제한다.
- 역할의 `otel_otlp_enabled` 기본값은 `otel_app_telemetry` 스위치로 대체한다.
- 잡음을 거르는 규칙(어떤 span과 시계열을 버릴지)은 이 ADR의 범위가 아니다. Business Telemetry 잡음 규칙 티켓에서 정한다.
