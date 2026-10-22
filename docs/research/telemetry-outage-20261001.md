# 조사: 2026-10-01 FUNA Cluster 앱 텔레메트리 수집 중단 원인과 잔재

- 티켓: [#240](https://github.com/ppzxc/infra-automation/issues/240) (지도 [#239](https://github.com/ppzxc/infra-automation/issues/239))
- 날짜: 2026-10-19
- 방법: ns0338·ns0325·ns0327과 옛 수집처 ns0270에서 읽기 전용으로 조회했다. 본 것은 systemd journal(옛 수집기 로그, dockerd, NetworkManager, sshd/sudo), `docker ps -a`·`docker inspect`·`docker images`, 파일 목록과 mtime, 리슨 소켓이다. infra-automation과 funa의 10-01 전후 커밋도 대조했다. 노드에서는 아무것도 바꾸거나 재시작하지 않았다.
- 상세 근거(주소, 포트, 바인드, 방화벽, 원본 로그)는 비공개 메모에 있다. 이 문서는 공개 저장소용 요약이다.

## 요약

1. **10-01 전에 노드에서 OTLP를 받던 것은 호스트 systemd 서비스 `otelcol.service`였다.** 저장소가 관리하지 않는 수동 설치본(`/usr/bin/otelcol`, contrib v0.159.0)이었고, 2026-08-27부터 한 프로세스로 계속 돌았다. OTLP 수신기(gRPC·HTTP)를 열어 Caddy와 funa-api의 트레이스·메트릭을 받고, journald·Valkey·node_exporter 수집분과 함께 `otlp/openobserve` exporter(gRPC)로 **ns0270의 옛 OpenObserve에 내부망으로 직접** 보냈다. 옛 Caddy `.env`의 OTLP endpoint(노드 내부 호스트명)가 이 수집기를 가리켰다.
2. **멈춘 원인은 노드가 아니라 수집처 쪽 변경이다.** 세 노드 수집기의 첫 전송 실패 시각이 모두 **2026-10-01 16:27:57.845 KST로 같다**(gRPC 연결 실패, 이어서 `Unavailable: no children to pick from`, 16:32부터 `no more retries left … Dropping data`). 같은 초에 ns0270에서 OpenObserve 컨테이너가 정지·재생성됐다(dockerd journal). 그 직전 ns0270에서는 운영자 수동 작업으로 네트워크 연결 설정 변경(16:01~16:04)과 compose 파일 편집, Uptime Kuma 재생성(16:26~16:27)이 있었다. 재생성된 OpenObserve는 지금 호스트 포트를 하나도 공개하지 않고 ingress Caddy 뒤에서 HTTP만 받는다. 그래서 노드 수집기가 쓰던 gRPC 직결 경로가 사라졌다고 판단한다. **compose 변경 내용 자체는 10-15에 파일이 다시 바뀌어 직접 확인하지 못했다.** 시각 일치와 이후 18일간 같은 연결 실패가 이어진 사실에서 추정했다.
3. **영향은 트레이스·앱 메트릭만이 아니다.** 옛 수집기는 exporter가 하나여서 같은 시각부터 그 노드의 로그와 호스트 메트릭도 옛 OpenObserve에 들어가지 않았다. 옛 OpenObserve의 스트림 통계로도 확인했다. logs·traces 스트림과 `node_*`·`container_*` 메트릭 스트림의 마지막 문서 시각이 모두 16:27:32~16:27:53이다. 실패는 journal에만 남았고 알림이 없어서, 새 Host Agents로 바뀔 때까지(ns0338 10-15, ns0325·ns0327 10-19) 계속 버려졌다. 10-15 이후에는 `sending queue is full`도 나왔다.
4. **원인과 같은 이유로 다시 끊길 가능성은 낮다.** 옛 서비스·바이너리·패키지는 세 노드 모두에서 사라졌고, `/etc/otelcol/config.yaml`은 Host Agents(otelcol-contrib 0.161.0)가 덮어썼다. 새 수집기는 ns0331로 도메인 기반 otlphttp를 쓴다. 다만 "수집처를 수동으로 바꾸면 노드는 조용히 버린다"는 구조는 그대로라, 수집처 쪽 무소식 감지가 필요하다(아래 4절).
5. **지금 노드에서 OTLP 포트를 쓰는 것은 없다.** 새 OTLP 수신기와 바로 충돌하는 잔재도 없다. 조건부로 충돌할 수 있는 잔재가 둘 있다(netdata otel 플러그인, 옛 docker 수집기 compose). 그 밖의 잔재는 3절에 정리했다.

## 1. 10-01 전 수집 경로

| 항목 | 내용 | 근거 |
|---|---|---|
| 수신 주체 | 호스트 `otelcol.service` (`/usr/bin/otelcol --config=/etc/otelcol/config.yaml`, 사용자 `otelcol`) | journal `_SYSTEMD_UNIT`·`_CMDLINE` 필드 |
| 버전 | otelcol-contrib v0.159.0 (`redisreceiver@v0.159.0` 등 caller) | journal |
| 실행 기간(ns0325) | 08-18 첫 기동, 08-27 12:40:58 재기동 → 같은 PID로 10-15 14:07까지 → 10-15 재기동 → 10-19 10:33 정지 | journal PID별 처음/마지막 시각 |
| 수신기 | `otlp`(gRPC·HTTP), `journald`, `fluentforward`, `prometheus/node_exporter`, `redis/valkey-7000`·`7001` | 08-27 기동 로그 (ns0325 기준. 나머지 두 노드는 같은 서비스와 같은 실패 로그만 확인) |
| 내보내기 | `otlp/openobserve` 하나(gRPC), ns0270 OpenObserve 내부망 직결 | 10-01 실패 로그의 대상 주소 |
| 보내던 쪽 | Caddy(옛 `.env`의 OTLP endpoint가 노드 내부 호스트명), funa-api(OTel Java agent) | ns0325·ns0327의 `/home/infrastructure/caddy.old-20261019/.env`, 지도 #239 배경 |

`/home/infrastructure/monitoring/`의 옛 docker 수집기(`collector`, 이미지 0.128.0, Loki/Tempo/Prometheus로 내보냄)는 이 시점에 이미 컨테이너가 없었다. 10-01 경로와는 관계없다.

## 2. 10-01 타임라인 (KST)

| 시각 | 위치 | 사건 | 근거 |
|---|---|---|---|
| 14:23 | funa 저장소 | 0.0.75 릴리스 커밋. 운영 배포 시점은 확인 못함. 수집 경로와는 무관하다(아래 참고) | funa `061905b0` |
| 15:57 | ns0270 | 운영자 수동 로그인 | sshd journal |
| 15:58~16:04 | ns0270 | 네트워크 연결 설정 변경(DNS), NetworkManager reload | sudo·NetworkManager journal |
| 16:11~16:12 | ns0325 | systemd-hostnamed 기동, NM dispatcher (원인 미확인, 수집기 로그에는 영향 없음) | journal |
| 16:21 | ns0270 | 운영자 재로그인 | sshd journal |
| 16:26:41~16:27:27 | ns0270 | Uptime Kuma 컨테이너 두 번 재생성 (kuma compose mtime 16:27) | dockerd journal |
| **16:27:57.816** | ns0270 | **OpenObserve 컨테이너 정지, 16:27:59 새 컨테이너 기동** | dockerd journal |
| **16:27:57.845** | ns0338·ns0325·ns0327 | **세 노드 수집기가 동시에 gRPC 연결 실패 시작** | 각 노드 otelcol journal |
| 16:28:01~ | 세 노드 | `Exporting failed. Will retry` (`Unavailable: no children to pick from`) | 〃 |
| 16:32:38~ | 세 노드 | `no more retries left … Dropping data`, 이후 시간당 약 4천 건 (시간당 수치는 ns0325 기준) | 〃 |

참고:
- 같은 날 infra-automation 커밋(`7127a54` … `f3b3f7a`)은 새 Host Agents와 백업 기능 개발이다. 이 시간대 ns0325 journal에는 sudo·ansible 기록이 없다(나머지 두 노드는 이 항목을 따로 보지 않았다).
- **이전에도 짧은 끊김이 있었다.** ns0325 수집기는 09-28 16시대와 10-01 12시대에 잠깐 gRPC 연결 실패를 냈다가 회복했다. ns0270 OpenObserve의 `.env` 수정 시각이 09-28 16:54로 첫 끊김과 같은 분이다. 이전 재생성은 잠깐 끊었다가 같은 경로로 돌아왔고, 16:27 재생성 뒤에는 회복하지 않았다. 단순 재시작이 아니라 공개 경로 자체가 바뀌었다는 추정을 뒷받침한다.
- funa 쪽 OTLP exporter를 `none`으로 바꾼 것은 10-19(`440ea49c`, ADR-0033 개정)이다. 10-01 중단 원인이 아니다.
- 옛 OpenObserve에서 노드·서비스별 마지막 수신 시각 일부가 16:03 무렵으로 더 이르게 보였다(스트림 단위 마지막 시각은 모두 16:27). 노드 로그로는 설명되지 않는다. ns0270의 DNS 변경(16:01~16:04)과 시각만 겹친다. 트래픽이 드문 스트림이었을 수도 있다. 미확정으로 남긴다.

## 3. 노드에 남은 잔재와 충돌 가능성

| 잔재 | 노드 | 새 OTLP 수신기와 충돌 | 같은 이유로 재발 | 비고 |
|---|---|---|---|---|
| 옛 `otelcol.service`, `/usr/bin/otelcol`, otelcol RPM | 세 노드 모두 없음 | 없음 | 없음 | Host Agents로 교체 완료 |
| `/etc/otelcol/config.yaml` | 세 노드 | 없음 | 없음 | Host Agents가 덮어씀 (옛 설정은 남아 있지 않음) |
| `otelcol` 사용자 UID | ns0338은 옛 UID 재사용, ns0325·ns0327은 새 UID | 없음 | 없음 | ns0325·ns0327의 `/var/spool/mail/otelcol`이 옛 UID 소유의 고아 파일 |
| netdata + `netdata-plugin-otel` 패키지 | 세 노드 | **조건부**: 서비스는 inactive/disabled다. 켜면 플러그인이 기본값으로 루프백의 OTLP gRPC 포트를 잡는다. 새 수신기가 같은 포트를 모든 주소나 루프백에 열면 바인드가 충돌한다 | 없음 | 제거하거나, 수신기 롤아웃 전에 disabled 상태를 확인한다 |
| `/home/infrastructure/monitoring/` (옛 docker 수집기 compose + config, 이미지 0.128.0) | ns0338·ns0325 (ns0327은 이미지만, 0.158.0도 있음) | **조건부·낮음**: 누가 `docker compose up`을 하면 `restart: unless-stopped`로 되살아난다. 호스트 포트는 공개하지 않아 바인드 충돌은 없다. 이름 `collector`, Loki/Tempo 대상이라 혼란만 생긴다 | 없음 | 정리 대상 |
| `/etc/environment`, `/etc/profile.d/98-node-env.sh`의 `OTEL_EXPORTER_OTLP_ENDPOINT` | 세 노드 | 없음 | 없음 | `roles/common` 템플릿 기본값이 루프백 gRPC endpoint를 가리킨다. 호스트 셸 프로세스에만 적용되고 컨테이너에는 안 간다. 새 수신기가 그 주소를 열면 의도와 맞는지 스펙에서 정한다 |
| Caddyfile `tracing {}` 활성 + proxy `.env`의 `OTEL_*` 주석 처리 | 세 노드 | 없음 | — | Caddy가 기본 endpoint(localhost)로 1분마다 export에 실패한다. 지도 #239 "현재 Caddy 잡음 정리" 항목 |
| `/home/infrastructure/caddy.old-20261019/.env` | ns0325·ns0327 | 없음 | 낮음 | 옛 OTLP endpoint(노드 내부 호스트명) 그대로. 이 디렉터리로 되돌리면 새 수신기 주소와 맞는지 다시 봐야 한다 |
| `/opt/services/funa/sdk-config.yml` | 세 노드 | 없음 | 없음 | 업스트림 데모 파일(`collector` 호스트). compose에 마운트되지 않음 |

현재 세 노드 모두 OTLP 포트를 리슨하는 프로세스가 없다(`ss -ltnup`).

## 4. 재발 관점에서 남는 것

- 옛 경로의 약점: (a) 수집기가 저장소 밖 수동 설치였다. (b) 수집처를 IP·포트로 직결했다. (c) 수집처를 바꾸는 쪽(ns0270 수동 compose 편집)이 소비자를 몰랐다. (d) 전송 실패가 노드 journal에만 남고 알림이 없었다.
- (a)와 (b)는 Host Agents로 해소됐다. 역할로 관리되고 도메인 기반 otlphttp로 ns0331에 보낸다.
- (c)와 (d)는 새 경로에도 그대로 있다. 트레이스·앱 메트릭 스트림을 새로 열 때 [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md)의 roster형 무소식 감지를 함께 거는 것이 맞다. 수집기 자체의 `Exporting failed`/`Dropping data` 로그를 system_logs 알림으로 잡는 방법도 있다.
- ns0270은 지도 #239 결정대로 다시 쓰지 않는다. ns0270 쪽 변경은 이번 경로와 관계가 끊겼다.

## 출처

- 노드 journal·파일 조회 원본: 비공개 메모(로컬)
- funa: ADR-0033 `docs/adr/0033-tracing-is-owned-by-the-otel-java-agent.md`(개정 2026-10-19), 커밋 `061905b0`(0.0.75), `440ea49c`(운영 compose exporter none)
- infra-automation: `roles/common/templates/environment.j2`, `roles/common/templates/node-env.sh.j2`(`OTEL_EXPORTER_OTLP_ENDPOINT` 기본값), 10-01 커밋 `7127a54`~`f3b3f7a`
