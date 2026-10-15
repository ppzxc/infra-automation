# Research: 단일 Docker 호스트의 컨테이너 로그 수집 업계 표준과 우리 설정(journald 드라이버 + otelcol)의 정합성

- Ticket: #221 follow-up (Map #209 / Spec #219)
- Date: 2026-10-15
- Method: 벤더 공식 문서와 업스트림 소스(moby, OpenTelemetry Collector Contrib, systemd man 원문)를 직접 읽었다. 블로그·포럼은 근거로 쓰지 않았고, 불가피하게 본 것은 "secondary"로 표시했다. 문서 페이지는 WebFetch로 요약 추출했으므로, 결론에 영향이 큰 사실(4096바이트 null, 16KiB 분할, PRIORITY 매핑)은 소스 원문을 직접 내려받아 재확인했다. 확인하지 못한 것은 "미확인"으로 적었다.
- 범위: Kubernetes가 아닌 평범한 Docker 호스트. 우리 설정 문맥은 ADR-0006 §2.3, ADR-0008, `roles/monitoring/templates/otelcol-contrib.yaml.j2`(`journald`, `journald/containers`), `rsyslog-containers.conf.j2`를 읽었다.

## TL;DR

1. **업계 기본값은 "로컬 파일 드라이버(json-file; `local`은 데몬 전용 형식이라 외부 에이전트가 읽을 수 없다 — 아래 정정 참고) + 에이전트가 파일을 tail 하거나 Docker 소켓으로 읽기"(접근 B/소켓)다.** Datadog은 6.33/7.33 이후 파일 tail이 기본이고 소켓보다 "성능이 낫다"고 적는다 [dd-docker]. Elastic Docker 통합은 `*-json.log` 경로를 기본으로 쓴다 [es-docker]. Vector는 Docker 소켓을 쓴다 [vec-docker]. Grafana는 Loki Docker 드라이버 대신 Alloy `loki.source.docker`를 권한다 [loki-drv]. 원격 드라이버(fluentd/gelf/splunk/awslogs/gcplogs)를 "표준"으로 권하는 벤더 문서는 찾지 못했다(미확인이 아니라 해당 문서에 그런 권고 문장이 없음).
2. **journald 경로는 1급 문서가 있는 선택지다.** Datadog은 `journald` 통합에 `container_mode`를 두고 [dd-journald], Elastic Filebeat `journald` 입력은 `CONTAINER_NAME`, `IMAGE_NAME`, `CONTAINER_PARTIAL_MESSAGE`를 문서에서 직접 다룬다 [es-journald], OTel `journald` 수신기는 컨테이너 배포 방법을 문서화한다 [otel-jd]. 다만 "Docker 호스트의 기본 권장"으로 명시한 벤더는 없다(추론).
3. **우리 선택(journald 드라이버 + 단일 otelcol)은 방향상 문제없지만, 소스를 읽다가 실제 위험 3가지를 찾았다.**
   - **(가장 중요) otelcol `journald` 수신기는 `--output=json`으로 `journalctl`을 띄우고 `all: true`일 때만 `--all`을 붙인다 [otel-jd-src]. `journalctl` man은 4096바이트보다 큰 필드를 `null`로 내보낸다고 적는다 [sd-journalctl]. 우리 템플릿은 `all`을 설정하지 않는다. 따라서 4KiB 넘는 컨테이너 로그 줄(대형 JSON, 스택 트레이스)의 `MESSAGE`가 `null`이 될 가능성이 높다(추론, 실호스트 재현 미확인).**
   - journald 속도 제한(기본 30초당 10000건, 서비스 단위)이 모든 컨테이너 로그에 공유 예산으로 걸릴 수 있다 [sd-journald].
   - `SystemMaxUse`(우리는 2G)에 닿으면 오래된 항목부터 지워지고, journal이 "수집 장애 시 버퍼"이자 "시스템 로그 저장소"를 겸하므로 컨테이너 폭주가 시스템 로그 보존을 밀어낸다(추론).
4. **권고:** 당장 갈아엎지 않는다. (a) `journald/containers`와 `journald`에 `all: true`를 켜고 실호스트에서 4KiB 초과 줄을 검증한다. (b) journald 드롭·용량을 알림으로 감시한다. (c) 컨테이너 로그가 큰 비중이면 장기적으로 `filelog` + `container` operator(json-file/local 드라이버, 로테이션 상한 명시)가 가장 "표준에 가까운" 대안이지만, 단일 호스트 otelcol만으로는 메타데이터 보강(compose 라벨)이 약해 비용이 크다(아래 §7).

## 1. 접근 방식별 업계 권고 (축 1)

| 벤더/출처 | 공식 권고(Docker 호스트) | 근거 |
|---|---|---|
| Docker | 기본 드라이버는 `json-file`. 로그를 다른 백엔드로 보내면 `docker logs`가 쓸모없어질 수 있고, 드라이버가 읽기를 지원하지 않으면 dual logging 캐시가 자동으로 켜진다. 선택 기준을 제시하는 문장은 없다 | [d-cfg], [d-overview], [d-dual] |
| Datadog | Agent가 Docker 소켓으로 컨테이너를 찾고, 파일 tail은 "소켓보다 성능이 낫다". 6.33.0+/7.33.0+는 파일이 기본. 파일 방식은 `/var/lib/docker/containers`를 Agent에 노출해야 한다. journald 드라이버는 별도 `journald` 통합 문서로 안내한다 | [dd-docker], [dd-journald] |
| Grafana | Loki Docker 드라이버는 서드파티 클라이언트이며 Alloy와 같은 지원 약속이 없다고 적고, 교착(deadlock) 회피를 위해 Alloy `loki.source.docker`/`discovery.docker`를 권한다. 드라이버 deprecation 문구는 확인되지 않음 | [loki-drv] |
| Elastic | Docker 통합은 소켓으로 컨테이너를 발견하고 `/var/lib/docker/containers/${docker.container.id}/*-json.log`를 읽는다. `container_logs` 데이터 스트림은 기본 활성 | [es-docker] |
| Elastic | Filebeat `journald` 입력도 GA이며, Docker 필드(`CONTAINER_ID_FULL`, `CONTAINER_NAME`, `IMAGE_NAME`)와 `CONTAINER_PARTIAL_MESSAGE` 태그를 문서화한다 | [es-journald] |
| OTel Collector Contrib | `filelog`에 `container` 파서 operator(docker/cri-o/containerd 포맷), `journald` 수신기, `docker_stats`(메트릭 전용). 컨테이너 로그 수집 방식을 단일 권고로 못 박은 문장은 없다 | [otel-container], [otel-jd], [otel-stats] |
| Vector | `docker_logs` 소스가 Docker 소켓으로 읽고 16KB 분할 조각을 기본 병합한다 | [vec-docker] |
| Fluent Bit | `tail` 입력(`docker`/`cri` 멀티라인 파서, `Docker_Mode`)과 `systemd` 입력이 별도로 있다. 컨테이너 전용 권고 문장은 확인되지 않음 | [fb-tail], [fb-systemd] |
| AWS | FireLens는 ECS 전용(Fargate/EC2) 기능이라 평범한 Docker 호스트에 해당하지 않는다. `awslogs` 드라이버 문서는 비차단 모드 권고를 싣지 않는다 | [aws-firelens], [d-awslogs] |
| GCP | Ops Agent 로깅 수신기 목록에 `files`, `systemd_journald`, `fluent_forward` 등이 있으나 Docker 컨테이너 로그 수집 방법은 해당 페이지에서 확인되지 않았다(미확인). `gcplogs` 드라이버는 Docker 문서에 옵션이 있다 | [gcp-ops], [d-gcplogs] |
| Splunk | Docker `splunk` 드라이버 옵션은 확인했다 [d-splunk]. Splunk OTel Collector가 Docker 컨테이너 로그를 어떻게 권하는지는 공식 문서 직접 확인에 실패했다(403). 검색 결과 요약상 파일 경로 마운트 방식 튜토리얼이 있다(secondary) | [d-splunk], 미확인 |
| Twelve-Factor | 앱은 stdout으로 이벤트 스트림을 내보내고, 라우팅·저장은 실행 환경이 맡는다. 앱이 로그 파일을 관리하지 않는다 | [12f] |

**해석(추론).** 업계 다수파는 "Docker가 로컬에 남긴 로그를 에이전트가 읽는다"이다. 이유는 (1) Twelve-Factor가 말하는 앱/실행환경 분리, (2) 에이전트 장애가 컨테이너 기동과 분리되는 점(§2), (3) `docker logs`가 유지되는 점이다. 원격 드라이버는 데몬이 직접 네트워크 I/O를 하므로 Docker 문서도 "STDOUT/STDERR 차단 시 앱이 예상치 못하게 실패할 수 있다"고 경고한다 [d-cfg]. journald는 "로컬 저장소 + 에이전트" 모델이라 구조상 B와 같은 계열이다.

## 2. 수집기 장애 시 동작 (축 2)

| 접근 | 수집기 다운 시 | 컨테이너 기동 | `docker logs` | 근거 |
|---|---|---|---|---|
| fluentd 드라이버(기본) | 기동 실패 | `fluentd-async` 없이는 연결 실패 시 컨테이너가 즉시 중지 | 원격 드라이버는 dual logging 캐시로 가능(문서가 드라이버별로 적진 않음) | [d-fluentd], [d-dual] |
| fluentd 드라이버(`fluentd-async`) | 메모리 버퍼(`fluentd-buffer-limit` 기본 1048576 이벤트). 가득 차면 기록 실패 | 기동 가능 | 동일 | [d-fluentd] |
| 임의 드라이버 `mode=blocking`(기본) | 앱의 쓰기가 막힘 | 드라이버별 | - | [d-cfg] |
| 임의 드라이버 `mode=non-blocking` | 버퍼(`max-buffer-size` 기본 1m)가 차면 새 메시지를 버림 | - | - | [d-cfg] |
| Loki 드라이버 | Loki 불통 시 메모리 보관 후 드롭. `loki-retries=0`이면 데몬이 무한 대기할 수 있음. `keep-file=true`면 JSON 파일 유지 | 완화 옵션 사용 시 가능 | `keep-file=true`일 때만 파일 유지 | [loki-drv] |
| gelf | TCP 재연결 기본 3회/1초 간격. 시작 시 불통 동작은 문서에 없음(미확인) | 미확인 | 미확인 | [d-gelf] |
| splunk | `splunk-verify-connection` 기본 true(시작 시 연결 검증). 실패 시 동작은 문서에 명시 없음 | 미확인 | 미확인 | [d-splunk] |
| awslogs | 불통 동작·비차단 모드 문서 없음(미확인) | 미확인 | 미확인 | [d-awslogs] |
| json-file + 에이전트 (`local` 제외: 데몬 전용 형식) | 호스트 파일이 버퍼. 에이전트는 오프셋(positions/체크포인트)으로 재개. 단 로테이션이 오프셋을 앞지르면 유실 | 영향 없음 | 영향 없음 | [d-json], [d-local], [alloy-file] |
| journald 드라이버 + 에이전트 | journal이 버퍼. 에이전트가 cursor(`storage`)로 재개. journal 용량·보존 한도 초과 시 유실 | 영향 없음 | 가능(`journalctl`, journal API, `docker logs`) | [d-jd], [otel-jd], [sd-journald] |

**우리 관점(추론).** 우리는 `journald/containers`에 `storage: file_storage`를 두어 cursor를 저장하므로 otelcol 재시작·장애 중 쌓인 항목을 이어서 읽는다 (`storage`가 없으면 cursor를 메모리에만 보관한다 [otel-jd]). otelcol이 죽어도 컨테이너와 `docker logs`는 영향이 없으므로, 이 축에서는 fluentd/gelf 직접 전송보다 낫다. 유실 가능 구간은 (1) otelcol 장애가 `SystemMaxUse`/`MaxRetentionSec` 도달보다 길 때, (2) journald 속도 제한이다.

## 3. 메타데이터 (축 3)

| 접근 | 컨테이너명/이미지 | compose 프로젝트·서비스 | 근거 |
|---|---|---|---|
| journald 드라이버 | 항목에 `CONTAINER_NAME`(시작 시점 이름; `docker rename`은 반영 안 됨), `IMAGE_NAME`, `CONTAINER_ID(_FULL)`, `CONTAINER_TAG`/`SYSLOG_IDENTIFIER` | `labels` 옵션으로 지정한 라벨만 필드가 된다. 변환 규칙은 소스상 대문자화 + 영숫자 외 문자는 `_` + 앞쪽 `_` 제거이므로 `com.docker.compose.project`는 `COM_DOCKER_COMPOSE_PROJECT`가 된다(소스에서 추론한 이름이고, Docker 문서는 이 필드명을 적지 않음). `env`/`env-regex`/`labels-regex`도 있음 | [d-jd], [moby-jd] |
| json-file 파일 + 에이전트 | 파일 경로의 컨테이너 ID만 있음. 이름·이미지는 Docker API 조회 필요 | Datadog은 파일 수집 로그에도 컨테이너 메타데이터 태그를 붙인다. Elastic은 `add_docker_metadata`(파일 경로에서 ID를 뽑아 Docker API 조회)로 보강한다 | [dd-docker], [es-docker] |
| Docker 소켓 에이전트 | Vector: `container_id`, `container_name`, `image`, `stream` 등 | Vector: 라벨을 `label` 아래에 첨부 | [vec-docker] |
| OTel `filelog` + `container` operator | `log.iostream`, `log.file.path`만 확실. 문서가 설명하는 메타데이터 보강은 Kubernetes 경로(파일 경로에서 pod·namespace 등) 중심 | Docker 컨테이너명·이미지·compose 라벨을 채우는 기능은 문서에 없음(미확인이 아니라 해당 operator 문서 범위 밖) | [otel-container] |
| 원격 드라이버 | `tag`와 `labels`/`env` 옵션으로 필드 추가(gelf는 `_` 접두어, awslogs·fluentd·splunk도 유사) | 동일 | [d-gelf], [d-fluentd], [d-splunk], [d-gcplogs] |

**해석(추론).** compose 라벨까지 로그 레코드 자체에 실어 보내려면 드라이버 `labels` 옵션(journald 포함)이 가장 단순하다. `filelog` + `container` operator 경로는 단일 otelcol만으로는 컨테이너 이름·compose 라벨을 얻기 어렵다(Docker 소켓에서 `docker inspect`를 읽는 구성요소가 contrib에 없는 한; 존재 여부는 이번 조사에서 미확인). 이것이 우리가 journald를 고른 가장 큰 합리적 이유다.

## 4. 구조화 JSON, 멀티라인, 긴 줄 (축 4)

**사실.**

- Docker는 컨테이너 출력을 읽을 때 16KiB 버퍼(`defaultBufSize = 16 * 1024`)로 나눠 읽고 조각에 부분 메시지 메타데이터(ID, ordinal, last)를 붙인다 [moby-copier]. journald 드라이버는 마지막 조각이 아닐 때 `CONTAINER_PARTIAL_MESSAGE=true`와 `CONTAINER_PARTIAL_ID/ORDINAL/LAST` 필드를 넣는다 [moby-jd]. Docker 문서는 이 필드가 "로그 무결성 표시와 긴 줄 처리 개선"용이라고 적는다 [d-jd].
- Vector는 "Docker는 기본으로 16kb를 넘는 메시지를 쪼갠다"고 적고 `auto_partial_merge: true`(기본)로 자동 병합한다 [vec-docker]. Elastic journald 입력은 `CONTAINER_PARTIAL_MESSAGE`가 true면 `partial_message` 태그만 붙인다(병합 여부는 문서에 없음) [es-journald].
- OTel `container` operator는 Docker 포맷에 부분 줄 태그가 없어 멀티라인은 별도 `recombine`이 필요하고, `max_log_size` 기본 1MiB를 넘으면 합쳐진 항목을 flush 한다 [otel-container]. `filelog`는 `multiline`(`line_start_pattern`/`line_end_pattern`)을 제공하고 `max_log_size_behavior` 기본은 `split`이다 [otel-filelog].
- Datadog은 멀티라인을 `com.datadoghq.ad.logs` 라벨의 `multi_line` 처리 규칙으로 지원한다 [dd-docker]. Fluent Bit은 `multiline.parser docker, cri`와 `Docker_Mode`(분할된 Docker 줄 재결합)를, Vector는 멀티라인 집계(기본 꺼짐)를 제공한다 [fb-tail], [vec-docker].
- **journalctl `-o json`은 4096바이트보다 큰 필드를 `null`로 출력하며 `--all`로 끌 수 있다** [sd-journalctl]. OTel `journald` 수신기는 항상 `--output=json`이고 설정 `all: true`일 때만 `--all`을 붙인다 [otel-jd-src]. 수신기 README는 `all` 기본 false("매우 긴 로그와 출력 불가능한 문자가 있는 로그는 `true`일 때만 포함")라고 적는다 [otel-jd]. `convert_message_bytes`는 바이트 배열로 읽힌 `MESSAGE`를 문자열로 바꿀 뿐이다 [otel-jd].
- stderr: moby journald 드라이버는 stderr 출처 메시지를 `PriErr`, 그 외를 `PriInfo`로 보낸다 [moby-jd]. 즉 `PRIORITY=3`(error)은 "앱이 error를 냈다"가 아니라 "stderr로 썼다"이다.

**추론(우리 설정).**

- **4096바이트 초과 JSON 줄 위험.** 우리 `journald/containers`는 `all`을 설정하지 않았다. 앱이 한 줄에 4KiB를 넘는 JSON(예외 스택 포함)을 stdout에 내면 `MESSAGE`가 `null`이거나 누락되어 body가 비는 것으로 예상된다. ADR-0008의 "원문 불변, 파싱 실패 줄도 버리지 않는다"와 ISMS 증적 목적에 직접 걸린다. **실호스트에서 5000바이트 줄을 한 번 찍어 확인하는 것이 선행 작업이다(미확인).**
- **16KiB 초과 줄.** journald 경로에서는 조각이 별개 journal 항목이다. 우리 파이프라인은 `CONTAINER_PARTIAL_MESSAGE`를 보지 않고 재결합도 없으므로, 16KiB 초과 줄은 서로 다른 로그 레코드 여러 개로 중앙에 도착하고 JSON 파싱은 중앙에서 실패한다.
- **멀티라인.** 스택 트레이스를 여러 줄로 출력하는 앱은 줄마다 별도 레코드가 된다. 앱이 JSON 한 줄 로그를 낸다는 전제(우리 compose 서비스)라면 문제 없다.
- stderr 우선순위가 severity로 그대로 올라가므로(`severity_parser`가 `PRIORITY` 3을 error로 매핑), JSON 본문의 `level`과 불일치할 수 있다. ADR-0008에 따라 중앙 의미 해석에서 본문 `level`을 우선하도록 해야 한다.

## 5. 앱 로그와 시스템 로그 분리, 중복 방지 (축 5)

**사실.**

- Docker journald 드라이버로 쓴 항목은 같은 journal에 시스템 로그와 섞인다 [d-jd]. 항목은 `CONTAINER_NAME` 등 필드로 구분된다 [d-jd].
- OTel `journald` 수신기는 `units`, `identifiers`, `matches`, `priority`(기본 info), `grep` 필터를 제공한다 [otel-jd]. 우리는 operator `filter`로 `CONTAINER_NAME` 유무를 갈랐다(템플릿).
- Datadog `journald` 통합은 `include_units`/`exclude_units`와 `container_mode: true`(컨테이너 로그의 `source`를 짧은 이미지 이름으로)를 제공한다. 같은 journal을 서로 다른 `source`/`service`로 두 번 읽으려면 별도 config(`config_id`)가 필요하다 [dd-journald]. Datadog 문서에 중복 방지 전용 설명은 없다.
- Elastic Filebeat `journald` 입력은 `units`, `include_matches`(정확 일치만), `syslog_identifiers`, `facilities`와 `container` 파서를 제공한다 [es-journald].
- Fluent Bit `systemd` 입력은 `Systemd_Filter`(여러 번 지정 가능)를 제공한다 [fb-systemd].

**추론(우리 설정).** `otelcol` 쪽은 두 수신기가 서로 `CONTAINER_NAME` 유무로 배타 분리하므로 otelcol 내부 중복은 없다. 남은 중복 경로는 rsyslog `imjournal`이 컨테이너 항목을 `/var/log/messages`에 쓰는 것이며, 우리는 `if ($!CONTAINER_NAME != "") then stop` 규칙(`00-` 접두어)으로 막는다(`rsyslog-containers.conf.j2`). `$!CONTAINER_NAME` 속성명이 `imjournal`의 변환 결과와 일치하는지는 `monitoring.md`도 "실호스트 확인"으로 남겨 두었고, 이번 조사에서는 rsyslog 공식 문서를 확인하지 않았다(미확인).

## 6. 로테이션·보존 상한이라는 운영 위험 (부가 축)

| 접근 | 상한 설정 | 기본값 | 근거 |
|---|---|---|---|
| json-file | `max-size`, `max-file` | `max-size` 기본 -1(무제한), `max-file` 기본 1, `max-file`은 `max-size`가 있어야 유효. 설정 없으면 로그가 무한히 쌓임 | [d-json] |
| local | `max-size`, `max-file`, `compress` | 20m, 5, 압축 기본 켜짐 | [d-local] |
| dual logging 캐시(원격 드라이버) | `cache-max-size`/`cache-max-file` 계열 | 5개 x 20MB, 압축 켜짐, `cache-disabled`로 끔 | [d-dual] |
| journald | `SystemMaxUse`, `SystemKeepFree`, `MaxRetentionSec` 등 | `SystemMaxUse` 기본은 파일시스템의 10%(상한 4G), `SystemKeepFree` 15%. 개별 파일은 `SystemMaxUse`의 1/8(상한 128M)이라 보통 일곱 개 정도의 과거 파일이 남음 | [sd-journald] |
| journald 속도 제한 | `RateLimitIntervalSec`, `RateLimitBurst` | 기본 30초에 10000건. 서비스 단위로 적용되며 초과분은 그 간격이 끝날 때까지 버려지고 "버려진 건수" 메시지가 남음. 실효값은 남은 디스크 용량에 따른 로그 배수가 곱해짐. 둘 중 하나를 0으로 하면 끔 | [sd-journald] |

**추론(우리 설정).**

- 우리 `common` 롤은 `SystemMaxUse` 2G, `MaxRetentionSec` 1month를 둔다(`roles/common/tasks/main.yml` COMMON-017). ADR-0006 §2.3은 "로컬 journald 3개월 유지"라고 적고 있어 코드(`1month` 기본)와 문서가 어긋나 있다. 어느 쪽이 의도인지 확인이 필요하다.
- 컨테이너 로그가 journal에 들어가면 보존 예산 2G를 시스템·보안 로그와 나눠 쓴다. 폭주하는 컨테이너 하나가 `sshd`/`sudo` 기록의 로컬 보존을 먼저 밀어낼 수 있다. otelcol이 정상이면 중앙에는 이미 가 있으므로 영향은 "로컬 사본·장애 구간 버퍼"에 한정된다.
- **속도 제한의 단위.** systemd 문서는 "서비스당"이라고만 적는다 [sd-journald]. Docker journald 드라이버는 dockerd가 journal 소켓으로 보내므로 로그 발신 서비스가 컨테이너별이 아니라 `docker.service`로 잡힌다는 해석이 가능하며, Kubernetes 이슈에 `Suppressed N messages from /system.slice/docker.service` 사례가 있다(secondary, 직접 열람하지 못하고 검색 요약으로만 확인: [k8s-41435]). 따라서 호스트의 모든 컨테이너가 하나의 예산을 공유할 가능성이 높다(추론, 미검증). 초당 약 333건 이상을 지속하는 컨테이너가 있으면 드롭이 발생한다.
- json-file은 현재 `docker_log_max_size`/`docker_log_max_file`을 `daemon.json`에 두고 있어(`roles/docker_engine`) 비교 대상 접근 B의 로테이션 상한은 이미 코드화되어 있다. 단 journald로 로그 드라이버를 바꾼 서비스에는 이 상한이 적용되지 않는다.

## 7. 우리 설정에 대한 평가와 권고

### (a) 사실 요약

- journald 드라이버 + 에이전트는 Datadog·Elastic·OTel 문서가 모두 다루는 경로이며 [dd-journald], [es-journald], [otel-jd], 컨테이너 필드(`CONTAINER_NAME`, `IMAGE_NAME`, 라벨)를 구조화해 준다 [d-jd].
- journald 항목의 `PRIORITY`는 stderr=3, 그 외=6(INFO)이다 [moby-jd].
- 4096바이트 초과 필드는 `journalctl -o json`에서 `null`이며 `--all`로만 풀린다 [sd-journalctl]. OTel 수신기는 `all` 기본 false다 [otel-jd], [otel-jd-src].
- journald 기본 속도 제한은 30초당 10000건이고 초과분은 드롭된다 [sd-journald].
- Docker는 16KiB 단위로 읽고 부분 조각에 `CONTAINER_PARTIAL_*` 필드를 붙인다 [moby-copier], [moby-jd].
- Datadog, Elastic, Vector, Grafana(Alloy)는 기본 경로로 파일 tail 또는 Docker 소켓을 쓴다 [dd-docker], [es-docker], [vec-docker], [loki-drv].

### (b) 추론

1. **정합성:** 단일 호스트 + 단일 otelcol + "compose 라벨까지 레코드에 싣고 싶다"는 제약에서 journald 드라이버는 합리적이다. 업계 다수파(파일/소켓)와 다르지만 "로컬 저장소 + 에이전트" 모델이라 장애 격리 특성이 같고, 원격 드라이버(fluentd/gelf)보다는 명백히 안전하다. 벤더가 "Docker 호스트의 기본으로 권장"하는 경로는 아니므로 문서·샘플·이슈 커버리지는 파일 경로보다 얇다.
2. **실제 위험(우선순위):**
   - P1: 4096바이트 초과 `MESSAGE`의 `null` 가능성(`all` 미설정).
   - P2: 16KiB 초과 줄의 조각 미재결합(JSON 파싱 실패, `log.parse_error` 증가).
   - P2: journald 속도 제한에 따른 버스트 드롭. 탐지 수단이 없으면 "조용한 유실"이다.
   - P3: `SystemMaxUse` 공유로 시스템·보안 로그 로컬 보존이 밀림. ADR(3개월)과 코드(1month) 불일치.
   - P3: stderr=error 가정이 앱 의미와 어긋남.
3. **대안(더 나은 선택지가 있는가):**
   - **대안 A: `json-file` 드라이버(`local`은 불가) + otelcol `filelog` + `container` operator.** 장점: 업계 기본 경로, 4096바이트 제약 없음, 컨테이너 단위 파일이라 속도 제한 공유 없음, 로테이션 상한이 컨테이너별(`max-size` x `max-file`)로 시스템 로그와 분리됨, `docker logs` 유지. 단점/비용: `filelog` 경로는 컨테이너 ID만 있어 컨테이너 이름과 compose 라벨 보강이 약함. 이를 메우려면 Docker 소켓 기반 수집기(Vector `docker_logs`, Alloy `loki.source.docker`, Datadog Agent)를 쓰거나, 파일 경로의 ID를 이름으로 바꾸는 사이드 매핑(예: Ansible이 만든 룩업)이 필요하다. 이는 "단일 otelcol" 제약과 충돌한다. 16KiB 조각도 Docker 포맷에는 부분 태그가 없어 `recombine` 설정을 직접 해야 한다 [otel-container]. 전환 비용: 서비스별 `logging:` 블록과 `daemon.json` 기본값 변경, 수신기 교체(`journald/containers` 제거, `filelog/containers` 추가), 체크포인트 ID 변경으로 인한 전환 시점 유실/중복, `rsyslog` 규칙(`MON-068/069`) 제거, ADR-0006 §2.3 개정.
   - **대안 B: 현 구조 유지 + 완화.** 비용이 가장 작고 현재 문제의 대부분(P1, P2 감시, P3)을 해소한다.
4. **권고:** **대안 B를 당장 적용하고, 컨테이너 로그량이 커지거나 P1/P2가 실측으로 확인되면 대안 A로 재평가한다.** 현재 데이터량·앱 로그 줄 길이 분포는 이번 조사에서 확인하지 못했다(미확인).

### 후속 작업(구체)

1. **실호스트 검증(선행):** 테스트 컨테이너로 1KiB, 5KiB, 20KiB 줄을 stdout에 쓰고, `journalctl -o json`과 otelcol 출력(OpenObserve `app_logs`)에서 `MESSAGE`가 온전한지 확인한다. 같은 확인에서 `COM_DOCKER_COMPOSE_PROJECT`/`_SERVICE` 필드명과 rsyslog `$!CONTAINER_NAME` 변환도 확인한다(`monitoring.md`에 이미 있는 TODO).
2. **`all: true` 적용:** `journald/containers`(와 필요하면 `journald`)에 `all: true`를 추가한다. 우려: 수신기 문서는 매우 긴 항목 때문에 큰 객체가 할당될 수 있다고 경고하는 쪽이므로 `memory_limiter` 설정과 함께 검증한다(`journalctl` man도 같은 주의를 적는다 [sd-journalctl]).
3. **조각 처리:** `CONTAINER_PARTIAL_MESSAGE` 항목에 `log.partial=true` 속성을 붙이는 operator를 추가하거나, 최소한 중앙 파싱 실패 알림(`log.parse_error`)에 원인 힌트를 남긴다. 실제 재결합은 `recombine`로 가능한지 별도 스파이크로 확인한다(미확인).
4. **속도 제한 대응:** `journald.conf.d`에 `RateLimitIntervalSec`/`RateLimitBurst`를 명시하는 항목을 `common` 롤에 추가할지 결정한다(`0`은 끔이므로 디스크 상한과 함께 판단). 동시에 `journalctl -u systemd-journald`의 "Suppressed" 메시지를 `system_logs`에서 알림으로 감시한다. 드롭 건수 알림은 OpenObserve 알림 SQL로 코드화할 수 있다.
5. **보존 정합:** ADR-0006 §2.3의 "로컬 journald 3개월"과 `common` 롤 기본값(`MaxRetentionSec=1month`, `SystemMaxUse=2G`)의 불일치를 해소한다. 컨테이너 로그량을 고려해 `SystemMaxUse` 상향이나, `LogNamespace`(journald 네임스페이스, OTel `namespace` 옵션이 대응 [otel-jd])로 컨테이너 로그를 분리하는 안을 평가한다. 네임스페이스 분리는 Docker 드라이버가 지원하는지 이번 조사에서 확인하지 못했다(미확인).
6. **severity 규칙:** 중앙 VRL(ADR-0008)에서 JSON 본문의 `level`을 우선하고, journald `PRIORITY`(stderr=3)는 본문에 레벨이 없을 때의 보조값으로만 쓰도록 문서화한다.
7. **재평가 조건 기록:** 대안 A로 전환할 트리거(예: 속도 제한 드롭이 월 N회 이상, 4KiB 초과 줄 비율이 N% 이상, 컨테이너 로그가 journal 예산의 절반 이상)를 이슈에 남긴다.

## 8. 확인하지 못한 항목 (미확인)

- Splunk 공식 문서에서 Splunk OTel Collector의 Docker 컨테이너 로그 권고(문서 페이지 403). 검색 결과 요약만 확인(secondary).
- GCP Ops Agent가 Docker 컨테이너 로그를 수집하는 공식 방법(`configuration` 페이지에 언급 없음).
- awslogs, gelf, splunk 드라이버가 수신 측 불통일 때 컨테이너 기동·`docker logs`에 미치는 영향(각 드라이버 문서에 명시 없음).
- Docker journald 드라이버 항목에 대한 journald 속도 제한이 컨테이너별인지 `docker.service` 단일 예산인지(공식 문서 부재, Kubernetes 이슈 검색 요약만 있음).
- 4096바이트 초과 컨테이너 로그가 우리 파이프라인에서 실제로 `null`이 되는지(소스·man 기반 추론, 실호스트 재현 없음).
- rsyslog `imjournal`의 `$!CONTAINER_NAME` 속성명(rsyslog 공식 문서 미열람).
- `docker_stats`는 메트릭 전용이라 로그 대체가 아님을 확인했으나 [otel-stats], contrib에 Docker `inspect` 기반으로 컨테이너 메타데이터를 로그에 붙이는 프로세서가 있는지는 확인하지 않았다.
- Docker 문서 중 오래된 버전은 "journald 속도 제한 1000건/30초"라고 적었다는 검색 요약이 있으나(secondary), 현재 systemd man 원문의 기본값은 10000건/30초이므로 후자를 따랐다.

## 9. 후속 결정과 정정 (2026-10-15)

- **정정:** 위 본문에서 `local` 드라이버를 파일 tail 대상으로 묶은 부분은 틀렸다. Docker 문서상 `local`은 데몬 전용 내부 저장 형식이라 외부 도구가 읽을 수 없고, `container` 파서가 읽는 것은 `json-file`의 `{"log","stream","time"}` 형식이다 [d-local], [d-json].
- **결정:** 사용자 결정으로 대안 A(`json-file` + `filelog`)로 전환했다(ADR-0006 §2.3 개정 2026-10-15).
- **컨테이너 이름·라벨 매핑(표준 방법 조사):** Filebeat `add_docker_metadata`, Datadog Agent, Grafana Alloy `discovery.docker`는 모두 Docker 소켓으로 컨테이너 ID를 조회한다. OTel 공식 경로는 `docker_observer` + `receiver_creator`이지만 로컬 실측에서 **포트를 노출하지 않은 컨테이너는 수신기가 만들어지지 않았다**. 그래서 소켓이 필요 없는 `json-file`의 `labels` 옵션(라벨을 줄마다 `attrs`로 기록)을 쓴다. ns0338 실호스트에서 모든 줄에 `attrs`가 붙고, 40KB 줄이 16384바이트 단위로 쪼개져 마지막 조각만 개행으로 끝남을 확인했다(`recombine` 가정).
- **남은 위험:** `body_` 접두어는 journald 본문(맵)을 OpenObserve가 펼칠 때 생기며(소스 확인) 파일 방식에서는 본문이 문자열이라 사라진다. rsyslog가 없는 호스트의 시스템 `journald` 수신기에는 4KiB `null` 문제가 남아 있어 `all: true`를 별도로 적용해야 한다.

## References

[d-cfg]: https://docs.docker.com/engine/logging/configure/
[d-overview]: https://docs.docker.com/engine/logging/
[d-dual]: https://docs.docker.com/engine/logging/dual-logging/
[d-jd]: https://docs.docker.com/engine/logging/drivers/journald/
[d-json]: https://docs.docker.com/engine/logging/drivers/json-file/
[d-local]: https://docs.docker.com/engine/logging/drivers/local/
[d-fluentd]: https://docs.docker.com/engine/logging/drivers/fluentd/
[d-gelf]: https://docs.docker.com/engine/logging/drivers/gelf/
[d-splunk]: https://docs.docker.com/engine/logging/drivers/splunk/
[d-awslogs]: https://docs.docker.com/engine/logging/drivers/awslogs/
[d-gcplogs]: https://docs.docker.com/engine/logging/drivers/gcplogs/
[moby-jd]: https://github.com/moby/moby/blob/master/daemon/logger/journald/journald.go
[moby-copier]: https://github.com/moby/moby/blob/master/daemon/logger/copier.go
[dd-docker]: https://docs.datadoghq.com/containers/docker/log/
[dd-journald]: https://docs.datadoghq.com/integrations/journald/
[loki-drv]: https://grafana.com/docs/loki/latest/send-data/docker-driver/
[alloy-docker]: https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.docker/
[alloy-file]: https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/
[es-docker]: https://www.elastic.co/docs/reference/integrations/docker
[es-journald]: https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-journald
[otel-jd]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/journaldreceiver/README.md
[otel-jd-src]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/operator/input/journald/config_linux.go
[otel-container]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/operators/container.md
[otel-filelog]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md
[otel-stats]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/dockerstatsreceiver/README.md
[vec-docker]: https://vector.dev/docs/reference/configuration/sources/docker_logs/
[fb-tail]: https://docs.fluentbit.io/manual/pipeline/inputs/tail
[fb-systemd]: https://docs.fluentbit.io/manual/pipeline/inputs/systemd
[sd-journald]: https://github.com/systemd/systemd/blob/main/man/journald.conf.xml
[sd-journalctl]: https://github.com/systemd/systemd/blob/main/man/journalctl.xml
[12f]: https://12factor.net/logs
[aws-firelens]: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_firelens.html
[gcp-ops]: https://docs.cloud.google.com/logging/docs/agent/ops-agent/configuration
[k8s-41435]: https://github.com/kubernetes/kubernetes/issues/41435
