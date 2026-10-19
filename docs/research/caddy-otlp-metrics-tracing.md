# Caddy v2.11 OTLP 메트릭·트레이스: 환경 변수, `per_host` 카디널리티, traceparent 전파

- 질문([#244](https://github.com/ppzxc/infra-automation/issues/244), 지도 [#239](https://github.com/ppzxc/infra-automation/issues/239)): 노드 Caddy(v2.11.4, xcaddy 빌드)의 메트릭과 트레이스를 OTLP로 내보내려면 무엇이 필요한가.
  1. `metrics { otlp }`와 `tracing`이 읽는 OTEL 환경 변수(엔드포인트, 프로토콜, 서비스 이름, resource attribute, sampler, propagator)
  2. `per_host`와 `observe_catchall_hosts`가 만드는 시계열과 카디널리티, 업무 호스트만 남기는 방법
  3. `tracing`이 upstream(funa)으로 W3C `traceparent`를 넘기는 조건, 클라이언트가 보낸 `traceparent`를 어떻게 다루는지, 액세스 로그의 trace id 필드명
  4. `tracing`을 둔 `handle` 밖의 요청(프로브, health 리스너, active health check)도 span을 만드는지
- 조사일: 2026-10-19
- **결정은 하지 않는다.** 마지막 절의 "선택지"는 지도에서 고를 재료다.

## 1차 출처

- Caddy 소스, 태그 [`v2.11.4`][caddy-tag] (노드 버전과 같은 태그)
  - [`modules/caddyhttp/metrics.go`][c-metrics]: `Metrics` 구조체, `provisionOTLP`, `scanConfigForHosts`, `shouldAllowHostMetrics`
  - [`modules/caddyhttp/tracing/tracer.go`][c-tracer], [`tracerprovider.go`][c-tp], [`module.go`][c-tmod]
  - [`modules/caddyhttp/routes.go`][c-routes]: 메트릭 계측이 붙는 위치, `handler` 라벨 값
  - [`modules/caddyhttp/app.go`][c-app], [`caddyconfig/httpcaddyfile/options.go`][c-opts], [`caddyconfig/httpcaddyfile/directives.go`][c-dirs](디렉티브 기본 순서)
  - [`context.go`][c-ctx]: 프로세스 전역 Prometheus 레지스트리(Go·process collector 포함)
  - [`go.mod`][c-gomod]: `contrib/exporters/autoexport`·`otelhttp`·`propagators/autoprop`·`bridges/prometheus` **v0.68.0**, `otel`·`otel/sdk`·`otel/sdk/metric` **v1.43.0**
- OpenTelemetry Go 소스(위 go.mod 버전 그대로, `go mod download`로 받은 모듈 캐시를 읽음)
  - `contrib/exporters/autoexport@v0.68.0`: `spans.go`, `metrics.go`, `registry.go`
  - `otel/exporters/otlp/otlptrace/otlptracehttp@v1.43.0/internal/otlpconfig/envconfig.go`, `options.go`, `internal/retry/retry.go`
  - `otel/sdk@v1.43.0`: `resource/resource.go`·`env.go`·`builtin.go`, `trace/provider.go`·`sampler_env.go`·`batch_span_processor.go`·`internal/env/env.go`
  - `otel/sdk/metric@v1.43.0/env.go`
  - `contrib/propagators/autoprop@v0.68.0/propagator.go`, `contrib/instrumentation/net/http/otelhttp@v0.68.0/handler.go`·`config.go`
- Caddy 공식 문서(Context7 `/caddyserver/website`): [`tracing` 디렉티브][d-tracing], [Global options `metrics`][d-opts], [Monitoring Caddy with metrics][d-metrics]
- 버전 경계 확인: `raw.githubusercontent.com/caddyserver/caddy/<tag>/modules/caddyhttp/metrics.go`를 v2.10.2, v2.11.0~v2.11.4 태그별로 받아 필드 존재를 grep했다.
- 참조 Caddyfile: 로컬 `caddy-boilerplate/cluster/runtime/Caddyfile`(노드 Caddyfile의 원형. 전역 `metrics { otlp; per_host; observe_catchall_hosts }`, `handle @valid_hosts` 안의 `tracing`)

### 로컬 재현

v2.11.4 태그 소스를 그대로 `go build`한 바이너리(플러그인 없음)로 참조 Caddyfile과 같은 모양의 설정을 띄워 확인했다. 사이트 블록에 명시 호스트 2개와 와일드카드 1개를 두고, 프로브 `handle`, `tracing`이 있는 업무 `handle`, 404 폴백 `handle`을 나눴다. upstream은 받은 `traceparent`/`tracestate`/`baggage` 헤더를 그대로 응답하는 두 번째 사이트다. exporter는 `OTEL_TRACES_EXPORTER=console`, `OTEL_METRICS_EXPORTER=console`로 stdout에 찍었다. HTTP와 HTTPS(`local_certs`) 두 경우를 모두 돌렸다.

노드 빌드에 들어간 플러그인 셋(mysql storage, rate limit, cloudflare DNS)은 `tracing`·`metrics` 코드를 건드리지 않으므로 결과가 같다고 본다(**추론**). 재현은 운영 노드에서 관측한 것이 아니다.

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 1차 출처(소스·문서)에 적힌 내용 |
| **재현** | 로컬 재현에서 직접 관측한 내용 |
| **추론** | 출처와 재현에서 끌어낸 판단. 운영 노드에서 관측한 것이 아니다 |
| **확인 못 함** | 확인하지 못한 항목 |

## 결론 요약

| 질문 | 답 | 절 |
|---|---|---|
| `metrics { otlp }`가 있나 | 있다. **v2.11.3에서 처음 들어왔다**(v2.11.0~v2.11.2에는 없다). 그보다 낮은 바이너리는 Caddyfile을 읽다가 `unrecognized servers option 'otlp'`로 실패한다 | §1.1 |
| 메트릭 exporter를 움직이는 변수 | `autoexport`가 `OTEL_METRICS_EXPORTER`(기본 `otlp`), `OTEL_EXPORTER_OTLP_[METRICS_]PROTOCOL`(기본 `http/protobuf`), `OTEL_EXPORTER_OTLP_[METRICS_]ENDPOINT`, `OTEL_METRIC_EXPORT_INTERVAL`(기본 60초) 등을 읽는다. `OTEL_METRICS_EXPORTER=otlp`는 기본값이라 생략해도 된다 | §1.2 |
| OTLP로 나가는 메트릭 범위 | Caddy HTTP 메트릭만이 아니라 **프로세스 전역 Prometheus 레지스트리 전체**(`go_*`, `process_*`, `promhttp_*`, `caddy_admin_*`, `caddy_config_*`, `caddy_reverse_proxy_upstreams_healthy`)가 나간다 | §1.3 |
| 트레이스 exporter를 움직이는 변수 | 같은 `autoexport`. `OTEL_TRACES_EXPORTER`(기본 `otlp`), `OTEL_EXPORTER_OTLP_[TRACES_]PROTOCOL`(기본 **`http/protobuf`**, 공식 문서의 "gRPC"는 코드와 다르다), 엔드포인트·헤더·TLS·압축·타임아웃, `OTEL_BSP_*`, `OTEL_TRACES_SAMPLER[_ARG]`(기본 `parentbased_always_on`, 즉 100%), `OTEL_PROPAGATORS`(기본 `tracecontext,baggage`) | §2 |
| 서비스 이름·resource | 메트릭·트레이스 둘 다 `resource.Default()`를 쓰므로 `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`가 둘 다에 적용된다. 미설정 시 `service.name=unknown_service:caddy`. Caddy가 `webengine.name=Caddy`, `webengine.version`을 덧붙인다(문서의 `web_engine.*`가 아니다) | §2.2 |
| `per_host` 시계열 | `caddy_http_*` 7종에 `host` 라벨이 붙는다. 값은 `r.Host`를 소문자로 바꾼 것이고 **포트가 붙어 오면 포트까지 라벨에 들어간다** | §3.1 |
| 업무 호스트만 남길 수 있나 | **Caddy 설정만으로는 안 된다.** HTTPS 요청은 `observe_catchall_hosts`가 없어도 설정에 없는 호스트를 그대로 라벨로 쓴다. 와일드카드 인증서가 있으면 `<아무거나>.<와일드카드 도메인>`마다 새 시계열이 생긴다. `observe_catchall_hosts`는 평문 HTTP 서버까지 같은 동작을 연다 | §3.2 |
| `handler` 라벨 | Caddyfile 사이트 블록은 최상위 route 하나(`subroute`)로 바뀌고 계측은 최상위 route에만 붙으므로 **사이트 안 모든 요청이 `handler="subroute"`**다. 경로 라벨은 없다. 프로브와 업무 API를 Caddy 메트릭으로는 가를 수 없다 | §3.3 |
| upstream으로 `traceparent` 전달 | 된다. `tracing`이 요청 헤더에 현재 span 컨텍스트를 **주입(덮어쓰기)**하고, `reverse_proxy`가 요청 헤더를 복제해 upstream에 보낸다. 부모는 Caddy의 server span이다(`reverse_proxy` 쪽 client span은 없다) | §4.1 |
| 클라이언트가 보낸 `traceparent` | **그대로 신뢰한다.** 클라이언트의 trace id를 이어받고, sampled 플래그가 `00`이면 Caddy span이 내보내지지 않으며 `-00`이 upstream까지 간다. 클라이언트 `baggage`도 upstream에 그대로 간다. 사이트 블록 수준 `request_header -traceparent`(+`-tracestate`, `-baggage`)로 끊을 수 있다(재현 확인) | §4.2 |
| 액세스 로그 필드 | `traceID`, `spanID`(최상위 필드, camelCase). 플레이스홀더 `{http.vars.trace_id}`, `{http.vars.span_id}`. **샘플링되지 않은 요청과 exporter가 `none`인 경우에도 기록된다** | §4.3 |
| `handle` 밖 요청의 span | 안 만든다. span은 `tracing` 핸들러를 지나는 요청에만 생긴다. 프로브 `handle`, 다른 사이트/리스너, `reverse_proxy` active health check는 span도 `traceID`도 없다(재현 확인) | §4.4 |
| 현재 노드의 1분 주기 export 실패 | 엔드포인트 변수가 없어 기본값(로컬 루프백의 OTLP/HTTP 기본 포트)으로 보내다 실패하는 것. OTLP exporter의 재시도 상한이 1분이라 실패 로그가 1분 단위로 나오는 것으로 보인다(**추론**). 임시로 막으려면 `OTEL_TRACES_EXPORTER=none`(trace id 로그·전파는 유지, 재현 확인) | §5 |

## 1. `metrics { otlp }`

### 1.1 존재와 버전 경계

- **출처**: v2.11.4 `Metrics` 구조체에 `OTLP bool \`json:"otlp,omitempty"\``가 있고, Caddyfile 파서가 `otlp` 하위 옵션을 `metrics.OTLP = true`로 바꾼다([`options.go`][c-opts] `unmarshalCaddyfileMetricsOptions`). 알 수 없는 하위 옵션이면 `unrecognized servers option '%s'` 오류를 낸다.
- **출처**: 태그별 `metrics.go`에서 `OTLP bool`은 v2.11.0·v2.11.1·v2.11.2에 없고 v2.11.3·v2.11.4에 있다. `ObserveCatchallHosts`는 v2.11.0부터 있고 v2.10.2에는 없다.
- **추론**: 노드에서 `metrics` 블록이 주석 처리된 이유가 예전 바이너리에서 `otlp`가 파싱 오류를 냈기 때문일 수 있다. 켜기 전에 노드에서 `caddy version`(또는 `caddy build-info`)으로 v2.11.3 이상인지 확인해야 한다. 노드 바이너리 버전은 이 조사에서 직접 보지 않았다(**확인 못 함**, 티켓 설명의 v2.11.4를 믿음).

### 1.2 동작과 환경 변수

- **출처**([`metrics.go`][c-metrics] `provisionOTLP`): `OTLP`가 참이면 `autoexport.WithFallbackMetricProducer`로 Prometheus→OTel 브리지(`bridges/prometheus`)를 기본 producer로 등록하고, `autoexport.NewMetricReader(ctx)`로 reader를 만든 뒤 `sdkmetric.NewMeterProvider(WithResource(res), WithReader(reader))`를 구성한다. 즉 **기존 Prometheus 메트릭을 주기적으로 읽어 OTLP로 push**한다. 스크레이프 엔드포인트(admin `/metrics`)는 그대로 남는다.
- **출처**(autoexport v0.68.0 `metrics.go`, `registry.go`):
  - `OTEL_METRICS_EXPORTER`: `otlp`(미설정 시 기본), `prometheus`, `console`, `none`.
  - 프로토콜: `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` → 없으면 `OTEL_EXPORTER_OTLP_PROTOCOL` → 없으면 `http/protobuf`. 허용 값은 `grpc`, `http/protobuf`뿐이다(그 밖이면 `invalid OTLP protocol` 오류로 Caddy provision 실패).
  - `OTEL_METRICS_PRODUCERS`(실험): 설정하면 Caddy가 등록한 fallback producer(브리지) 대신 쓰인다. 건드리지 않는다.
  - reader는 `sdkmetric.NewPeriodicReader`이므로 `OTEL_METRIC_EXPORT_INTERVAL`(기본 60000ms), `OTEL_METRIC_EXPORT_TIMEOUT`을 따른다(`otel/sdk/metric@v1.43.0/env.go`).
  - 엔드포인트·헤더·TLS·압축·타임아웃은 OTLP 메트릭 exporter가 `OTEL_EXPORTER_OTLP_*`와 `OTEL_EXPORTER_OTLP_METRICS_*`에서 읽는다(트레이스와 같은 규칙, §2.1).
- **출처**(공식 문서 options.md/metrics.md): "The exporter is configured by standard OpenTelemetry `OTEL_*` environment variables… Set `OTEL_METRICS_EXPORTER=none` to disable metric export without changing the Caddyfile." 문서의 예시는 `OTEL_METRICS_EXPORTER=otlp`를 함께 적지만 코드상 기본값이라 생략해도 결과가 같다.
- **재현**: `metrics { per_host; observe_catchall_hosts; otlp }` + `OTEL_METRICS_EXPORTER=console`, `OTEL_METRIC_EXPORT_INTERVAL=2000`으로 2초마다 메트릭이 stdout에 출력됐다.

### 1.3 나가는 메트릭 범위

- **출처**: 브리지는 `ctx.GetMetricsRegistry()`(프로세스 전역 레지스트리)를 gatherer로 쓴다. 이 레지스트리에는 [`context.go`][c-ctx]가 `NewProcessCollector`, `NewGoCollector`를 등록한다.
- **재현**: console 출력의 메트릭 이름은 `caddy_http_*` 7종(`requests_in_flight`, `requests_total`, `request_errors_total`, `request_duration_seconds`, `request_size_bytes`, `response_size_bytes`, `response_duration_seconds`) 외에 `caddy_admin_http_requests_total`, `caddy_config_last_reload_successful`, `caddy_config_last_reload_success_timestamp_seconds`, `caddy_reverse_proxy_upstreams_healthy`, `go_*` 약 30종, `process_*` 약 10종, `promhttp_metric_handler_*`였다.
- **추론**: 필요 없는 런타임 메트릭을 줄이려면 Caddy 쪽에는 스위치가 없으므로 노드 otelcol에서 메트릭 이름으로 거른다.

## 2. `tracing`이 읽는 환경 변수

### 2.1 exporter

- **출처**([`tracer.go`][c-tracer]): `autoexport.NewSpanExporter(ctx)`로 exporter를 만들고, `sdktrace.NewTracerProvider(WithBatcher(exporter), WithResource(res))`로 provider를 만든다. **Caddy는 sampler, propagator, endpoint를 코드로 지정하지 않는다.** 전부 환경 변수와 라이브러리 기본값이다.
- **출처**(autoexport v0.68.0 `spans.go`): `OTEL_TRACES_EXPORTER`: `otlp`(기본), `console`, `none`. 프로토콜은 `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` → `OTEL_EXPORTER_OTLP_PROTOCOL` → `http/protobuf`.
- **출처와 문서의 충돌**: Caddy 공식 `tracing` 문서는 "It uses gRPC as an exporter protocol"이라고 쓰지만, v2.11.4가 쓰는 autoexport v0.68.0의 기본은 `http/protobuf`다. **코드가 기준이다.** 프로토콜을 명시해 두면 이 차이에 기대지 않아도 된다.
- **출처**(otlptracehttp v1.43.0 `envconfig.go`, `options.go`):
  - `OTEL_EXPORTER_OTLP_ENDPOINT`는 **기준 URL**이다. 그 경로 뒤에 `/v1/traces`(메트릭은 `/v1/metrics`)를 붙인다. 그래서 하나만 두면 트레이스와 메트릭이 같은 수신기의 각 경로로 간다.
  - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`(메트릭은 `..._METRICS_ENDPOINT`)는 **그대로** 쓴다. 경로가 없으면 `/`로 보낸다. 공식 문서 예시(`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://host:port`)를 그대로 따르면 경로가 `/`가 되므로, 신호별 변수를 쓸 때는 `/v1/traces`까지 적어야 한다.
  - 스킴이 `http`이면 평문, 그 밖이면 TLS. `OTEL_EXPORTER_OTLP_[TRACES_]HEADERS`, `..._CERTIFICATE`, `..._CLIENT_CERTIFICATE`/`..._CLIENT_KEY`, `..._INSECURE`, `..._COMPRESSION`, `..._TIMEOUT`을 읽는다.
  - 엔드포인트 변수가 없으면 `localhost` + OTLP/HTTP 기본 포트로 보낸다(`DefaultCollectorHost`, `DefaultCollectorHTTPPort`). 컨테이너 안에서는 이 주소가 컨테이너 자신이라 연결이 거부된다.
- **출처**(`otel/sdk@v1.43.0/trace`): 배치 처리기는 `OTEL_BSP_SCHEDULE_DELAY`(기본 5000ms), `OTEL_BSP_EXPORT_TIMEOUT`, `OTEL_BSP_MAX_QUEUE_SIZE`, `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`를, span 한도는 `OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT` 등을 읽는다.

### 2.2 서비스 이름과 resource attribute

- **출처**: 트레이스([`tracer.go`][c-tracer] `newResource`)와 메트릭([`metrics.go`][c-metrics] `provisionOTLP`) 모두 `resource.Merge(resource.Default(), {webengine.name, webengine.version})`를 쓴다. `resource.Default()`는 `defaultServiceNameDetector`, `fromEnv`, `telemetrySDK` detector를 돌리며(`resource.go`), `fromEnv`는 `OTEL_RESOURCE_ATTRIBUTES`와 `OTEL_SERVICE_NAME`을 읽는다(`env.go`, `OTEL_SERVICE_NAME`이 `service.name`보다 우선). 서비스 이름이 없으면 `unknown_service:<실행 파일 이름>`이다(`builtin.go`).
- **재현**: 미설정 시 메트릭 resource는 `service.name=unknown_service:caddy`. `OTEL_SERVICE_NAME=caddy-test`를 주자 span resource가 `service.name=caddy-test`로 바뀌었다. 두 신호 모두 `webengine.name=Caddy`가 붙었다. 공식 metrics 문서는 `web_engine.name`이라고 쓰지만 실제 키는 `webengine.name`이다(semconv v1.17/v1.26 기준 이름).
- **출처**: `resource.Default()`는 `sync.Once`로 프로세스당 한 번만 계산된다. **추론**: OTEL_* 값을 바꾼 뒤에는 `caddy reload`가 아니라 컨테이너를 다시 만들어야 반영된다(환경 변수 자체가 프로세스 시작 때 고정되므로 어차피 마찬가지다).

### 2.3 sampler, propagator

- **출처**(`trace/provider.go`, `sampler_env.go`): 코드에서 sampler를 주지 않으면 `OTEL_TRACES_SAMPLER`/`OTEL_TRACES_SAMPLER_ARG`를 읽고, 그것도 없으면 `ParentBased(AlwaysSample)`이다. 허용 값은 `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio`.
  - 즉 기본은 **업무 경로 요청 100% 샘플링**이고, 들어온 요청에 부모 컨텍스트가 있으면 그 sampled 플래그를 따른다.
- **출처**(autoprop v0.68.0): `OTEL_PROPAGATORS`가 없으면 `tracecontext` + `baggage`. 지원 값 `tracecontext`, `baggage`, `b3`, `b3multi`, `jaeger`, `xray`, `ottrace`, `none`. `none`이 들어 있으면 no-op propagator가 된다.
  - **추론**: `OTEL_PROPAGATORS=none`은 클라이언트 컨텍스트를 무시하는 방법처럼 보이지만 **upstream 주입까지 꺼서** funa와 한 트레이스로 이어지지 않는다. 쓰면 안 된다. 같은 이유로 `tracecontext`는 반드시 남겨야 한다.

### 2.4 정리: 노드에 둘 변수 후보

| 변수 | 필요 | 비고 |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | 필수 | 노드 otelcol OTLP/HTTP 수신기 기준 URL(경로 없이). 트레이스·메트릭이 `/v1/traces`, `/v1/metrics`로 갈린다 |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | 권장 | `http/protobuf`. 기본값과 같지만 문서와 코드가 어긋나므로 명시해 둔다 |
| `OTEL_SERVICE_NAME` | 필수 | 예: `caddy`. 없으면 `unknown_service:caddy` |
| `OTEL_RESOURCE_ATTRIBUTES` | 선택 | `host.name`, `deployment.environment.name` 등. 노드 otelcol의 resource processor가 붙인다면 중복이다 |
| `OTEL_PROPAGATORS` | 선택 | 기본 `tracecontext,baggage`. 클라이언트 baggage를 막으려면 이 값이 아니라 헤더 제거로 막는다(§4.2) |
| `OTEL_TRACES_SAMPLER` | 선택 | 기본 `parentbased_always_on`(100%) |
| `OTEL_METRICS_EXPORTER` | 불필요 | 기본 `otlp`. 끄는 스위치(`none`)로만 의미가 있다 |
| `OTEL_METRIC_EXPORT_INTERVAL` | 선택 | 기본 60초 |

## 3. `per_host`와 `observe_catchall_hosts`

### 3.1 라벨 셋

- **출처**([`metrics.go`][c-metrics] `initHTTPMetrics`):
  - `requests_in_flight`, `requests_total`, `request_errors_total`: `server`, `handler` (+`host`)
  - `request_duration_seconds`, `response_duration_seconds`: `server`, `handler`, `code`, `method` (+`host`), 버킷 `prometheus.DefBuckets` 11개
  - `request_size_bytes`, `response_size_bytes`: 같은 라벨, 버킷 8개(256부터 ×4)
  - `method`·`code`는 `SanitizeMethod`·`SanitizeCode`를 거쳐 값 집합이 제한된다.
- **출처**(`metricsInstrumentedRoute.ServeHTTP`): `host` 값은 허용되면 `strings.ToLower(r.Host)`, 아니면 `_other`.
- **재현**: `Host: APP.test:<포트>`로 보낸 요청이 `host="app.test:<포트>"`라는 **별도 시계열**이 됐다(재현은 비표준 테스트 포트를 썼다). 포트는 지워지지 않는다. 브라우저는 HTTPS 기본 포트를 Host에 쓰지 않지만 클라이언트가 임의로 붙이면 새 값이 된다.
- **추론**(카디널리티): 호스트 값 하나당 대략 `requests_*` 3개 + 히스토그램 4종 × (code×method 조합) × (버킷+2) 시계열이 생긴다. code×method 조합이 10개면 호스트 하나에 약 500 시계열이다.

### 3.2 어떤 호스트가 자기 라벨을 얻나

- **출처**(`scanConfigForHosts`): 허용 목록은 **각 서버의 최상위 route**의 `host` 매처 값 중 `*`나 `{`가 없는 것(`fuzzy` 아님)이다. 하위 route(subroute 안의 `@valid_hosts` 같은 매처)는 훑지 않는다. 참조 Caddyfile에서는 사이트 주소의 두 명시 호스트가 들어가고 와일드카드 주소는 빠진다. `{$ENV}` 치환은 Caddyfile 변환 때 끝나므로 fuzzy가 아니다.
- **출처**(`shouldAllowHostMetrics`): 목록에 없는 호스트는 `ObserveCatchallHosts || (isHTTPS && hasHTTPSServer)`이면 **그 이름 그대로** 라벨이 된다. 구조체 주석: "This is automatically enabled for HTTPS servers… but disabled for HTTP servers by default". 공식 문서도 "If an HTTPS server is configured, the host is observed, even if not explicitly configured"라고 쓴다.
- **재현**(HTTPS, `per_host`만, `observe_catchall_hosts` 없음): `x1.wild.test`, `x2.wild.test`, `x3.wild.test`(설정에 없는 와일드카드 하위 호스트, 404 폴백으로 처리됨)가 각각 별도 `host` 라벨을 얻었다.
- **재현**(HTTP, `per_host`만): 와일드카드 하위 호스트는 `_other`로 묶였다. `per_host`+`observe_catchall_hosts`로 바꾸자 같은 요청이 `r1.wild.test`…`r4.wild.test`로 각각 갈라졌다.
- **재현**: 어느 사이트 주소에도 맞지 않는 Host(`attacker.example`)는 route가 매치되지 않아 **메트릭 자체가 기록되지 않았다**(계측이 route에 붙어 있기 때문).
- **추론**: 노드는 HTTPS 서버이고 사이트 주소에 와일드카드 호스트가 있다. `strict_sni_host`는 Host와 SNI가 같기만 요구하고, 와일드카드 인증서는 그 아래 아무 이름의 SNI나 받아 준다. 따라서 **`observe_catchall_hosts`를 빼도** 외부에서 `<임의 문자열>.<와일드카드 도메인>`로 요청할 때마다 새 시계열이 생긴다. `observe_catchall_hosts`는 여기에 더해 평문 HTTP 리스너(HTTP→HTTPS 리다이렉트 서버 등)에서 아무 Host 헤더나 라벨로 만들게 한다. 노드에 둘 이유가 없다.
- **결론**: Caddy v2.11.4에는 "HTTPS에서도 명시 호스트만 라벨로" 하는 설정이 없다. 업무 호스트만 남기려면 아래 중 하나다.

### 3.3 `handler` 라벨과 경로

- **출처**([`routes.go`][c-routes]): 계측 래퍼는 `ProvisionHandlers(ctx, metrics)`에 `metrics`가 넘어온 route에만 붙고, `handler` 라벨은 그 route의 **첫 번째 핸들러 모듈 이름**이다. `RouteList.Provision`(subroute 안)은 `metrics`로 `nil`을 넘긴다. 즉 최상위 route만 계측된다.
- **재현**: 참조 Caddyfile 모양을 변환하면 사이트 블록이 최상위 route 하나(`host` 매처 + `subroute` 핸들러)가 되고, 메트릭은 프로브·업무·404 폴백 구분 없이 `handler="subroute"`로 나왔다.
- **추론**: Caddy 메트릭에는 경로 라벨이 없고 `handle` 블록도 구분되지 않는다. #239의 "프로브는 잡음"을 Caddy 메트릭에서 지킬 수 없다. 프로브를 빼고 싶다면 트레이스(§4.4)나 액세스 로그로 본다. 굳이 메트릭에서 가르려면 프로브를 별도 사이트/리스너로 옮겨 `server` 라벨로 구분해야 한다.

### 3.4 선택지(결정 아님)

| 선택지 | 내용 | 대가 |
|---|---|---|
| A. `per_host` 끄기 | `host` 라벨이 사라지고 `server`·`handler`·`code`·`method`만 남는다 | 플로팅 도메인과 노드 도메인을 Caddy 메트릭으로 가를 수 없다(둘 다 같은 funa로 가므로 실익이 작을 수 있다) |
| B. `per_host` 유지 + otelcol에서 정규화 | 노드 otelcol의 transform/filter 처리기로 허용 목록에 없는 `host` 값을 `_other`로 바꾸거나 포트를 떼어낸다 | otelcol 설정에 업무 호스트 목록이 필요하다. Caddy 메모리 안의 시계열은 그대로 늘어난다(admin `/metrics` 스크레이프 대상도 마찬가지) |
| C. 와일드카드 사이트 주소 분리 | 와일드카드 호스트를 별도 사이트/서버로 빼서 업무 사이트와 섞이지 않게 한다 | 와일드카드 쪽 catch-all은 여전히 HTTPS라 자기 라벨을 얻는다. 근본 해결은 아니다 |
| 공통 | `observe_catchall_hosts`는 빼는 쪽이 안전하다 | 없음(HTTPS 호스트 관측은 그것 없이도 이미 된다) |

## 4. 트레이스 전파

### 4.1 upstream으로 `traceparent`

- **출처**([`tracer.go`][c-tracer]): `tracing` 핸들러는 `otelhttp.NewHandler`로 감싸져 있다. otelhttp가 들어온 요청 헤더에서 컨텍스트를 `Extract`하고 server span(`SpanKindServer`)을 시작한 뒤 Caddy의 `serveHTTP`를 부른다. `serveHTTP`는 `ot.propagators.Inject(ctx, propagation.HeaderCarrier(r.Header))`로 **들어온 요청 객체의 헤더에 현재 span 컨텍스트를 써 넣는다**(기존 `traceparent`를 덮어씀). 이어서 다음 핸들러를 호출한다.
- **출처**(reverseproxy `cloneRequest`): `reverse_proxy`는 `origReq.Header.Clone()`으로 헤더를 복제해 upstream에 보낸다. `modules/caddyhttp/reverseproxy` 안에는 otel 계측이 없다(소스 grep). 따라서 upstream이 받는 `traceparent`의 parent-id는 **Caddy server span의 span id**다.
- **재현**: 헤더 없이 보낸 요청에서 upstream이 `traceparent: 00-<새 trace id>-<Caddy span id>-01`을 받았다. 같은 요청의 액세스 로그 `traceID`/`spanID`, console로 나온 span의 TraceID와 일치했다.
- **조건 정리**
  1. 요청이 `tracing`이 있는 `handle` 안에서 `reverse_proxy`에 닿아야 한다.
  2. `OTEL_PROPAGATORS`에 `tracecontext`가 있어야 한다(기본 포함).
  3. 샘플링 여부와 무관하게 주입된다. 샘플링되지 않으면 flags가 `00`으로 나가고, funa가 parent-based sampler면 funa도 그 트레이스를 버린다.
  4. 같은 `handle` 안에서 `tracing` 뒤에 `request_header -traceparent` 같은 헤더 조작을 두면 주입한 값이 지워진다. `tracing`은 기본 디렉티브 순서의 맨 앞이다([`directives.go`][c-dirs] `defaultDirectiveOrder`의 첫 항목).

### 4.2 클라이언트가 보낸 `traceparent`·`baggage`

- **출처**(otelhttp v0.68.0 `handler.go`, `config.go`): `WithPublicEndpointFn`이 주어지면 들어온 컨텍스트를 parent 대신 link로 두고 새 root를 만든다. **Caddy는 이 옵션을 쓰지 않는다.** 그래서 들어온 컨텍스트가 항상 parent가 된다.
- **재현**
  - `traceparent: 00-1111…-2222…-01` + `baggage: user=evil` → Caddy span이 trace id `1111…`로 내보내졌고, upstream은 `00-1111…-<Caddy span id>-01`과 `baggage: user=evil`을 받았다.
  - `traceparent: 00-3333…-4444…-00` → Caddy span이 **내보내지지 않았고**(ParentBased), upstream은 `-00`을 받았다. 액세스 로그에는 `traceID":"3333…"`이 남았다.
- **추론(영향)**: 인터넷 클라이언트가 (1) 트레이스 id를 골라 다른 요청과 섞거나, (2) `-00`으로 자기 요청의 트레이싱을 끄거나, (3) `-01`로 샘플링 비율을 우회하거나, (4) 임의 `baggage`를 funa까지 넘길 수 있다. funa가 baggage를 로그나 span 속성으로 옮기는 설정이면 신뢰할 수 없는 값이 들어간다.
- **재현(대응)**: 사이트 블록 최상위에 아래를 두면 `handle`보다 먼저 실행되어(`request_header`가 `handle`보다 앞 순서) `tracing`이 클라이언트 컨텍스트를 보지 못한다. 같은 `-00` 요청이 새 root(`-01`)로 시작했고 upstream의 `baggage`는 비었다.

  ```caddyfile
  request_header -traceparent
  request_header -tracestate
  request_header -baggage
  ```

  **출처 기반 주의**: 이 순서는 `tracing`이 `handle` 안에 있을 때만 성립한다. `tracing`을 사이트 블록 최상위로 옮기면 기본 순서상 `tracing`이 `request_header`보다 먼저 돌아 제거가 추출 뒤에 일어난다.
- **추론**: Caddy 앞단에 신뢰할 수 있는 트레이싱 프록시가 없으므로(Caddy가 엣지) 클라이언트 컨텍스트를 이어받을 이유가 약하다. 이어받을지, 끊을지는 지도에서 정한다.

### 4.3 액세스 로그 필드

- **출처**([`tracer.go`][c-tracer]): `spanCtx.IsValid()`이면 `ExtraLogFields`에 `traceID`, `spanID`를 추가하고, 변수 `trace_id`, `span_id`를 세팅한다(`{http.vars.trace_id}`, `{http.vars.span_id}`). 공식 문서도 "added to access logs as the standard `traceID` and `spanID` fields"라고 쓴다.
- **재현**: JSON 액세스 로그 최상위에 `"traceID":"<32 hex>","spanID":"<16 hex>"`가 찍혔다. 참조 Caddyfile의 `format filter`는 이 두 필드를 건드리지 않는다.
- **재현**: 샘플링되지 않은 요청(`-00`)과 `OTEL_TRACES_EXPORTER=none`일 때도 `traceID`가 기록됐다. 즉 로그의 trace id가 OpenObserve에 있는 트레이스를 보장하지 않는다. 기본 샘플링(100%)이고 클라이언트 컨텍스트를 끊으면(§4.2) 업무 경로 요청의 로그 trace id는 모두 내보내진 트레이스를 가리킨다(**추론**).
- `spanID`는 Caddy server span의 id이고, funa span의 parent id와 같다.

### 4.4 `handle` 밖 요청은 span을 만들지 않는다

- **출처**: span은 `tracing` 핸들러(otelhttp 래퍼)를 지날 때만 생긴다. Caddy는 전역 tracer provider를 설정하지 않으며(`otel.SetTracerProvider` 호출 없음, 소스 grep) provider는 `tracing` 모듈 인스턴스가 있을 때만 만들어진다. `reverse_proxy` active health check는 핸들러 체인을 거치지 않는 자체 요청이고 reverseproxy 패키지에 otel 계측이 없다.
- **재현**: 프로브(`handle @probe`) 요청은 span이 없고 액세스 로그에 `traceID`도 없었다. `traceparent`를 받은 upstream 사이트(같은 프로세스의 다른 서버)도 자기 span을 만들지 않았다. 404 폴백 `handle` 요청도 span이 없었다. 내보내진 span은 업무 `handle`을 지난 요청 수와 같았다.
- **추론**: health 전용 리스너나 다른 사이트 블록에 `tracing`을 두지 않는 한 그쪽 요청은 트레이스 잡음이 되지 않는다. `tracing`은 업무 앱 경로의 `handle`(노드의 `@funa_apps` 등) 안에만 두면 된다. 노드 Caddyfile 본문은 이 조사에서 보지 않았다(**확인 못 함**).
- **추론**: 현재 span 이름 `"{http.request.method} {http.request.orig_uri.path}"`는 경로에 id가 들어가면 span 이름 카디널리티가 커진다. OTel 관례는 `{method} {route}`처럼 낮은 카디널리티 이름이다. Caddy는 라우트 템플릿을 모르므로, 이름을 `{method}`나 고정 문자열로 두고 경로는 span 속성 `url.path`(otelhttp가 이미 넣음)로 보는 방법이 있다. span 속성에는 `url.path`, `client.address`, `user_agent.original` 등이 들어가고 **쿼리 문자열(`url.query`)은 없었다**(재현).

## 5. 현재 노드 상태에 대한 해석

- **출처**: 엔드포인트 변수가 없으면 OTLP/HTTP exporter는 `localhost`의 기본 포트로 보낸다. OTLP exporter 재시도 설정의 `MaxElapsedTime`은 1분이다(`otlptracehttp/internal/retry/retry.go`). 배치 처리기 주기는 5초다.
- **추론**: 업무 요청이 있는 동안 배치마다 export를 시도하고, 재시도가 1분 만에 포기될 때마다 `traces export: … connection refused`가 남는다. 그래서 1분 단위 오류로 보인다.
- **선택지(결정 아님)**
  - 수집 경로가 열리기 전 임시 차단: 컨테이너 환경에 `OTEL_TRACES_EXPORTER=none`. Caddyfile을 바꾸지 않고, `traceID` 로그와 upstream 전파는 유지된다(**재현**: `none`일 때도 액세스 로그에 `traceID`가 남았고 upstream은 `traceparent: 00-<trace id>-<span id>-01`을 받았다).
  - `metrics { otlp }`를 수집 경로보다 먼저 켜면 60초 주기의 메트릭 export 실패가 하나 더 생긴다. 켜는 순서는 엔드포인트 변수 → `otlp`다.
  - 예전 `.env`에 있던 `OTEL_METRICS_EXPORTER=otlp`는 `metrics` 블록이 주석인 동안 아무 효과가 없었다(메트릭 OTLP는 `otlp` 하위 옵션이 있을 때만 구성됨).

## 확인 못 함

- 노드 Caddy 바이너리의 실제 버전과 플러그인 목록(`caddy build-info`). 이 조사는 티켓 설명의 v2.11.4를 전제로 한다.
- 노드 Caddyfile 본문(`@funa_apps` 구성, 별도 health 리스너 유무). 이 조사는 boilerplate를 원형으로 썼다.
- funa(Java agent)의 sampler·propagator 설정. upstream이 `-00`을 받았을 때 funa가 버리는지는 funa 쪽 설정에 달렸다.
- OpenObserve가 OTLP 메트릭의 Prometheus 브리지 출력(히스토그램 → OTLP histogram)을 어떻게 저장하는지.

[caddy-tag]: https://github.com/caddyserver/caddy/tree/v2.11.4
[c-metrics]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/metrics.go
[c-tracer]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/tracing/tracer.go
[c-tp]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/tracing/tracerprovider.go
[c-tmod]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/tracing/module.go
[c-routes]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/routes.go
[c-app]: https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/app.go
[c-opts]: https://github.com/caddyserver/caddy/blob/v2.11.4/caddyconfig/httpcaddyfile/options.go
[c-dirs]: https://github.com/caddyserver/caddy/blob/v2.11.4/caddyconfig/httpcaddyfile/directives.go
[c-ctx]: https://github.com/caddyserver/caddy/blob/v2.11.4/context.go
[c-gomod]: https://github.com/caddyserver/caddy/blob/v2.11.4/go.mod
[d-tracing]: https://caddyserver.com/docs/caddyfile/directives/tracing
[d-opts]: https://caddyserver.com/docs/caddyfile/options#metrics
[d-metrics]: https://caddyserver.com/docs/metrics
