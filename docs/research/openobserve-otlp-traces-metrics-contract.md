# Research: OpenObserve OTLP contract for traces, app metrics and log→trace links

- Ticket: [#242](https://github.com/ppzxc/infra-automation/issues/242) (map [#239](https://github.com/ppzxc/infra-automation/issues/239))
- Date: 2026-10-19
- Versions checked: ns0331 reports `version: v1.0.4` (`GET /api/default/config`, commit `1e257e69…` = tag **v1.0.4**). Source links point at that tag. Latest release today is **v1.1.1** (2026-10-16). I diffed the files that matter here against v1.1.1, and they still behave the same way (details in §6). otelcol-contrib is pinned at 0.161.0 (`roles/monitoring/vars/main.yml`).
- Method:
  1. Read the v1.0.4 source for the HTTP traces handler, the OTLP traces/metrics/logs converters, `flatten.rs`, the org settings, retention, the ingestion-route auth table, and the web "View Trace" action.
  2. Read the official docs through Context7 (`/websites/openobserve_ai`, `/open-telemetry/opentelemetry-collector-contrib`, `/caddyserver/website`).
  3. Ran read-only GETs against ns0331 and against the previous instance, ns0270, which already holds Caddy and funa traces and metrics. The GETs covered stream lists, stream schemas, `GET /api/default/settings` and `GET /api/default/config`. No data was sent and no setting was changed.
- Builds on: [host-agents-openobserve-rustfs-contract.md](host-agents-openobserve-rustfs-contract.md) (logs/metrics contract, auth, TLS, compression).

## TL;DR

| Question | Answer |
|---|---|
| Traces path | `POST <o2>/api/<org>/v1/traces`. The `otlphttp` exporter derives it from the same `endpoint: <o2>/api/<org>` we already use (no trailing slash). Content type is `application/x-protobuf` (the exporter default) or JSON. |
| Traces auth | Same as logs: `Authorization: Basic base64(<org>:<o2oi_ token>)`. `/{org}/v1/traces` (POST) is listed in the ingestion-route table, so the per-host org ingestion token is accepted. |
| Traces stream selection | Same `stream-name` header as logs. **No header means the stream is called `default`**. The name goes through `format_stream_name` (non `[a-zA-Z0-9_:]` → `_`, lowercased). A dedicated `otlphttp/traces` exporter with `stream-name: <traces stream>` is needed. Reusing `otlphttp/metrics`, which sends no header, would land spans in `default`, and that is exactly what ns0270 shows. |
| OTLP metric → stream | **One stream per metric name.** `stream = format_stream_name(metric.name)`: dots → `_`, lowercased, no unit or type suffix added. `stream-name` is ignored for metrics. A histogram `X` writes to `X_bucket` (with `le`), `X_count`, `X_sum`, and `X_min`/`X_max` when the data point carries them. The `X` stream itself holds only metadata (0 docs). The same metric from different services shares one stream and is separated by the `service_name` label. |
| ECS `trace.id` / `span.id` | OpenObserve flattens **structured fields only**. Both a dotted key `trace.id` and a nested `{"trace":{"id":…}}` become `trace_id` (`format_key`: lowercase, non-alnum → `_`, nesting joined with `_`). **But our container receiver ships the JSON line as a string `body`, and OpenObserve does not parse a string body.** So `trace.id` doesn't become a column on ns0331 today (live `app_logs` has no trace field). |
| Field the log→trace link needs | The log record must have a column whose name equals the **org setting `trace_id_field_name`** (default `trace_id`; ns0331 = `trace_id`, `span_id`). The UI shows "View Trace" only when `record[trace_id_field_name]` is present. That is one value per org, set under *Management → Organization Parameters* or `POST /api/{org}/settings`. Recommended: fill the native OTLP LogRecord TraceID/SpanID in otelcol. OpenObserve then writes them as hex `trace_id`/`span_id` regardless of the source field name, and the defaults match. |
| Trace retention | Per stream: stream setting `data_retention` (days; `0` = use the global value), via the UI *Stream details → Data Retention* or `PUT /api/{org}/streams/{stream}/settings?type=traces`. Global: `ZO_COMPACT_DATA_RETENTION_DAYS`, which is **365 on ns0331**. The traces stream does not exist on ns0331 yet, so the per-stream value can only be set after the first span arrives (or by creating the settings ahead of time with a write). |

## 1. Traces ingestion

**Route.** `src/api/http/src/handler/http/router/mod.rs` maps `/{org_id}/v1/traces`, `/{org_id}/traces` and `/{org_id}/otel/v1/traces` to `traces::traces_write` ([router][r-router], lines 812–816). The `otlphttp` exporter appends `/v1/traces` to `endpoint`, as it does for logs and metrics. The docs agree: endpoint `https://<host>/api/<org>/v1/traces` with `Authorization: Basic …` ([traces doc][d-traces]).

**Handler** (`traces_write` in [`api/search/src/traces/mod.rs`][r-traces-http]):
- If the `Content-Type` is `application/x-protobuf` it goes to `otlp_proto`. Anything starting with `application/json` goes to `otlp_json`. A missing header defaults to JSON.
- `in_stream_name = headers.get(cfg.grpc.stream_header_key)`. The header key comes from `ZO_GRPC_STREAM_HEADER_KEY`, default `stream-name` ([config.rs][r-config] line 1308), the same key the logs handler reads.
- **An `organization` header, if present, overrides the org in the path.** Our exporters don't send one, so the path org applies. Keep it that way.

**Stream name** (`handle_otlp_request` in [`core/traces/mod.rs`][r-traces]):
```rust
let traces_stream_name = match in_stream_name {
    Some(name) => format_stream_name(name.to_string()),
    None => "default".to_owned(),
};
```
`format_stream_name` replaces `[^a-zA-Z0-9_:]+` with `_` and lowercases when `ZO_FORMAT_STREAM_NAME_TO_LOWERCASE` is on, which is the default ([schema.rs][r-schema]).

**Auth.** The validator lets an `o2oi_` org ingestion token through only when `ingestion_routes::is_ingestion_allowed(method, path)` is true ([validator.rs][r-validator]). The route table lists `/{org}/v1/traces` with `methods: ["POST"]` as `IngestionKind::Write` ([ingestion_routes.rs][r-ingest-routes]). The current `O2_BASIC_AUTH` (`base64(<org>:<o2_ingest_token>)`, `roles/monitoring/templates/secrets.env.j2`) therefore works for traces without change.

**Ingest time window.** Spans whose timestamp is older than `ZO_INGEST_ALLOWED_UPTO` (default **5 h**) or more than `ZO_INGEST_ALLOWED_IN_FUTURE` (default 24 h) ahead are **skipped**. The request still succeeds ([traces/mod.rs][r-traces] "skipping span with timestamp older than allowed retention period"; [config.rs][r-config] lines 2247–2251). Logs apply the same limit. With the persistent queue and `max_elapsed_time: 0`, a backlog older than 5 h is delivered and then silently dropped server-side.

**What a span row looks like** (live schema of the `default` traces stream on ns0270, 104 fields; the converter code agrees):
- Fixed span columns: `trace_id`, `span_id`, `reference_parent_span_id`, `reference_parent_trace_id`, `operation_name`, `span_kind`, `span_status`, `start_time`, `end_time`, `duration`, `events`, `links`, `flags`, `status_code`, `status_message`.
- **`service_name`** comes from resource `service.name`. That is how the map's "one stream, split by `service.name`" decision is queried.
- **Every other resource attribute gets a `service_` prefix.** For example `host.name` → `service_host_name`, `service.version` → `service_service_version`, `deployment.environment.name` → `service_deployment_environment_name` (`resource_attribute_key`: `format!("service_{raw_key}")`).
- Span attributes keep their own name, flattened. For example `http.route` → `http_route`, `db.statement` → `db_statement`, `messaging.system` → `messaging_system`. On a collision with a reserved span field or a resource key they get an `attr_` prefix (`span_attribute_key`).
- OpenObserve adds `infer_service_name`, `infer_service_type` and `infer_service_system`. It also adds `o2_db_*` columns for DB spans.

Consequence for the spec: **resource attributes are named differently per signal.** On spans they are `service_host_name`. On logs and metrics they stay unprefixed (`host_name`). SQL that joins signals must account for this. `service_name` is the same in all three.

## 2. OTLP metrics → metric streams

From `handle_otlp_request` in [`core/metrics/otlp.rs`][r-metrics]:
- `metric_name = format_stream_name(metric.name)` gives the stream name. `__name__` holds the same value. The `stream-name` header is not consulted.
- Every resource attribute and data-point attribute becomes a label via `format_label_name` (`format_key`), so `service.name` → `service_name` and `http.route` → `http_route`. There is no prefix, unlike traces. The scope becomes `instrumentation_library_name` and `instrumentation_library_version`.
- Gauge and sum rows land in `<name>`.
- A histogram data point is split into rows named `<name>_count`, `<name>_sum` (if set), `<name>_min` and `<name>_max` (only if the point carries min/max), and `<name>_bucket` with a cumulative `le` label. Exponential histograms are converted to `_bucket`/`le` too. Summaries become `_count`, `_sum` and a quantile row.
- **Each derived name is its own stream** (`local_metric_name != metric_name` → separate schema, partitioning and alert lookup). The code comment says so directly: "a histogram's rows all carry a `_count` / `_sum` / `_bucket` name and none carry the base".

Empirical names on ns0270 (683 metric streams in total):

| Source | OTLP / scraped name | OpenObserve stream(s) |
|---|---|---|
| Java agent (JVM) | `jvm.memory.used` (gauge) | `jvm_memory_used`, with labels `jvm_memory_pool_name`, `jvm_memory_type`, `service_name`, `host_name`, … |
| Java agent (JVM) | `jvm.gc.duration` (histogram, unit `s`) | `jvm_gc_duration_bucket`/`_count`/`_sum`/`_min`/`_max`. `jvm_gc_duration` itself has 0 docs (metadata only) |
| Java agent (HTTP) | `http.server.request.duration` (histogram) | `http_server_request_duration_bucket` (labels `http_route`, `http_request_method`, `http_response_status_code`, `le`, …) plus `_count`/`_sum`/`_min`/`_max` |
| Caddy (Prometheus exposition, scraped) | `caddy_http_requests_total` | `caddy_http_requests_total` |
| Caddy (Prometheus exposition, scraped) | `caddy_http_request_duration_seconds` (histogram) | `caddy_http_request_duration_seconds_bucket`/`_count`/`_sum` (no `_min`/`_max`: Prometheus histograms carry none) |

Notes:
- OpenObserve **adds no unit suffix**. OTel-SDK names stay unit-less (`http_server_request_duration`, not `…_seconds`).
- The Caddy names reached ns0270 through a Prometheus scrape (that instance also has `up` and `scrape_*` streams). Whether `_total` survives on our path depends on otelcol's Prometheus receiver name handling at the pinned 0.161.0, not on OpenObserve. Check the first real ingest before writing alerts against these names.
- `service.name` doesn't partition metric streams. `jvm_memory_used` from every JVM shares one stream and is filtered by the `service_name` label. Stream count grows with the number of distinct metric names, not the number of services. The earlier contract already flags metric stream explosion; ns0270 reached 683 streams.

## 3. Logs: ECS nested fields and the log→trace link

### 3.1 How OpenObserve names log fields

In `handle_logs_request` ([`core/logs/otlp.rs`][r-logs]):
1. Resource attributes are copied with their raw keys. Then `severity`, `body = get_val(body)`, `dropped_attributes_count`, and **every LogRecord attribute under its raw key** (for example `trace.id`) are copied.
2. **If the LogRecord TraceId/SpanId are valid (non-zero), they are written as `rec["trace_id"]` / `rec["span_id"]` in lowercase hex.** This happens after the attributes.
3. `flatten::flatten_with_level(rec, flatten_level)` runs. The level is the per-stream `flatten_level`, otherwise `ZO_INGEST_FLATTEN_LEVEL`, which is **3 on ns0331**. Deeper objects are stored as a JSON string.

`flatten`/`format_key` ([flatten.rs][r-flatten]):
- Key chars are lowercased, and anything outside `[a-z0-9_]` becomes `_`. Nested keys are joined with `_`. Arrays are stored as JSON strings.
- So **`trace.id` (dotted attribute) and `{"trace":{"id":…}}` (nested map) both become `trace_id`**, and `span.id` becomes `span_id`. ECS fields at depth 2 are within level 3.
- **camelCase loses its word boundary:** `traceID` → `traceid`, `spanID` → `spanid`.
- **Collisions are not rejected.** The docstring says flattening "will return an error if … keys colliding", but the code only does `flattened.insert(key, value)`, so the last write wins. If a record carries both an attribute `trace.id` and a native TraceId, both map to `trace_id`.
- Live evidence of the separator on ns0331 `app_logs`: `attrs["com.docker.compose.project"]` → `attrs_com_docker_compose_project`, and journald `body._COMM` → `body__comm`.

### 3.2 What our pipeline does today

`filelog/containers` in `roles/monitoring/templates/otelcol-contrib.yaml.j2`:
- It parses a JSON line only into the **temporary** `attributes._lvl` to lift the level into severity, then removes `_lvl`. `body` stays the original **string** (ADR-0008).
- OpenObserve stores a string body as one `body` column and doesn't parse JSON out of it (`rec["body"] = get_val(body)`).
- Result: an ECS line's `trace.id` reaches ns0331 only inside the `body` text. The live `app_logs` schema has no `trace_id`, `span_id` or `trace_*` column. **Today no log on ns0331 can link to a trace.**

### 3.3 What the link requires

**Server side.**
- Org settings hold one `trace_id_field_name` and one `span_id_field_name`. Defaults are `trace_id` / `span_id` (`default_trace_id_field_name` in [common/meta/organization.rs][r-org]). ns0331 has the defaults (`GET /api/default/settings` → `"trace_id_field_name":"trace_id","span_id_field_name":"span_id"`).
- You can set them in the UI under *Management → Organization Parameters → Log details* ([correlation doc][d-correlation]) or with `POST /api/{org}/settings` ([router][r-router] line 762; [settings.rs][r-org-settings]).

**UI side** (`useViewTraceAction.ts` @ v1.0.4, [link][r-viewtrace]):
```ts
showViewTraceBtn.value = !tracesMenuHidden && !serviceStreamsEnabled &&
  record?.[organizationSettings.trace_id_field_name];
```
- `service_streams_enabled` is enterprise-only and `false` on ns0331 (`GET /api/default/config`), so the button depends only on that field being present in the log record.
- The docs say the same: "confirm that in your log stream the trace ID and span ID are available in the `trace_id` and `span_id` respectively. If not, … configure … in the Organization parameter section" ([correlation doc][d-correlation]).
- Spans always store `trace_id`/`span_id`. The mapping only names the column on the **log** side.

**Constraint: one field name per org.** Sources that name the ID differently can't all link through the setting. ns0270's `default` log stream already shows both `trace_id`/`span_id`/`trace_flags` and `traceid`/`spanid`:
- Caddy's `tracing` directive writes **`traceID`/`spanID`** into access logs ([Caddy tracing docs][d-caddy-tracing]). Flattened, these become `traceid`/`spanid`.
- ECS (funa logback) writes `trace.id`/`span.id`, which become `trace_id`/`span_id` once structured.

**Recommended contract (otelcol side, keeps the body untouched).**
- Normalize both sources onto the **native OTLP LogRecord TraceID/SpanID**:
  1. Parse the JSON line into a temporary attribute, the same pattern as `_lvl`.
  2. Run `trace_parser` with `trace_id.parse_from` / `span_id.parse_from` pointing at `…["trace"]["id"]` or `…["traceID"]` ([stanza trace_parser][d-trace-parser]). The OTTL alternative is `set(trace_id.string, …)`.
  3. Remove the temporary attribute.
- OpenObserve then writes the IDs as hex `trace_id`/`span_id` for every source, which matches the default org setting. Nothing changes on the server, and the IDs are the canonical 32/16-hex form that spans use.
- **Don't** also keep a `trace.id` attribute, because it collides on `trace_id` (§3.1).
- Apps that export logs over OTLP directly (an OTel SDK/agent with a logs exporter) fill the native IDs already.

## 4. Trace stream retention

- **Per stream:** `StreamSettings.data_retention` (days). `0` means unset, which falls back to the global value. Set it in the UI under *Streams → stream details → Data Retention in days* ([stream details doc][d-stream-details]) or with **`PUT /api/{org}/streams/{stream}/settings?type=traces`**. The v1.0.4 router only has `put(stream::update_settings)` on that path ([router][r-router] line 799). The API reference page shows `POST`, which doesn't match v1.0.4 ([stream settings API doc][d-stream-settings]).
- **Global:** `ZO_COMPACT_DATA_RETENTION_DAYS` (default 3650, minimum 3) ([env vars doc][d-env]). **ns0331: `data_retention_days: 365`** (`GET /api/default/config`), so a traces stream without its own setting keeps 365 days.
- **How the compactor applies it:** `generate_jobs()` uses `stream_settings.data_retention` when it is > 0, otherwise the global value ([compaction/retention.rs][r-retention] lines 87–97). This is already recorded in ADR-0006 (`docs/adr/0006-host-agents-otelcol-resticprofile.md` line 162). It covers trace streams too, because the loop runs over all stream types except enrichment tables and file lists.
- `ZO_TRACES_FILE_RETENTION`/`ZO_TRACES_QUERY_RETENTION` (default `hourly`) are **partition granularity, not retention**.
- **Where to manage it:** `roles/openobserve_config` currently manages templates, destinations, functions, pipelines and alerts, not stream settings. It is the natural home for a declarative `data_retention` on the traces stream. Because the stream appears only on first ingest (ns0331 has no traces stream today), the task has to run after the first span or tolerate a missing stream.

## 5. Contract snippet (for the spec)

```yaml
exporters:
  otlphttp/traces:
    endpoint: "<o2>/api/<org>"              # same as logs/metrics, no trailing slash
    headers:
      Authorization: "Basic ${env:O2_BASIC_AUTH}"   # org ingestion token works on /v1/traces
      stream-name: <traces stream>          # omitted => "default"
service:
  pipelines:
    traces/otlp:
      receivers: [otlp]
      processors: [memory_limiter, resource/host, batch]
      exporters: [otlphttp/traces]
    metrics/otlp:                           # unchanged: one stream per metric name
      exporters: [otlphttp/metrics]
```

## 6. Version notes

- Everything above was read at **v1.0.4**, the version both ns0331 and ns0270 run.
- I diffed these v1.0.4 files against **v1.1.1**: `traces/mod.rs`, `api/search/traces/mod.rs`, `metrics/otlp.rs`, `logs/otlp.rs`, `flatten.rs`, `common/meta/organization.rs`, `useViewTraceAction.ts`. The behaviour described here is unchanged: `None => "default"`, the `service_` resource prefix, `format_stream_name(metric.name)`, the conditional `_sum`/`_min`/`_max`, `rec["trace_id"]` from the LogRecord, default `trace_id`/`span_id`, and the View Trace condition. The diffs are refactors (`Cow` key formatting, allocation changes) and new tests. An upgrade to v1.1.x doesn't change this contract.
- `service_streams_enabled` (enterprise) hides "View Trace" in favour of the correlation view. That doesn't apply to our opensource build.

## Sources

[r-router]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/http/src/handler/http/router/mod.rs
[r-traces-http]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/search/src/traces/mod.rs
[r-traces]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/traces/mod.rs
[r-metrics]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/metrics/otlp.rs
[r-logs]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/logs/otlp.rs
[r-flatten]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/utils/flatten.rs
[r-schema]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/utils/schema.rs
[r-config]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/config.rs
[r-org]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/common/src/meta/organization.rs
[r-org-settings]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/management/src/request/organization/settings.rs
[r-retention]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/compaction/src/retention.rs
[r-validator]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/common/src/auth/validator.rs
[r-ingest-routes]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/common/src/meta/ingestion_routes.rs
[r-viewtrace]: https://github.com/openobserve/openobserve/blob/v1.0.4/web/src/composables/useLogs/useViewTraceAction.ts
[d-traces]: https://openobserve.ai/docs/ingestion/traces/opentelemetry
[d-correlation]: https://openobserve.ai/docs/user-guide/data-exploration/traces/traces
[d-stream-details]: https://openobserve.ai/docs/user-guide/data-processing/streams/stream-details
[d-stream-settings]: https://openobserve.ai/docs/reference/api/stream/setting
[d-env]: https://openobserve.ai/docs/administration/configuration/environment-variables
[d-trace-parser]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/operators/trace_parser.md
[d-caddy-tracing]: https://caddyserver.com/docs/caddyfile/directives/tracing

- OpenObserve source @ v1.0.4 (links above), compared with v1.1.1.
- OpenObserve docs: traces ingestion, log↔trace correlation, stream details, stream settings API, environment variables.
- OpenTelemetry Collector contrib: stanza `trace_parser` operator.
- Caddy docs: `tracing` directive (`traceID`/`spanID` in access logs).
- Live read-only checks: ns0331 (`/api/default/config`, `/api/default/settings`, `/api/default/streams?type={logs,metrics,traces}`, `app_logs` schema) and ns0270 (`default` traces/logs schemas, metric stream list and schemas of `jvm_memory_used`, `http_server_request_duration_bucket`, `caddy_http_requests_total`).
