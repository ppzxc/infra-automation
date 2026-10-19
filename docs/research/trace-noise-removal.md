# Research: dropping noise per trace (OTel Java agent 2.30, otelcol-contrib 0.161, Caddy 2.11)

- Ticket: [#243](https://github.com/ppzxc/infra-automation/issues/243) (map [#239](https://github.com/ppzxc/infra-automation/issues/239))
- Date: 2026-10-19
- Versions checked: OTel Java agent **v2.30.0** (bundles `opentelemetry-samplers` **1.58.0-alpha**, SDK 1.64.0), otelcol-contrib **v0.161.0**, Caddy **v2.11.x** (source read at v2.11.7, with version gates noted). Every source link points at the matching tag.
- Method: read source and READMEs at those tags with `gh api`. Official docs came through Context7 (`/open-telemetry/opentelemetry-java-instrumentation`, `/open-telemetry/opentelemetry-collector-contrib`, `/websites/opentelemetry_io`, `/websites/spring_io_spring-boot`) and opentelemetry.io. Local files read: funa `docker/prod/{compose.yml,Dockerfile,example.application.yml}`, funa ADR-0033, `caddy-boilerplate/cluster/runtime/Caddyfile`.
- The **Business Telemetry** definition comes from the map #239 notes ("지도를 그리며 합의한 것"). It is not in `CONTEXT.md` on `main` yet.
- **Caveat.** Every Caddy-side statement below is based on the **caddy-boilerplate** Caddyfile (cluster variant), not on the node-local `/opt/services/proxy` file. Check the live file before relying on the root-origin table.
- This is a public repo. Ports, the management base path and addresses are left out on purpose. "Management server" means funa's separate actuator port.

## TL;DR

1. **The choice of tool depends on which process creates the root span** (section 1 table).
   - Caddy probes and unserved hosts produce **no spans at all**, because the `tracing` directive sits only inside `handle @valid_hosts`.
   - Caddy active health checks reach the funa management server **without `traceparent`**, so funa makes the root. The same holds for scheduler jobs, Lettuce background commands and Rabbit consumers with no producer context.
   - Paths that go through a `@valid_hosts` route (docs, any app health path proxied by Caddy) get their root from **Caddy**. A funa-side sampler cannot remove that span.
2. **Agent 2.30 can drop whole trace subtrees at the source with `parent_based { root: rule_based_routing }`.** The sampler is already bundled, so no extension jar is needed. It has three costs:
   - It is reachable **only through declarative configuration** (`-Dotel.config.file`). `OTEL_TRACES_SAMPLER` cannot select it.
   - Declarative config **ignores every `OTEL_*` env var not templated in the YAML**, which changes ADR-0033's env-only model.
   - The pieces are alpha or experimental, and 2.32 already deprecates `rule_based_routing` in favour of `composite/development` `rule_based`.
3. **`OTEL_INSTRUMENTATION_SPRING_SCHEDULING_ENABLED=false` works against trace-level dropping.** It removes the one INTERNAL span that could serve as a single droppable root, so each JDBC call inside the `@Scheduled` job becomes its own root CLIENT span.
4. **Collector:**
   - **`filter` is span-level.** It can't see the rest of the trace. Dropping a noisy root leaves its children as orphans, and dropping children needs an attribute those children carry (they don't carry the root's `url.path`).
   - **`tail_sampling` is trace-level.** It holds spans in memory for `decision_wait` and its default verdict is **not sampled**, so it needs `always_sample` plus a `drop` policy.
   - **The one-collector requirement holds for HTTP.** Caddy and funa sit on the same node's local bridge network.
   - **It can break for RabbitMQ.** A consumer on another node sends its spans to a different collector.
5. **Metrics:**
   - **Agent HTTP metrics** don't carry `server.address` or `server.port` by default (opt-in in semconv). Drop management traffic by `http.route`.
   - **Caddy HTTP metrics** have no path label. Their noise dimension is `host`. With `per_host` and `observe_catchall_hosts`, plus the HTTPS auto-allow, **any Host header that passes TLS becomes its own `host` value**, so collapse or drop non-allowlisted hosts in a `transform` or `filter` processor.
   - **`metrics { otlp }` exists only from Caddy v2.11.3.**
6. **Suggested combination (not a decision):**
   - Narrow Caddy's `tracing` to business routes.
   - Set `parent_based { root: rule_based_routing }` in funa for funa-origin roots (management, scheduler threads, root CLIENT spans).
   - Run a collector `tail_sampling` with `always_sample` plus positive-evidence `drop` policies as a safety net.
   - Use `transform`/`filter` for metric series.
   - Details in section 5.

## 1. Who creates the root, per noise source

| Noise source | What happens (boilerplate Caddyfile / funa compose) | Root created by | What can remove the whole trace |
|---|---|---|---|
| Caddy probes `/ping` `/healthz` | `handle @probe { log_skip; respond "OK" 200 }`, outside `handle @valid_hosts` where `tracing` lives | **none** (no span) | Nothing needed for traces. Caddy metrics still count them under the `static_response` handler. |
| Requests to unserved hosts | Fall through to `handle { respond 404 }`, no `tracing` | **none** | Nothing needed for traces. They are **metric** noise (`host` label, §4.2). |
| Caddy active health checks to the funa management server | `reverse_proxy` `health_uri`/`health_port`, every few seconds. The checker builds a plain `http.NewRequestWithContext` ([healthchecks.go L444][caddy-hc]) and is not wrapped by the tracing handler, so it sends no `traceparent` | **funa** (SERVER span on the management port) | Agent sampler (§2), or collector `tail_sampling`/`filter` on the root |
| Docker/compose healthcheck | funa compose defines none | – | – |
| `/healthz/app`-style app health proxied through a `@valid_hosts` route (if the live Caddyfile has one) | Goes through `tracing`, so Caddy injects a sampled `traceparent` | **Caddy** | Scope `tracing` in Caddy, or collector `tail_sampling`. A funa sampler can only drop funa's half. |
| API docs (swagger and similar) | funa has no springdoc at runtime: `swagger-parser` is a test-only dependency (`libs.versions.toml`, `testImplementation`). If docs are served, they would arrive through a `@valid_hosts` route | **Caddy** | Same as above |
| `@Scheduled` job (`CodeServiceImpl.execute` refreshes a code cache, default once a day) | `OTEL_INSTRUMENTATION_SPRING_SCHEDULING_ENABLED=false` is set, so there is no INTERNAL root. `mapper.findAll()` becomes a root JDBC CLIENT span on a `scheduling-N` thread | **funa** (JDBC CLIENT root) | Agent sampler matching `thread.name` (§2.3) |
| Lettuce reconnect / background commands | Commands issued outside a request have no parent, so they become CLIENT roots (verify in real data) | **funa** | Agent sampler (CLIENT kind) |
| RabbitMQ consumer (`DummyListener` `@RabbitListener`) | A CONSUMER span. It is a child if the producer propagated context, and a root otherwise | **funa** (root only if no producer context) | Agent sampler or collector. Whether it counts as noise is a definition question: the map says RabbitMQ child spans are business. |

funa compose places funa only on the external `backend` bridge network, under alias `funa-api`, and Caddy reaches it through that alias (funa `docker/prod/compose.yml` header, ADR-0023). A bridge network is node-local, so **a request that enters a node's Caddy is served by that node's funa**, and both halves of an HTTP trace are exported to the same node collector. That is the condition `tail_sampling` needs (§3.2).

## 2. OTel Java agent 2.30: options at the source

### 2.1 What is *not* there

- **No HTTP server path-ignore property.** ADR-0033 already found that `OTEL_INSTRUMENTATION_HTTP_SERVER_IGNORE_PATHS` doesn't exist. The 2.30–2.32 release notes add nothing like it ([v2.30.0][rel230], [v2.31.0][rel231], [v2.32.0][rel232]).
- **`otel.instrumentation.<name>.enabled=false` is all-or-nothing per library.** Turning off `lettuce`, `jdbc` or `rabbitmq` would also strip those child spans from business traces, which the definition forbids. That leaves `spring-scheduling`, `spring-security`, `spring-data` and similar wrapper instrumentations as the only safe targets ([suppressing instrumentation][otel-disable]).
- **`otel.javaagent.exclude-classes`** silences all instrumentation for given classes. The docs warn it "can leave some instrumentation partially applied" ([advanced-configuration-options.md][adv-cfg]). It is not path-aware.

### 2.2 `rule_based_routing` sampler (contrib), already bundled in the agent

- **Packaging.** `sdk-autoconfigure-support` at v2.30.0 has `implementation("io.opentelemetry.contrib:opentelemetry-samplers")` ([build.gradle.kts][sdkac-build]), pinned to `otelContribVersion = "1.58.0-alpha"` ([dependencyManagement][depmgmt]). The samplers README says: "if using the java agent, this sampler is already included in versions 2.21+ and no additional dependency is required" ([samplers README][samplers-readme]). **No extension jar is needed.** The extension approach ADR-0033 rejected isn't required for this.
- **Only reachable via declarative config.** In 1.58.0 the `ConfigurableSamplerProvider` SPI file lists only `LinksParentAlwaysOnSamplerProvider` ([SPI file][samplers-spi]). `rule_based_routing` is registered only as a declarative `ComponentProvider` (`RuleBasedRoutingSamplerComponentProvider`). **`OTEL_TRACES_SAMPLER` cannot select it.**
- **Matching semantics** ([RuleBasedRoutingSampler.java][rbrs]):
  - It applies to exactly **one `span_kind`**. Other kinds go to `fallback_sampler`. To cover SERVER and CLIENT, nest a second `rule_based_routing` as the `fallback_sampler` (the schema allows any sampler there; check that the agent parses the nesting).
  - Rules are tried in order. The first rule whose attribute is present and whose regex **`find()`s** (a substring match, not a full match) decides: `DROP` → always_off, `RECORD_AND_SAMPLE` → always_on. Anchor patterns with `^`.
  - Only **string** attributes known **at span start** are visible. `url.path` is there for HTTP server spans. `http.route` isn't (it is set after routing), and `server.port` is a long, so it can't be matched.
  - **`thread.name` is special-cased.** The sampler reads `Thread.currentThread().getName()`, so scheduler threads can be matched without any attribute.
- **Placement and the Caddy sampled flag.** Use it as the `root` of `parent_based` (the README's own example). Then:
  - **Remote parent sampled** (a business request through Caddy): funa follows Caddy, the rule is not consulted, and every child (JDBC, Rabbit publish) is kept. This is the "lose nothing under a business root" property.
  - **No parent** (Caddy health checks to the management port, scheduler threads, Lettuce background, Rabbit with no producer context): the rule decides. A DROP leaves the span non-sampled, and every child inherits non-sampled through `parent_based`, so **the whole subtree disappears at the source and no orphan is created.**
  - **Remote parent not sampled**: funa drops too.
  - It is possible to override `remote_parent_sampled` with a rule sampler, so funa could drop docs paths even when Caddy sampled. Caddy's root span would still be exported, leaving a one-span Caddy trace. Scope it in Caddy instead.
- **Maturity.**
  - The artifact is `-alpha`.
  - Java agent declarative config is "still experimental", supported in agent **2.26.0+**, enabled with `-Dotel.config.file=...` ([agent declarative config][agent-decl]).
  - **v2.32.0 deprecates declarative `rule_based_routing`** "in favor of the SDK incubator composite/development `rule_based` sampler, whose configuration and matching behavior differ" ([v2.32.0 notes][rel232], PR #20249). An agent upgrade past 2.31 means migrating the sampler block. The `composite/development` `rule_based` sampler matches by `span_kinds` plus `attribute_values` (exact values) or patterns, and has a `parent_threshold` catch-all ([config types spec][spec-types]).

### 2.3 What adopting declarative config costs funa

- **Every `OTEL_*` env var is ignored unless the YAML templates it with `${VAR}`.** The docs say so in a warning ([declarative configuration][sdk-decl]). The three exporter settings and three `OTEL_INSTRUMENTATION_SPRING_*_ENABLED` settings in compose would move into the YAML, under `distribution.javaagent.instrumentation.disabled` and `tracer_provider`, and so on. That changes ADR-0033 ("configured only by `OTEL_*` env") and needs an amendment.
- **Startup-only options stay as properties or env** (`otel.javaagent.enabled`, `otel.javaagent.extensions`, `otel.javaagent.debug`, `otel.javaagent.logging`) ([agent declarative config][agent-decl]).
- **Switching it on.** The page documents only the system property `-Dotel.config.file`, not an env var name. The funa Dockerfile `ENTRYPOINT` is fixed, so without an image change the property goes in `JAVA_TOOL_OPTIONS` (read by the JVM itself), with the YAML mounted like `application.yml`. Whether `OTEL_CONFIG_FILE` also works in 2.30 is **unverified**.
- **The scheduling flag interacts.**
  - Keep `SPRING_SCHEDULING_ENABLED=false`: the scheduled JDBC call is a root CLIENT span on a `scheduling-` thread. Drop it with a CLIENT-kind rule `thread.name: ^scheduling-`. Spring Boot's documented example prefix is `scheduling-`, funa doesn't override it, and virtual threads are off in `example.application.yml` ([Boot task scheduling][boot-sched]).
  - Or re-enable it: the job becomes one INTERNAL root with children, and an INTERNAL-kind rule on `thread.name` drops the whole job trace.
  - Either way works. Re-enabling gives a clean single root if a job ever needs to be kept for debugging.
- **Sketch** (not validated against the 2.30 parser; replace the management path with the real value at deploy time):

```yaml
file_format: "1.0"
tracer_provider:
  sampler:
    parent_based:
      root:
        rule_based_routing:          # SERVER roots: management server, probes reaching funa directly
          span_kind: SERVER
          rules:
            - { action: DROP, attribute: url.path, pattern: "^/<management-base-path>/" }
          fallback_sampler:
            rule_based_routing:      # CLIENT roots: scheduler JDBC, Lettuce background
              span_kind: CLIENT
              rules:
                - { action: DROP, attribute: thread.name, pattern: "^scheduling-" }
                - { action: DROP, attribute: thread.name, pattern: "^lettuce-" }   # verify thread names in real data
              fallback_sampler:
                always_on:
```

### 2.4 Caddy's side of the sampled flag

- **Propagation.** Caddy's `tracing` wraps the handler in `otelhttp.NewHandler(..., otelhttp.WithPropagators(autoprop.NewTextMapPropagator()))` and injects the context into the upstream request headers ([tracer.go][caddy-tracer]). It **extracts an incoming client `traceparent`**, so the client's sampled flag is honoured.
- **Sampler.** Caddy passes no `WithSampler` (only `WithBatcher` and `WithResource`), so the Go SDK default applies: `ParentBased(AlwaysSample())`, overridable by `OTEL_TRACES_SAMPLER` ([provider.go][go-provider], [sampler_env.go][go-sampler-env]).
- **Finding.** An external client that sends `traceparent` with flags `00` makes Caddy **and** funa (parent_based) drop a business trace. A client sending `01` forces sampling and chooses the trace id. Possible mitigations are stripping inbound `traceparent`/`tracestate` before `tracing` runs, or setting Caddy to `always_on`. The first depends on directive order, which wasn't verified.

## 3. Collector (otelcol-contrib 0.161.0)

### 3.1 `filter` processor: span level

- **Stability and syntax.** Alpha for traces. Since 0.146 the syntax is `trace_conditions: [OTTL...]`, ORed, with the `error_mode` default `ignore` ([filter README][filter-readme]).
- **Root detection.** OTTL has `IsRootSpan()` in span context ([ottlfuncs][ottlfuncs]), so `IsRootSpan() and IsMatch(span.attributes["url.path"], "^/...")` drops only noisy roots.
- **Orphan problem.** The README's own warning: "Dropping a span may lead to orphaned spans if the dropped span is a parent. Dropping a span may lead to orphaned logs if the log references the dropped span" ([filter README §Warnings][filter-readme]). Children of a noise root (an actuator health check's JDBC/Redis probes, a Caddy root's funa child) don't carry the root's `url.path`. `filter` sees one span at a time, so it **cannot drop a trace**. It can only drop spans that each carry their own evidence.
- **Cost.** Stateless and cheap. Good for noise roots with **no** children, and for metrics.
- **Ordering hazard.** A `filter` placed **before** `tail_sampling` in the same pipeline can remove the root that the trace-level policy would have used, so the drop policy never fires and the children get sampled. Put trace-level decisions first, or don't drop roots in `filter`.

### 3.2 `tail_sampling` processor: trace level

- **Requirement.** Beta. "All spans for a given trace MUST be received by the same collector instance" ([tail README][tail-readme]). It groups by `trace_id` itself (no `groupbytrace` needed).
- **Topology fit.**
  - **HTTP: holds.** One collector per node, and Caddy plus funa on that node's local bridge network (§1).
  - **RabbitMQ: can break.** If funa on node A publishes and funa on node B consumes, B's CONSUMER spans reach B's collector without A's root. B then decides on a **partial trace** with only its own spans. Use the design below so a partial trace defaults to keep. Whether funa publishes across nodes was not checked; `DummyListener` is only a consumer.
- **Decision flow.**
  - Any `drop` → not sampled. Any `sample` → sampled. **Otherwise not sampled** ([tail README §Policy Decision Flow][tail-readme]). `invert_match` decisions are deprecated in favour of `drop` and `not`.
  - The shape is therefore `always_sample` plus a `drop` policy whose sub-policies (`ottl_condition`, `string_attribute` with regex) fire only on **positive noise evidence**. Example: a span with `IsRootSpan() and IsMatch(span.attributes["url.path"], "...")`, or `resource.attributes["service.name"] == "<caddy service>" and span.name matches a docs path`.
  - Traces with no evidence, including partial traces, are then kept.
- **Timing.**
  - `decision_wait` defaults to 30s. `sampling_strategy` defaults to `trace-complete`.
  - `decision_wait_after_root_received` (default 0s, off) lets the decision come early once the root arrives. In this topology the Caddy root ends last, after funa's spans, so this fits well.
  - Both SDKs batch-export on roughly 5s schedules, so `decision_wait` must cover export delay plus request duration.
  - `span-ingest` mode decides per batch with no re-evaluation, which doesn't fit "decide by the root".
- **Memory.**
  - The processor keeps up to `num_traces` traces (default 50,000) in a ring buffer. Overflow evicts the oldest trace **unsampled** (`otelcol_processor_tail_sampling_sampling_trace_dropped_too_early`).
  - Rough sizing: memory ≈ new traces/s × `decision_wait` × average trace bytes. Real request rates aren't known yet, so size it after collection is on, consistent with map #239's "잡음 검증 방법".
  - `maximum_trace_size_bytes` caps a runaway trace. `decision_cache` (`sampled_cache_size` and `non_sampled_cache_size`, default 0 = off) lets late spans inherit the decision instead of opening a new trace.
  - Watch `..._trace_removal_age` and `..._decision_timer_latency` ([tail README §Monitoring][tail-readme]).
  - Note the existing `memory_limiter` in the node template: it refuses data under pressure, and `tail_sampling` adds resident memory on top.
- **Late spans.** With no decision cache, a span arriving after its trace was released starts a fresh decision ([tail README §Late-arriving spans][tail-readme]). A late child of a dropped noise root would then be judged alone, with no root evidence, and **kept**. Set `non_sampled_cache_size`.

### 3.3 Summary

| | `filter` | `tail_sampling` |
|---|---|---|
| Unit | span (and span event) | trace (`trace_id`) |
| State and memory | none | spans held for `decision_wait` × traffic |
| Children of a dropped root | **orphaned** | dropped with the root |
| Cross-node traces | n/a | partial-trace decisions |
| Stability | alpha (traces) | beta |
| Best use | single-span noise, metric series | Caddy-rooted noise, safety net |

## 4. Metric noise

### 4.1 App (agent) metrics

- **Attributes.** For `http.server.request.duration`, `server.address` and `server.port` are **Opt-In**: "opting in to it may allow an attacker to trigger cardinality limits". `http.route` is "Conditionally Required … if and only if it's available" ([semconv HTTP metrics][semconv-http]). The management port therefore doesn't appear by default. Identify management traffic by `http.route` (the actuator route under the management base path; confirm the recorded value in real data). Requests to unmatched routes carry no `http.route`, so they don't add cardinality.
- **Dropping.** Use `filter` `metric_conditions` with `datapoint.attributes["http.route"]` and `IsMatch`, or `HasAttrOnDatapoint(key, value)` ([filter README][filter-readme]). If every datapoint of a metric is dropped, the metric is dropped. JVM runtime metrics, which the map keeps, carry no `http.route`, so they are unaffected.
- **Scope.** `metric.name` conditions drop whole instruments. In the agent, metric-name filtering exists only for JMX (`otel.jmx.metrics.included`/`excluded`, added in 2.32, [notes][rel232]), so drop by name in the collector.

### 4.2 Caddy metrics

- **Version gate.** `metrics { otlp }` (push via OTLP from the Prometheus registry) was added in commit `2a3ed96f` (2026-04-25) and is **present at v2.11.3, absent at v2.11.2** ([metrics.go@v2.11.3][caddy-metrics-3]). Check the node's exact patch version. Earlier versions need Prometheus scraping instead.
- **Labels.** Caddy HTTP metrics are labelled `server`, `handler`, `code`, `method`, plus `host` with `per_host`. **There is no path label** ([metrics.go@v2.11.7][caddy-metrics]). Probe traffic is visible only as `handler="static_response"` and can't be separated from other static responses by path.
- **Cardinality hazard.** `shouldAllowHostMetrics` allows a raw lower-cased `r.Host` when the host is in the configured host matchers, **or** when `ObserveCatchallHosts`, **or** when `isHTTPS && hasHTTPSServer`. Otherwise it uses `_other` ([metrics.go L270–L285, L326–L335][caddy-metrics]).
  - With the boilerplate's `per_host` and `observe_catchall_hosts`, plus a wildcard site and certificate, **every subdomain, or any Host header that passes TLS/SNI, becomes its own `host` value**. Under `strict_sni_host` the Host must equal the SNI.
  - That is the "unserved hosts" noise. The `_other` protection is effectively bypassed by the HTTPS auto-allow.
  - Options:
    - (a) Drop `observe_catchall_hosts` in Caddy. This doesn't help for HTTPS because of the auto-allow.
    - (b) In the collector, `transform` with `set(datapoint.attributes["host"], "_other") where not IsMatch(datapoint.attributes["host"], "<allowlist regex>")`. This keeps the counts but collapses cardinality.
    - (c) `filter` `metric_conditions` to drop those datapoints. This loses the attack signal.
  - (b) keeps evidence of scanning without unbounded series.
- **Transform processor.** Beta for metrics. Statements in `datapoint` context support `set`, `delete_key`, `keep_keys` and `limit` ([transform README][transform-readme]).

## 5. Suggested combination (for the spec decision, not decided here)

- **Layer 1, Caddy (cheapest).**
  - Keep probes and unserved hosts outside `tracing`, as the boilerplate already does.
  - If the live Caddyfile proxies docs or app-health paths through a `@valid_hosts` route, give them a `handle` without `tracing`.
  - Decide whether inbound client `traceparent` is trusted (§2.4).
- **Layer 2, funa agent: `parent_based { root: rule_based_routing }` through declarative config.**
  - It drops management-port SERVER roots and scheduler/Lettuce CLIENT roots with their whole subtree, at zero collector cost.
  - Price: an ADR-0033 amendment (env → YAML), an alpha/experimental dependency, and a sampler migration when upgrading past 2.31.
  - Alternative if declarative config is too much: skip it and rely on layer 3.
- **Layer 3, node collector traces pipeline.** Run `tail_sampling` with `always_sample` plus positive-evidence `drop` sub-policies (Caddy-rooted noise paths, funa root noise if layer 2 isn't adopted).
  - Set `decision_wait_after_root_received`, `non_sampled_cache_size` and `maximum_trace_size_bytes`.
  - Size `num_traces` after real volume is measured.
  - Avoid `filter` on traces except for childless single spans, and never ahead of `tail_sampling` on roots.
- **Layer 4, metrics pipeline.** Use `filter` `metric_conditions` on the agent `http.route` (management) and `transform` to collapse Caddy `host` to an allowlist or `_other`. Keep JVM metrics.

## 6. Open questions

1. **Live Caddyfile.** Check `tracing` placement, any proxied health or docs paths, the Caddy patch version (≥ v2.11.3 for `metrics { otlp }`), and whether `observe_catchall_hosts` is set.
2. **Root CLIENT spans in real data.** Do JDBC and Lettuce calls outside a request produce root CLIENT spans in 2.30, and what are the Lettuce thread names?
3. **Env var for declarative config.** Does agent 2.30 accept `OTEL_CONFIG_FILE` as an env var, or only `-Dotel.config.file` (`JAVA_TOOL_OPTIONS`)? Does it parse a nested `rule_based_routing` as `fallback_sampler`?
4. **RabbitMQ.** Does funa publish to queues consumed on another node? This decides whether `tail_sampling` sees partial traces. Are root CONSUMER spans (no producer context) business or noise?
5. **`http.route` for management.** What exact value does the agent record for the management server's actuator requests?

## Sources

[rel230]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.30.0
[rel231]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.31.0
[rel232]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.32.0
[otel-disable]: https://opentelemetry.io/docs/zero-code/java/agent/disable/
[adv-cfg]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/blob/v2.30.0/docs/advanced-configuration-options.md
[sdkac-build]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/blob/v2.30.0/sdk-autoconfigure-support/build.gradle.kts
[depmgmt]: https://github.com/open-telemetry/opentelemetry-java-instrumentation/blob/v2.30.0/dependencyManagement/build.gradle.kts
[samplers-readme]: https://github.com/open-telemetry/opentelemetry-java-contrib/blob/main/samplers/README.md
[samplers-spi]: https://github.com/open-telemetry/opentelemetry-java-contrib/blob/v1.58.0/samplers/src/main/resources/META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.traces.ConfigurableSamplerProvider
[rbrs]: https://github.com/open-telemetry/opentelemetry-java-contrib/blob/v1.58.0/samplers/src/main/java/io/opentelemetry/contrib/sampler/RuleBasedRoutingSampler.java
[agent-decl]: https://opentelemetry.io/docs/zero-code/java/agent/declarative-configuration/
[sdk-decl]: https://opentelemetry.io/docs/languages/sdk-configuration/declarative-configuration/
[spec-types]: https://opentelemetry.io/docs/specs/otel/configuration/types
[boot-sched]: https://docs.spring.io/spring-boot/reference/features/task-execution-and-scheduling.html
[caddy-tracer]: https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddyhttp/tracing/tracer.go
[caddy-hc]: https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddyhttp/reverseproxy/healthchecks.go#L444
[caddy-metrics]: https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddyhttp/metrics.go
[caddy-metrics-3]: https://github.com/caddyserver/caddy/blob/v2.11.3/modules/caddyhttp/metrics.go
[go-provider]: https://github.com/open-telemetry/opentelemetry-go/blob/main/sdk/trace/provider.go
[go-sampler-env]: https://github.com/open-telemetry/opentelemetry-go/blob/main/sdk/trace/sampler_env.go
[filter-readme]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/processor/filterprocessor/README.md
[tail-readme]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/processor/tailsamplingprocessor/README.md
[transform-readme]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/processor/transformprocessor/README.md
[ottlfuncs]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/pkg/ottl/ottlfuncs/README.md#isrootspan
[semconv-http]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/

- OTel Java agent v2.30.0, 2.31.0, 2.32.0 release notes: [v2.30.0][rel230], [v2.31.0][rel231], [v2.32.0][rel232]
- Agent build and dependency pins at v2.30.0: [sdk-autoconfigure-support/build.gradle.kts][sdkac-build], [dependencyManagement/build.gradle.kts][depmgmt]
- Contrib samplers 1.58.0: [README][samplers-readme], [SPI file][samplers-spi], [RuleBasedRoutingSampler.java][rbrs]
- Declarative config: [Java agent page][agent-decl], [SDK page][sdk-decl], [config types spec (`composite/development` `rule_based`)][spec-types]
- [Suppressing agent instrumentation][otel-disable], [advanced configuration options][adv-cfg]
- Caddy v2.11.7: [tracing/tracer.go][caddy-tracer], [reverseproxy/healthchecks.go][caddy-hc], [caddyhttp/metrics.go][caddy-metrics]. OTLP metrics at [v2.11.3][caddy-metrics-3]
- OTel Go SDK: [provider.go][go-provider], [sampler_env.go][go-sampler-env]
- otelcol-contrib v0.161.0: [filter][filter-readme], [tail_sampling][tail-readme], [transform][transform-readme], [OTTL `IsRootSpan`][ottlfuncs]
- [Semantic conventions: HTTP metrics][semconv-http]
- [Spring Boot task scheduling][boot-sched]
- Local: funa `docker/prod/compose.yml`, `docker/prod/Dockerfile`, `docker/prod/example.application.yml`, `docs/adr/0033-…`. `caddy-boilerplate/cluster/runtime/Caddyfile`
