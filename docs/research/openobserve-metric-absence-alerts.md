# Research: OpenObserve metric alerts and absence ("no data") detection

- Ticket: [#164](https://github.com/ppzxc/infra-automation/issues/164) (map [#162](https://github.com/ppzxc/infra-automation/issues/162))
- Date: 2026-10-13
- Version checked: ns0332 OpenObserve reports `build_type: opensource`, `commit_hash: 1e257e69…` on `GET /config`. That commit is tag **v1.0.4**. Every source link below points at that tag.
- Method: (1) read the v1.0.4 source of the alert model, evaluator, scheduler and notification code; (2) read the official docs through Context7; (3) ran read-only queries against ns0332 (`POST /api/default/_search`, `GET /api/default/prometheus/api/v1/query[_range]`, `GET /api/v2/default/alerts`, `GET /api/default/streams`). Nothing was created or changed on the server.

## TL;DR

1. **Metric alerts work with both SQL and PromQL.** Set `stream_type: "metrics"`, put a metrics stream in `stream_name`, and pick either `query_condition.type: "sql"` (same body shape as our logs alerts) or `type: "promql"` (`promql` plus a required `promql_condition`). In PromQL mode `trigger_condition.threshold` counts *series*, not rows. The only code blocker on our side is that `filter_plugins/openobserve_config.py` hardcodes `stream_type: 'logs'`, `type: 'sql'` and `operator: '>='`.
2. **OpenObserve has no "no data" alert feature** in the opensource build. Anomaly detection is enterprise-only. **`operator: '<'` with `threshold: 1` is a trap:** zero rows count as "matched", and the alert state and history say it fired, but **the scheduler skips the notification when the payload is empty**. What does work is making the SQL itself **return one row per missing thing**:
   - **Roster form (recommended).** Generate one `UNION ALL` branch per expected host from the Ansible inventory: `SELECT 'nsXXXX' AS host_name, count(*) AS n FROM <stream> WHERE host_name = 'nsXXXX' HAVING count(*) < 1`. Live test: 21 branches over 15 minutes took about 170 ms and returned exactly the 9 silent hosts plus a fake host. No host can age out of this form.
   - **Staleness form (complement).** Use a long `period` (for example 7 days) and `GROUP BY host_name HAVING max(_timestamp) < to_unixtime(now()) * 1000000 - N`. It needs no roster, but a host silent for longer than `period` drops out and the alert quietly clears.
3. **`row_template` and `context_attributes` work for metric alerts**, SQL and PromQL alike, because the notification code doesn't depend on stream type. PromQL rows carry the series labels, `value` and `_timestamp`. `{alert_url}` for a SQL alert on a metrics stream is built as a `/web/logs?stream_type=metrics…` link (not verified in the UI). For PromQL alerts it is a `/web/metrics` link.

## 1. Metric alerts: v2 body differences

The API model is `Alert` in [`api/management/src/models/alerts/mod.rs`][m-api]. Our PUT/POST body keys (`query_condition`, `trigger_condition.period/threshold/frequency/silence`) map 1:1 onto it. GET responses show the same object under `condition` (seen live).

| Field | Logs (today) | Metrics, SQL | Metrics, PromQL | Source |
|---|---|---|---|---|
| `stream_type` | `"logs"` | `"metrics"` | `"metrics"` | `StreamType` on `Alert` [m-alert] |
| `stream_name` | `system_logs` | for example `system_filesystem_usage`. It must exist in the metrics schema, or save fails with `StreamNotFound` | same | [alert.rs validation][c-alert] |
| `query_condition.type` | `"sql"` | `"sql"` | `"promql"` | `QueryType` = `custom`, `sql`, `promql`, `slo` [m-mod] |
| `query_condition.sql` | required, no `SELECT *` | required, no `SELECT *` | – | `SqlMissingQuery`, `SqlContainsSelectStar` [c-alert] |
| `query_condition.promql` | – | – | required | `PromqlMissingQuery` [c-alert] |
| `query_condition.promql_condition` | – | – | **required**: `{"column":"value","operator":">=","value":85}`. The evaluator runs `(<promql>) <op> <value>` | [c-mod] |
| `query_condition.aggregation` | not used | optional. If set, the threshold moves to `having.value` and `trigger_condition.threshold` becomes a group-count gate | not used | [c-mod] |
| `trigger_condition.threshold`/`operator` | row count (`>= 1`) | row count | **series count** gate. `warning_threshold` is rejected (`WarningOnCoverageGate`) | [c-alert], [c-mod] |
| `is_real_time` | false | must be false. Realtime requires `type: custom` | must be false | `RealtimeMissingCustomQuery` [c-alert] |

One alert has exactly one `stream_type`. Every stream named in its SQL is schema-checked under that type, so **one SQL alert cannot mix metrics and logs streams**. For example, it can't use a metrics roster for a `backup_logs` alert ([core/alerts/mod.rs][c-mod], `get_stream_schema_from_cache(org, stream, stream_type)`).

Evaluation window: the scheduler always evaluates `[end − period, end]` (`start_time = final_end_time − period`, [scheduler/handlers.rs][c-sched]), so `period` really is the lookback for both SQL and PromQL. The stream's `max_query_range` caps it. That is `0` (unlimited) on every ns0332 stream.

PromQL specifics ([core/alerts/mod.rs][c-mod]):
- The alert runs a **range** query over `period` with `step = max(minimal, period / MAX_DATA_POINTS)` and takes `samples.last()` of each series, which is the last sample *present* in the window, not the value at `end`. A series that recovered (or vanished) can keep firing until its old samples leave the window. Keep `period` short, 1 to 5 minutes.
- Each returned series becomes one row: all labels, plus `value` and `_timestamp`. `value` is a raw float (for example `81.7925159468466`). Unlike SQL, there's no `round()` at notification time.

## 2. Absence detection

### What exists, and what doesn't

| Option | Verdict | Evidence |
|---|---|---|
| "No data" alert feature | **Does not exist** in v1.0.4 opensource. The docs only mention Datadog's `notify_no_data` as something to "configure the equivalent" for | [docs: Datadog migration][d-dd]; no such field in `Alert`/`TriggerCondition` [m-alert], [m-mod] |
| Anomaly detection | **Enterprise only.** Routes sit under `#[cfg(feature = "enterprise")]`, and ns0332 is `opensource` | [router][c-router] lines ~1033–1042; [docs: alert types][d-alerts] |
| `operator: '<'`, `threshold: 1` (count alert, zero rows) | **Fires silently.** The evaluator returns `data = Some([])`, so the level is Critical and the state/history say "fired". The scheduler only notifies `if let Some(data) … && !data.is_empty()`. The comment says verbatim: *"a `<`/`<=` alert can match with an EMPTY payload … only the notification is skipped."* | [c-mod] count path; [c-sched] ~2168–2180 |
| Aggregation condition (`aggregation.having`) | Doesn't help. It classifies the groups that come back, and a silent host returns no group | [c-mod] |
| `multi_time_range` (`offSet` comparisons) | Runs extra copies of the SQL at shifted windows. It doesn't produce rows for absent keys, so it doesn't solve absence | `CompareHistoricData` [m-mod] |
| `pending_period_sec` | A "for" duration: it fires only after the condition has been pending that long. Useful against flapping (disk, short gaps), but not an absence feature | [c-sched] ~2208–2260 |
| Composite alerts | Combine other alerts' states (AND/OR/NOT). Not explored further; same blind spot | [docs: alert types][d-alerts] |
| **SQL that emits a row per missing key** | **Works.** Ungrouped `count(*) … HAVING count(*) < 1` returns exactly one row when nothing matched. `UNION ALL` of such branches gives one row per missing host | live tests below |
| Long `period` + `max(_timestamp)` staleness | Works, but it ages out | live tests below |

### Live tests on ns0332 (read-only)

At test time, 9 hosts had last sent data about 21.5 hours earlier. This is the CentOS 6 incident in #161.

| Query | Result |
|---|---|
| `SELECT host_name, max(_timestamp) AS last_seen FROM system_memory_usage GROUP BY host_name HAVING max(_timestamp) < to_unixtime(now()) * 1000000 - 15 * 60000000` over 24h | the 9 silent hosts. Over 7d: same 9, `took` 113 ms |
| same with `now() - INTERVAL '15 minutes'` | **error** (`Search SQL execute error`) |
| same with `cast(now() - INTERVAL '15 minutes' as bigint)` | **wrong**: every host (unit mismatch). Use `to_unixtime(now()) * 1000000` |
| roster `UNION ALL` of 21 branches (20 real hosts + `ns9999`), `HAVING count(*) < 1`, 15 min window | exactly the 9 silent hosts + `ns9999`, `took` 169 ms. Wrapped as `SELECT count(*) FROM (…)` → 10, so the server's COUNT pre-query wrapper works too |
| single branch for a live host | 0 rows |
| `(VALUES ('ns0266'),…) AS r(host_name) LEFT JOIN system_memory_usage …` (also the `unnest(make_array(…))` form and a pre-aggregated subquery) | **wrong**: every roster host came back, including a live one, with the joined columns dropped. **Joins against an inline roster are unreliable on this version. Do not use them.** |
| logs-to-logs join (`system_logs` roster LEFT JOIN `backup_logs`) | matched the plain query, but only because every roster host also had backup rows. Not proven, so not recommended |
| PromQL `count by (host_name)(max_over_time(system_memory_usage[7d])) unless count by (host_name)(max_over_time(system_memory_usage[15m]))` via `query_range` | the 9 silent hosts |
| PromQL `absent_over_time(system_memory_usage{host_name="nsXXXX"}[15m])` | `{}` → 1 (works per host, but the row has no `host_name` label) |

## 3. `row_template` / `context_attributes` on metric alerts

- Both are plain fields on `Alert`, independent of stream type ([m-alert]). `context_attributes` keys are trimmed and stored at save. The notification renderer substitutes them into the row template and the message template ([c-alert] `process_row_template`, ~3068–3200).
- `{rows}` is the row template rendered once per payload row. With an empty payload there are no rows, and as shown above, an empty payload means **no notification at all**.
- PromQL rows: `{host_name}`, `{mountpoint}` (any series label), `{value}`, `{_timestamp}`. SQL rows: whatever columns the SQL selects.
- `{alert_url}`: PromQL → `/web/metrics?stream_type=metrics&…&query=<base64 promql>`. SQL or custom → `/web/logs?stream_type=<stream_type>&…&sql_mode=true`, so for a SQL metric alert it is a logs-explorer link with `stream_type=metrics` (whether the UI opens it cleanly was not checked). The time range comes from `_timestamp` columns in the rows if any, otherwise from `[end − period, end]` ([c-alert] `get_alert_start_end_time`). The absence queries below select no `_timestamp` column, so the link covers the alert period.
- `{alert_count}` for count alerts is the exact count. For PromQL it is the series count.

## 4. Recommended shapes

All three are scheduled, non-realtime. The `filter_plugins/openobserve_config.py` change they need:
- `stream_type` per alert (default `logs`)
- `operator` per alert (default `>=`)
- for PromQL, `query_condition: {type: promql, promql, promql_condition}` instead of `sql`

### (a) Disk usage: SQL on `system_filesystem_usage` (recommended over PromQL)

```json
{
  "name": "infra-disk-usage-high",
  "stream_type": "metrics",
  "stream_name": "system_filesystem_usage",
  "is_real_time": false,
  "query_condition": {
    "type": "sql",
    "sql": "SELECT host_name, mountpoint, round(100.0 * max(CASE WHEN state = 'used' THEN value END) / (max(CASE WHEN state = 'used' THEN value END) + max(CASE WHEN state = 'free' THEN value END)), 1) AS used_pct FROM system_filesystem_usage WHERE type NOT IN ('squashfs','tmpfs','devtmpfs','overlay') GROUP BY host_name, mountpoint HAVING 100.0 * max(CASE WHEN state = 'used' THEN value END) / (max(CASE WHEN state = 'used' THEN value END) + max(CASE WHEN state = 'free' THEN value END)) >= 90"
  },
  "trigger_condition": {"period": 10, "operator": ">=", "threshold": 1, "frequency": 5, "frequency_type": "minutes", "silence": 240},
  "row_template": "{host_name} {mountpoint} {used_pct}%",
  "row_template_type": "String"
}
```

- Live: 27 host/mount pairs in a 10-minute window. The top values were 83.7% (`ns0334 /`) and 73.7%. `used / (used + free)` matches `df`'s Use% (reserved blocks excluded).
- Limitations:
  - Within the window, `max()` takes the largest used and the largest free separately, so the percentage is approximate. The SQL value (83.7%) and the instant PromQL value (81.8%) differed by 2 points.
  - Filesystem types to exclude must be listed. ns0340's snap `squashfs` is always 100%. `vfat` `/boot/efi` is included.
  - A host that stops reporting simply drops out. That's Silent Host's job.
- PromQL alternative, if wanted:

  ```
  max by (host_name, mountpoint)(system_filesystem_usage{state="used",type!="squashfs"}) / ignoring(state)(max by (host_name, mountpoint)(system_filesystem_usage{state="used",type!="squashfs"}) + max by (host_name, mountpoint)(system_filesystem_usage{state="free",type!="squashfs"})) * 100
  ```

  Use it with `promql_condition {column: value, operator: ">=", value: 90}`, `period` 5, and `threshold` 1 (series). It was verified live through `/prometheus/api/v1/query`. The value isn't rounded in `{rows}`.

### (b) Silent Host: roster `UNION ALL` on a metrics stream

```json
{
  "name": "infra-silent-host",
  "stream_type": "metrics",
  "stream_name": "system_memory_usage",
  "query_condition": {
    "type": "sql",
    "sql": "SELECT 'ns0217' AS host_name, count(*) AS n FROM system_memory_usage WHERE host_name = 'ns0217' HAVING count(*) < 1 UNION ALL SELECT 'ns0235' AS host_name, count(*) AS n FROM system_memory_usage WHERE host_name = 'ns0235' HAVING count(*) < 1 UNION ALL …"
  },
  "trigger_condition": {"period": 15, "operator": ">=", "threshold": 1, "frequency": 5, "frequency_type": "minutes", "silence": 60},
  "row_template": "{host_name}",
  "row_template_type": "String"
}
```

- Generate the branch list in Ansible from the inventory: hosts that run Host Agents metrics, minus Host Agents Exclusion and Backup Only hosts that don't send metrics. Then `o2c_plan` updates the alert whenever the inventory changes.
- `system_memory_usage` is a good heartbeat. Every host emits it every scrape (about 30 s; 90 rows per 15 min across 3 states).
- Limitations:
  - The roster lives in the alert. A host added to monitoring without re-running `OpenObserve — Config` is not watched.
  - The SQL grows linearly (about 130 chars per host). 21 hosts cost 169 ms per run.
  - Same-host renames (FQDN vs inventory name) must match `host_name` as sent by the collector.
  - It says nothing about *logs* silence. Add a second alert on `system_logs` (logs stream type) only if log-only gaps matter.
- Optional complement, with no roster and catching unknown hosts: the staleness form with `period: 10080` (7d), `GROUP BY host_name HAVING max(_timestamp) < to_unixtime(now()) * 1000000 - 15 * 60000000`, selecting `(to_unixtime(now()) * 1000000 - max(_timestamp)) / 60000000 AS silent_minutes` for the row template. It took 113 ms live. Hosts silent longer than 7 days age out, and the alert clears without a notice.

### (c) Missing backup: roster `UNION ALL` on `backup_logs`

```json
{
  "name": "backup-missing",
  "stream_type": "logs",
  "stream_name": "backup_logs",
  "query_condition": {
    "type": "sql",
    "sql": "SELECT 'ns0217' AS host_name, count(*) AS n FROM backup_logs WHERE host_name = 'ns0217' AND job = 'backup' AND success = true HAVING count(*) < 1 UNION ALL …"
  },
  "trigger_condition": {"period": 1560, "operator": ">=", "threshold": 1, "frequency": 60, "frequency_type": "minutes", "silence": 720},
  "row_template": "{host_name}",
  "row_template_type": "String"
}
```

- `period` 1560 = 26 hours, which is the nightly backup plus slack. The roster is the hosts with backups enabled. Live test over 26h: the 9 silent hosts plus `ns9999`, 150 ms.
- Explicit *failures* (`success = false`) stay a separate "row returned → fire" alert. This one only covers "no successful run arrived".
- Limitations:
  - **It double-pages with Silent Host.** All 9 currently silent hosts also show up as missing backups, and the two can't be correlated in one SQL because metrics and logs are different stream types. That is a Spec decision: accept it, give it a longer `silence`, or use `system_logs` liveness inside the same logs-type SQL.
  - Maintenance events have an empty `host_name`, with the host in `host`. A missing-maintenance variant must filter on `host`.
  - A backup schedule change requires adjusting `period`.
  - A cron `frequency_type` could align runs to after the backup window.

## Sources

[m-api]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/management/src/models/alerts/mod.rs
[m-alert]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/meta/alerts/alert.rs
[m-mod]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/meta/alerts/mod.rs
[c-mod]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/alerts/mod.rs
[c-alert]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/alerts/alert.rs
[c-sched]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/alerts/scheduler/handlers.rs
[c-router]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/http/src/handler/http/router/mod.rs
[d-alerts]: https://openobserve.ai/docs/user-guide/analytics/alerts
[d-dd]: https://openobserve.ai/docs/migration/migrate-from-datadog-to-openobserve/dashboards-and-alerts

- API model: [models/alerts/mod.rs][m-api]
- Alert struct, `context_attributes`, `row_template`, `pending_period_sec`: [config/meta/alerts/alert.rs][m-alert]
- `QueryCondition`, `TriggerCondition`, `QueryType`, `Operator`, `Aggregation`, `CompareHistoricData`: [config/meta/alerts/mod.rs][m-mod]
- Evaluation (SQL count/hybrid/aggregation, PromQL range query and `samples.last()`): [core/alerts/mod.rs][c-mod]
- Save-time validation, row template rendering, `alert_url`: [core/alerts/alert.rs][c-alert]
- Scheduler window (`start_time = end − period`), empty-payload notification skip, pending period: [core/alerts/scheduler/handlers.rs][c-sched]
- Enterprise-only anomaly routes: [router/mod.rs][c-router]
- Docs: [Alerts overview][d-alerts], [Alert conditions (PromQL mode is metrics-only)](https://openobserve.ai/docs/user-guide/analytics/alerts/alert-conditions), [Scheduled alerts](https://openobserve.ai/docs/user-guide/analytics/alerts/scheduled-alerts), [Datadog migration][d-dd]
