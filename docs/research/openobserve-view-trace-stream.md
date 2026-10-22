# Research: which traces stream OpenObserve's "View Trace" opens

- Ticket: [#251](https://github.com/ppzxc/infra-automation/issues/251) (map [#239](https://github.com/ppzxc/infra-automation/issues/239)). Blocks [#252](https://github.com/ppzxc/infra-automation/issues/252).
- Date: 2026-10-19
- Versions: ns0331 runs **v1.0.4** (`GET /api/default/config` → commit `1e257e69ef0feb6029f3111d54697244a3f507db`, the commit tag `v1.0.4` points to). Compared with **v1.1.1** (commit `5ddbb78268041273e2b347eaf0dbef87cf671b5a`). Links below are permalinks to those commits.
- Method: read the web UI source (`web/src`) along the full path, from the log row's View Trace button through the router push to the trace-details page. Also read the server handler that orders the stream list. Diffed every file on the path against v1.1.1. Ran read-only GETs against ns0331 (`/api/default/config`, `/api/default/settings`, `/api/default/streams?type=traces`). The OpenObserve docs (Context7 `/websites/openobserve_ai`, "Configure and view log and trace correlation") describe the button but not how the stream is chosen, so the source code is the authority here.
- Builds on: [openobserve-otlp-traces-metrics-contract.md](https://github.com/ppzxc/infra-automation/blob/research/openobserve-otlp-traces-contract/docs/research/openobserve-otlp-traces-metrics-contract.md) (§3.3, when the button is shown).

## Answer

**Naming the traces stream `app_traces` does not break View Trace.** The stream is not hard-coded to `default`:

- The button has a **traces-stream dropdown** next to it. Whatever the dropdown holds is passed to the trace-details page as the URL query parameter `stream=`.
- The dropdown starts on the **first traces stream in the org's stream list**. The server sorts that list **by name, ascending**.
- The user can switch the dropdown. The choice lasts for the browser session (in-memory module state) but is **not** saved to localStorage, so a reload resets it.
- The trace-details page takes the stream from `?stream=` first.
- **No org setting or server config chooses this stream.** The only controls are the dropdown and a hand-edited `stream=` in the URL.
- v1.1.1 behaves the same.

With `app_traces` as the only traces stream in the org, it is preselected and the link works without any user action. Renaming it to `default` is unnecessary.

## 1. Code path (v1.0.4)

### 1.1 Button and stream dropdown

[`web/src/composables/useLogs/useViewTraceAction.ts`][vta] holds the shared state for both places that render the action: the inline JSON preview under an expanded row ([`JsonPreview.vue`][jp] l.36–58) and the row-detail drawer header ([`DetailTable.vue`][dt] l.42–62). Both render

```vue
<OSelect v-model="searchObj.meta.selectedTraceStream" :options="tracesStreams" … />
<OButton @click="…">View Trace</OButton>
```

and both show it only when `showViewTraceBtn && (tracesStreams.length || isTracesStreamsLoading)`.

`setViewTraceBtn(record)` sets `showViewTraceBtn` to `!tracesMenuHidden && !serviceStreamsEnabled && record[trace_id_field_name]`. The first time that comes out true, it calls `getTracesStreams()`:

```ts
const res = await getStreams("traces", false);
tracesStreams.value = (res?.list ?? []).map((o) => o.name);
if (!searchObj.meta.selectedTraceStream?.length && tracesStreams.value.length)
  searchObj.meta.selectedTraceStream = tracesStreams.value[0];
```

- **Default = `tracesStreams[0]`**, and only when nothing is selected yet. A user's earlier pick is kept.
- `selectedTraceStream` starts as `""` in `DEFAULT_LOGS_CONFIG.meta` ([`utils/logs/constants.ts`][const] l.159). `searchObj` is a module-level `reactive` ([`searchState.ts`][ss] l.230). Nothing writes it to localStorage: the only references are the ones listed here. The value therefore lasts across SPA navigation in one tab and resets on a page reload.
- `hasLoadedTracesStreams` latches after the first fetch, and `useStreams` caches per session. **A traces stream created after the page loaded doesn't appear until the browser reloads.**

### 1.2 Order of the stream list

`getStreams("traces")` calls `GET /api/{org}/streams?type=traces` without `sort` ([`services/stream.ts`][svc] l.19–45), or returns the session cache built from the same response. `setStreams` stores the list as-is, without re-sorting ([`useStreams.ts`][us] l.400–430). On the server, `list` defaults to `sort=name` and `asc=true` and sorts with `a.name.cmp(&b.name)` ([`src/api/management/src/request/stream/mod.rs`][srv] l.558–569, `stream_comparator`). So **the first stream is the alphabetically smallest name**: byte order, and stream names are lowercased at ingest.

### 1.3 Click → router push

`JsonPreview` emits `view-trace` with the record. `SearchResult.vue` handles it in `redirectToTraces(row)` ([`SearchResult.vue`][sr] l.594, l.743, l.1933–1963):

```ts
router.push({
  name: "traceDetails",
  query: {
    stream: searchObj.meta.selectedTraceStream,
    from: ts - 900000000, to: ts + 900000000,      // ±15 min, µs
    refresh: 0,
    org_identifier: <org>,
    trace_id: log[organizationSettings.trace_id_field_name],
    span_id:  log[organizationSettings.span_id_field_name],
    reload: "true",
  },
});
```

### 1.4 Trace-details page

[`TraceDetails.vue`][td] l.1475–1484 (standalone mode):

```ts
effectiveStreamName = route.query.stream || searchObj.data.stream.selectedStream.value || ""
```

That means `?stream=` wins, and the traces page's own selection is only a fallback when `stream` is empty. A bookmarked or hand-built URL such as `/web/traces/trace-details?stream=app_traces&trace_id=…&from=…&to=…&org_identifier=default` therefore opens `app_traces` explicitly.

### 1.5 The traces page itself (for comparison)

The **Traces** menu (not the View Trace link) picks its stream in `loadStreamLists()` ([`plugins/traces/Index.vue`][ti] l.526–580). The order is:

1. `?stream=` in the URL
2. the stream already selected in memory
3. a localStorage value `oo_selected_stream_traces_<org>` ([`utils/streamPersist.ts`][sp]), read only when `auto_query_enabled` is on. It is **off** on ns0331.

If none of these matches, no stream is selected. It does not fall back to the first stream. The View Trace link doesn't use this logic or that localStorage key.

### 1.6 Out of scope: the correlated-logs path

`CorrelatedLogsTable.vue` (l.1224–1250) builds the same route from `selectedTraceStream`. That tab only shows when `service_streams_enabled` is on **and** the build is enterprise ([`DetailTable.vue`][dt] l.746–773). On ns0331, `service_streams_enabled` is `false` (and the View Trace button itself is hidden whenever it is true), so that path never runs here.

## 2. v1.1.1

- `useViewTraceAction.ts` is byte-identical.
- `redirectToTraces` is identical; it moved to [`SearchResult.vue` l.1894][sr11] (push at l.1914).
- `effectiveStreamName` is unchanged ([`TraceDetails.vue` l.1632][td11]).
- `selectedTraceStream` has the same references in `constants.ts`, `JsonPreview.vue`, `DetailTable.vue`, `CorrelatedLogsTable.vue` and `SearchResult.vue`. `useStreams.ts` is unchanged.
- The only `TraceDetails.vue` changes on this path are unrelated: span paging and quote-escaping the `trace_id` in the logs-correlation SQL.

**Upgrading from v1.0.4 to v1.1.1 does not change this behavior.**

## 3. ns0331 today (read-only)

| Check | Value |
|---|---|
| `version` / `commit_hash` | `v1.0.4` / `1e257e69…` |
| `service_streams_enabled` | `false`, so the button is gated only on the trace-id field |
| `auto_query_enabled` | `false`, so the traces page doesn't restore its localStorage stream |
| `custom_hide_menus` | empty, so the Traces menu is not hidden |
| org settings `trace_id_field_name` / `span_id_field_name` | `trace_id` / `span_id` |
| traces streams | **none** (`total: 0`) |

The org has no traces stream yet, so the `tracesStreams.length` condition fails. **View Trace won't appear on ns0331, even on a log record with `trace_id`, until the first span lands in `app_traces`** and the user reloads the page.

## 4. Risks and options

The real risk is a wrong preselection, not a broken link. If a second traces stream ever exists and sorts **before** `app_traces`, the dropdown silently preselects it. The user then lands on trace details with no matching trace unless they notice the dropdown and switch.

- A stray `default` stream is **harmless for preselection**, because `app_traces` < `default`. The ingest contract says a missing `stream-name` header creates one, as seen on ns0270.
- A name such as `aaa_*`, or any name below `app_traces`, would take over.

| Option | Verdict |
|---|---|
| Keep `app_traces`, as the only traces stream in the org | **Recommended.** It is preselected automatically and the link works. No rename and no setting are needed. |
| Rename to `default` | Not needed. It gains nothing over `app_traces` and gives up the explicit name. |
| Org setting or server config | **None exists.** Org settings control only which log field holds the trace/span ID (`trace_id_field_name`, `span_id_field_name`), not the target stream. |
| User picks a stream | Always possible through the dropdown next to the button. Needed only if there are several traces streams. |
| URL `?stream=` | Honored by trace-details. Useful for links built outside the logs UI, such as alert templates and dashboards. |

Guardrail worth carrying into the spec (#252): keep one traces stream per org. Make sure every exporter that sends spans sets `stream-name: app_traces`, so no `default` traces stream and no other traces stream appears.

[vta]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/composables/useLogs/useViewTraceAction.ts
[jp]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/plugins/logs/JsonPreview.vue#L36-L58
[dt]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/plugins/logs/DetailTable.vue#L42-L62
[const]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/utils/logs/constants.ts#L159
[ss]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/composables/useLogs/searchState.ts#L230
[svc]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/services/stream.ts#L19-L45
[us]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/composables/useStreams.ts#L400-L430
[srv]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/api/management/src/request/stream/mod.rs#L558-L569
[sr]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/plugins/logs/SearchResult.vue#L1933-L1963
[td]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/plugins/traces/TraceDetails.vue#L1475-L1484
[ti]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/plugins/traces/Index.vue#L526-L580
[sp]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/web/src/utils/streamPersist.ts
[sr11]: https://github.com/openobserve/openobserve/blob/5ddbb78268041273e2b347eaf0dbef87cf671b5a/web/src/plugins/logs/SearchResult.vue#L1894-L1924
[td11]: https://github.com/openobserve/openobserve/blob/5ddbb78268041273e2b347eaf0dbef87cf671b5a/web/src/plugins/traces/TraceDetails.vue#L1632-L1642
