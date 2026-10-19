"""Business Telemetry noise rules (ADR-0012, Spec #253 / Ticket-7) against a real otelcol-contrib binary.

Synthetic OTLP goes through the rendered ``traces/otlp`` and ``metrics/otlp`` pipelines; the external exporters are
file exporters (``tests/otelcol_harness.py``). The management path is private, so the tests use a dummy value.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otelcol_harness as h  # noqa: E402
import test_app_telemetry as app  # noqa: E402

MGMT = "/mgmt-dummy"
FAST = {"otel_trace_decision_wait": "2s"}


def _harness(tmp_path, version, **over):
    over = dict(FAST, otel_app_management_path=MGMT, **over)
    return h.OtlpHarness(tmp_path, app._render(tmp_path, version, **over))


def _root(tid, service, root_attrs):
    return h.resource_spans(service, [h.span(tid, "1" * 16, "root", attributes=root_attrs)])


@pytest.mark.parametrize("version", list(h.VERSIONS))
def test_only_caddy_business_traces_leave_with_every_child_span(tmp_path, version):
    binary = h.binary(version)
    harness = _harness(tmp_path, version)
    with harness.running(binary) as col:
        # business request: Caddy root, funa child and JDBC grandchildren arrive as separate exports
        col.send("traces", _root("a" * 32, "caddy", {"url.path": "/api/orders"}))
        col.send("traces", h.resource_spans("funa", [
            h.span("a" * 32, "2" * 16, "GET /api/orders", parent="1" * 16, attributes={"http.route": "/api/orders"}),
            h.span("a" * 32, "3" * 16, "SELECT", parent="2" * 16, attributes={"db.system": "postgresql"}),
            h.span("a" * 32, "4" * 16, "UPDATE", parent="2" * 16, attributes={"db.system": "postgresql"})]))
        # funa-rooted noise (management health check, scheduler job): no caddy span in the trace
        col.send("traces", h.resource_spans("funa", [
            h.span("b" * 32, "1" * 16, "GET health", attributes={"http.route": MGMT + "/health"}),
            h.span("b" * 32, "2" * 16, "SELECT", parent="1" * 16, attributes={"db.system": "postgresql"})]))
        # documentation request through caddy, with its funa child
        col.send("traces", _root("c" * 32, "caddy", {"url.path": "/docs/index.html"}))
        col.send("traces", h.resource_spans("funa", [
            h.span("c" * 32, "2" * 16, "GET /docs", parent="1" * 16, attributes={"url.path": "/docs/index.html"})]))
        col.wait_for("otlphttp/app_traces", "traces", 4, timeout=40)
        col.settle(4)
    spans = harness.read("otlphttp/app_traces", "traces")
    assert {s["traceId"] for s in spans} == {"a" * 32}, [(s["traceId"], s["name"]) for s in spans]
    assert sorted(s["name"] for s in spans) == ["GET /api/orders", "SELECT", "UPDATE", "root"]


def _names(harness):
    return sorted({m["name"] for m in harness.read("otlphttp/metrics", "metrics")})


def _routed(name, *routes):
    pts = [{"asInt": str(i), "timeUnixNano": "1", "attributes": h._kv({"http.route": r})} for i, r in enumerate(routes)]
    return {"name": name, "gauge": {"dataPoints": pts}}


@pytest.mark.parametrize("version", list(h.VERSIONS))
def test_caddy_keeps_http_metrics_only_and_funa_drops_management_and_docs_routes(tmp_path, version):
    binary = h.binary(version)
    harness = _harness(tmp_path, version)
    with harness.running(binary) as col:
        col.send("metrics", h.resource_metrics("caddy", [
            h.gauge("caddy_http_requests_total", 1), h.gauge("go_goroutines", 1), h.gauge("process_cpu_seconds_total", 1),
            h.gauge("caddy_admin_http_requests_total", 1), h.gauge("promhttp_metric_handler_requests_total", 1)]))
        col.send("metrics", h.resource_metrics("funa", [
            h.gauge("jvm.memory.used", 1), h.gauge("db.client.connections.usage", 1),
            h.gauge("http.client.request.duration", 1),
            _routed("http.server.active_requests", "/api/orders"),
            # one instrument: management (0), docs (1) and business (2, 3) datapoints
            _routed("http.server.request.duration", MGMT + "/health", "/docs/swagger", "/api/other", "/api/orders"),
            _routed("http.server.response.body.size", MGMT + "/info")]))
        col.wait_for("otlphttp/metrics", "metrics", 6, timeout=40)
        col.settle(3)
    assert _names(harness) == sorted([
        "caddy_http_requests_total", "jvm.memory.used", "db.client.connections.usage", "http.client.request.duration",
        "http.server.request.duration", "http.server.active_requests"])
    kept = [dp["asInt"] for m in harness.read("otlphttp/metrics", "metrics") if m["name"] == "http.server.request.duration"
            for dp in m["gauge"]["dataPoints"]]
    assert sorted(kept) == ["2", "3"]


@pytest.mark.parametrize("version", list(h.VERSIONS))
def test_empty_management_path_renders_no_management_rule_but_still_drops_docs(tmp_path, version):
    binary = h.binary(version)
    cfg = app._render(tmp_path, version, **FAST)          # repo default: empty
    assert "mgmt" not in str(cfg["processors"]).lower() and "actuator" not in str(cfg["processors"])
    harness = h.OtlpHarness(tmp_path, cfg)
    with harness.running(binary) as col:
        col.send("metrics", h.resource_metrics("funa", [
            _routed("http.server.request.duration", "/docs/x"),
            _routed("http.server.active_requests", "/actuator/health")]))
        col.wait_for("otlphttp/metrics", "metrics", 1, timeout=40)
        col.settle(3)
    assert _names(harness) == ["http.server.active_requests"]
