"""Business Telemetry intake switch (ADR-0012, Spec #253 / Ticket-4) against a real otelcol-contrib binary.

The rendered config of a host with ``otel_app_telemetry: true`` receives synthetic OTLP/HTTP; the external
exporters are swapped for file exporters (``tests/otelcol_harness.py``) so the test sees what would be shipped.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otelcol_harness as h  # noqa: E402
import test_host_agents as base  # noqa: E402

INPUTS = {"otel_docker_metrics": False, "otel_app_telemetry": True,
          "otel_logs": [{"path": "/var/log/secure", "stream": "security_logs", "service": "auth"}]}
TRACE_A = "a" * 32


def _render(tmp_path, version, **over):
    over.setdefault("host_agents_os_path", h.VERSIONS[version][1])
    over.setdefault("host_agents_inputs", INPUTS)
    over.setdefault("otel_trace_decision_wait", "2s")      # tail_sampling holds spans for this long
    cfg, _ = base._render_config(tmp_path, **over)
    return cfg


@pytest.mark.parametrize("version", list(h.VERSIONS))
def test_otlp_spans_and_metrics_reach_their_exporters_and_logs_reach_none(tmp_path, version):
    binary = h.binary(version)
    cfg = _render(tmp_path, version)
    host = {a["key"]: a["value"] for a in cfg["processors"]["resource/host"]["attributes"]}
    harness = h.OtlpHarness(tmp_path, cfg)
    assert set(harness.files) == {"otlphttp/app_traces", "otlphttp/metrics"}
    with harness.running(binary) as col:
        # (only Caddy-rooted traces pass the noise rules) the SDK claims another host: the collector's Resource Attribute wins, service.name stays the app's
        spoof = {"host.name": "spoofed", "deployment.environment.name": "spoofed"}
        assert col.send("traces", h.resource_spans("caddy", [h.span(TRACE_A, "1" * 16, "GET /x"),
                                                     h.span(TRACE_A, "2" * 16, "SELECT", parent="1" * 16)], spoof)) == 200
        assert col.send("metrics", h.resource_metrics("caddy", [h.gauge("caddy_http_requests_total", 7)], spoof)) == 200
        col.send("logs", h.resource_logs("funa", [h.log_record("otlp-log")]))     # rejected or dropped, never exported
        col.wait_for("otlphttp/app_traces", "traces", 2)
        col.wait_for("otlphttp/metrics", "metrics", 1)
        col.settle()
    spans = harness.read("otlphttp/app_traces", "traces")
    assert sorted(s["name"] for s in spans) == ["GET /x", "SELECT"]
    metrics = harness.read("otlphttp/metrics", "metrics")
    assert [m["name"] for m in metrics] == ["caddy_http_requests_total"]
    for item, service in [(spans[0], "caddy"), (metrics[0], "caddy")]:
        assert item["_res"]["service.name"] == service
        assert item["_res"]["host.name"] == host["host.name"] != "spoofed"
        assert item["_res"]["deployment.environment.name"] == host["deployment.environment.name"]
    # the OTLP log went nowhere
    for exporter in harness.files:
        assert harness.read(exporter, "logs") == []


@pytest.mark.parametrize("version", list(h.VERSIONS))
def test_rendered_switch_on_config_passes_collector_validation(tmp_path, version):
    import subprocess
    binary = h.binary(version)
    cfg = _render(tmp_path, version)
    doc = dict(cfg)
    doc["processors"] = dict(doc["processors"], memory_limiter={"check_interval": "1s", "limit_mib": 400, "spike_limit_mib": 100})
    import yaml
    text = yaml.safe_dump(doc).replace(base_storage_dir(), str(tmp_path))
    path = tmp_path / "validate.yaml"
    path.write_text(text)
    res = subprocess.run([binary, "validate", f"--config={path}"], capture_output=True, text=True,
                         env={"O2_BASIC_AUTH": "dGVzdA==", "PATH": "/usr/bin:/bin"})
    assert res.returncode == 0, res.stdout + res.stderr


def base_storage_dir():
    import yaml
    return yaml.safe_load((base.ROLE / "defaults" / "main.yml").read_text())["otelcol_storage_dir"]
