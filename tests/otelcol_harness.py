"""Real-binary harness for OTLP-in tests (Spec #253 / Ticket-4; reused by the noise-rule tests).

Take a *rendered* ``otelcol-contrib.yaml`` (dict), run it through a real otelcol-contrib binary with

* the OTLP HTTP receiver moved to a free loopback port,
* every external exporter (``otlphttp/*``) swapped for a ``file`` exporter, and
* only the pipelines the OTLP receiver feeds kept (plus the connectors/pipelines downstream of them),

then send synthetic OTLP/HTTP JSON and read back what each (former) exporter would have shipped::

    harness = OtlpHarness(tmp_path, cfg)                  # cfg: rendered config dict
    with harness.running(binary) as col:
        col.send("traces", resource_spans("funa", [span(...)]))
        col.send("metrics", resource_metrics("caddy", [gauge("caddy_http_requests_total", 1)]))
        col.wait_for("otlphttp/app_traces", "traces", 1)  # exporter name as in the rendered config
    spans = harness.read("otlphttp/app_traces", "traces")

``binary(version)`` resolves ``OTELCOL_BIN_0_119_0`` / ``OTELCOL_BIN_0_161_0`` and skips when unset.
``harness.read(...)`` flattens a signal into dicts with ``_res`` (resource attributes) and ``_attrs`` (item attributes).
"""

import contextlib
import copy
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

VERSIONS = {"0.119.0": ("OTELCOL_BIN_0_119_0", "legacy_el6"), "0.161.0": ("OTELCOL_BIN_0_161_0", "modern")}
_ITEMS = {"traces": ("resourceSpans", "scopeSpans", "spans"),
          "metrics": ("resourceMetrics", "scopeMetrics", "metrics"),
          "logs": ("resourceLogs", "scopeLogs", "logRecords")}


def binary(version):
    env = VERSIONS[version][0]
    path = os.environ.get(env)
    if not path or not Path(path).exists():
        pytest.skip(f"set {env} to an otelcol-contrib {version} binary")
    out = subprocess.run([path, "--version"], capture_output=True, text=True).stdout
    assert version in out, out
    return path


def anyval(v):
    key, val = next(iter(v.items()))
    if key == "kvlistValue":
        return {e["key"]: anyval(e["value"]) for e in val["values"]}
    return val


def attrs(items):
    return {a["key"]: anyval(a["value"]) for a in items or []}


# ---- synthetic OTLP/JSON payload builders -------------------------------------------------------

def _kv(d):
    out = []
    for k, v in (d or {}).items():
        if isinstance(v, bool):
            out.append({"key": k, "value": {"boolValue": v}})
        elif isinstance(v, int):
            out.append({"key": k, "value": {"intValue": str(v)}})
        else:
            out.append({"key": k, "value": {"stringValue": str(v)}})
    return out


def resource(service, extra=None):
    return {"attributes": _kv(dict({"service.name": service}, **(extra or {})))}


def span(trace_id, span_id, name="span", parent=None, attributes=None):
    now = time.time_ns()                     # recent: some backends silently drop old spans
    s = {"traceId": trace_id, "spanId": span_id, "name": name, "kind": 2,
         "startTimeUnixNano": str(now - 1_000_000), "endTimeUnixNano": str(now), "attributes": _kv(attributes)}
    if parent:
        s["parentSpanId"] = parent
    return s


def resource_spans(service, spans, resource_attrs=None):
    return {"resourceSpans": [{"resource": resource(service, resource_attrs),
                               "scopeSpans": [{"scope": {"name": "synthetic"}, "spans": spans}]}]}


def gauge(name, value, attributes=None):
    return {"name": name, "gauge": {"dataPoints": [{"asInt": str(value), "timeUnixNano": str(time.time_ns()),
                                                    "attributes": _kv(attributes)}]}}


def resource_metrics(service, metrics, resource_attrs=None):
    return {"resourceMetrics": [{"resource": resource(service, resource_attrs),
                                 "scopeMetrics": [{"scope": {"name": "synthetic"}, "metrics": metrics}]}]}


def log_record(body, attributes=None):
    return {"timeUnixNano": str(time.time_ns()), "body": {"stringValue": body}, "attributes": _kv(attributes)}


def resource_logs(service, records, resource_attrs=None):
    return {"resourceLogs": [{"resource": resource(service, resource_attrs),
                              "scopeLogs": [{"scope": {"name": "synthetic"}, "logRecords": records}]}]}


# ---- config rewriting -----------------------------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _names(components):
    return list(components or [])


def rewrite_for_harness(cfg, out_dir, port, receiver="otlp"):
    """Return (harness_cfg, {exporter name: file path}); see the module docstring."""
    cfg = copy.deepcopy(cfg)
    pipes = cfg["service"]["pipelines"]
    keep, frontier = set(), [n for n, p in pipes.items() if receiver in _names(p.get("receivers"))]
    while frontier:                                        # pipelines fed by OTLP, then by connectors they feed
        name = frontier.pop()
        if name in keep:
            continue
        keep.add(name)
        for exp in _names(pipes[name].get("exporters")):
            if exp in cfg.get("connectors", {}):
                frontier += [n for n, p in pipes.items() if exp in _names(p.get("receivers"))]
    out, files, file_exporters = {}, {}, {}
    for name in keep:
        p = copy.deepcopy(pipes[name])
        p["receivers"] = [r for r in p["receivers"] if r == receiver or r in cfg.get("connectors", {})]
        exporters = []
        for exp in p.get("exporters", []):
            if exp in cfg.get("connectors", {}):
                exporters.append(exp)
                continue
            # a file exporter per (exporter, signal): one exporter id may serve several signal pipelines
            file_id = "file/" + exp.replace("/", "_")
            files[exp] = Path(out_dir) / (exp.replace("/", "_") + ".json")
            file_exporters[file_id] = {"path": str(files[exp])}
            exporters.append(file_id)
        p["exporters"] = exporters
        out[name] = p
    harness = {
        "receivers": {receiver: copy.deepcopy(cfg["receivers"][receiver])},
        "processors": cfg.get("processors", {}),
        "exporters": file_exporters,
        "service": {"pipelines": out, "telemetry": {"metrics": {"level": "none"}}},
    }
    if "connectors" in cfg:
        harness["connectors"] = cfg["connectors"]
    http = harness["receivers"][receiver]["protocols"]["http"]
    http["endpoint"] = f"127.0.0.1:{port}"
    # memory_limiter percentages need cgroup/mount info that some dev hosts (WSL) cannot provide
    if "memory_limiter" in harness["processors"]:
        harness["processors"]["memory_limiter"] = {"check_interval": "1s", "limit_mib": 400, "spike_limit_mib": 100}
    used = {p for pl in out.values() for p in pl.get("processors", [])}
    harness["processors"] = {k: v for k, v in harness["processors"].items() if k in used}
    return harness, files


class Collector:
    def __init__(self, harness, proc, port):
        self._h, self._proc, self.port = harness, proc, port

    def send(self, signal, payload):
        """POST OTLP/HTTP JSON; return the HTTP status (404 when no pipeline of that signal exists)."""
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/{signal}", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as err:
            return err.code

    def wait_for(self, exporter, signal, count, timeout=30, settle=1.5):
        """Block until `count` items reached the exporter, then `settle` more to catch surplus items."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.5)
            if len(self._h.read(exporter, signal)) >= count:
                time.sleep(settle)
                return
        raise AssertionError(f"{exporter}/{signal}: fewer than {count} items within {timeout}s")

    def settle(self, seconds=3.0):
        """Wait for the batch timeout so that a negative assertion ('nothing was exported') is meaningful."""
        time.sleep(seconds)


class OtlpHarness:
    def __init__(self, tmp_path, cfg, receiver="otlp"):
        self.port = _free_port()
        self.out_dir = Path(tmp_path) / "harness-out"
        self.out_dir.mkdir()
        self.config, self.files = rewrite_for_harness(cfg, self.out_dir, self.port, receiver)
        self.path = Path(tmp_path) / "harness.yaml"
        self.path.write_text(yaml.safe_dump(self.config))

    @contextlib.contextmanager
    def running(self, bin_path):
        proc = subprocess.Popen([bin_path, f"--config={self.path}"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                if proc.poll() is not None:
                    raise AssertionError("collector exited: " + proc.stderr.read())
                with socket.socket() as s:
                    if s.connect_ex(("127.0.0.1", self.port)) == 0:
                        break
                time.sleep(0.2)
            else:
                raise AssertionError("collector did not open the OTLP port")
            yield Collector(self, proc, self.port)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
            if proc.stderr:
                proc.stderr.close()

    def read(self, exporter, signal):
        path = self.files[exporter]
        if not path.exists():
            return []
        r_key, s_key, i_key = _ITEMS[signal]
        items = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except ValueError:                               # the exporter is mid-write
                continue
            for rs in doc.get(r_key, []):
                res = attrs(rs.get("resource", {}).get("attributes"))
                for ss in rs.get(s_key, []):
                    for it in ss.get(i_key, []):
                        it["_res"] = res
                        it["_attrs"] = attrs(it.get("attributes"))
                        items.append(it)
        return items
