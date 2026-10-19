"""Host metrics expansion (Spec #253 / Ticket-1, #254).

The rendered ``hostmetrics`` receiver is run through a real otelcol-contrib binary (0.119.0 = legacy_el6,
0.161.0 = current) and the metric names the ``file`` exporter writes are asserted. Set
``OTELCOL_BIN_0_119_0`` / ``OTELCOL_BIN_0_161_0``; each version's test skips without it.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_envelope_parsing as env  # noqa: E402
import test_host_agents as base  # noqa: E402

# names the collector already emitted before #254: they must keep their name
EXISTING = {
    "system.cpu.time", "system.memory.usage", "system.disk.io", "system.filesystem.usage",
    "system.cpu.load_average.1m", "system.network.io", "system.paging.usage", "system.processes.count",
}
ADDED = {
    "system.uptime", "system.linux.memory.available", "system.memory.limit", "system.cpu.utilization",
    "system.memory.utilization", "system.filesystem.utilization", "system.paging.utilization",
}
EL6_ONLY = {"system.cpu.logical.count"}


def _scrape(binary, tmp_path, os_path):
    cfg, _ = base._render_config(tmp_path, host_agents_os_path=os_path)
    rcv = dict(cfg["receivers"]["hostmetrics"], collection_interval="1s")
    out = tmp_path / "metrics.json"
    harness = {"receivers": {"hostmetrics": rcv}, "exporters": {"file": {"path": str(out)}},
               "service": {"pipelines": {"metrics": {"receivers": ["hostmetrics"], "exporters": ["file"]}}}}
    path = tmp_path / "harness.yaml"
    path.write_text(yaml.safe_dump(harness))
    proc = subprocess.Popen([binary, f"--config={path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(6)
    finally:
        proc.terminate()
        proc.wait(timeout=20)
    names = set()
    for line in (out.read_text().splitlines() if out.exists() else []):
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        for rm in doc["resourceMetrics"]:
            for sm in rm["scopeMetrics"]:
                names.update(m["name"] for m in sm["metrics"])
    return names


@pytest.mark.parametrize("version", list(env.VERSIONS))
def test_real_collector_emits_the_added_host_metrics_and_keeps_the_existing_ones(tmp_path, version):
    binary = env._binary(version)
    os_path = env.VERSIONS[version][1]
    names = _scrape(binary, tmp_path, os_path)
    assert ADDED <= names, ADDED - names
    assert EXISTING <= names, EXISTING - names
    if os_path == "legacy_el6":
        assert EL6_ONLY <= names


def test_logical_count_is_requested_only_on_the_el6_path(tmp_path):
    el6, _ = base._render_config(tmp_path, host_agents_os_path="legacy_el6")
    modern, _ = base._render_config(tmp_path, host_agents_os_path="modern")
    el6_cpu = el6["receivers"]["hostmetrics"]["scrapers"]["cpu"]
    assert el6_cpu["metrics"]["system.cpu.logical.count"] == {"enabled": True}
    # 0.161.0 already emits it by default, so the modern/EL7 config does not ask for it
    assert "system.cpu.logical.count" not in modern["receivers"]["hostmetrics"]["scrapers"]["cpu"].get("metrics", {})
    for cfg in (el6, modern):
        assert "system" in cfg["receivers"]["hostmetrics"]["scrapers"]
