"""conntrack 메트릭 자동 감지 (Spec #253 / Ticket-2, #255).

Probe가 커널 conntrack 파일을 읽어 ``host_agents_conntrack`` fact를 만들고(modern·raw 경로 공통 프로브),
그 fact가 참인 호스트의 설정에서만 ``system.network.conntrack.count/.max``가 켜진다. 스위치는 없다.
실제 바이너리 테스트는 ``OTELCOL_BIN_0_119_0`` / ``OTELCOL_BIN_0_161_0``가 없으면 건너뛴다.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "filter_plugins"))
import test_envelope_parsing as env  # noqa: E402
import test_host_agents as base  # noqa: E402
from host_agents import host_agents_os_probe_cmd, host_agents_parse_os_probe  # noqa: E402

CONNTRACK_MARKER = "__HOST_AGENTS_CONNTRACK__"
COUNT, MAX = "system.network.conntrack.count", "system.network.conntrack.max"
CT_DIR = Path("/proc/sys/net/netfilter")
HOST_HAS_CONNTRACK = (CT_DIR / "nf_conntrack_count").is_file() and (CT_DIR / "nf_conntrack_max").is_file()


def _probe(conntrack_section, redhat="CentOS release 6.10 (Final)"):
    out = base._probe(redhat=redhat) if redhat else base._probe(os_release=base.ROCKY9)
    return out + (f"{CONNTRACK_MARKER}\n{conntrack_section}\n" if conntrack_section is not None else "")


@pytest.mark.parametrize("redhat", ["CentOS release 6.10 (Final)", "", "CentOS Linux release 7.9.2009 (Core)"])
def test_probe_fact_means_the_same_on_every_os_path(redhat):
    assert host_agents_parse_os_probe(_probe("present", redhat))["conntrack"] is True
    assert host_agents_parse_os_probe(_probe("absent", redhat))["conntrack"] is False


@pytest.mark.parametrize("section", [None, "", "garbage", "PRESENT?"])
def test_probe_without_a_clear_present_answer_means_no_conntrack(section):
    assert host_agents_parse_os_probe(_probe(section))["conntrack"] is False


def test_probe_command_agrees_with_the_kernel_files_of_this_host():
    out = subprocess.run(["sh", "-c", host_agents_os_probe_cmd()], capture_output=True, text=True).stdout
    assert host_agents_parse_os_probe(out)["conntrack"] is HOST_HAS_CONNTRACK


def test_probe_command_only_reads():
    cmd = host_agents_os_probe_cmd()
    assert "nf_conntrack_count" in cmd and "nf_conntrack_max" in cmd
    assert not any(w in cmd for w in ("modprobe", "sysctl", "> ", "tee", "rm "))


def _enabled(cfg):
    metrics = (cfg["receivers"]["hostmetrics"]["scrapers"]["network"] or {}).get("metrics", {})
    return {k for k, v in metrics.items() if v.get("enabled")}


def _render(tmp_path, name, **over):
    d = tmp_path / name
    d.mkdir()
    return base._render_config(d, **over)[0]


@pytest.mark.parametrize("os_path", ["modern", "legacy_el7", "legacy_el6"])
def test_conntrack_metrics_render_only_when_the_fact_is_true(tmp_path, os_path):
    on = _render(tmp_path, "on", host_agents_os_path=os_path, host_agents_conntrack=True)
    assert {COUNT, MAX} <= _enabled(on)
    for name, over in (("false", {"host_agents_conntrack": False}), ("unset", {})):
        off = _render(tmp_path, name, host_agents_os_path=os_path, **over)
        assert not _enabled(off) & {COUNT, MAX}
        assert "network" in off["receivers"]["hostmetrics"]["scrapers"]      # other network metrics stay


def test_conntrack_keeps_the_other_scrapers(tmp_path):
    off = _render(tmp_path, "off")
    on = _render(tmp_path, "on", host_agents_conntrack=True)
    assert set(on["receivers"]["hostmetrics"]["scrapers"]) == set(off["receivers"]["hostmetrics"]["scrapers"])


# ---- real collector -------------------------------------------------------------------------------

def _scrape(tmp_path, binary, os_path, conntrack):
    cfg = _render(tmp_path, "r", host_agents_os_path=os_path, host_agents_conntrack=conntrack)
    hm = cfg["receivers"]["hostmetrics"]
    hm = dict(hm, collection_interval="1s", scrapers={"network": hm["scrapers"]["network"]})
    out = tmp_path / "m.json"
    harness = {"receivers": {"hostmetrics": hm}, "exporters": {"file": {"path": str(out)}},
               "service": {"pipelines": {"metrics": {"receivers": ["hostmetrics"], "exporters": ["file"]}}}}
    cfg_path = tmp_path / "h.yaml"
    cfg_path.write_text(yaml.safe_dump(harness))
    log = tmp_path / "err.log"
    with open(log, "w") as lf:
        proc = subprocess.Popen([binary, f"--config={cfg_path}"], stdout=lf, stderr=subprocess.STDOUT)
        try:
            time.sleep(6)
        finally:
            proc.terminate()
            proc.wait(timeout=20)
    names = set()
    if out.exists():
        for line in out.read_text().splitlines():
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            for rm in doc["resourceMetrics"]:
                for sm in rm["scopeMetrics"]:
                    names |= {m["name"] for m in sm["metrics"]}
    return names, log.read_text()


@pytest.mark.parametrize("version", list(env.VERSIONS))
def test_real_collector_accepts_the_conntrack_config(tmp_path, version):
    binary = env._binary(version)
    env._render(tmp_path, env.VERSIONS[version][1], host_agents_conntrack=True)
    (tmp_path / "var" / "otelcol").mkdir(parents=True)
    rendered = tmp_path / "config.yaml"
    doc = yaml.safe_load(rendered.read_text().replace(env.base_storage_dir(), str(tmp_path / "var" / "otelcol")))
    doc["processors"]["memory_limiter"] = {"check_interval": "1s", "limit_mib": 400, "spike_limit_mib": 100}
    rendered.write_text(yaml.safe_dump(doc))
    assert COUNT in json.dumps(doc["receivers"]["hostmetrics"])
    res = subprocess.run([binary, "validate", f"--config={rendered}"], capture_output=True, text=True,
                         env=dict(os.environ, O2_BASIC_AUTH="dGVzdA=="))
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.skipif(not HOST_HAS_CONNTRACK, reason="this machine has no nf_conntrack files")
@pytest.mark.parametrize("version", list(env.VERSIONS))
def test_real_collector_scrapes_conntrack_only_when_enabled(tmp_path, version):
    binary = env._binary(version)
    path = env.VERSIONS[version][1]
    (tmp_path / "on").mkdir()
    names, log = _scrape(tmp_path / "on", binary, path, True)
    assert {COUNT, MAX} <= names, (names, log)
    (tmp_path / "off").mkdir()
    names, log = _scrape(tmp_path / "off", binary, path, False)
    assert not names & {COUNT, MAX} and "system.network.io" in names
