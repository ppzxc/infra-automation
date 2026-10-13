"""Host Audit 러너 메모리 harness (#153, Spec #148).

작은 규모로 harness가 끝까지 도는지만 기본 실행에서 확인한다. 24대 × 실운영 규모 측정은 무거워서
`pytest -m heavy_harness -s` 또는 scripts/host_audit_memory_harness.py로 수동 실행한다.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("psutil", reason="harness meter needs psutil (pip install psutil)")

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import host_audit_memory_harness as harness  # noqa: E402


def test_process_tree_peak_includes_children_not_just_the_parent():
    """The parent only waits; the memory is allocated by a child. A parent-only meter would miss it."""
    child = "x = bytearray(150 * 1024 * 1024); x[::4096] = b'1' * len(x[::4096]); import time; time.sleep(1.0)"
    parent = "import subprocess, sys; subprocess.run([sys.executable, '-c', %r])" % child
    m = harness.measure([sys.executable, "-c", parent], interval=0.05)
    assert m["returncode"] == 0
    assert m["tree_peak_rss_mb"] >= 150
    assert m["main_peak_rss_mb"] < m["tree_peak_rss_mb"]
    assert m["elapsed_s"] >= 1.0


def test_generate_makes_run_directory_and_previous_findings(tmp_path):
    harness.generate_run(tmp_path, hosts=3, cves=5)
    assert sorted(p.name for p in (tmp_path / "hosts").glob("*.json")) == ["h001.json", "h002.json", "h003.json"]
    assert len(list((tmp_path / "packages").glob("*.json"))) == 3
    trivy = json.loads((tmp_path / "trivy" / "h002.json").read_text())
    assert len(trivy["Results"][0]["Vulnerabilities"]) == 5
    prior = json.loads((tmp_path / "package_findings" / "previous_findings.json").read_text())
    assert len(prior["sections"]["package_vulnerability"]["hosts"]) == 3


def test_small_run_goes_through_the_real_tasks_end_to_end(tmp_path):
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    result = harness.run(tmp_path, hosts=3, cves=20)
    assert result["returncode"] == 0, result["output_tail"]
    assert result["hosts"] == 3 and result["cves_per_host"] == 20
    assert result["tree_peak_rss_mb"] >= result["main_peak_rss_mb"] > 0
    assert result["elapsed_s"] > 0
    findings = json.loads((tmp_path / "findings.json").read_text())
    assert len(findings["sections"]["package_vulnerability"]["hosts"]) == 3
    assert (tmp_path / "package_vulnerability.json").exists()


@pytest.mark.heavy_harness
def test_production_scale_baseline(tmp_path):
    """24 hosts x ~23k CVE (~550k total). Run by hand: pytest -m heavy_harness -s"""
    result = harness.run(tmp_path, hosts=24, cves=23000)
    print(json.dumps(result, indent=2))
    assert result["returncode"] == 0
