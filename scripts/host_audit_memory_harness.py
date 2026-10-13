#!/usr/bin/env python3
"""Host Audit 러너 메모리·시간 측정 harness (#153, Spec #148).

합성 데이터(호스트 수 x 호스트당 CVE 수)로 실행 디렉터리와 이전 정기 실행의 findings를 만들고,
실제 태스크(AUD-322~324 분류·섹션, AUD-021 보고서 모델, AUD-510 findings 저장, Audit Baseline 비교)를
ansible-playbook으로 돌린다. 지표는 프로세스 트리 전체(자식 포함)의 최대 RSS 합계와 소요 시간이다.
러너 컨테이너의 OOM은 cgroup 단위라 ansible-playbook 본 프로세스만 재면 일을 서브프로세스로 옮긴 것이
개선처럼 보일 수 있다. 그래서 본 프로세스 최대값은 참고용으로만 함께 적는다.

사용:
  python3 scripts/host_audit_memory_harness.py --hosts 24 --cves 23000
  python3 scripts/host_audit_memory_harness.py --hosts 3 --cves 20 --workdir /tmp/ha-run
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "host_audit"
SECTION = "package_vulnerability"
STARTED_AT = "2026-10-12T22:00:00Z"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
MB = 1024 * 1024


def _rss(proc):
    try:
        return proc.memory_info().rss
    except psutil.Error:
        return 0


def measure(argv, interval=0.1, cwd=None, env=None):
    """argv를 실행하며 프로세스 트리 전체 RSS 합계의 최대값(MB), 본 프로세스 최대값, 소요 시간을 잰다.

    RSS 합계는 부모와 자식이 공유하는 페이지를 중복 집계하므로 약간 크게 나온다(보수적).
    """
    start = time.monotonic()
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    chunks = []
    reader = threading.Thread(target=lambda: chunks.append(proc.stdout.read()), daemon=True)
    reader.start()
    root = psutil.Process(proc.pid)
    tree_peak = main_peak = 0
    while proc.poll() is None:
        try:
            procs = [root] + root.children(recursive=True)
        except psutil.Error:
            procs = [root]
        main_peak = max(main_peak, _rss(root))
        tree_peak = max(tree_peak, sum(_rss(p) for p in procs))
        time.sleep(interval)
    reader.join()
    return {"returncode": proc.returncode, "elapsed_s": round(time.monotonic() - start, 1),
            "tree_peak_rss_mb": round(tree_peak / MB, 1), "main_peak_rss_mb": round(main_peak / MB, 1),
            "output": (chunks[0] if chunks else b"").decode("utf-8", "replace")}


def _name(i):
    return "h%03d" % (i + 1)


def _vulns(host_index, cves):
    return [{"VulnerabilityID": "CVE-2024-%d" % (host_index * 100000 + n), "PkgName": "pkg%d" % (n % 400),
             "InstalledVersion": "1.0-%d" % n, "FixedVersion": "1.0-%d" % (n + 1), "Status": "fixed",
             "Severity": SEVERITIES[n % 4], "Title": "synthetic vulnerability %d" % n} for n in range(cves)]


def generate_run(out, hosts, cves):
    """실행 디렉터리(hosts/ packages/ trivy/)와 이전 정기 실행의 previous_findings.json을 만든다."""
    out = Path(out)
    for sub in ("hosts", "packages", "trivy", "sbom"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    os_info = {"family": "ubuntu", "major": "22", "version": "22.04", "name": "Ubuntu 22.04"}
    prior_ids = {}
    for i in range(hosts):
        h = _name(i)
        (out / "hosts" / (h + ".json")).write_text(json.dumps({
            "schema_version": 2, "inventory_hostname": h, "collected_at": STARTED_AT, "status": "ok", "reason": "",
            "declared": {"fqdn": h + ".example", "ip": "10.0.%d.%d" % (i // 250, i % 250 + 1),
                         "environment": "prod", "groups": ["servers"]},
            "identity": {"hostname": h, "fqdn": h + ".example", "ips": ["10.0.0.1"], "account": "root"},
            "os": os_info}))
        (out / "packages" / (h + ".json")).write_text(json.dumps({
            "inventory_hostname": h, "status": "ok", "reason": "", "os": os_info,
            "packages": [{"name": "pkg%d" % n, "version": "1.0"} for n in range(400)]}))
        vulns = _vulns(i, cves)
        (out / "trivy" / (h + ".json")).write_text(json.dumps({
            "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
            "Results": [{"Vulnerabilities": vulns}]}))
        # 이전 실행: 현재 발견의 80%는 그대로(지속), 나머지 20%만큼은 이번에 사라진 다른 CVE(해소)
        prior_ids[h] = sorted(set("%s|%s" % (v["VulnerabilityID"], v["PkgName"]) for v in vulns[: cves * 4 // 5]) |
                              set("CVE-2023-%d|pkg0" % n for n in range(cves // 5)))
    (out / "previous_findings.json").write_text(json.dumps({
        "run_id": "previous", "sections": {SECTION: {"hosts": sorted(prior_ids), "ids": prior_ids}}}))
    return out


def _pick(filename, *ids):
    tasks = yaml.safe_load((ROLE / "tasks" / filename).read_text(encoding="utf-8"))
    return [next(t for t in tasks if "[%s]" % i in t.get("name", "")) for i in ids]


def build_playbook(out, hosts):
    out = Path(out)
    previous = json.loads((out / "previous_findings.json").read_text())
    names = [_name(i) for i in range(hosts)]
    play = {
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(ROLE / "defaults" / "main.yml"), str(ROLE / "vars" / "main.yml")],
        "vars": {
            "host_audit_run": {"run_id": "harness", "run_kind": "scheduled", "started_at": STARTED_AT,
                               "timezone": "Asia/Seoul", "target_hosts": names, "output_dir": str(out)},
            "host_audit_trivy_db": {"usable": True}, "host_audit_trivy_version": "0.0.0",
            "_host_audit_storage_active": False,
            "host_audit_baseline_history": {"state": "ok", "reason": "", "baseline": previous, "pointers": []},
        },
        "tasks": (_pick("report.yml", "AUD-020") + _pick("packages_scan.yml", "AUD-310", "AUD-322", "AUD-323", "AUD-324")
                  + _pick("report.yml", "AUD-021") + _pick("storage_upload.yml", "AUD-510")),
    }
    return [play]


def _ansible_version():
    try:
        return subprocess.run(["ansible", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    except (OSError, IndexError):
        return "unknown"


def run(workdir, hosts, cves, interval=0.1):
    """합성 데이터를 만들고 실제 태스크를 돌려 측정 결과 dict를 돌려준다."""
    workdir = Path(workdir)
    generate_run(workdir, hosts, cves)
    pb = workdir / "harness_playbook.yml"
    pb.write_text(yaml.safe_dump(build_playbook(workdir, hosts), allow_unicode=True))
    env = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.builtin.default", ANSIBLE_FORKS="1")
    m = measure(["ansible-playbook", "-i", "localhost,", str(pb)], interval=interval, cwd=str(ROOT_DIR), env=env)
    return {"hosts": hosts, "cves_per_host": cves, "total_cves": hosts * cves,
            "returncode": m["returncode"], "elapsed_s": m["elapsed_s"],
            "tree_peak_rss_mb": m["tree_peak_rss_mb"], "main_peak_rss_mb": m["main_peak_rss_mb"],
            "output_tail": m["output"][-2000:], "workdir": str(workdir),
            "conditions": {"python": sys.version.split()[0], "cpus": os.cpu_count(), "ansible": _ansible_version(),
                           "meter": "psutil RSS sum of process tree, %.2fs sampling" % interval}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hosts", type=int, default=24)
    ap.add_argument("--cves", type=int, default=23000, help="호스트당 CVE 수")
    ap.add_argument("--workdir", help="실행 디렉터리(기본: 임시 디렉터리, 끝나면 삭제)")
    ap.add_argument("--interval", type=float, default=0.1)
    args = ap.parse_args(argv)
    tmp = None if args.workdir else tempfile.mkdtemp(prefix="host-audit-harness-")
    try:
        result = run(args.workdir or tmp, args.hosts, args.cves, args.interval)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result["returncode"]


if __name__ == "__main__":
    sys.exit(main())
