#!/usr/bin/env python3
"""Trivy 판정(AUD-321) 동시 실행 수별 시간·프로세스 트리 최대 메모리 측정 (#158, Spec #148).

실제 trivy 바이너리와 취약점 DB가 있는 곳에서 수동으로 돌린다(기본 pytest 대상 아님).
입력 SBOM 하나를 --hosts 개로 복제해 러너와 같은 명령줄(`trivy sbom --offline-scan --skip-db-update`)을
동시 실행 수 N으로 돌리고, 전체 시간과 프로세스 트리 전체(자식 포함) RSS 합계의 최대값을 잰다.
러너 컨테이너의 OOM은 cgroup 단위이므로 개별 프로세스가 아니라 동시에 떠 있는 trivy 전체의 합이 기준이다.

사용:
  python3 scripts/measure_trivy_concurrency.py --trivy ~/.cache/host-audit/trivy/0.75.0/64bit/trivy \\
      --cache-dir ~/.cache/host-audit/trivy-cache --sbom run/sbom/ns0001.cdx.json --hosts 24 --levels 1 2 3
(DB가 없으면 먼저 `trivy --cache-dir <dir> image --download-db-only`.)
결과 표(Markdown)를 stdout에 낸다. 이슈 코멘트에 측정 조건(호스트 수, SBOM 크기, CPU/메모리 상한)과 함께 붙인다.
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import psutil
except ImportError:  # 개발·측정용 의존성: 러너 이미지에는 필요 없다
    sys.exit("psutil이 필요합니다(프로세스 트리 RSS 측정): pip install psutil")

MB = 1024 * 1024


def _tree_rss(root):
    total = 0
    try:
        for p in [root] + root.children(recursive=True):
            try:
                total += p.memory_info().rss
            except psutil.Error:
                pass
    except psutil.Error:
        pass
    return total


class Sampler:
    """측정 대상 프로세스들의 RSS 합계 최대값을 0.05초 간격으로 기록한다."""

    def __init__(self):
        self.procs = []
        self.lock = threading.Lock()
        self.peak = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def add(self, pid):
        with self.lock:
            self.procs.append(psutil.Process(pid))

    def _run(self):
        while not self.stop.is_set():
            with self.lock:
                procs = list(self.procs)
            self.peak = max(self.peak, sum(_tree_rss(p) for p in procs if p.is_running()))
            time.sleep(0.05)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()


def _run_one(argv, sampler):
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    sampler.add(proc.pid)
    _, err = proc.communicate()
    return proc.returncode, err.decode(errors="replace")[-300:]


def measure(trivy, cache_dir, sbom, hosts, level):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        jobs = []
        for i in range(hosts):
            copy = tmp / f"h{i:03d}.cdx.json"
            shutil.copyfile(sbom, copy)
            jobs.append([trivy, "--cache-dir", str(cache_dir), "sbom", "--quiet", "--skip-db-update", "--offline-scan",
                         "--skip-version-check", "--scanners", "vuln", "--format", "json",
                         "--output", str(tmp / f"h{i:03d}.json"), str(copy)])
        started = time.monotonic()
        with Sampler() as sampler, ThreadPoolExecutor(max_workers=level) as pool:
            results = list(pool.map(lambda a: _run_one(a, sampler), jobs))
        elapsed = time.monotonic() - started
    failed = [r for r in results if r[0] != 0]
    return elapsed, sampler.peak / MB, failed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--sbom", required=True, help="실제 규모에 가까운 CycloneDX SBOM 하나")
    ap.add_argument("--hosts", type=int, default=24)
    ap.add_argument("--levels", type=int, nargs="+", default=[1, 2, 3])
    args = ap.parse_args()

    sbom = Path(args.sbom)
    print(f"SBOM {sbom.name} {sbom.stat().st_size / 1024:.0f} KiB x {args.hosts} 호스트, "
          f"CPU {psutil.cpu_count()}코어, 메모리 {psutil.virtual_memory().total / 1024 / MB:.1f} GiB\n")
    print("| 동시 실행 수 | 전체 시간(초) | 트리 최대 RSS 합계(MiB) | 실패 수 |")
    print("|---|---|---|---|")
    for level in args.levels:
        elapsed, peak, failed = measure(args.trivy, args.cache_dir, sbom, args.hosts, level)
        print(f"| {level} | {elapsed:.1f} | {peak:.0f} | {len(failed)} |")
        for rc, err in failed[:2]:
            print(f"rc={rc}: {err}", file=sys.stderr)


if __name__ == "__main__":
    main()
