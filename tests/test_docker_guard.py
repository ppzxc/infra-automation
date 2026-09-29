"""scripts/docker-guard.sh must kill a run whose Docker daemon froze, and must
not interfere with a healthy one.

A stub `docker` on PATH answers until a flag file appears, then hangs -- the
symptom seen with Docker Desktop under sustained `docker exec` load.
"""
import os
import stat
import subprocess
import time
import uuid
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent / "scripts" / "docker-guard.sh"

STUB = """#!/bin/sh
[ -e "$FREEZE" ] && exec sleep 30
exit 0
"""


def _env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(STUB)
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{env['PATH']}",
        FREEZE=str(tmp_path / "freeze"),
        GUARD_INTERVAL="0.1",
        GUARD_FAILS="2",
        GUARD_PROBE_TIMEOUT="0.4",
        GUARD_GRACE="0.3",
    )
    return env


def _count_processes(marker):
    out = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines() if marker in line and "ps -eo" not in line)


def test_exit_status_of_healthy_run_passes_through(tmp_path):
    res = subprocess.run(
        [str(GUARD), "sh", "-c", "sleep 0.2; exit 7"],
        env=_env(tmp_path), capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 7


def test_frozen_daemon_kills_the_run_and_its_children(tmp_path):
    env = _env(tmp_path)
    marker = f"sleep {uuid.uuid4().int % 90000 + 10000}.5"  # unique: matches only our children
    freezer = subprocess.Popen(["sh", "-c", f"sleep 0.3; touch {env['FREEZE']}"])
    start = time.monotonic()
    res = subprocess.run(
        [str(GUARD), "sh", "-c", f"{marker} & {marker} & wait"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    freezer.wait()
    assert res.returncode == 125
    assert "stopped responding" in res.stderr
    assert time.monotonic() - start < 15, "guard must not wait for the command's full runtime"
    time.sleep(0.3)
    assert _count_processes(marker) == 0, "children of the killed run were left running"
