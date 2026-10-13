"""Collector restart liveness (Spec #161 / Ticket-2, MON-119 init script, MON-216 handler).

1. The rendered CentOS 6 SysV init script is executed with real bash against fake collector
   binaries (exits at once / stays alive / ignores TERM): only exit codes, output and process
   liveness are observed.
2. The legacy ``Restart otelcol-contrib (raw)`` handler is run on localhost with fake
   ``service``/``systemctl`` commands: a dead collector after the restart fails the host,
   a live one does not, and without a change nothing restarts.
"""

import os
import pty
import shutil
import signal
import subprocess
import time
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "monitoring"


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class Init:
    """A rendered init script wired to a sandbox directory and a fake collector."""

    def __init__(self, tmp_path):
        self.bin = tmp_path / "otelcol-contrib"
        self.pidfile = tmp_path / "otelcol.pid"
        self.log = tmp_path / "otelcol.log"
        (tmp_path / "config.yaml").write_text("x: 1\n")
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters["bool"] = bool
        text = env.from_string((ROLE / "templates" / "otelcol-contrib.init.j2").read_text()).render(
            otelcol_run_as_root=True, host_agents_bin_dir=str(tmp_path),
            otelcol_config_path=str(tmp_path / "config.yaml"),
            otelcol_secrets_path=str(tmp_path / "no-secrets.env"),
            otelcol_sysv_log_path=str(self.log), otelcol_sysv_pid_path=str(self.pidfile),
            otelcol_sysv_start_grace=1, otelcol_sysv_stop_timeout=2)
        self.script = tmp_path / "init.sh"
        self.script.write_text(text)

    def binary(self, body):
        self.bin.write_text("#!/bin/bash\n" + body)
        self.bin.chmod(0o755)

    def run(self, action):
        return subprocess.run(["bash", str(self.script), action], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=60)

    def pid(self):
        return int(self.pidfile.read_text())


@pytest.fixture
def init(tmp_path):
    i = Init(tmp_path)
    yield i
    if i.pidfile.exists():
        try:
            os.kill(i.pid(), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass


def test_start_fails_with_log_tail_when_the_collector_dies_at_once(init):
    init.binary("echo 'fatal: cannot lock storage'; exit 1\n")
    r = init.run("start")
    assert r.returncode != 0
    assert "fatal: cannot lock storage" in r.stdout + r.stderr
    assert init.run("status").returncode != 0


def test_start_and_status_succeed_while_the_collector_stays_alive(init):
    init.binary("while :; do sleep 1; done\n")
    assert init.run("start").returncode == 0
    assert init.run("status").returncode == 0
    assert _pid_alive(init.pid())


def test_restart_waits_for_a_term_ignoring_collector_and_leaves_one_process(init):
    init.binary("trap '' TERM\nwhile :; do sleep 1; done\n")
    assert init.run("start").returncode == 0
    old = init.pid()
    r = init.run("restart")
    assert r.returncode == 0, r.stdout + r.stderr
    new = init.pid()
    assert new != old
    assert not _pid_alive(old) and _pid_alive(new)
    assert init.run("status").returncode == 0


def _restart_from_a_pty_session(init):
    """A session-leader shell on a pty runs `restart` and exits, like an SSH session ending."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "-c", f"bash {init.script} restart >/dev/null 2>&1; exit 0"])
    try:                                    # drain the pty until the session leader is gone
        while True:
            try:
                if not os.read(fd, 1024):
                    break
            except OSError:
                break
    finally:
        os.close(fd)
    os.waitpid(pid, 0)


def test_collector_survives_the_pty_session_that_restarted_it_ending(init):
    init.binary("while :; do sleep 1; done\n")
    assert init.run("start").returncode == 0
    for _ in range(3):
        _restart_from_a_pty_session(init)
        time.sleep(2)
        assert init.run("status").returncode == 0, "collector died with the pty session"
        assert _pid_alive(init.pid())


# --- handler -----------------------------------------------------------------------------------

def _fake_commands(tmp_path, mode, restart_rc=0, activating=False):
    """mode: up (restart brings it up), recover (only a later start does), dead (never comes up).

    restart_rc is the exit code of `restart` (EL6 init returns 1 when the collector dies within the
    start grace); activating makes the first is-active report `activating` (systemd auto-restart).
    """
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    calls = tmp_path / "calls.log"
    alive = tmp_path / "alive"
    seen = tmp_path / "activating-seen"
    on_restart = f"touch {alive}" if mode == "up" else "true"
    on_start = f"touch {alive}" if mode in ("up", "recover") else "true"
    gate = (f'if [ ! -e {seen} ]; then touch {seen}; echo activating; exit 3; fi; ' if activating else "")
    for cmd in ("service", "systemctl"):
        p = bindir / cmd
        p.write_text(f'#!/bin/bash\necho "{cmd} $*" >> {calls}\n'
                     f'case "$*" in *restart*) {on_restart}; exit {restart_rc};; *start*) {on_start}; exit 0;;\n'
                     f'*status*|*is-active*) {gate}[ -e {alive} ]; exit $?;; esac\nexit 0\n')
        p.chmod(0o755)
    (bindir / "journalctl").write_text("#!/bin/bash\necho JOURNAL-TAIL\n")
    (bindir / "journalctl").chmod(0o755)
    return bindir, calls


def _run_handler(tmp_path, os_path, mode, change=True, **fake):
    bindir, calls = _fake_commands(tmp_path, mode, **fake)
    log = tmp_path / "otelcol.log"
    log.write_text("old line\nCOLLECTOR-LOG-TAIL boom\n")
    roles = tmp_path / "roles"            # role copy: tasks_from must live inside the role
    shutil.copytree(ROLE, roles / "monitoring")
    tasks = roles / "monitoring" / "tasks" / "trigger.yml"
    tasks.write_text(yaml.safe_dump([{
        "name": "trigger", "ansible.builtin.command": "true",
        "changed_when": change, "notify": "Restart otelcol-contrib (raw)"}]))
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"host_agents_os_path": os_path, "otelcol_sysv_log_path": str(log),
                 "otelcol_alive_grace_seconds": 0},
        "tasks": [{"ansible.builtin.include_role": {"name": "monitoring", "tasks_from": "trigger"}}],
    }]))
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", ANSIBLE_ROLES_PATH=str(roles))
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, cwd=ROOT, env=env, timeout=180)
    return r, (calls.read_text() if calls.exists() else "")


@pytest.mark.parametrize("os_path,tail", [("legacy_el6", "COLLECTOR-LOG-TAIL"), ("legacy_el7", "JOURNAL-TAIL")])
def test_handler_retries_start_once_then_fails_the_host_with_log_tail_when_still_dead(tmp_path, os_path, tail):
    r, calls = _run_handler(tmp_path, os_path, mode="dead")
    assert r.returncode != 0, r.stdout
    assert calls.count("restart") == 1
    assert len([c for c in calls.splitlines() if c.endswith(" start otelcol-contrib") or c.endswith("otelcol-contrib start")]) == 1
    assert tail in r.stdout + r.stderr
    assert "failed=1" in r.stdout


@pytest.mark.parametrize("os_path", ["legacy_el6", "legacy_el7"])
def test_handler_is_ok_when_the_retry_start_recovers_the_collector(tmp_path, os_path):
    r, calls = _run_handler(tmp_path, os_path, mode="recover")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "restart" in calls and "start" in calls.replace("restart", "")


@pytest.mark.parametrize("os_path", ["legacy_el6", "legacy_el7"])
def test_handler_does_not_retry_when_the_collector_is_alive_after_restart(tmp_path, os_path):
    r, calls = _run_handler(tmp_path, os_path, mode="up")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "restart" in calls and ("status" in calls or "is-active" in calls)
    assert "start" not in calls.replace("restart", "")


@pytest.mark.parametrize("os_path", ["legacy_el6", "legacy_el7"])
def test_without_a_change_nothing_restarts_or_is_probed(tmp_path, os_path):
    r, calls = _run_handler(tmp_path, os_path, mode="dead", change=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls == ""
    assert "changed=0" in r.stdout


def _starts(calls):
    return [c for c in calls.splitlines() if c.split()[1:] in (["start", "otelcol-contrib"], ["otelcol-contrib", "start"])]


@pytest.mark.parametrize("os_path", ["legacy_el6", "legacy_el7"])
def test_failed_restart_does_not_skip_the_liveness_check_and_a_retry_start_recovers(tmp_path, os_path):
    # EL6 init `restart` returns 1 when the collector dies within the start grace.
    r, calls = _run_handler(tmp_path, os_path, mode="recover", restart_rc=1)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(_starts(calls)) == 1


@pytest.mark.parametrize("os_path,tail", [("legacy_el6", "COLLECTOR-LOG-TAIL"), ("legacy_el7", "JOURNAL-TAIL")])
def test_failed_restart_of_a_collector_that_stays_dead_fails_the_host_with_log_tail(tmp_path, os_path, tail):
    r, calls = _run_handler(tmp_path, os_path, mode="dead", restart_rc=1)
    assert r.returncode != 0, r.stdout
    assert len(_starts(calls)) == 1
    assert tail in r.stdout + r.stderr
    assert "failed=1" in r.stdout


def test_el7_auto_restart_in_progress_is_waited_for_instead_of_read_as_dead(tmp_path):
    # Restart=always unit: is-active says `activating` (rc 3) between crash and respawn.
    r, calls = _run_handler(tmp_path, "legacy_el7", mode="up", activating=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _starts(calls) == []


def test_tunables_are_declared_in_role_defaults_and_documented():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    for name in ("otelcol_sysv_pid_path", "otelcol_sysv_start_grace", "otelcol_sysv_stop_timeout",
                 "otelcol_alive_grace_seconds"):
        assert name in defaults, name
    doc = (ROOT / "docs" / "monitoring.md").read_text()
    assert all(n in doc for n in ("otelcol_sysv_pid_path", "otelcol_sysv_start_grace", "otelcol_sysv_stop_timeout",
                                  "otelcol_alive_grace_seconds"))
