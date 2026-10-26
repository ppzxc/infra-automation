"""시각 동기 수집기 (Spec #322 / Ticket-14, #336).

수집 스크립트를 가짜 chronyc·ntpq·timedatectl(픽스처를 그대로 출력)로 실행해, 도구 출력이 어떤 JSON 줄이 되는지만 본다.
픽스처 출처(실제 캡처와 형식 기준 모의 구분)는 tests/fixtures/time_sync/README.md에 있다.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
MON = ROOT_DIR / "roles" / "monitoring"
SCRIPT = MON / "files" / "host-agents-time-sync.sh"
FIXTURES = ROOT_DIR / "tests" / "fixtures" / "time_sync"

FIELDS = {"ts", "schema", "run_id", "kind", "family", "tool", "sync_status", "synced", "offset_ms", "stratum", "message"}


def _fixture(name):
    return (FIXTURES / name).read_text()


def _fake_tools(tmp_path, tools):
    """tools: {command name: (stdout text, exit code)}. A command that is not listed does not exist on the fake host."""
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    for name, (text, rc) in tools.items():
        out = tmp_path / f"{name}.out"
        out.write_text(text)
        tool = bindir / name
        tool.write_text(f"#!/bin/sh\ncat '{out}'\nexit {rc}\n")
        tool.chmod(0o755)
    return bindir


def _run(tmp_path, tools):
    tmp_path.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "time-sync.jsonl"
    env = {"PATH": "/usr/bin:/bin", "TIME_SYNC_PATH": str(_fake_tools(tmp_path, tools)), "TIME_SYNC_LOG": str(log),
           # 시험 호스트가 가진 도구만 후보로 준다(개발 기기에 진짜 timedatectl이 있어도 "도구 없음"을 시험할 수 있게)
           "TIME_SYNC_TOOLS": " ".join(n for n in ("chronyc", "ntpq", "timedatectl") if n in tools) or "none-installed"}
    res = subprocess.run(["/bin/sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    lines = log.read_text().splitlines() if log.exists() else []
    recs = [json.loads(line) for line in lines]
    assert len(recs) == 1, recs                       # 실행마다 정확히 한 줄
    return recs[0]


def test_chrony_synced_host_reports_a_signed_offset_in_milliseconds(tmp_path):
    rec = _run(tmp_path, {"chronyc": (_fixture("chronyc_tracking_rocky9_synced.txt"), 0)})
    assert FIELDS <= set(rec)
    assert (rec["kind"], rec["family"], rec["tool"], rec["sync_status"], rec["synced"]) == (
        "time_sync", "timesync", "chronyc", "synced", True)
    assert rec["offset_ms"] == pytest.approx(-0.035, abs=0.001)         # "slow of NTP time"은 음수
    assert rec["stratum"] == 3 and rec["schema"] == 1


def test_chrony_fast_clock_is_a_positive_offset(tmp_path):
    rec = _run(tmp_path, {"chronyc": (_fixture("chronyc_tracking_el7_synced.txt"), 0)})
    assert rec["synced"] is True and rec["offset_ms"] == pytest.approx(0.026, abs=0.001)


def test_chrony_offset_over_one_second_is_reported_in_milliseconds(tmp_path):
    rec = _run(tmp_path, {"chronyc": (_fixture("chronyc_tracking_rocky9_offset_2s.txt"), 0)})
    assert rec["sync_status"] == "synced" and rec["offset_ms"] == pytest.approx(-2350.0)


def test_chrony_not_synchronised_is_unsynced_without_an_offset(tmp_path):
    rec = _run(tmp_path, {"chronyc": (_fixture("chronyc_tracking_not_synchronised.txt"), 0)})
    assert (rec["tool"], rec["sync_status"], rec["synced"], rec["offset_ms"]) == ("chronyc", "unsynced", False, None)


def test_ntpd_host_takes_the_offset_of_the_selected_peer_in_milliseconds(tmp_path):
    rec = _run(tmp_path, {"ntpq": (_fixture("ntpq_p_synced.txt"), 0)})
    assert (rec["tool"], rec["sync_status"], rec["synced"]) == ("ntpq", "synced", True)
    assert rec["offset_ms"] == pytest.approx(-0.432) and rec["stratum"] == 2


def test_ntpd_offset_over_one_second_stays_in_milliseconds(tmp_path):
    rec = _run(tmp_path, {"ntpq": (_fixture("ntpq_p_offset_1500ms.txt"), 0)})
    assert rec["synced"] is True and rec["offset_ms"] == pytest.approx(1500.25)


def test_ntpd_without_a_selected_peer_is_unsynced(tmp_path):
    rec = _run(tmp_path, {"ntpq": (_fixture("ntpq_p_no_sys_peer.txt"), 0)})
    assert (rec["sync_status"], rec["synced"], rec["offset_ms"]) == ("unsynced", False, None)


def test_centos6_host_whose_ntpd_is_stopped_is_unsynced_and_says_why(tmp_path):
    rec = _run(tmp_path, {"ntpq": (_fixture("ntpq_el6_daemon_down.txt"), 0)})
    assert (rec["tool"], rec["sync_status"], rec["synced"], rec["offset_ms"]) == ("ntpq", "unsynced", False, None)
    assert "not answering" in rec["message"]


def test_timedatectl_only_host_has_a_sync_flag_but_no_offset(tmp_path):
    for name, synced in (("timedatectl_rocky9_synced.txt", True), ("timedatectl_el7_synced.txt", True),
                         ("timedatectl_unsynced.txt", False)):
        rec = _run(tmp_path / name, {"timedatectl": (_fixture(name), 0)})
        assert (rec["tool"], rec["synced"], rec["offset_ms"]) == ("timedatectl", synced, None), name
        assert rec["sync_status"] == ("synced" if synced else "unsynced")


def test_a_stopped_chronyd_falls_through_to_the_next_tool(tmp_path):
    """chronyc exits non-zero when chronyd is not running; timedatectl still knows the clock state."""
    rec = _run(tmp_path, {"chronyc": ("506 Cannot talk to daemon\n", 1),
                          "timedatectl": (_fixture("timedatectl_unsynced.txt"), 0)})
    assert (rec["tool"], rec["sync_status"], rec["synced"]) == ("timedatectl", "unsynced", False)


def test_a_tool_that_exists_but_does_not_answer_is_unsynced_not_missing(tmp_path):
    rec = _run(tmp_path, {"chronyc": ("506 Cannot talk to daemon\n", 1)})
    assert (rec["tool"], rec["sync_status"], rec["synced"]) == ("chronyc", "unsynced", False)
    assert "not answering" in rec["message"]


def test_a_host_without_any_time_tool_leaves_a_no_tool_line(tmp_path):
    rec = _run(tmp_path, {})
    assert FIELDS <= set(rec)
    assert (rec["tool"], rec["sync_status"], rec["synced"], rec["offset_ms"]) == ("none", "no_tool", None, None)


def test_the_collector_never_depends_on_the_host_locale(tmp_path):
    """timedatectl prints Korean labels on a ko_KR host; the script must force the C locale."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "LC_ALL=C" in text


def test_the_collector_is_read_only_and_installs_nothing():
    text = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("ntpdate", "rdate", "chronyc makestep", "timedatectl set", "yum ", "dnf ", "apt"):
        assert forbidden not in text, forbidden


def test_a_hung_tool_is_cut_off_by_the_timeout_and_reported_as_error(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    hung = bindir / "chronyc"
    hung.write_text("#!/bin/sh\nsleep 30\n")
    hung.chmod(0o755)
    log = tmp_path / "time-sync.jsonl"
    env = {"PATH": "/usr/bin:/bin", "TIME_SYNC_PATH": str(bindir), "TIME_SYNC_LOG": str(log), "TIME_SYNC_TOOLS": "chronyc",
           "TIME_SYNC_TIMEOUT": "1"}
    assert subprocess.run(["/bin/sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60).returncode == 0
    (rec,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert (rec["tool"], rec["sync_status"], rec["synced"]) == ("chronyc", "error", None)


def test_the_script_never_fails_even_when_the_log_cannot_be_written(tmp_path):
    res = subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True, timeout=60,
                         env={"PATH": "/usr/bin:/bin", "TIME_SYNC_LOG": "/nonexistent/dir/time-sync.jsonl",
                              "TIME_SYNC_TOOLS": "none-installed"})
    assert res.returncode == 0


def test_the_script_uses_posix_tools_only():
    raw = SCRIPT.read_text()
    assert raw.startswith("#!/bin/sh")
    code = "\n".join(ln for ln in raw.splitlines() if not ln.lstrip().startswith("#"))
    for banned in ("jq", "python", "perl", "[[ ", "echo -e", "gensub", "strftime", "systime"):
        assert banned not in code, banned
    assert not re.search(r"(^|[\s=(])\$'", code)              # bash 전용 $'...' 인용 없음
    dash = shutil.which("dash")
    if dash:
        assert subprocess.run([dash, "-n", str(SCRIPT)]).returncode == 0


# --- 배포 템플릿과 태스크 -------------------------------------------------------------------------------------

def _render(name):
    defaults = yaml.safe_load((MON / "defaults" / "main.yml").read_text(encoding="utf-8"))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(MON / "templates")), undefined=jinja2.StrictUndefined)
    return env.get_template(name).render(**defaults)


def test_cron_runs_every_five_minutes_as_root_with_explicit_paths():
    lines = [ln for ln in _render("host-agents-time-sync.cron.j2").splitlines() if ln and not ln.startswith(("#", "SHELL", "PATH"))]
    assert lines == ["*/5 * * * * root TIME_SYNC_LOG=/var/log/host-agents/time-sync.jsonl TIME_SYNC_TIMEOUT=20 "
                     "/usr/local/sbin/host-agents-time-sync >/dev/null 2>&1"]


def test_logrotate_rotates_daily_and_recreates_a_root_owned_file():
    text = _render("host-agents-time-sync.logrotate.j2")
    assert text.splitlines()[1] == "/var/log/host-agents/time-sync.jsonl {"
    for directive in ("daily", "rotate 3", "missingok", "notifempty", "compress", "create 0640 root root"):
        assert f"    {directive}" in text


def test_collector_tasks_cover_both_paths_and_the_disable_switch():
    text = (MON / "tasks" / "time_sync.yml").read_text(encoding="utf-8")
    for spec in ("MON-250", "MON-251", "MON-252", "MON-253", "MON-254", "MON-260", "MON-261", "MON-262", "MON-263"):
        assert f"[{spec}]" in text
    assert "host_agents_is_legacy" in text and "host_agents_os_path == 'modern'" in text
    main = (MON / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "import_tasks: time_sync.yml" in main
