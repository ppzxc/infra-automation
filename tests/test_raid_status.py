"""RAID 상태 수집기 (Spec #322 / Ticket-13, #335).

수집 스크립트를 가짜 ssacli(픽스처를 그대로 출력)로 실행해, 도구 출력이 어떤 정규화 JSON 줄이 되는지만 본다.
픽스처는 2026-10-22에 운영 서버에서 읽기 전용으로 받은 실제 출력이다(시리얼·WWN·SAS 주소 등은 지움).
CentOS 6(gawk 3.1.7)·CentOS 7(gawk 4.0)·Ubuntu(mawk)에서 같은 결과가 나오는 것은 컨테이너로 확인했다.
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
SCRIPT = MON / "files" / "host-agents-raid-status.sh"
FIXTURES = ROOT_DIR / "tests" / "fixtures" / "raid_ssacli"

needs_flock = pytest.mark.skipif(not shutil.which("flock"), reason="flock not installed")

COMMON = {"ts", "schema", "run_id", "kind", "family", "tool", "hw_type", "hw_id", "hw_parent", "hw_name",
          "hw_state", "raw_state", "operation", "progress_pct", "raw"}


def _fake_tool(tmp_path, name="ssacli", body=None):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    tool = bindir / name
    tool.write_text(body or (
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  version) printf '\\n   SSACLI Version: 9.99.0.0 2026-01-01\\n';;\n"
        "  ctrl) cat \"$FAKE_FIXTURE\";;\n"
        "esac\n"))
    tool.chmod(0o755)
    return bindir


def _run(tmp_path, fixture_text=None, tool="ssacli", body=None, env=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    bindir = _fake_tool(tmp_path, tool, body) if (fixture_text is not None or body) else tmp_path / "empty"
    bindir.mkdir(exist_ok=True)
    fx = tmp_path / "fixture.txt"
    if fixture_text is not None:
        fx.write_text(fixture_text)
    log = tmp_path / "raid.jsonl"
    full = {"PATH": "/usr/bin:/bin", "RAID_STATUS_PATH": str(bindir), "RAID_STATUS_LOG": str(log),
            "RAID_STATUS_LOCK": str(tmp_path / "raid.lock"), "FAKE_FIXTURE": str(fx),
            "RAID_STATUS_TOOLS": "ssacli hpssacli hpacucli", **(env or {})}
    res = subprocess.run(["/bin/sh", str(SCRIPT)], env=full, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    lines = log.read_text().splitlines() if log.exists() else []
    return [json.loads(line) for line in lines]


def _by_kind(recs, kind):
    return [r for r in recs if r["kind"] == kind]


def _fixture(name):
    return (FIXTURES / name).read_text()


# --- 실제 출력 픽스처 ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.txt")))
def test_every_real_fixture_becomes_valid_records_with_one_ok_tool_status(tmp_path, name):
    recs = _run(tmp_path, _fixture(name))
    (status,) = _by_kind(recs, "tool_status")
    assert status["status"] == "ok" and status["tool"] == "ssacli" and status["tool_version"] == "9.99.0.0 2026-01-01"
    assert recs[-1] is status                                   # 실행의 마지막 줄
    assert len({r["run_id"] for r in recs}) == 1 and len({r["ts"] for r in recs}) == 1
    (ctrl,) = _by_kind(recs, "controller")
    assert len(_by_kind(recs, "logical_drive")) == 1 and len(_by_kind(recs, "physical_drive")) >= 4
    for r in recs:
        if r["kind"] != "tool_status":
            assert COMMON <= set(r), r["kind"]
            assert isinstance(json.loads(r["raw"]), dict)       # raw는 JSON을 담은 문자열 하나다
            assert r["hw_id"].startswith(ctrl["hw_id"])
    assert ctrl["hw_state"] == "ok" and ctrl["raw_state"] == "OK" and ctrl["hw_model"].startswith("Smart Array P440")
    assert isinstance(ctrl["temperature_c"], int)


@pytest.mark.parametrize("name, cache, backup_power, battery_rec, ld_effective", [
    ("hpssacli240_el6_ok.txt", "ok", "battery", True, "wb"),
    ("ssacli330_el7_ok.txt", "ok", "battery", True, "wb"),
    ("ssacli660_el9_ok.txt", "ok", "battery", True, "wb"),
    ("hpssacli240_el6_perm_disabled_cable_error.txt", "permanently_disabled", "none", False, "wt"),
    ("hpssacli220_el7_perm_disabled_no_battery.txt", "permanently_disabled", "none", False, "wt"),
    ("ssacli660_el9_perm_disabled_no_backup_power.txt", "permanently_disabled", "none", False, "wt"),
    ("ssacli330_el7_temp_disabled_cable_error.txt", "temporarily_disabled", "battery", True, "wt"),
    ("ssacli660_el9_temp_disabled_cable_error.txt", "temporarily_disabled", "battery", True, "wt"),
])
def test_cache_and_backup_power_states_follow_the_controller_report(tmp_path, name, cache, backup_power,
                                                                   battery_rec, ld_effective):
    recs = _run(tmp_path, _fixture(name))
    (ctrl,) = _by_kind(recs, "controller")
    assert ctrl["cache_status"] == cache and ctrl["cache_present"] is True
    assert ctrl["backup_power"] == backup_power
    assert ctrl["backup_power_state"] == ("ok" if battery_rec else "none")
    assert ctrl["backup_power_operation"] == "none" and ctrl["write_cache_without_battery"] is False
    assert (len(_by_kind(recs, "cache_battery")) == 1) is battery_rec
    (ld,) = _by_kind(recs, "logical_drive")
    assert ld["write_cache_effective"] == ld_effective and ld["raid_level"] == "RAID10"
    if cache != "ok":
        assert ctrl["cache_reason"]                              # 원인 문장(또는 Cache Status Details)이 남는다


def test_cable_error_reason_is_kept_for_both_tool_generations(tmp_path):
    old = _by_kind(_run(tmp_path / "a", _fixture("hpssacli240_el6_perm_disabled_cable_error.txt")), "controller")[0]
    new = _by_kind(_run(tmp_path / "b", _fixture("ssacli330_el7_temp_disabled_cable_error.txt")), "controller")[0]
    assert old["cache_reason"] == "Cable Error"                 # hpssacli 2.40: Cache Status Details만 있다
    assert "cable error" in new["cache_reason"]                 # ssacli 3.30+: Cache Disable Reason 문장


def test_unassigned_drives_are_reported_with_their_role(tmp_path):
    recs = _run(tmp_path, _fixture("ssacli660_el9_perm_disabled_no_backup_power.txt"))
    roles = sorted(r["drive_role"] for r in _by_kind(recs, "physical_drive"))
    assert roles == ["data"] * 4 + ["unassigned"] * 2
    assert all(r["hot_spare"] is False and r["predictive_failure"] is False for r in _by_kind(recs, "physical_drive"))
    (ld,) = _by_kind(recs, "logical_drive")
    assert ld["write_cache_configured"] == "wt"                 # 6.60은 캐시가 꺼지면 LD Caching도 Disabled로 보고한다


def test_physical_drive_fields_and_raw_hold_every_reported_key(tmp_path):
    recs = _run(tmp_path, _fixture("ssacli330_el7_ok.txt"))
    pd = next(r for r in _by_kind(recs, "physical_drive") if r["slot"] == "1I:1:1")
    assert pd["hw_id"] == "ssa:slot=0/pd1I:1:1" and pd["hw_parent"] == "ssa:slot=0"
    assert pd["hw_model"] == "ATA MM1000GBKAL" and pd["media"] == "hdd" and pd["temperature_c"] == 37
    raw = json.loads(pd["raw"])
    assert raw["Serial Number"].startswith("REDACTED") and raw["Rotational Speed"] == "7200"
    ctrl_raw = json.loads(_by_kind(recs, "controller")[0]["raw"])
    assert "Port Name" not in ctrl_raw and ctrl_raw["Firmware Version"] == "3.00-0"


# --- 합성 상황 (실제 출력을 바꿔 만든 것) ---------------------------------------------------------------

def test_synthetic_recharging_battery_is_charging_not_a_fault(tmp_path):
    text = _fixture("ssacli330_el7_temp_disabled_cable_error.txt").replace(
        "Battery/Capacitor Status: OK", "Battery/Capacitor Status: Recharging")
    recs = _run(tmp_path, text)
    (ctrl,) = _by_kind(recs, "controller")
    (bat,) = _by_kind(recs, "cache_battery")
    assert ctrl["backup_power_operation"] == "charging" and bat["operation"] == "charging"
    assert bat["hw_state"] == "degraded" and bat["raw_state"] == "Recharging"


@pytest.mark.parametrize("status, state, op, pct", [
    ("Recovering, 41% complete", "degraded", "rebuild", 41),
    ("Interim Recovery Mode", "degraded", "none", None),
    ("Failed", "failed", "none", None),
    ("Transforming, 12% complete", "ok", "expand", 12),
    ("Something New", "unknown", "none", None),
])
def test_synthetic_logical_drive_states_are_normalized(tmp_path, status, state, op, pct):
    ld_ok = "         Status: OK\n         Unrecoverable Media Errors"
    text = _fixture("ssacli330_el7_ok.txt")
    assert ld_ok in text
    recs = _run(tmp_path, text.replace(ld_ok, f"         Status: {status}\n         Unrecoverable Media Errors", 1))
    (ld,) = _by_kind(recs, "logical_drive")
    assert (ld["hw_state"], ld["operation"], ld["progress_pct"], ld["raw_state"]) == (state, op, pct, status)


def test_synthetic_failed_drive_detail_blocks_map_to_failed_and_predicted(tmp_path):
    text = _fixture("ssacli330_el7_ok.txt")
    head, *pds = text.split("\n      physicaldrive 1I:1:")
    detail = [i for i, p in enumerate(pds) if "\n         Port: " in p]
    pds[detail[1]] = pds[detail[1]].replace("Status: OK", "Status: Failed", 1)
    pds[detail[2]] = pds[detail[2]].replace("Status: OK", "Status: Predictive Failure", 1)
    recs = _run(tmp_path, "\n      physicaldrive 1I:1:".join([head] + pds))
    states = sorted((r["hw_state"], r["predictive_failure"]) for r in _by_kind(recs, "physical_drive"))
    assert states == [("failed", False), ("ok", False), ("ok", False), ("predicted_failure", True)]


def test_hostile_values_stay_one_valid_json_line_each(tmp_path):
    text = _fixture("ssacli660_el9_ok.txt").replace("Model: ATA     MM1000GFJTE", 'Model: "q" \\ back\ttab', 1)
    recs = _run(tmp_path, text)
    models = [r["hw_model"] for r in _by_kind(recs, "physical_drive")]
    assert '"q" \\ back tab' in models


# --- 도구 상태 -----------------------------------------------------------------------------------------------

def test_no_tool_leaves_a_single_no_tool_line(tmp_path):
    (rec,) = _run(tmp_path)
    assert rec["kind"] == "tool_status" and rec["status"] == "no_tool" and rec["tool"] == "none"


def test_older_tool_names_are_found_in_order(tmp_path):
    recs = _run(tmp_path, _fixture("hpssacli240_el6_ok.txt"), tool="hpssacli")
    assert {r["tool"] for r in recs} == {"hpssacli"}


def test_tool_errors_and_missing_controllers_are_reported_not_raised(tmp_path):
    err = _run(tmp_path / "a", body="#!/bin/sh\necho 'Error: something \"bad\"'\nexit 3\n")
    assert [(r["status"], r["exit_code"]) for r in err] == [("error", 3)] and "bad" in err[0]["message"]
    none = _run(tmp_path / "b", body="#!/bin/sh\n[ \"$1\" = version ] && exit 0\necho\necho 'Error: No controllers detected.'\n")
    assert [r["status"] for r in none] == ["no_controller"]


def test_a_hung_tool_is_cut_off_by_the_timeout(tmp_path):
    recs = _run(tmp_path, body="#!/bin/sh\n[ \"$1\" = version ] && exit 0\nsleep 30\n", env={"RAID_STATUS_TIMEOUT": "1"})
    assert [r["status"] for r in recs] == ["timeout"]


@needs_flock
def test_an_overlapping_run_leaves_a_locked_line_and_does_not_call_the_tool(tmp_path):
    lock = tmp_path / "raid.lock"
    holder = subprocess.Popen(["flock", str(lock), "sleep", "10"])
    try:
        for _ in range(50):
            if lock.exists():
                break
        recs = _run(tmp_path, _fixture("ssacli660_el9_ok.txt"))
    finally:
        holder.kill()
        holder.wait()
    assert [r["status"] for r in recs] == ["locked"]


def test_the_script_never_fails_even_when_the_log_cannot_be_written(tmp_path):
    res = subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True, timeout=60,
                         env={"PATH": "/usr/bin:/bin", "RAID_STATUS_PATH": str(tmp_path),
                              "RAID_STATUS_LOG": "/nonexistent/dir/raid.jsonl",
                              "RAID_STATUS_LOCK": str(tmp_path / "x" / "raid.lock")})
    assert res.returncode == 0


def test_the_script_uses_posix_tools_only_and_never_changes_the_controller():
    raw = SCRIPT.read_text()
    assert raw.startswith("#!/bin/sh")
    code = "\n".join(ln for ln in raw.splitlines() if not ln.lstrip().startswith("#"))
    for banned in ("jq", "python", "perl", "[[ ", "echo -e", "gensub", "strftime", "systime"):
        assert banned not in code, banned
    assert not re.search(r"(^|[\s=(])\$'", code)              # bash 전용 $'...' 인용 없음
    # 읽기 전용: 도구에 넘기는 명령은 version과 show뿐이다
    for verb in ("modify", "create", "delete", "add ", "remove", "rescan", "set "):
        assert f'"$tool" {verb}' not in code and f"$tool {verb}" not in code
    dash = shutil.which("dash")
    if dash:
        assert subprocess.run([dash, "-n", str(SCRIPT)]).returncode == 0


# --- 배포 템플릿 ---------------------------------------------------------------------------------------------

def _render(name):
    defaults = yaml.safe_load((MON / "defaults" / "main.yml").read_text(encoding="utf-8"))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(MON / "templates")), undefined=jinja2.StrictUndefined)
    return env.get_template(name).render(**defaults)


def test_cron_runs_every_five_minutes_as_root_with_explicit_paths():
    lines = [ln for ln in _render("host-agents-raid-status.cron.j2").splitlines() if ln and not ln.startswith(("#", "SHELL", "PATH"))]
    assert lines == ["*/5 * * * * root RAID_STATUS_LOG=/var/log/host-agents/raid.jsonl "
                     "RAID_STATUS_LOCK=/var/lib/host-agents/raid-status.lock RAID_STATUS_TIMEOUT=60 "
                     "/usr/local/sbin/host-agents-raid-status >/dev/null 2>&1"]


def test_logrotate_rotates_daily_and_recreates_a_root_owned_file():
    text = _render("host-agents-raid-status.logrotate.j2")
    assert text.splitlines()[1] == "/var/log/host-agents/raid.jsonl {"
    for directive in ("daily", "rotate 3", "missingok", "notifempty", "compress", "create 0640 root root"):
        assert f"    {directive}" in text


def test_collector_tasks_cover_both_paths_and_the_disable_switch():
    text = (MON / "tasks" / "raid_status.yml").read_text(encoding="utf-8")
    for spec in ("MON-230", "MON-231", "MON-232", "MON-233", "MON-234", "MON-240", "MON-241", "MON-242", "MON-243"):
        assert f"[{spec}]" in text
    assert "host_agents_is_legacy" in text and "host_agents_os_path == 'modern'" in text
    main = (MON / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "import_tasks: raid_status.yml" in main
