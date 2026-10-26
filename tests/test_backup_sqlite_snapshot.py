"""백업 전 SQLite 스냅샷 (Spec #322 / Ticket-1, #323).

호스트별 입력 `backup_sqlite_snapshots`(SQLite 파일 절대 경로 목록)가 있으면 백업 직전에 각 파일을 SQLite online backup으로
스냅샷 파일에 쓰고, 그 스냅샷을 백업한다. 입력이 없는 호스트는 동작이 바뀌지 않는다.
스냅샷 스크립트는 가짜 sqlite3(표준 라이브러리 sqlite3로 `.backup`·`PRAGMA`만 흉내 냄)로 논리를 시험하고, 진짜 sqlite3 CLI가
있으면(CI) 같은 시험을 진짜로도 돌린다. 백업 실패 기록은 진짜 resticprofile로 확인한다.
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from test_backup import HOOK, ROLE, ROOT_DIR, _render, _run, _task, _vars, needs_restic

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from host_agents import host_agents_resolve_inputs  # noqa: E402

SNAPSHOT = ROLE / "files" / "host-agents-sqlite-snapshot.sh"
HOST_AGENTS_PROFILE = "profiles.yaml.j2"

FAKE_SQLITE3 = '''#!{python}
"""sqlite3 CLI의 일부만 흉내 낸다: sqlite3 [-batch] DB [.timeout N | .backup 'FILE' | SQL ...]. FAKE_SQLITE_EXIT0=1이면 실패해도 0으로 끝난다(오래된 CLI)."""
import os, sqlite3, sys
args = [a for a in sys.argv[1:] if a != "-batch"]
db, cmds = args[0], args[1:]
code = 0
try:
    conn = sqlite3.connect(db)          # 진짜 CLI처럼 없는 파일은 빈 DB로 만든다(스크립트가 먼저 존재를 확인해야 하는 이유)
    for cmd in cmds:
        if cmd.startswith(".timeout"):
            continue
        if cmd.startswith(".backup"):
            target = cmd.split("'")[1]
            dest = sqlite3.connect(target)
            conn.backup(dest)
            dest.close()
        else:
            for row in conn.execute(cmd):
                print("|".join(str(c) for c in row))
except Exception as exc:
    print("Error: %s" % exc, file=sys.stderr)
    code = 0 if os.environ.get("FAKE_SQLITE_EXIT0") == "1" else 1
sys.exit(code)
'''

real_sqlite3 = pytest.mark.skipif(not shutil.which("sqlite3"), reason="sqlite3 CLI not installed")


def _make_db(path, rows=3):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    conn.executemany("INSERT INTO t (v) VALUES (?)", [(f"row{i}",) for i in range(rows)])
    conn.commit()
    conn.close()


def _fake_bin(tmp_path):
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    tool = bindir / "sqlite3"
    tool.write_text(FAKE_SQLITE3.format(python=sys.executable))
    tool.chmod(0o755)
    return bindir


def _snapshot(tmp_path, dbs, dest=None, env=None, real=False):
    dest = dest or tmp_path / "snap"
    full = {"PATH": "/usr/bin:/bin", **(env or {})}
    if not real:
        full["PATH"] = f"{_fake_bin(tmp_path)}:{full['PATH']}"
    return subprocess.run(["/bin/sh", str(SNAPSHOT), str(dest), *map(str, dbs)], env=full, capture_output=True, text=True, timeout=60)


def _rows(path):
    conn = sqlite3.connect(path)
    try:
        return [r[0] for r in conn.execute("SELECT v FROM t ORDER BY id")]
    finally:
        conn.close()


# --- 입력 (host_agents_inputs) -------------------------------------------------------------------------------

REQUIRED = {"o2_ingest_token": "t", "restic_password": "p", "rustfs_access_key": "a", "rustfs_secret_key": "s"}


def _resolve(**kv):
    return host_agents_resolve_inputs(dict(REQUIRED, **kv), ["/var/log/messages"], [], ["/etc"], "hosts/h/agents")


def test_without_the_input_the_resolved_list_is_empty():
    res = _resolve()
    assert res["errors"] == [] and res["backup_sqlite_snapshots"] == []


def test_the_input_is_a_deduplicated_list_of_absolute_paths():
    res = _resolve(backup_sqlite_snapshots=["/data/o2/meta.sqlite", "/data/o2/meta.sqlite", "/data/rustfs/x.db"])
    assert res["errors"] == [] and res["backup_sqlite_snapshots"] == ["/data/o2/meta.sqlite", "/data/rustfs/x.db"]


@pytest.mark.parametrize("bad", ["relative.db", "/data/it's.db", "/data/with space.db", "/data/../etc/x.db", "/data/a;b.db", "/"])
def test_unsafe_or_relative_paths_are_errors_naming_the_key(bad):
    res = _resolve(backup_sqlite_snapshots=[bad])
    assert len(res["errors"]) == 1 and "backup_sqlite_snapshots" in res["errors"][0] and "hosts/h/agents" in res["errors"][0]


# --- 렌더링: 입력이 없으면 아무것도 바뀌지 않는다 ----------------------------------------------------------------

def _dirs(tmp_path, *names):
    for name in names:
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    return tmp_path


def _profile(tmp_path, inputs):
    return yaml.safe_load(_render(tmp_path, HOST_AGENTS_PROFILE, "profiles.yaml", host_agents_inputs=inputs))["default"]


def test_no_input_leaves_the_profile_and_the_service_unit_untouched(tmp_path):
    _dirs(tmp_path, "a", "b", "c", "d")
    without_key = _render(tmp_path / "a", HOST_AGENTS_PROFILE, "p.yaml", host_agents_inputs={"backup_pre_hooks": []})
    empty = _render(tmp_path / "b", HOST_AGENTS_PROFILE, "p.yaml", host_agents_inputs={"backup_pre_hooks": [], "backup_sqlite_snapshots": []})
    assert without_key == empty and "sqlite" not in empty
    prof = yaml.safe_load(empty)["default"]
    assert prof["backup"]["run-before"] == ["/usr/local/sbin/host-agents-backup-event start"]
    unit_a = _render(tmp_path / "c", "host-agents-backup.service.j2", "u.service", host_agents_inputs={"backup_pre_hooks": []})
    unit_b = _render(tmp_path / "d", "host-agents-backup.service.j2", "u.service",
                     host_agents_inputs={"backup_pre_hooks": [], "backup_sqlite_snapshots": []})
    assert unit_a == unit_b and "ReadWritePaths=/var/cache/restic /var/log/host-agents /var/lib/host-agents -/var/backups\n" in unit_a


def test_the_input_adds_a_snapshot_step_between_the_start_event_and_the_pre_hooks(tmp_path):
    prof = _profile(tmp_path, {"backup_pre_hooks": ["pg_dump -f /var/backups/db.sql mydb"],
                               "backup_sqlite_snapshots": ["/data/o2/meta.sqlite", "/data/rustfs/x.db"]})
    before = prof["backup"]["run-before"]
    assert before[0] == "/usr/local/sbin/host-agents-backup-event start"
    assert before[1] == ("/usr/local/sbin/host-agents-sqlite-snapshot /var/backups/host-agents-sqlite "
                         "/data/o2/meta.sqlite /data/rustfs/x.db")
    assert before[2:] == ["pg_dump -f /var/backups/db.sql mydb"]


def test_the_service_sandbox_may_write_next_to_each_source_database(tmp_path):
    """ProtectSystem=strict makes the source directory read-only; a WAL database needs its -shm file even to be read."""
    unit = _render(tmp_path, "host-agents-backup.service.j2", "u.service",
                   host_agents_inputs={"backup_pre_hooks": [], "backup_sqlite_snapshots": ["/data/o2/meta.sqlite", "/data/rustfs/x.db"]})
    line = next(ln for ln in unit.splitlines() if ln.startswith("ReadWritePaths="))
    assert line.endswith("-/var/backups -/data/o2 -/data/rustfs")


def _sources(tmp_path, snapshots):
    tasks = [dict(_task("[BAK-012]"))]
    out = tmp_path / "out.json"
    pre = [{"ansible.builtin.set_fact": {"_backup_conditional": {"results": []}}}]
    tasks.append({"ansible.builtin.copy": {"dest": str(out), "content": "{{ backup_sources | to_json }}"}})
    inputs = {"backup_paths": ["/etc"], "backup_exclude_paths": [], "backup_pre_hooks": []}
    if snapshots is not None:
        inputs["backup_sqlite_snapshots"] = snapshots
    res = _run(tmp_path, pre + tasks, _vars(host_agents_inputs=inputs, host_agents_os_family="RedHat", host_agents_os_major_version="9",
                                            host_agents_is_legacy=False))
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(out.read_text())


def test_the_snapshot_directory_is_a_backup_source_only_when_the_input_is_set(tmp_path):
    _dirs(tmp_path, "a", "b", "c")
    assert _sources(tmp_path / "a", None) == ["/etc"]
    assert _sources(tmp_path / "b", []) == ["/etc"]
    assert _sources(tmp_path / "c", ["/data/o2/meta.sqlite"]) == ["/etc", "/var/backups/host-agents-sqlite"]


# --- 스냅샷 스크립트 ---------------------------------------------------------------------------------------------

def test_a_snapshot_is_a_consistent_copy_in_the_destination_directory(tmp_path):
    db = tmp_path / "data" / "meta.sqlite"
    _make_db(db, rows=5)
    res = _snapshot(tmp_path, [db])
    assert res.returncode == 0, res.stderr
    (snap,) = (tmp_path / "snap").iterdir()
    assert snap.name.endswith(".sqlite-snapshot") and _rows(snap) == [f"row{i}" for i in range(5)]
    assert stat.S_IMODE(snap.stat().st_mode) == 0o600 and stat.S_IMODE((tmp_path / "snap").stat().st_mode) == 0o700
    assert not [p for p in (tmp_path / "snap").iterdir() if p.name.startswith(".")]          # 임시 파일이 남지 않는다


def test_a_database_that_a_writer_holds_open_in_wal_mode_is_snapshotted_with_its_committed_rows(tmp_path):
    db = tmp_path / "wal.sqlite"
    _make_db(db, rows=2)
    writer = sqlite3.connect(db)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO t (v) VALUES ('committed-in-wal')")
    writer.commit()
    writer.execute("BEGIN")
    writer.execute("INSERT INTO t (v) VALUES ('uncommitted')")
    try:
        assert _snapshot(tmp_path, [db]).returncode == 0
    finally:
        writer.rollback()
        writer.close()
    (snap,) = (tmp_path / "snap").iterdir()
    assert _rows(snap) == ["row0", "row1", "committed-in-wal"]


def test_two_databases_with_the_same_file_name_do_not_overwrite_each_other(tmp_path):
    a, b = tmp_path / "a" / "meta.sqlite", tmp_path / "b" / "meta.sqlite"
    _make_db(a, rows=1)
    _make_db(b, rows=4)
    assert _snapshot(tmp_path, [a, b]).returncode == 0
    snaps = sorted((tmp_path / "snap").iterdir())
    assert sorted(len(_rows(s)) for s in snaps) == [1, 4]


def test_a_snapshot_of_a_database_that_left_the_input_is_not_kept(tmp_path):
    a, b = tmp_path / "a.sqlite", tmp_path / "b.sqlite"
    _make_db(a)
    _make_db(b)
    assert _snapshot(tmp_path, [a, b]).returncode == 0
    assert _snapshot(tmp_path, [a]).returncode == 0
    assert len(list((tmp_path / "snap").iterdir())) == 1


@pytest.mark.parametrize("exit0", ["0", "1"])
def test_a_missing_source_fails_the_step_and_is_not_created_by_the_cli(tmp_path, exit0):
    ok = tmp_path / "ok.sqlite"
    _make_db(ok)
    res = _snapshot(tmp_path, [tmp_path / "missing.sqlite", ok], env={"FAKE_SQLITE_EXIT0": exit0})
    assert res.returncode != 0 and "missing.sqlite" in res.stderr
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.parametrize("exit0", ["0", "1"])
def test_a_source_that_is_not_a_database_fails_even_when_an_old_cli_exits_zero(tmp_path, exit0):
    """Old sqlite3 CLIs return 0 after a failed dot-command, so the script judges the snapshot, not the exit code."""
    bad = tmp_path / "bad.sqlite"
    bad.write_text("this is not a database " * 50)
    res = _snapshot(tmp_path, [bad], env={"FAKE_SQLITE_EXIT0": exit0})
    assert res.returncode != 0
    assert not list((tmp_path / "snap").glob("*.sqlite-snapshot"))


def test_a_missing_sqlite3_command_fails_the_step(tmp_path):
    db = tmp_path / "ok.sqlite"
    _make_db(db)
    res = subprocess.run(["/bin/sh", str(SNAPSHOT), str(tmp_path / "snap"), str(db)], env={"PATH": str(tmp_path / "empty")},
                         capture_output=True, text=True, timeout=60)
    assert res.returncode != 0


@real_sqlite3
def test_the_real_sqlite3_cli_makes_the_same_snapshot(tmp_path):
    db = tmp_path / "meta.sqlite"
    _make_db(db, rows=4)
    assert _snapshot(tmp_path, [db], real=True).returncode == 0
    (snap,) = (tmp_path / "snap").iterdir()
    assert len(_rows(snap)) == 4
    assert _snapshot(tmp_path, [tmp_path / "missing.sqlite"], real=True).returncode != 0
    assert not (tmp_path / "missing.sqlite").exists()


def test_the_script_is_posix_sh_and_never_writes_to_the_source():
    text = SNAPSHOT.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for banned in ("[[ ", "echo -e", "python", "jq"):
        assert banned not in code, banned
    for verb in ("INSERT", "UPDATE", "DELETE", "DROP", "VACUUM", "wal_checkpoint"):
        assert verb not in code, verb
    dash = shutil.which("dash")
    if dash:
        assert subprocess.run([dash, "-n", str(SNAPSHOT)]).returncode == 0


# --- 스냅샷이 실패하면 백업 결과도 실패로 남는다 (진짜 resticprofile) ---------------------------------------------

def _backup(tmp_path, snapshots, env_extra=None):
    (tmp_path / "pw").write_text("pw")
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "f").write_text("x")
    snap_dir = tmp_path / "snapdir"
    env = dict(os.environ, BACKUP_EVENT_LOG=str(tmp_path / "b.jsonl"), BACKUP_EVENT_START_FILE=str(tmp_path / "s"),
               PATH=f"{_fake_bin(tmp_path)}:{os.environ['PATH']}", **(env_extra or {}))
    prof = _render(tmp_path, HOST_AGENTS_PROFILE, "p.yaml", backup_repository=str(tmp_path / "repo"),
                   backup_password_path=str(tmp_path / "pw"), backup_cache_dir=str(tmp_path / "cache"),
                   backup_status_file=str(tmp_path / "status.json"), backup_sources=[str(src), str(snap_dir)], backup_excludes=[],
                   backup_event_script_path=str(HOOK), backup_sqlite_snapshot_script_path=str(SNAPSHOT),
                   backup_sqlite_snapshot_dir=str(snap_dir), backup_restic_binary=shutil.which("restic"), inventory_hostname="web01",
                   host_agents_inputs={"backup_pre_hooks": [], "backup_sqlite_snapshots": [str(s) for s in snapshots]})
    assert "sqlite" in prof

    def run(*cmd):
        return subprocess.run(["resticprofile", "-f", "yaml", "-c", str(tmp_path / "p.yaml"), "-n", "default", *cmd],
                              env=env, capture_output=True, text=True)
    return run, env


@needs_restic
def test_a_good_snapshot_is_part_of_the_backup_and_a_failed_one_makes_the_backup_result_fail(tmp_path):
    db = tmp_path / "data" / "meta.sqlite"
    _make_db(db, rows=3)
    run, env = _backup(tmp_path, [db])
    assert run("init").returncode == 0
    res = run("backup")
    assert res.returncode == 0, res.stdout + res.stderr
    listing = subprocess.run(["restic", "ls", "latest", "-r", str(tmp_path / "repo"), "--password-file", str(tmp_path / "pw")],
                             capture_output=True, text=True, env=env)
    assert ".sqlite-snapshot" in listing.stdout

    db.write_text("not a database anymore " * 40)          # 다음 백업의 스냅샷이 실패한다
    res = run("backup")
    assert res.returncode != 0
    ok, bad = [json.loads(ln) for ln in (tmp_path / "b.jsonl").read_text().splitlines()]
    assert ok["success"] is True
    assert bad["success"] is False and bad["exit_code"] != 0 and bad["command"] == "backup"


# --- 배포: 스크립트 배포와 sqlite3 확인 (입력이 있는 호스트에서만) --------------------------------------------------

def test_the_sqlite3_check_runs_before_the_backup_files_are_written():
    """A missing sqlite3 must stop the host before the credentials, hook, logrotate and profile are written (BAK-020~027)."""
    names = [t.get("name", "") for t in _flat_tasks("main.yml")]
    check = next(i for i, n in enumerate(names) if n.startswith("[BAK-028]"))
    for spec in ("[BAK-020]", "[BAK-022]", "[BAK-025]", "[BAK-026]", "[BAK-024]"):
        assert check < next(i for i, n in enumerate(names) if n.startswith(spec)), spec
    legacy = [t.get("name", "") for t in _flat_tasks("legacy.yml")]
    assert next(i for i, n in enumerate(legacy) if n.startswith("[BAK-218]")) < next(i for i, n in enumerate(legacy) if n.startswith("[BAK-203]"))


def test_deploy_tasks_exist_for_both_paths_and_only_act_when_the_input_is_set():
    modern = [t for t in _flat_tasks("main.yml") if t.get("name", "").startswith(("[BAK-028]", "[BAK-029]"))]
    legacy = [t for t in _flat_tasks("legacy.yml") if t.get("name", "").startswith(("[BAK-218]", "[BAK-219]"))]
    assert [t["name"][:9] for t in modern] == ["[BAK-028]", "[BAK-029]"] and [t["name"][:9] for t in legacy] == ["[BAK-218]", "[BAK-219]"]
    for task in modern + legacy:
        assert "backup_sqlite_snapshots" in str(task.get("when", "")), task["name"]


def _flat_tasks(filename):
    def flat(items):
        for t in items:
            yield t
            yield from flat(t.get("block", []))
    return list(flat(yaml.safe_load((ROLE / "tasks" / filename).read_text(encoding="utf-8"))))


def _toolbin(tmp_path, with_sqlite3):
    """A PATH with the basics ansible-playbook needs and, only when asked, a sqlite3 (never the machine's own)."""
    bindir = tmp_path / "toolbin"
    bindir.mkdir(parents=True, exist_ok=True)
    for name in ("sh", "bash", "mkdir", "rm", "rmdir", "chmod", "cat", "sleep", "ls", "mv", "cp", "uname", "id", "env", "dirname",
                 "basename", "python3", "date", "sed", "awk", "grep", "ansible-playbook", "tr", "head", "touch"):
        found = shutil.which(name)
        if found and not (bindir / name).exists():
            (bindir / name).symlink_to(found)
    if with_sqlite3:
        (bindir / "sqlite3").symlink_to(_fake_bin(tmp_path) / "sqlite3")
    return str(bindir)


def _assert_sqlite_task(tmp_path, snapshots, with_sqlite3):
    tmp_path.mkdir(parents=True, exist_ok=True)
    task = dict(_task("[BAK-028]"))
    task.pop("tags", None)
    return _run(tmp_path, [task], _vars(host_agents_inputs={"backup_sqlite_snapshots": snapshots}, inventory_hostname="ns0331", host_agents_os_path="modern"),
                extra_env={"PATH": _toolbin(tmp_path, with_sqlite3)})


def test_deploy_stops_with_a_clear_error_when_sqlite3_is_missing_on_a_host_that_uses_the_input(tmp_path):
    res = _assert_sqlite_task(tmp_path / "a", ["/data/o2/meta.sqlite"], with_sqlite3=False)
    out = res.stdout + res.stderr
    assert res.returncode != 0 and "sqlite3 명령이 없습니다" in out and "ns0331" in out and "backup_sqlite_snapshots" in out


def test_deploy_checks_nothing_for_a_host_without_the_input(tmp_path):
    res = _assert_sqlite_task(tmp_path / "b", [], with_sqlite3=False)
    assert res.returncode == 0, res.stdout + res.stderr


def test_deploy_passes_when_sqlite3_exists(tmp_path):
    res = _assert_sqlite_task(tmp_path / "c", ["/data/o2/meta.sqlite"], with_sqlite3=True)
    assert res.returncode == 0, res.stdout + res.stderr
