"""Backup role (ADR-0006 §2.4~2.5, Spec #38 / Ticket-5).

Templates are rendered through a local playbook (like tests/test_host_agents.py); the repo probe/init tasks
are extracted from the role and executed against a real local restic repository.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "backup"
MON = ROOT_DIR / "roles" / "monitoring"

needs_restic = pytest.mark.skipif(not (shutil.which("restic") and shutil.which("resticprofile")),
                                  reason="restic/resticprofile not installed")


def _vars(**over):
    v = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    v.update(yaml.safe_load((MON / "vars" / "main.yml").read_text(encoding="utf-8")))
    v.update({
        "inventory_hostname": "h1", "backup_restic_binary": "/opt/host-agents/restic/0.19.1/restic",
        "backup_repository": "s3:https://rustfs.example:9000/backup-prod-h1",
        "backup_sources": ["/etc", "/var/spool/cron", "/usr/local/bin", "/usr/local/etc", "/usr/local/sbin", "/opt/services"],
        "backup_excludes": v["backup_standard_excludes"] + ["/data/tmp"],
        "backup_schedule_hour": 2, "backup_schedule_minute": 7,
        "backup_run_command": "/usr/local/bin/resticprofile backup",
        "host_agents_inputs": {"backup_pre_hooks": ["pg_dump -f /var/backups/db.sql mydb"]},
        "host_agents_secrets": {"rustfs_access_key": "AKIA-secret", "rustfs_secret_key": "S3-secret", "restic_password": "pw-secret"},
    })
    v.update(over)
    return v


def _run(tmp_path, tasks, vars_, extra_env=None):
    (tmp_path / "vars.yml").write_text(yaml.safe_dump(vars_))
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                   "become": False, "vars_files": [str(tmp_path / "vars.yml")], "tasks": tasks}]))
    env = dict(os.environ, **(extra_env or {}))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    return res


def _render(tmp_path, name, dest, **over):
    res = _run(tmp_path, [{"ansible.builtin.template": {"src": str(ROLE / "templates" / name), "dest": str(tmp_path / dest)}}],
               _vars(**over))
    assert res.returncode == 0, res.stdout + res.stderr
    return (tmp_path / dest).read_text()


def _flat(items):
    for t in items:
        yield t
        yield from _flat(t.get("block", []))


def _tasks():
    return list(_flat(yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))))


def _task(prefix):
    return next(t for t in _tasks() if t.get("name", "").startswith(prefix))


# --- profile ---------------------------------------------------------------------------------------------

def test_profile_has_mandatory_paths_excludes_hooks_and_no_secrets(tmp_path):
    text = _render(tmp_path, "profiles.yaml.j2", "profiles.yaml", rustfs_ca_file="/etc/ca.pem")
    prof = yaml.safe_load(text)["default"]
    for path in ("/etc", "/var/spool/cron", "/usr/local/bin", "/usr/local/etc", "/usr/local/sbin"):
        assert path in prof["backup"]["source"]
    assert {"/home/*/.cache", "**/node_modules", "*.tmp", "*.swp", "/etc/restic/password", "/data/tmp"} <= set(prof["backup"]["exclude"])
    assert prof["backup"]["exclude-caches"] is True and prof["backup"]["retry-lock"] == "30m"
    assert prof["backup"]["run-before"][1:] == ["pg_dump -f /var/backups/db.sql mydb"]
    assert prof["repository"] == "s3:https://rustfs.example:9000/backup-prod-h1" and prof["cacert"] == "/etc/ca.pem"
    assert prof["password-file"] == "/etc/restic/password"
    assert not any(s in text for s in ("AKIA-secret", "S3-secret", "pw-secret"))


def test_profile_has_only_the_event_hook_and_no_ca_when_unset(tmp_path):
    text = _render(tmp_path, "profiles.yaml.j2", "profiles.yaml", host_agents_inputs={"backup_pre_hooks": []})
    prof = yaml.safe_load(text)["default"]
    assert prof["backup"]["run-before"] == ["/usr/local/sbin/host-agents-backup-event start"] and "cacert" not in prof


@needs_restic
def test_validate_wrapper_accepts_good_and_rejects_bad_profiles_given_an_extensionless_temp_file(tmp_path):
    """Run the role's real `validate:` command line the way the template module does (extensionless temp path)."""
    restic = tmp_path / "restic"
    restic.symlink_to(shutil.which("restic"))
    rp = tmp_path / "resticprofile"
    rp.symlink_to(shutil.which("resticprofile"))
    _render(tmp_path, "profiles.yaml.j2", "good.yaml", backup_restic_binary=str(restic))
    shutil.copy(tmp_path / "good.yaml", tmp_path / "good")
    (tmp_path / "bad").write_text("default: [")
    raw = _task("[BAK-024]")["ansible.builtin.template"]["validate"]
    cmd = raw.replace("{{ host_agents_install_root }}/resticprofile/{{ host_agents_versions['default'].resticprofile }}/resticprofile", str(rp))
    cmd = cmd.replace("{{ backup_profile_name }}", "default")
    assert "{{" not in cmd
    ok = subprocess.run(cmd % str(tmp_path / "good"), shell=True, capture_output=True, text=True)
    bad = subprocess.run(cmd % str(tmp_path / "bad"), shell=True, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert bad.returncode != 0
    assert not list(tmp_path.glob("*.yaml.yaml")) and not (tmp_path / "good.yaml.yaml").exists()


def test_profile_points_at_the_versioned_restic_binary(tmp_path):
    prof = yaml.safe_load(_render(tmp_path, "profiles.yaml.j2", "profiles.yaml"))
    assert prof["global"]["restic-binary"] == "/opt/host-agents/restic/0.19.1/restic"


# --- schedule --------------------------------------------------------------------------------------------

def _schedule(tmp_path, host):
    tasks = [t for t in _tasks() if t.get("name", "").startswith(("[BAK-012]", "[BAK-013]"))]
    tasks = [dict(t, **{}) for t in tasks]
    for t in tasks:                                           # stat results / OS facts are inputs of the real run
        t.pop("when", None)
    pre = [{"ansible.builtin.set_fact": {"_backup_conditional": {"results": []}, "ansible_service_mgr": "systemd", "host_agents_os_path": "modern"}}]
    out = tmp_path / "out.json"
    tasks.append({"ansible.builtin.copy": {"dest": str(out), "content": "{{ {'h': backup_schedule_hour, 'm': backup_schedule_minute} | to_json }}"}})
    vars_ = _vars(inventory_hostname=host, host_agents_os_family="RedHat", host_agents_os_major_version="9",
                  host_agents_inputs={"backup_paths": ["/etc"], "backup_exclude_paths": [], "backup_pre_hooks": []})
    res = _run(tmp_path, pre + tasks, vars_)
    assert res.returncode == 0, res.stdout + res.stderr
    import json
    return json.loads(out.read_text())


def test_schedule_is_stable_per_host_and_inside_window(tmp_path):
    seen = set()
    for host in ("web01", "db02", "ns0266", "a", "z9"):
        r1, r2 = _schedule(tmp_path, host), _schedule(tmp_path, host)
        assert r1 == r2
        assert 2 <= r1["h"] <= 3 and 0 <= r1["m"] <= 59
        seen.add((r1["h"], r1["m"]))
    assert len(seen) > 1                                       # actually spread across hosts


def test_timer_is_persistent_and_service_is_confined(tmp_path):
    timer = _render(tmp_path, "host-agents-backup.timer.j2", "t")
    assert "Persistent=true" in timer and "OnCalendar=*-*-* 02:07:00" in timer
    svc = _render(tmp_path, "host-agents-backup.service.j2", "s")
    assert "ProtectSystem=strict" in svc and "ReadWritePaths=/var/cache/restic /var/log/host-agents /var/lib/host-agents -/var/backups\n" in svc
    assert "EnvironmentFile=/etc/restic/env" in svc and "User=root" in svc


def test_cron_file_runs_as_root_at_the_seeded_time_and_sources_env(tmp_path):
    cron = _render(tmp_path, "host-agents-backup.cron.j2", "c", backup_schedule_hour=3, backup_schedule_minute=45)
    line = next(ln for ln in cron.splitlines() if ln.startswith("45 3 * * * root"))
    assert "/etc/restic/env" in line and "resticprofile backup" in line


def test_run_command_unlocks_stale_only_then_backs_up():
    cmd = _task("[BAK-013]")["ansible.builtin.set_fact"]["backup_run_command"]
    assert "unlock;" in cmd and "--remove-all" not in cmd and cmd.rstrip().endswith("backup")
    assert "30m" in (ROLE / "templates" / "profiles.yaml.j2").read_text()


def test_cron_scheduler_is_used_only_on_rocky8_or_non_systemd():
    expr = _task("[BAK-012]")["ansible.builtin.set_fact"]["backup_use_cron"]
    assert "'8'" in expr and "ansible_service_mgr | default('systemd')" in expr


# --- credentials -----------------------------------------------------------------------------------------

def test_credential_tasks_are_private_and_never_diffed():
    for prefix, mod in (("[BAK-022]", "ansible.builtin.template"), ("[BAK-023]", "ansible.builtin.copy"),
                        ("[BAK-024]", "ansible.builtin.template")):
        t = _task(prefix)
        assert t[mod]["mode"] == "0600"
    for prefix in ("[BAK-022]", "[BAK-023]"):
        t = _task(prefix)
        assert t["no_log"] is True and t["diff"] is False
    assert _task("[BAK-020]")["ansible.builtin.file"]["mode"] == "0700"


def test_env_file_renders_keys_only_in_the_env_file(tmp_path):
    env = _render(tmp_path, "restic.env.j2", "env", rustfs_region="us-east-1")
    assert "AWS_ACCESS_KEY_ID='AKIA-secret'" in env and "AWS_DEFAULT_REGION='us-east-1'" in env


# --- Deploy vs Config ------------------------------------------------------------------------------------

def test_repo_init_belongs_to_deploy_tags_only():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    for block in main:
        names = {t.get("name", "")[:9] for t in block.get("block", [])}
        if names & {"[BAK-050]", "[BAK-052]"}:
            assert "agents_config" not in block["tags"]
    cfg = next(b for b in main if b.get("name") == "Apply backup configuration")
    assert set(cfg["tags"]) == {"agents_config", "backup"}
    assert not {"[BAK-050]", "[BAK-052]"} & {t["name"][:9] for t in cfg["block"]}


def _probe_and_init(tmp_path, repo_exists_first=False):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for tool in ("restic", "resticprofile"):
        (bindir / tool).unlink(missing_ok=True)
        (bindir / tool).symlink_to(shutil.which(tool))
    (tmp_path / "pw").write_text("pw")
    (tmp_path / "env").write_text("")
    (tmp_path / "profiles.yaml").write_text(yaml.safe_dump({
        "version": "1", "default": {"repository": str(tmp_path / "repo"), "password-file": str(tmp_path / "pw")}}))
    tasks = [t for t in _tasks() if t.get("name", "").startswith(("[BAK-050]", "[BAK-051]", "[BAK-052]"))]
    res = _run(tmp_path, tasks, _vars(host_agents_bin_dir=str(bindir), backup_env_path=str(tmp_path / "env"),
                                      backup_profile_path=str(tmp_path / "profiles.yaml"), backup_init_enabled=True))
    return res


@needs_restic
def test_repo_is_initialised_once_and_the_probe_never_reports_changed(tmp_path):
    first = _probe_and_init(tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    assert (tmp_path / "repo" / "config").exists()
    assert "changed=1" in first.stdout                       # only the init task changed
    second = _probe_and_init(tmp_path)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout


@needs_restic
def test_probe_errors_other_than_missing_repo_fail_without_init(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "config").write_text("garbage")      # exists but unreadable with this password
    res = _probe_and_init(tmp_path)
    assert res.returncode != 0
    assert (tmp_path / "repo" / "config").read_text() == "garbage"


def test_init_can_be_disabled_for_environments_without_rustfs():
    assert "backup_init_enabled | bool" in str(_task("[BAK-050]")["when"])


# --- delivery of restic (.bz2) ----------------------------------------------------------------------------

def test_version_and_checksum_tables_cover_both_architectures_for_every_agent():
    consts = yaml.safe_load((MON / "vars" / "main.yml").read_text(encoding="utf-8"))
    versions = consts["host_agents_versions"]["default"]
    assert versions["restic"] == "0.19.1" and versions["resticprofile"] == "0.33.1"
    for agent, key in (("restic", "restic"), ("resticprofile", "resticprofile")):
        by_arch = consts["host_agents_checksums"][agent][versions[key]]
        assert set(by_arch) == {"amd64", "arm64"} and all(len(v) == 64 for v in by_arch.values())


def test_bz2_delivery_decompresses_to_the_plain_binary_name_in_the_cache(tmp_path):
    import bz2
    payload = b"#!/bin/sh\necho restic-fixture\n"
    cache = tmp_path / "cache"
    tarball = cache / "restic" / "9.9.9" / "restic_9.9.9_linux_amd64.bz2"
    tarball.parent.mkdir(parents=True)
    tarball.write_bytes(bz2.compress(payload))
    sha = __import__("hashlib").sha256(tarball.read_bytes()).hexdigest()
    tasks = [{"ansible.builtin.include_tasks": str(MON / "tasks" / "deliver_binary.yml"),
              "vars": {"_deliver_agent": "restic", "_deliver_binary": "restic", "_deliver_version": "9.9.9",
                       "_deliver_format": "bz2", "_deliver_url": f"file://{tarball}", "_deliver_sha256": sha,
                       "_deliver_handler": "noop"}}]
    vars_ = yaml.safe_load((MON / "defaults" / "main.yml").read_text(encoding="utf-8"))
    vars_.update(yaml.safe_load((MON / "vars" / "main.yml").read_text(encoding="utf-8")))
    vars_.update({"host_agents_cache_dir": str(cache), "host_agents_install_root": str(tmp_path / "opt"),
                  "host_agents_bin_dir": str(tmp_path / "usrbin"), "host_agents_os_arch": "amd64",
                  "host_agents_owner": __import__("getpass").getuser(),
                  "host_agents_group": subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()})
    (tmp_path / "usrbin").mkdir()
    for attempt in (1, 2):
        res = _run(tmp_path, tasks, vars_)
        assert res.returncode == 0, res.stdout + res.stderr
        built = cache / "restic" / "9.9.9" / "amd64" / "restic"
        assert built.read_bytes() == payload and oct(built.stat().st_mode & 0o777) == "0o755"
        assert (tmp_path / "opt" / "restic" / "9.9.9" / "restic").read_bytes() == payload
        if attempt == 2:
            assert "MON-055" not in res.stdout or "changed" not in res.stdout.split("MON-055")[1].split("TASK")[0]


# --- observability (Ticket-6) ----------------------------------------------------------------------------

HOOK = ROLE / "files" / "host-agents-backup-event.sh"


def _hook(tmp_path, *args, env=None):
    log, start = tmp_path / "backup.jsonl", tmp_path / "backup.start"
    full = {"PATH": os.environ["PATH"], "BACKUP_EVENT_LOG": str(log), "BACKUP_EVENT_START_FILE": str(start), **(env or {})}
    res = subprocess.run(["/bin/sh", str(HOOK), *args], env=full, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_hook_emits_one_valid_json_line_with_documented_fields_on_success(tmp_path):
    _hook(tmp_path, "start")
    (ev,) = _hook(tmp_path, "finish", "web01", env={"PROFILE_COMMAND": "backup"})
    assert set(ev) == {"job", "host", "command", "success", "exit_code", "duration", "error", "ts"}
    assert ev["job"] == "backup" and ev["host"] == "web01" and ev["command"] == "backup"
    assert ev["success"] is True and ev["exit_code"] == 0 and ev["error"] == ""
    assert isinstance(ev["duration"], int) and ev["duration"] >= 0
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ev["ts"])
    assert not (tmp_path / "backup.start").exists()
    assert len((tmp_path / "backup.jsonl").read_text().splitlines()) == 1


def test_hook_reports_failures_and_escapes_hostile_error_text_into_a_single_line(tmp_path):
    err = 'fatal: "bad" \\ path\nsecond line\ttab \x01 한글'
    (ev,) = _hook(tmp_path, "finish", "h1", env={"ERROR": err, "ERROR_EXIT_CODE": "3"})
    assert ev["success"] is False and ev["exit_code"] == 3
    assert '"bad"' in ev["error"] and "\\" in ev["error"] and "\n" not in ev["error"]
    assert len((tmp_path / "backup.jsonl").read_text().splitlines()) == 1


def test_hook_truncates_long_errors_and_never_fails_the_backup(tmp_path):
    (ev,) = _hook(tmp_path, "finish", "h1", env={"ERROR": "x" * 5000, "ERROR_EXIT_CODE": "abc"})
    assert len(ev["error"]) <= 500 and ev["exit_code"] == 1
    res = subprocess.run(["/bin/sh", str(HOOK), "finish", "h1"], capture_output=True, text=True,
                         env={"PATH": os.environ["PATH"], "BACKUP_EVENT_LOG": "/nonexistent/dir/x.jsonl"})
    assert res.returncode == 0


def test_hook_uses_posix_tools_only():
    raw = HOOK.read_text()
    assert raw.startswith("#!/bin/sh")
    text = "\n".join(ln for ln in raw.splitlines() if not ln.lstrip().startswith("#"))
    for banned in ("jq", "python", "perl", "awk -v", "[[", "$'", "echo -e"):
        assert banned not in text
    dash = shutil.which("dash")
    if dash:
        assert subprocess.run([dash, "-n", str(HOOK)]).returncode == 0


def test_profile_wires_status_file_and_hooks_around_user_hooks(tmp_path):
    prof = yaml.safe_load(_render(tmp_path, "profiles.yaml.j2", "profiles.yaml"))["default"]
    assert prof["status-file"] == "/var/lib/host-agents/restic-status.json"
    before = prof["backup"]["run-before"]
    assert before[0] == "/usr/local/sbin/host-agents-backup-event start"
    assert "pg_dump -f /var/backups/db.sql mydb" in before
    assert prof["backup"]["run-finally"] == ["/usr/local/sbin/host-agents-backup-event finish h1"]
    bare = yaml.safe_load(_render(tmp_path, "profiles.yaml.j2", "p2.yaml", host_agents_inputs={"backup_pre_hooks": []}))["default"]
    assert bare["backup"]["run-before"] == ["/usr/local/sbin/host-agents-backup-event start"]


def test_logrotate_config_covers_the_jsonl_file(tmp_path):
    conf = _render(tmp_path, "host-agents-backup.logrotate.j2", "lr")
    assert conf.splitlines()[1] == "/var/log/host-agents/backup.jsonl {"
    for directive in ("weekly", "rotate 8", "missingok", "notifempty", "compress", "create 0640 root root"):
        assert directive in conf
    assert _task("[BAK-027]")["ansible.builtin.template"]["dest"] == "{{ backup_logrotate_path }}"


def test_confined_service_may_write_the_result_directories(tmp_path):
    svc = _render(tmp_path, "host-agents-backup.service.j2", "s")
    rw = next(ln for ln in svc.splitlines() if ln.startswith("ReadWritePaths="))
    assert "/var/log/host-agents" in rw and "/var/lib/host-agents" in rw and "/var/cache/restic" in rw


def test_hook_script_deploy_is_executable_root_owned():
    t = _task("[BAK-026]")["ansible.builtin.copy"]
    assert t["mode"] == "0755" and t["owner"] == "root" and t["dest"] == "{{ backup_event_script_path }}"


def test_inventory_event_is_deploy_only_and_last():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    for block in main:
        names = [t.get("name", "")[:9] for t in block.get("block", [])]
        if "[BAK-061]" in names:
            assert "agents_config" not in block["tags"]
            assert names[-1] == "[BAK-061]"
        if block.get("name") == "Apply backup configuration":
            assert "[BAK-061]" not in names


class _O2(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _O2.seen.append((self.path, self.headers.get("Authorization"), json.loads(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"code":200}')

    def log_message(self, *a):
        pass


def test_inventory_event_posts_host_and_deployed_at_to_backup_logs(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _O2)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _O2.seen.clear()
    try:
        tasks = [t for t in _tasks() if t.get("name", "").startswith(("[BAK-060]", "[BAK-061]"))]
        for t in tasks:
            t.pop("no_log", None)
            t.pop("delegate_to", None)
        res = _run(tmp_path, tasks, _vars(o2_endpoint=f"http://127.0.0.1:{srv.server_port}", o2_org="default",
                                          host_agents_shared_secrets={"openobserve": {"controller_ingest_token": "ctl-tok"}},
                                          inventory_hostname="web01"))
    finally:
        srv.shutdown()
    assert res.returncode == 0, res.stdout + res.stderr
    ((path, auth, body),) = _O2.seen
    assert path == "/api/default/backup_logs/_json"
    assert auth == "Basic " + base64.b64encode(b"default:ctl-tok").decode()
    assert len(body) == 1 and body[0]["job"] == "inventory" and body[0]["host"] == "web01"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body[0]["deployed_at"])


def test_inventory_event_requires_the_controller_token():
    cond = _task("[BAK-060]")["ansible.builtin.assert"]["that"]
    assert any("controller_ingest_token" in c for c in cond)
    assert "backup_inventory_event_enabled | bool" in str(_task("[BAK-061]")["when"])
    assert "not ansible_check_mode" in str(_task("[BAK-061]")["when"])


def test_alert_contract_documents_stable_fields_and_every_standard_alert():
    doc = (ROOT_DIR / "docs" / "backup.md").read_text(encoding="utf-8")
    for field in ("`job`", "`host`", "`command`", "`success`", "`exit_code`", "`duration`", "`error`", "`ts`", "`deployed_at`"):
        assert field in doc
    for alert in ("백업 실패", "백업 누락", "무결성 검사 실패", "유지보수 누락", "수집 중단", "미실행 호스트", "26h", "8일", "15분"):
        assert alert in doc


@needs_restic
def test_hook_records_success_and_failure_through_real_resticprofile(tmp_path):
    (tmp_path / "pw").write_text("pw")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "f").write_text("x")
    env = dict(os.environ, BACKUP_EVENT_LOG=str(tmp_path / "b.jsonl"), BACKUP_EVENT_START_FILE=str(tmp_path / "s"))

    def run(repo, *cmd):
        prof = _render(tmp_path, "profiles.yaml.j2", "p.yaml", backup_repository=str(repo), backup_password_path=str(tmp_path / "pw"),
                       backup_cache_dir=str(tmp_path / "cache"), backup_status_file=str(tmp_path / "status.json"),
                       backup_sources=[str(tmp_path / "src")], backup_excludes=[], backup_event_script_path=str(HOOK),
                       host_agents_inputs={"backup_pre_hooks": []}, backup_restic_binary=shutil.which("restic"),
                       inventory_hostname="web01")
        return subprocess.run(["resticprofile", "-f", "yaml", "-c", str(tmp_path / "p.yaml"), "-n", "default", *cmd],
                              env=env, capture_output=True, text=True)

    assert run(tmp_path / "repo", "init").returncode == 0
    assert run(tmp_path / "repo", "backup").returncode == 0
    assert (tmp_path / "status.json").exists()
    assert run(tmp_path / "missing", "backup").returncode != 0
    ok, bad = [json.loads(ln) for ln in (tmp_path / "b.jsonl").read_text().splitlines()]
    assert ok["success"] is True and ok["host"] == "web01" and ok["command"] == "backup"
    assert bad["success"] is False and bad["exit_code"] != 0 and bad["error"]


# --- central Repo Maintenance (Ticket-7) -----------------------------------------------------------------

import sys  # noqa: E402

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from backup_maintenance import (  # noqa: E402
    backup_maintenance_event,
    backup_maintenance_events,
    backup_maintenance_failed,
    backup_maintenance_subset_due,
)

MAINT = ROLE / "tasks" / "maintenance.yml"
MAINT_TASKS = ("[BAK-077]", "[BAK-085]", "[BAK-078]", "[BAK-079]", "[BAK-080]", "[BAK-081]", "[BAK-082]", "[BAK-083]")


@pytest.mark.parametrize("date,expected", [
    ("2026-10-04", True),    # first Sunday
    ("2026-10-11", False),   # second Sunday
    ("2026-10-05", False),   # Monday inside the first week
    ("2026-11-01", True),    # Sunday on the 1st
    ("2026-02-07", False),   # Saturday on the 7th
    ("2026-02-01", True),
])
def test_monthly_read_subset_is_due_only_on_the_first_sunday(date, expected):
    assert backup_maintenance_subset_due(date) is expected


def test_subset_day_is_judged_in_the_schedule_timezone_not_utc():
    # Sunday 05:00 KST == Saturday 20:00 UTC: still the first Sunday for the Asia/Seoul schedule.
    assert backup_maintenance_subset_due("2026-10-03T20:00:00+00:00") is True
    assert backup_maintenance_subset_due("2026-10-03T20:00:00+00:00", "auto", "UTC") is False


def test_read_subset_can_be_forced_or_skipped_and_rejects_unknown_modes():
    assert backup_maintenance_subset_due("2026-10-11", "always") is True
    assert backup_maintenance_subset_due("2026-10-04", "never") is False
    with pytest.raises(ValueError):
        backup_maintenance_subset_due("2026-10-04", "sometimes")


def test_event_payload_matches_the_alert_contract():
    ok = backup_maintenance_event({"rc": 0, "delta": "0:01:05.123456", "stderr": ""}, "h1", "check")
    assert ok == {"job": "maintenance", "host": "h1", "command": "check", "success": True, "duration": 65, "error": ""}
    bad = backup_maintenance_event({"rc": 1, "delta": "1 day, 0:00:02", "stderr": "Fatal: pack \x01 missing\n" + "x" * 900}, "h1", "forget")
    assert set(bad) == {"job", "host", "command", "success", "duration", "error"}
    assert bad["success"] is False and bad["duration"] == 86402 and bad["command"] == "forget"
    assert 0 < len(bad["error"]) <= 500 and "\n" not in bad["error"] and "\x01" not in bad["error"]


def test_skipped_steps_emit_no_events_and_do_not_count_as_failures():
    steps = [{"command": "check", "result": {"rc": 0, "delta": "0:00:01"}},
             {"command": "check", "result": {"skipped": True}},
             {"command": "forget", "result": {"skipped": True}}]
    assert [e["command"] for e in backup_maintenance_events(steps, "h1")] == ["check"]
    assert backup_maintenance_failed([s["result"] for s in steps]) is False
    assert backup_maintenance_failed([{"rc": 0}, {"rc": 2}]) is True


class _Collector(BaseHTTPRequestHandler):
    posts = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).posts.append((self.path, self.headers["Authorization"], json.loads(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def collector():
    handler = type("H", (_Collector,), {"posts": []})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, handler.posts
    server.shutdown()


def _maint_tasks():
    return [t for t in yaml.safe_load(MAINT.read_text(encoding="utf-8")) if t["name"].startswith(MAINT_TASKS)]


def _restic_repo(tmp_path):
    """A real local restic repository holding two snapshots."""
    env = dict(os.environ, RESTIC_REPOSITORY=str(tmp_path / "repo"), RESTIC_PASSWORD="pw")
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("data")
    subprocess.run(["restic", "init"], env=env, check=True, capture_output=True)
    for day in ("2025-01-01", "2025-03-01"):      # different day/week/month so a tight retention policy forgets the older one
        subprocess.run(["restic", "backup", "--time", f"{day} 03:00:00", str(src)], env=env, check=True, capture_output=True)
    return env


def _maintain(tmp_path, server, **over):
    vars_ = _vars(
        _maint_restic_bin=shutil.which("restic"), _maint_restic_password="pw", _maint_access_key="ak",
        _maint_secret_key="sk", _maint_ingest_token="tok", rustfs_region="", backup_maintenance_ca_file="",
        backup_maintenance_repository=str(tmp_path / "repo"), o2_endpoint=f"http://127.0.0.1:{server.server_port}",
        o2_org="default", backup_inventory_validate_certs=False)
    vars_.update(over)
    return _run(tmp_path, _maint_tasks(), vars_)


def _snapshots(env):
    return json.loads(subprocess.run(["restic", "snapshots", "--json"], env=env, capture_output=True, text=True).stdout)


@needs_restic
def test_healthy_repo_is_checked_then_pruned_and_reported(tmp_path, collector):
    server, posts = collector
    env = _restic_repo(tmp_path)
    res = _maintain(tmp_path, server, backup_maintenance_read_subset="never",
                    backup_retention_daily=1, backup_retention_weekly=1, backup_retention_monthly=1)
    assert res.returncode == 0, res.stdout + res.stderr
    ((path, auth, events),) = posts
    assert path == "/api/default/backup_logs/_json"
    assert base64.b64decode(auth.split()[1]).decode() == "default:tok"
    assert [(e["command"], e["success"], e["job"], e["host"]) for e in events] == [("check", True, "maintenance", "h1"), ("forget", True, "maintenance", "h1")]
    assert len(_snapshots(env)) == 1          # retention applied: the older snapshot was forgotten


@needs_restic
def test_failed_check_prevents_prune_and_fails_the_host(tmp_path, collector):
    server, posts = collector
    env = _restic_repo(tmp_path)
    for pack in (tmp_path / "repo" / "data").rglob("*"):
        if pack.is_file():
            pack.unlink()                      # index references packs that no longer exist -> check fails
    res = _maintain(tmp_path, server, backup_maintenance_read_subset="never")
    assert res.returncode != 0
    ((_, _, events),) = posts                  # evidence is posted even though the host fails
    assert [(e["command"], e["success"]) for e in events] == [("check", False)]
    assert events[0]["error"] and len(events[0]["error"]) <= 500
    assert len(_snapshots(env)) == 2           # nothing was forgotten or pruned


@needs_restic
def test_monthly_run_adds_the_read_subset_check_before_prune(tmp_path, collector):
    server, posts = collector
    _restic_repo(tmp_path)
    res = _maintain(tmp_path, server, backup_maintenance_read_subset="always")
    assert res.returncode == 0, res.stdout + res.stderr
    ((_, _, events),) = posts
    assert [e["command"] for e in events] == ["check", "check", "forget"]


def test_maintenance_uses_the_pinned_restic_and_has_no_version_table_of_its_own():
    raw = MAINT.read_text(encoding="utf-8")
    assert "host_agents_versions['default'].restic" in raw and "host_agents_checksums.restic" in raw
    assert not re.search(r'"?\d+\.\d+\.\d+"?', re.sub(r"v\{\{.*?\}\}", "", raw).replace("0.0", ""))
    assert "monitoring/vars/main.yml" in raw
    assert "--keep-daily={{ backup_retention_daily }}" in raw


def test_maintenance_playbook_runs_on_the_controller_for_servers_only():
    (play,) = yaml.safe_load((ROOT_DIR / "playbooks" / "host_agents_maintenance.yml").read_text(encoding="utf-8"))
    assert play["connection"] == "local" and play["hosts"] == "{{ target_hosts | default('servers') }}:&servers"
    assert play["tasks"][0]["ansible.builtin.include_role"] == {"name": "backup", "tasks_from": "maintenance"}


def test_every_secret_bearing_maintenance_task_is_no_log():
    names = {"[BAK-071]", "[BAK-072]", "[BAK-077]", "[BAK-085]", "[BAK-078]", "[BAK-079]", "[BAK-080]", "[BAK-081]", "[BAK-082]"}
    tasks = [t for t in yaml.safe_load(MAINT.read_text(encoding="utf-8")) if t["name"][:9] in names]
    assert len(tasks) == len(names) and all(t.get("no_log") is True for t in tasks)


def test_maintenance_resolves_endpoints_from_the_openbao_kv_like_deploy(tmp_path):
    """Repo Maintenance 경로(BAK-072)도 agents/openobserve·agents/rustfs의 엔드포인트 키로 defaults를 해석한다."""
    fixture = {
        "host": {"restic_password": "pw"},
        "openobserve": {"controller_ingest_token": "t", "o2_endpoint": "https://o2.bao.invalid:5080", "o2_org": "acme"},
        "rustfs": {"maintenance_access_key": "a", "maintenance_secret_key": "s",
                   "rustfs_endpoint": "https://rfs.bao.invalid:9000"},
    }
    resolve = [t for t in yaml.safe_load(MAINT.read_text(encoding="utf-8")) if t["name"].startswith("[BAK-072]")]
    dump = {"name": "Dump", "ansible.builtin.copy": {
        "content": "{{ {'o2_endpoint': o2_endpoint, 'o2_org': o2_org, 'rustfs_endpoint': rustfs_endpoint,"
                   " 'rustfs_bucket': rustfs_bucket} | to_json }}", "dest": str(tmp_path / "eff.json")}}
    res = _run(tmp_path, resolve + [dump], _vars(host_agents_kv_fixture=fixture))
    assert res.returncode == 0, res.stdout + res.stderr
    assert json.loads((tmp_path / "eff.json").read_text()) == {
        "o2_endpoint": "https://o2.bao.invalid:5080", "o2_org": "acme",
        "rustfs_endpoint": "https://rfs.bao.invalid:9000", "rustfs_bucket": "backup-prod-h1"}


def test_maintenance_bucket_honours_the_host_kv_override(tmp_path):
    fixture = {"host": {"restic_password": "pw", "rustfs_bucket": "backup-prod-custom"},
               "openobserve": {"controller_ingest_token": "t", "o2_endpoint": "https://o2.bao.invalid:5080"},
               "rustfs": {"maintenance_access_key": "a", "maintenance_secret_key": "s", "rustfs_endpoint": "https://rfs.bao.invalid:9000"}}
    resolve = [t for t in yaml.safe_load(MAINT.read_text(encoding="utf-8")) if t["name"].startswith("[BAK-072]")]
    dump = {"name": "Dump", "ansible.builtin.copy": {"content": "{{ rustfs_bucket }}", "dest": str(tmp_path / "bucket.txt")}}
    res = _run(tmp_path, resolve + [dump], _vars(host_agents_kv_fixture=fixture))
    assert res.returncode == 0, res.stdout + res.stderr
    assert (tmp_path / "bucket.txt").read_text() == "backup-prod-custom"


def test_deploy_and_maintenance_use_the_bucket_root_as_the_repository():
    for path in (ROLE / "tasks" / "main.yml", MAINT):
        raw = path.read_text(encoding="utf-8")
        assert "rustfs_bucket }}/{{ inventory_hostname" not in raw and "rustfs_bucket ~ '/' ~ inventory_hostname" not in raw
    assert 'backup_repository: "s3:{{ rustfs_endpoint }}/{{ rustfs_bucket }}"' in (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
