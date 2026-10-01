"""Backup role (ADR-0006 §2.4~2.5, Spec #38 / Ticket-5).

Templates are rendered through a local playbook (like tests/test_host_agents.py); the repo probe/init tasks
are extracted from the role and executed against a real local restic repository.
"""
import os
import shutil
import subprocess
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
        "backup_repository": "s3:https://rustfs.example:9000/host-backups/h1",
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
    assert prof["backup"]["run-before"] == ["pg_dump -f /var/backups/db.sql mydb"]
    assert prof["repository"] == "s3:https://rustfs.example:9000/host-backups/h1" and prof["cacert"] == "/etc/ca.pem"
    assert prof["password-file"] == "/etc/restic/password"
    assert not any(s in text for s in ("AKIA-secret", "S3-secret", "pw-secret"))


def test_profile_omits_hooks_and_ca_when_unset(tmp_path):
    text = _render(tmp_path, "profiles.yaml.j2", "profiles.yaml", host_agents_inputs={"backup_pre_hooks": []})
    prof = yaml.safe_load(text)["default"]
    assert "run-before" not in prof["backup"] and "cacert" not in prof


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
    pre = [{"ansible.builtin.set_fact": {"_backup_conditional": {"results": []}, "ansible_service_mgr": "systemd"}}]
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
    assert "ProtectSystem=strict" in svc and "ReadWritePaths=/var/cache/restic" in svc
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
    assert "'8'" in expr and "ansible_service_mgr != 'systemd'" in expr


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
