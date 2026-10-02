"""Host Agents on CentOS 7 (legacy_el7, ADR-0006 §2.9, Spec #38 / Ticket-9).

There is no CentOS 7 image, so (ADR-0006 Seam 3) the legacy path is covered by:
* structure tests (OS-path gates, tags, SPEC-IDs),
* byte-identical rendering of the modern ``template`` result vs the legacy ``lookup('template')`` content,
* the real ``legacy.yml`` task files (shared with CentOS 6) executed with ``ansible-playbook`` on a local connection, with a fake
  ``scp``/``systemctl`` on PATH and every host path redirected into a temp dir,
* the documented canary runbook on the first real CentOS 7 host.
"""
import bz2
import getpass
import grp
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
MON = ROOT_DIR / "roles" / "monitoring"
BAK = ROOT_DIR / "roles" / "backup"

needs_restic = pytest.mark.skipif(not (shutil.which("restic") and shutil.which("resticprofile")),
                                  reason="restic/resticprofile not installed")


def _yaml(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _flat(items):
    for t in items:
        yield t
        yield from _flat(t.get("block", []))


def _tasks(path):
    return list(_flat(_yaml(path)))


def _task(path, prefix):
    return next(t for t in _tasks(path) if t.get("name", "").startswith(prefix))


# --------------------------------------------------------------------------
# Structure: OS-path gates, tags, IDs
# --------------------------------------------------------------------------

def test_no_legacy_path_is_skipped_by_the_probe_anymore():
    # legacy_el6 landed in #48: the probe no longer ends the role for any OS path.
    probe = _yaml(MON / "tasks" / "probe.yml")
    assert not [t for t in probe if "ansible.builtin.meta" in t]
    assert not [t for t in probe if t.get("name", "").startswith(("[MON-028]",))]


@pytest.mark.parametrize("role", [MON, BAK])
def test_modern_blocks_are_gated_and_legacy_file_is_imported_behind_the_gate(role):
    main = _yaml(role / "tasks" / "main.yml")
    for block in (b for b in main if "block" in b and b.get("name", "").split()[0] != "Emit"):
        cond = block.get("when")
        conds = cond if isinstance(cond, list) else [cond]
        modern = "host_agents_os_path == 'modern'" in conds
        nested_modern = any(t.get("when") == "host_agents_os_path == 'modern'" for t in block["block"]
                            if "block" in t)
        # The shared backup config block gates its module tasks individually (controller-only derivations are shared).
        assert modern or nested_modern, block["name"]
    imp = next(t for t in main if t.get("ansible.builtin.import_tasks") == "legacy.yml")
    assert imp["when"] == "host_agents_is_legacy | bool"
    consts = _yaml(MON / "vars" / "main.yml")
    assert consts["host_agents_is_legacy"] == \
        "{{ (host_agents_os_path | default('modern')) in ['legacy_el6', 'legacy_el7'] }}"


def test_backup_shared_derivations_and_event_run_for_legacy_hosts_too():
    main = _yaml(BAK / "tasks" / "main.yml")
    flat = list(_flat(main))
    use_cron = next(t for t in flat if t.get("name", "").startswith("[BAK-012]"))["ansible.builtin.set_fact"]["backup_use_cron"]
    assert use_cron.startswith("{{ host_agents_is_legacy | bool or")
    stat = next(t for t in flat if t.get("name", "").startswith("[BAK-011]"))
    assert stat["when"] == "host_agents_os_path == 'modern'"
    event_block = next(b for b in main if b.get("name") == "Emit the inventory registration event")
    assert "when" in event_block and event_block["when"] == "enable_backup | bool"      # not OS-gated
    assert [t["name"].split("]")[0] for t in event_block["block"]] == ["[BAK-060", "[BAK-061"]
    assert main[-1] is event_block                                                       # still the last task


def test_legacy_task_files_use_only_raw_or_controller_side_modules():
    allowed_controller = {"ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.import_tasks",
                          "ansible.builtin.include_tasks", "ansible.builtin.meta", "ansible.builtin.debug",
                          "ansible.builtin.get_url", "ansible.builtin.unarchive", "ansible.builtin.shell",
                          "ansible.builtin.stat", "ansible.builtin.file", "ansible.builtin.command"}
    for path in (MON / "tasks" / "legacy.yml", BAK / "tasks" / "legacy.yml",
                 MON / "tasks" / "legacy_deliver_binary.yml", MON / "tasks" / "legacy_switch_binary.yml"):
        for t in _tasks(path):
            mods = [k for k in t if k.startswith("ansible.builtin.")]
            for m in mods:
                assert m == "ansible.builtin.raw" or m in allowed_controller, (path.name, t.get("name"), m)
            # Anything that is not raw must not touch the target: only controller-side tasks may remain.
            if mods and mods[0] in {"ansible.builtin.stat", "ansible.builtin.file", "ansible.builtin.shell",
                                    "ansible.builtin.command", "ansible.builtin.get_url", "ansible.builtin.unarchive"}:
                assert t.get("delegate_to") == "localhost", (path.name, t.get("name"))


def test_legacy_blocks_keep_the_modern_tag_split():
    for role, expected in ((MON, {"Install otelcol on CentOS 6/7": {"agents_install", "otel"},
                                  "Apply otelcol configuration on CentOS 6/7": {"agents_config", "otel"},
                                  "Enable otelcol service on CentOS 6/7": {"agents_install", "otel"}}),
                           (BAK, {"Deliver restic and resticprofile on CentOS 6/7": {"agents_install", "backup"},
                                  "Apply backup configuration on CentOS 6/7": {"agents_config", "backup"},
                                  "Enable backup schedule on CentOS 6/7": {"agents_install", "backup"}})):
        blocks = {b["name"]: set(b["tags"]) for b in _yaml(role / "tasks" / "legacy.yml") if "block" in b}
        assert blocks == expected
    # repo init / inventory event must stay out of agents_config (Config runs never init or register).
    init = next(b for b in _yaml(BAK / "tasks" / "legacy.yml") if b["name"] == "Enable backup schedule on CentOS 6/7")
    assert "agents_config" not in init["tags"]
    assert any(t["name"].startswith("[BAK-217]") for t in init["block"])


def test_every_binary_include_passes_tags_with_apply():
    for path in (MON / "tasks" / "legacy.yml", BAK / "tasks" / "legacy.yml"):
        for t in _tasks(path):
            inc = t.get("ansible.builtin.include_tasks")
            if inc:
                assert isinstance(inc, dict) and inc["apply"]["tags"], t["name"]


def test_legacy_profile_validation_matches_the_modern_command():
    modern = _task(BAK / "tasks" / "main.yml", "[BAK-024]")["ansible.builtin.template"]["validate"]
    legacy = _task(BAK / "tasks" / "legacy.yml", "[BAK-208]")
    assert legacy["ansible.builtin.import_tasks"].endswith("raw_upload.yml")
    # Same command; legacy picks the row per host (default on CentOS 7, legacy_el6 on CentOS 6), modern is always default.
    assert "host_agents_versions[host_agents_version_row].resticprofile" in legacy["vars"]["_raw_validate"]
    assert legacy["vars"]["_raw_validate"].replace("[host_agents_version_row]", "['default']").split() == modern.split()
    assert legacy["vars"]["_raw_secret"] is True and legacy["vars"]["_raw_mode"] == "0600"


def test_secret_files_are_raw_secret_and_unit_is_notifying():
    for path, prefixes in ((MON / "tasks" / "legacy.yml", ["[MON-206]"]),
                           (BAK / "tasks" / "legacy.yml", ["[BAK-204]", "[BAK-205]"])):
        for p in prefixes:
            v = _task(path, p)["vars"]
            assert v["_raw_secret"] is True and v["_raw_mode"] == "0600"
    unit = _task(MON / "tasks" / "legacy.yml", "[MON-213]")["vars"]
    assert unit["_raw_handler"] == ["Reload systemd daemon (raw)", "Restart otelcol-contrib (raw)"]
    names = [t["name"] for t in _tasks(MON / "tasks" / "legacy.yml") if "name" in t]
    assert names.index(next(n for n in names if n.startswith("[MON-209]"))) < names.index(
        next(n for n in names if n.startswith("[MON-213]")))                               # symlink before unit
    assert any("[MON-207]" in n for n in names)
    handlers = [h["name"] for h in _yaml(MON / "handlers" / "main.yml")]
    assert "Reload systemd daemon (raw)" in handlers and "Restart otelcol-contrib (raw)" in handlers


def _gated_ids(path):
    """(SPEC-ID, effective OS gate) for every task in a legacy file; the gate is the task's own os_path condition."""
    out = []
    for t in _tasks(path):
        if not t.get("name", "").startswith("[") or "block" in t:
            continue
        conds = t.get("when", [])
        conds = conds if isinstance(conds, list) else [conds]
        gate = next((c.split("== ")[1].strip("'") for c in conds if str(c).startswith("host_agents_os_path == ")), None)
        out.append((t["name"].split("]")[0].lstrip("["), gate))
    return out


def test_spec_id_bands_follow_the_os_gate_of_each_legacy_task():
    # 1xx = CentOS 6 only, 2xx = CentOS 7 only or shared by both legacy paths (ADR-0006 §3, docs §3-4/3-5).
    mon = _gated_ids(MON / "tasks" / "legacy.yml")
    assert mon
    for spec_id, gate in mon:
        band = int(spec_id.split("-")[1]) // 100
        assert band in (1, 2), spec_id
        assert (gate == "legacy_el6") == (band == 1), (spec_id, gate)
        assert gate in (None, "legacy_el6", "legacy_el7"), (spec_id, gate)
    assert {i for i, g in mon if g == "legacy_el6"} == {"MON-110", "MON-114", "MON-119", "MON-121", "MON-122"}
    assert {i for i, g in mon if g == "legacy_el7"} == {"MON-201", "MON-202", "MON-213", "MON-215"}
    # Shared raw helpers keep their bands: MON-100~109 (fetch/upload) and MON-210~212 (install dir/smoke/switch).
    for path in (MON / "tasks" / "legacy_deliver_binary.yml", MON / "tasks" / "legacy_switch_binary.yml",
                 MON / "tasks" / "raw_upload.yml"):
        for spec_id, gate in _gated_ids(path):
            assert gate is None and (100 <= int(spec_id[4:]) <= 109 or 210 <= int(spec_id[4:]) <= 212), spec_id
    bak = _gated_ids(BAK / "tasks" / "legacy.yml")
    assert bak and all(i.startswith("BAK-2") and g is None for i, g in bak), bak    # backup differs only by version row


# --------------------------------------------------------------------------
# Rendering: the legacy content is the modern template output, byte for byte
# --------------------------------------------------------------------------

def _id(flag):
    return subprocess.run(["id", flag], capture_output=True, text=True).stdout.strip()


def _env_vars(tmp_path):
    """Role defaults + constants, redirected into tmp_path, as extra-vars (highest precedence)."""
    v = {}
    for f in (MON / "defaults" / "main.yml", BAK / "defaults" / "main.yml", MON / "vars" / "main.yml"):
        v.update(_yaml(f))
    t = str(tmp_path)
    for d in ("etc/systemd", "etc/cron.d", "etc/logrotate.d", "sbin"):     # exist on a real host
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    v.update({
        "host_agents_os_path": "legacy_el7", "host_agents_os_arch": "amd64", "host_agents_os_type": "linux",
        "host_agents_os_description": "CentOS Linux 7 (Core)", "host_agents_os_family": "RedHat",
        "host_agents_os_major_version": "7",
        "host_agents_owner": _id("-un"), "host_agents_group": _id("-gn"),
        "host_agents_cache_dir": t + "/cache", "host_agents_install_root": t + "/opt", "host_agents_bin_dir": t + "/bin",
        "otelcol_storage_dir": t + "/var/otelcol", "otelcol_config_dir": t + "/etc/otelcol",
        "otelcol_config_path": t + "/etc/otelcol/config.yaml", "otelcol_secrets_dir": t + "/etc/otelcol-contrib",
        "otelcol_secrets_path": t + "/etc/otelcol-contrib/secrets.env", "otelcol_systemd_unit_dir": t + "/etc/systemd",
        "otel_backup_log_path": t + "/var/log/backup.jsonl",
        "o2_endpoint": "https://o2.example:5080", "o2_org": "default",
        "host_agents_inputs": {"otel_logs": [{"path": "/var/log/messages", "stream": "system_logs"},
                                             {"path": "/var/log/secure", "stream": "security_logs"}],
                               "otel_docker_metrics": False, "backup_pre_hooks": ["pg_dump -f /var/backups/db.sql mydb"],
                               "backup_paths": ["/etc"], "backup_exclude_paths": []},
        "host_agents_secrets": {"o2_ingest_token": "s3cr3t-token", "rustfs_access_key": "AKIA-secret",
                                "rustfs_secret_key": "S3-secret", "restic_password": "pw-secret"},
        "host_agents_journald": False,
        "backup_config_dir": t + "/etc/restic", "backup_env_path": t + "/etc/restic/env",
        "backup_password_path": t + "/etc/restic/password", "backup_profile_path": t + "/etc/restic/profiles.yaml",
        "backup_cache_dir": t + "/var/cache/restic", "backup_event_script_path": t + "/sbin/host-agents-backup-event",
        "backup_log_dir": t + "/var/log/host-agents", "backup_log_path": t + "/var/log/host-agents/backup.jsonl",
        "backup_state_dir": t + "/var/lib/host-agents", "backup_status_file": t + "/var/lib/host-agents/status.json",
        "backup_logrotate_path": t + "/etc/logrotate.d/host-agents-backup", "backup_cron_path": t + "/etc/cron.d/host-agents-backup",
        "backup_restic_binary": t + "/opt/restic/0.19.1/restic",
        "backup_repository": t + "/repo", "backup_sources": ["/etc", "/opt/services"],
        "backup_excludes": v["backup_standard_excludes"] + ["/data/tmp"],
        "backup_schedule_hour": 2, "backup_schedule_minute": 7,
        "backup_run_command": t + "/bin/resticprofile backup",
        "rustfs_endpoint": "https://rustfs.example:9000", "rustfs_ca_file": "",
        "backup_init_enabled": False,
    })
    return v


def _play(tmp_path, tasks, extra, check=False, tags=None, path_env=None, handlers=None):
    import sys
    vars_file = tmp_path / "vars.json"
    vars_file.write_text(json.dumps(extra))
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "connection": "local", "become": False,
        "vars": {"ansible_user": getpass.getuser(), "ansible_host": "127.0.0.1", "ansible_port": 2222,
                 "ansible_ssh_private_key_file": "/tmp/secret-key-path"},
        "tasks": tasks, "handlers": handlers or []}]))
    env = dict(os.environ, ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"), ANSIBLE_NOCOLOR="1",
               ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"), **(path_env or {}))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb), "-e", "@" + str(vars_file)]
    if check:
        cmd += ["--check", "--diff"]
    if tags:
        cmd += ["--tags", tags]
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR,
                          timeout=300, env=env)


RENDERED = [  # (role, template, secret?)
    (MON, "otelcol-contrib.yaml.j2"), (MON, "secrets.env.j2"), (MON, "otelcol-contrib.service.j2"),
    (BAK, "profiles.yaml.j2"), (BAK, "restic.env.j2"), (BAK, "host-agents-backup.cron.j2"),
    (BAK, "host-agents-backup.logrotate.j2"),
]


@pytest.mark.parametrize("role,name", RENDERED, ids=[n for _, n in RENDERED])
def test_lookup_render_is_byte_identical_to_the_template_module(tmp_path, role, name):
    extra = _env_vars(tmp_path)
    extra["otelcol_run_as_root"] = False                      # one source, compared against itself (modern flavor)
    tasks = [
        {"ansible.builtin.template": {"src": str(role / "templates" / name), "dest": str(tmp_path / "via-template")}},
        {"ansible.builtin.copy": {"content": "{{ lookup('ansible.builtin.template', '%s') }}" % (role / "templates" / name),
                                  "dest": str(tmp_path / "via-lookup")}},
    ]
    res = _play(tmp_path, tasks, extra)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (tmp_path / "via-lookup").read_bytes() == (tmp_path / "via-template").read_bytes()


def test_unit_runs_as_root_with_the_remaining_hardening_on_legacy_only(tmp_path):
    def unit(root):
        extra = _env_vars(tmp_path)
        extra["otelcol_run_as_root"] = root
        res = _play(tmp_path, [{"ansible.builtin.template": {"src": str(MON / "templates" / "otelcol-contrib.service.j2"),
                                                           "dest": str(tmp_path / "u")}}], extra)
        assert res.returncode == 0, res.stdout + res.stderr
        return (tmp_path / "u").read_text()
    legacy, modern = unit(True), unit(False)
    for line in ("User=root", "Group=root", "NoNewPrivileges=true", "ProtectSystem=full", "ProtectHome=true",
                 "PrivateTmp=true", "EnvironmentFile="):
        assert line in legacy
    assert "CAP_DAC_READ_SEARCH" not in legacy and "AmbientCapabilities" not in legacy
    assert "User=otelcol" in modern and "AmbientCapabilities=CAP_DAC_READ_SEARCH" in modern
    assert "User=root" not in modern
    assert _yaml(MON / "defaults" / "main.yml")["otelcol_run_as_root"] == \
        "{{ host_agents_is_legacy | default(false) | bool }}"


# --------------------------------------------------------------------------
# Execution: the real legacy task files under ansible-playbook (local connection)
# --------------------------------------------------------------------------

def _fakebin(tmp_path):
    """Fake scp (copy) and systemctl (stateful, logged) on PATH."""
    b = tmp_path / "fakebin"
    b.mkdir(exist_ok=True)
    (b / "scp").write_text('#!/bin/sh\necho "$@" >> %s/scp.log\nfor a; do last="$a"; done\n'
                           'src=""; for a; do prev="$src"; src="$a"; done\ncp "$prev" "${last#*:}"\n' % tmp_path)
    (b / "systemctl").write_text(
        '#!/bin/sh\necho "$@" >> %(t)s/systemctl.log\nst=%(t)s/systemctl.state; touch "$st"\n'
        'case "$1" in\n is-enabled) grep -q "^enabled $2$" "$st";;\n is-active) grep -q "^active $2$" "$st";;\n'
        ' enable) echo "enabled $2" >> "$st";;\n start) echo "active $2" >> "$st";;\n *) true;;\nesac\n' % {"t": tmp_path})
    for f in ("scp", "systemctl"):
        (b / f).chmod(0o755)
    return {"PATH": "%s:%s" % (b, os.environ["PATH"])}


def _release_tar(tmp_path, name, member, body):
    """Deterministic tarball (fixed gzip/tar mtimes) so repeated runs see the same SHA256."""
    import gzip
    tgz = tmp_path / name
    if not tgz.exists():
        info = tarfile.TarInfo(member)
        info.size, info.mode, info.mtime = len(body), 0o755, 0
        with open(tgz, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
                tarfile.open(fileobj=gz, mode="w") as t:
            t.addfile(info, io.BytesIO(body))
    return tgz


def _fake_otel_release(tmp_path):
    body = b"#!/bin/sh\n[ \"$1\" = validate ] && exit 0\n[ \"$1\" = --version ] && echo otelcol-contrib 9.9.9 && exit 0\nexit 3\n"
    tgz = _release_tar(tmp_path, "otelcol-contrib_9.9.9_linux_amd64.tar.gz", "otelcol-contrib", body)
    return tgz, hashlib.sha256(tgz.read_bytes()).hexdigest(), body


def _mon_extra(tmp_path):
    extra = _env_vars(tmp_path)
    tgz, sha, _ = _fake_otel_release(tmp_path)
    extra["host_agents_versions"] = {"default": dict(extra["host_agents_versions"]["default"], otelcol_contrib="9.9.9")}
    extra["host_agents_checksums"] = dict(extra["host_agents_checksums"],
                                         otelcol_contrib={"9.9.9": {"amd64": sha}})
    # deliver URL is file://: patch via the cache seed instead of the network (fetch_binary downloads with get_url).
    return extra, tgz


def _run_mon(tmp_path, check=False, tags=None):
    extra, tgz = _mon_extra(tmp_path)
    cache = tmp_path / "cache" / "otelcol-contrib" / "9.9.9"
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / tgz.name
    if not target.exists():
        shutil.copy(tgz, target)
    (tmp_path / "bin").mkdir(exist_ok=True)
    tasks = [{"ansible.builtin.import_role": {"name": "monitoring", "tasks_from": "legacy.yml"}}]
    return _play(tmp_path, tasks, extra, check=check, tags=tags, path_env=_fakebin(tmp_path))


def _mon_state(tmp_path):
    t = tmp_path
    return {"bin": t / "bin" / "otelcol-contrib", "cfg": t / "etc" / "otelcol" / "config.yaml",
            "env": t / "etc" / "otelcol-contrib" / "secrets.env", "unit": t / "etc" / "systemd" / "otelcol-contrib.service"}


def test_otelcol_legacy_deploy_installs_validates_switches_and_enables_then_is_idempotent(tmp_path):
    res = _run_mon(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    s = _mon_state(tmp_path)
    opt = tmp_path / "opt" / "otelcol-contrib" / "9.9.9"
    assert s["bin"].is_symlink() and s["bin"].readlink() == opt / "otelcol-contrib"
    assert (opt / "otelcol-contrib").read_bytes() == _fake_otel_release(tmp_path)[2]
    assert oct(s["env"].stat().st_mode & 0o777) == "0o600" and oct(s["cfg"].stat().st_mode & 0o777) == "0o640"
    assert "User=root" in s["unit"].read_text()
    assert "s3cr3t-token" not in res.stdout + res.stderr
    assert "o2.example:5080/api/default" in s["cfg"].read_text()
    log = (tmp_path / "systemctl.log").read_text().splitlines()
    assert "daemon-reload" in log and "enable otelcol-contrib" in log and "start otelcol-contrib" in log
    assert "restart otelcol-contrib" in log                              # first install restarts through the handler
    assert "-P 2222" in (tmp_path / "scp.log").read_text()
    # Second run: nothing changes, nothing restarts, nothing is uploaded again.
    (tmp_path / "systemctl.log").unlink()
    (tmp_path / "scp.log").unlink()
    res2 = _run_mon(tmp_path)
    assert res2.returncode == 0, res2.stdout + res2.stderr
    assert "changed=0" in res2.stdout, res2.stdout
    assert not (tmp_path / "scp.log").exists()
    assert not (tmp_path / "systemctl.log").exists() or "restart" not in (tmp_path / "systemctl.log").read_text()


def test_smoke_failure_fails_the_host_and_keeps_the_old_symlink(tmp_path):
    res = _run_mon(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    s = _mon_state(tmp_path)
    old_target = s["bin"].readlink()
    # A new "release" whose binary cannot run (e.g. glibc/kernel too old) must not switch the symlink.
    extra, _ = _mon_extra(tmp_path)
    body = b"#!/bin/sh\nexit 127\n"
    tgz = _release_tar(tmp_path, "otelcol-contrib_9.9.10_linux_amd64.tar.gz", "otelcol-contrib", body)
    cache = tmp_path / "cache" / "otelcol-contrib" / "9.9.10"
    cache.mkdir(parents=True)
    shutil.copy(tgz, cache / tgz.name)
    extra["host_agents_versions"] = {"default": dict(extra["host_agents_versions"]["default"], otelcol_contrib="9.9.10")}
    extra["host_agents_checksums"] = {"otelcol_contrib": {"9.9.10": {"amd64": hashlib.sha256(tgz.read_bytes()).hexdigest()}}}
    res = _play(tmp_path, [{"ansible.builtin.import_role": {"name": "monitoring", "tasks_from": "legacy.yml"}}],
                extra, path_env=_fakebin(tmp_path))
    assert res.returncode != 0 and "MON-211" in res.stdout
    assert s["bin"].readlink() == old_target                              # fallback: previous version stays in service


def test_config_tag_run_reapplies_config_without_reinstalling(tmp_path):
    assert _run_mon(tmp_path).returncode == 0
    s = _mon_state(tmp_path)
    s["cfg"].write_text("stale: true\n")
    s["env"].unlink()
    (tmp_path / "scp.log").unlink()
    (tmp_path / "systemctl.log").unlink()
    res = _run_mon(tmp_path, tags="agents_config")
    assert res.returncode == 0, res.stdout + res.stderr
    # The tag filter must reach the include/import'ed raw tasks, not only the blocks.
    assert "o2.example:5080/api/default" in s["cfg"].read_text() and s["env"].exists()
    assert not (tmp_path / "scp.log").exists()                           # no binary upload on a Config run
    log = (tmp_path / "systemctl.log").read_text().splitlines()
    assert "restart otelcol-contrib" in log and "daemon-reload" not in log


def test_install_tag_run_installs_binary_and_unit_without_touching_config(tmp_path):
    res = _run_mon(tmp_path, tags="agents_install")
    s = _mon_state(tmp_path)
    # Binary delivery and the unit run; nothing from the config phase is written.
    assert (tmp_path / "opt" / "otelcol-contrib" / "9.9.9" / "otelcol-contrib").exists() and s["unit"].exists()
    assert not s["cfg"].exists() and not s["env"].exists()


def test_check_mode_probes_and_prints_diff_without_secrets_or_changes(tmp_path):
    first = _run_mon(tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    s = _mon_state(tmp_path)
    s["cfg"].write_text("stale: true\n")
    s["env"].write_text("O2_BASIC_AUTH=old-secret-value\n")
    res = _run_mon(tmp_path, check=True, tags="agents_config")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "-stale: true" in res.stdout and "remote:" in res.stdout
    assert "old-secret-value" not in res.stdout and "s3cr3t-token" not in res.stdout
    assert "secret content hidden" in res.stdout
    assert s["cfg"].read_text() == "stale: true\n" and s["env"].read_text() == "O2_BASIC_AUTH=old-secret-value\n"


# ---- backup ---------------------------------------------------------------------------------------------

def _fake_backup_releases(tmp_path):
    restic = bz2.compress(b"#!/bin/sh\necho restic-fixture\n")
    rtgz = tmp_path / "restic_0.19.1_linux_amd64.bz2"
    rtgz.write_bytes(restic)
    rp = _release_tar(tmp_path, "resticprofile_no_self_update_0.33.1_linux_amd64.tar.gz", "resticprofile",
                      b"#!/bin/sh\necho resticprofile-fixture\n")
    return rtgz, rp


def _run_bak(tmp_path, check=False, tags=None):
    extra = _env_vars(tmp_path)
    rtgz, rp = _fake_backup_releases(tmp_path)
    extra["host_agents_checksums"] = dict(extra["host_agents_checksums"],
                                         restic={"0.19.1": {"amd64": hashlib.sha256(rtgz.read_bytes()).hexdigest()}},
                                         resticprofile={"0.33.1": {"amd64": hashlib.sha256(rp.read_bytes()).hexdigest()}})
    for agent, ver, f in (("restic", "0.19.1", rtgz), ("resticprofile", "0.33.1", rp)):
        d = tmp_path / "cache" / agent / ver
        d.mkdir(parents=True, exist_ok=True)
        if not (d / f.name).exists():
            shutil.copy(f, d / f.name)
    (tmp_path / "bin").mkdir(exist_ok=True)
    tasks = [{"ansible.builtin.import_role": {"name": "backup", "tasks_from": "legacy.yml"}}]
    return _play(tmp_path, tasks, extra, check=check, tags=tags, path_env=_fakebin(tmp_path),
                 handlers=[])


@needs_restic
def test_backup_legacy_deploy_writes_cron_profile_evidence_files_and_is_idempotent(tmp_path):
    # The real resticprofile validates the profile, so the "delivered" tools are the real binaries.
    extra = _env_vars(tmp_path)
    pytest.importorskip("yaml")
    rtgz = tmp_path / "restic_0.19.1_linux_amd64.bz2"
    rtgz.write_bytes(bz2.compress(Path(shutil.which("restic")).read_bytes()))
    rp_body = Path(shutil.which("resticprofile")).read_bytes()
    rp = _release_tar(tmp_path, "resticprofile_no_self_update_0.33.1_linux_amd64.tar.gz", "resticprofile", rp_body)
    extra["host_agents_checksums"] = dict(extra["host_agents_checksums"],
                                         restic={"0.19.1": {"amd64": hashlib.sha256(rtgz.read_bytes()).hexdigest()}},
                                         resticprofile={"0.33.1": {"amd64": hashlib.sha256(rp.read_bytes()).hexdigest()}})
    for agent, ver, f in (("restic", "0.19.1", rtgz), ("resticprofile", "0.33.1", rp)):
        d = tmp_path / "cache" / agent / ver
        d.mkdir(parents=True)
        shutil.copy(f, d / f.name)
    (tmp_path / "bin").mkdir()
    extra["backup_init_enabled"] = True
    extra["backup_run_command"] = "%s/bin/resticprofile -f yaml -c %s -n default backup" % (tmp_path, extra["backup_profile_path"])
    tasks = [{"ansible.builtin.import_role": {"name": "backup", "tasks_from": "legacy.yml"}}]
    handlers = [{"name": "Refresh backup tooling", "ansible.builtin.debug": {"msg": "refreshed"}}]
    res = _play(tmp_path, tasks, extra, path_env=_fakebin(tmp_path), handlers=handlers)
    assert res.returncode == 0, res.stdout + res.stderr
    t = tmp_path
    cron = (t / "etc" / "cron.d" / "host-agents-backup").read_text()
    assert cron.splitlines()[-1].startswith("7 2 * * * root set -a; . %s/etc/restic/env" % t)
    prof = yaml.safe_load((t / "etc" / "restic" / "profiles.yaml").read_text())["default"]
    assert prof["backup"]["run-finally"] and prof["status-file"].endswith("status.json")
    assert (t / "bin" / "restic").is_symlink() and (t / "bin" / "resticprofile").is_symlink()
    for p, mode in (("etc/restic/env", "0o600"), ("etc/restic/password", "0o600"), ("etc/restic/profiles.yaml", "0o600"),
                    ("sbin/host-agents-backup-event", "0o755"), ("etc/cron.d/host-agents-backup", "0o644")):
        assert oct((t / p).stat().st_mode & 0o777) == mode, p
    assert (t / "etc" / "restic" / "password").read_text() == "pw-secret"
    assert (t / "var" / "log" / "host-agents").is_dir() and (t / "var" / "lib" / "host-agents").is_dir()
    assert "AKIA-secret" not in res.stdout and "pw-secret" not in res.stdout and "S3-secret" not in res.stdout
    assert (t / "sbin" / "host-agents-backup-event").read_text() == (BAK / "files" / "host-agents-backup-event.sh").read_text()
    # The repository does not exist yet in the profile's S3 location, so init is attempted over raw.
    assert "BAK-215" in res.stdout and "BAK-216" in res.stdout
    res2 = _play(tmp_path, tasks, dict(extra, backup_init_enabled=False), path_env=_fakebin(tmp_path), handlers=handlers)
    assert res2.returncode == 0, res2.stdout + res2.stderr
    assert "changed=0" in res2.stdout, res2.stdout


def test_backup_legacy_install_tag_run_has_no_config_phase_and_config_tag_has_no_install(tmp_path):
    extra = _env_vars(tmp_path)
    _fake_backup_releases(tmp_path)
    res = _play(tmp_path, [{"ansible.builtin.import_role": {"name": "backup", "tasks_from": "legacy.yml"}}],
                extra, tags="agents_config", path_env=_fakebin(tmp_path))
    # No binaries exist, so the validated profile push fails — but the phase selection is already visible.
    out = res.stdout
    assert "BAK-203" in out and "BAK-209" not in out and "BAK-213" not in out and "BAK-215" not in out
    assert (tmp_path / "etc" / "restic" / "env").exists() and not (tmp_path / "scp.log").exists()


def test_backup_repo_probe_assertion_matches_the_modern_logic():
    modern = _task(BAK / "tasks" / "main.yml", "[BAK-051]")["ansible.builtin.assert"]["that"]
    legacy = _task(BAK / "tasks" / "legacy.yml", "[BAK-216]")["ansible.builtin.assert"]["that"]
    assert " ".join(str(modern).split()) == " ".join(str(legacy).split())
    for p in ("[BAK-050]", "[BAK-052]"):
        assert _task(BAK / "tasks" / "main.yml", p)["no_log"] is True
    assert _task(BAK / "tasks" / "legacy.yml", "[BAK-215]")["no_log"] is True
    assert "LC_ALL=C" in _task(BAK / "tasks" / "legacy.yml", "[BAK-215]")["ansible.builtin.raw"]
    assert _task(BAK / "tasks" / "legacy.yml", "[BAK-217]")["no_log"] is True


def test_binary_upload_wires_password_auth_through_sshpass_env_without_leaking_it():
    raw = (MON / "tasks" / "raw_upload.yml").read_text(encoding="utf-8")
    tasks = yaml.safe_load(raw)
    scp = next(t for blk in tasks if "block" in blk for t in blk["block"] if t.get("name", "").startswith("[MON-104]"))
    assert "SSHPASS" in str(scp["environment"]) and "ansible_password" in str(scp["environment"])
    assert "ansible_password" not in str(scp["ansible.builtin.command"]["argv"])
    check = next(t for blk in tasks if "block" in blk for t in blk["block"] if t.get("name", "").startswith("[MON-109]"))
    assert "sshpass" in str(check) and check["delegate_to"] == "localhost" and check["check_mode"] is False
