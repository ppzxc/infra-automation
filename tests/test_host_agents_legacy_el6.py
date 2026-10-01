"""Host Agents on CentOS 6 (legacy_el6, ADR-0006 §2.8~2.9, Spec #38 / #48).

There is no CentOS 6 image, so (like legacy_el7) the path is covered by structure tests, the real
``legacy_el6.yml`` task files executed with ``ansible-playbook`` on a local connection (fake ``scp``,
``service`` and ``chkconfig`` on PATH), the real otelcol-contrib v0.119.0 ``validate`` when the binary is
available (``OTELCOL_EL6_BIN``), and the documented canary runbook on the first real CentOS 6 host.
"""
import bz2
import hashlib
import os
import shutil
from pathlib import Path

import pytest
import yaml

import test_host_agents_legacy_el7 as el7

ROOT_DIR = Path(__file__).resolve().parent.parent
MON = ROOT_DIR / "roles" / "monitoring"
BAK = ROOT_DIR / "roles" / "backup"
_yaml, _task, _play, _release_tar = el7._yaml, el7._task, el7._play, el7._release_tar


def _env_vars(tmp_path):
    v = el7._env_vars(tmp_path)
    (tmp_path / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
    v.update({"host_agents_os_path": "legacy_el6", "host_agents_os_description": "CentOS release 6.10 (Final)",
              "host_agents_os_major_version": "6", "otelcol_sysv_init_dir": str(tmp_path / "etc" / "init.d"),
              "host_agents_today": "2026-10-01"})
    return v


def _fakebin(tmp_path):
    """Fake scp (copy) plus stateful SysV ``service``/``chkconfig`` (logged). No systemctl on purpose."""
    b = tmp_path / "fakebin"
    b.mkdir(exist_ok=True)
    (b / "scp").write_text('#!/bin/sh\necho "$@" >> %s/scp.log\nfor a; do last="$a"; done\n'
                           'src=""; for a; do prev="$src"; src="$a"; done\ncp "$prev" "${last#*:}"\n' % tmp_path)
    st = tmp_path / "sysv.state"
    (b / "service").write_text(
        '#!/bin/sh\necho "service $*" >> %(t)s/sysv.log\ntouch %(s)s\n'
        'case "$2" in\n status) grep -q "^running $1$" %(s)s;;\n start|restart) echo "running $1" >> %(s)s;;\n'
        ' *) true;;\nesac\n' % {"t": tmp_path, "s": st})
    (b / "chkconfig").write_text(
        '#!/bin/sh\ntouch %(s)s\nif [ "$1" = --list ]; then\n'
        '  if grep -q "^on $2$" %(s)s; then echo "$2 0:off 1:off 2:on 3:on 4:on 5:on 6:off"; exit 0; fi\n'
        '  grep -q "^added $2$" %(s)s && { echo "$2 0:off 1:off 2:off 3:off 4:off 5:off 6:off"; exit 0; }\n'
        '  exit 1\nfi\necho "chkconfig $*" >> %(t)s/sysv.log\n'
        'if [ "$1" = --add ]; then echo "added $2" >> %(s)s; exit 0; fi\n'
        'if [ "$2" = on ]; then grep -q "^added $1$" %(s)s || exit 1; echo "on $1" >> %(s)s; fi\n' % {"t": tmp_path, "s": st})
    for f in ("scp", "service", "chkconfig"):
        (b / f).chmod(0o755)
    # A host without systemctl: the dev box's systemctl must not be found first.
    return {"PATH": "%s:%s" % (b, os.environ["PATH"])}


def _fake_otel(tmp_path, version, body=None):
    body = body or (b"#!/bin/sh\n[ \"$1\" = validate ] && exit 0\n"
                    b"[ \"$1\" = --version ] && echo otelcol-contrib %s && exit 0\nexit 3\n" % version.encode())
    tgz = _release_tar(tmp_path, "otelcol-contrib_%s_linux_amd64.tar.gz" % version, "otelcol-contrib", body)
    cache = tmp_path / "cache" / "otelcol-contrib" / version
    cache.mkdir(parents=True, exist_ok=True)
    if not (cache / tgz.name).exists():
        shutil.copy(tgz, cache / tgz.name)
    return hashlib.sha256(tgz.read_bytes()).hexdigest()


def _mon_extra(tmp_path, el6_version="8.8.8", default_version="1.1.1"):
    """legacy_el6 and default rows get different fake versions so the selected row is observable."""
    extra = _env_vars(tmp_path)
    sums = {default_version: {"amd64": "0" * 64}, el6_version: {"amd64": _fake_otel(tmp_path, el6_version)}}
    extra["host_agents_versions"] = {
        "default": dict(extra["host_agents_versions"]["default"], otelcol_contrib=default_version),
        "legacy_el6": dict(extra["host_agents_versions"]["legacy_el6"], otelcol_contrib=el6_version)}
    extra["host_agents_checksums"] = dict(extra["host_agents_checksums"], otelcol_contrib=sums)
    (tmp_path / "bin").mkdir(exist_ok=True)
    return extra


def _run_mon(tmp_path, extra=None, check=False, tags=None):
    extra = extra or _mon_extra(tmp_path)
    tasks = [{"ansible.builtin.import_role": {"name": "monitoring", "tasks_from": "legacy_el6.yml"}}]
    return _play(tmp_path, tasks, extra, check=check, tags=tags, path_env=_fakebin(tmp_path))


# --------------------------------------------------------------------------
# Structure: gates and tag split
# --------------------------------------------------------------------------

def test_both_roles_import_the_el6_file_only_on_legacy_el6_with_the_modern_tag_split():
    for role, prefix, expected in (
            (MON, "otelcol", {"Install otelcol on CentOS 6": {"agents_install", "otel"},
                              "Apply otelcol configuration on CentOS 6": {"agents_config", "otel"},
                              "Enable otelcol service on CentOS 6": {"agents_install", "otel"}}),
            (BAK, "backup", {"Deliver restic and resticprofile on CentOS 6": {"agents_install", "backup"},
                             "Apply backup configuration on CentOS 6": {"agents_config", "backup"},
                             "Enable backup schedule on CentOS 6": {"agents_install", "backup"}})):
        imp = next(t for t in _yaml(role / "tasks" / "main.yml") if t.get("ansible.builtin.import_tasks") == "legacy_el6.yml")
        assert imp["when"] == "host_agents_os_path == 'legacy_el6'"
        blocks = {t["name"]: set(t["tags"]) for t in _yaml(role / "tasks" / "legacy_el6.yml") if "block" in t}
        assert blocks == expected


# --------------------------------------------------------------------------
# Version row (ADR-0006 §2.8)
# --------------------------------------------------------------------------

def test_legacy_el6_row_pins_go123_builds_with_checksums_for_both_architectures():
    v = _yaml(MON / "vars" / "main.yml")
    assert v["host_agents_versions"]["legacy_el6"] == {
        "otelcol_contrib": "0.119.0", "restic": "0.17.3", "resticprofile": "0.29.1"}
    assert v["host_agents_version_expiry"] == {"legacy_el6": "2027-12-31"}
    for agent, key in (("otelcol_contrib", "otelcol_contrib"), ("restic", "restic"), ("resticprofile", "resticprofile")):
        by_arch = v["host_agents_checksums"][agent][v["host_agents_versions"]["legacy_el6"][key]]
        assert set(by_arch) == {"amd64", "arm64"} and all(len(s) == 64 for s in by_arch.values())
    # Release tarball SHA256s, computed from the downloaded artifacts (not upstream checksums.txt).
    assert v["host_agents_checksums"]["otelcol_contrib"]["0.119.0"]["amd64"] == \
        "4ee77545daaad658f7282bff98704bc1f31107890e2a2e1d4b1fc31da4648111"


def test_centos6_delivers_the_legacy_el6_row_not_the_default_row(tmp_path):
    res = _run_mon(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    link = tmp_path / "bin" / "otelcol-contrib"
    assert link.readlink() == tmp_path / "opt" / "otelcol-contrib" / "8.8.8" / "otelcol-contrib"
    assert not (tmp_path / "opt" / "otelcol-contrib" / "1.1.1").exists()


@pytest.mark.parametrize("today,warned", [("2027-12-31", False), ("2028-01-01", True)])
def test_expiry_is_a_warning_not_a_failure(tmp_path, today, warned):
    extra = _mon_extra(tmp_path)
    extra["host_agents_today"] = today
    for tags in (None, "agents_config"):                       # Deploy, then Config: the warning shows on both
        res = _run_mon(tmp_path, extra, tags=tags)
        assert res.returncode == 0, res.stdout + res.stderr
        assert ("legacy_el6 버전 행이 만료" in res.stdout) is warned, res.stdout


# --------------------------------------------------------------------------
# SysV init + chkconfig sentinel (ADR-0006 §2.9)
# --------------------------------------------------------------------------

def _render_init(tmp_path, root):
    extra = _env_vars(tmp_path)
    extra["otelcol_run_as_root"] = root
    out = tmp_path / ("init-root" if root else "init-user")
    res = _play(tmp_path, [{"ansible.builtin.template": {"src": str(MON / "templates" / "otelcol-contrib.init.j2"),
                                                       "dest": str(out)}}], extra)
    assert res.returncode == 0, res.stdout + res.stderr
    return out.read_text()


def test_init_script_runs_as_root_loads_secrets_and_registers_with_chkconfig(tmp_path):
    legacy = _render_init(tmp_path, True)
    assert "# chkconfig: 2345 90 10" in legacy                     # chkconfig --add reads this header
    assert 'nohup "$EXEC" --config="$CONFIG"' in legacy and "su -s" not in legacy and 'USER="' not in legacy
    assert 'SECRETS="%s/etc/otelcol-contrib/secrets.env"' % tmp_path in legacy and '. "$SECRETS"' in legacy
    assert 'EXEC="%s/bin/$PROG"' % tmp_path in legacy
    modern_sysv = _render_init(tmp_path, False)                     # modern non-systemd hosts keep the otelcol user
    assert "su -s /bin/sh $USER" in modern_sysv and 'USER="otelcol"' in modern_sysv
    assert _yaml(MON / "defaults" / "main.yml")["otelcol_run_as_root"] == \
        "{{ host_agents_os_path | default('modern') in ['legacy_el6', 'legacy_el7'] }}"


def test_sysv_sentinel_uses_chkconfig_list_and_never_systemctl():
    import sys
    sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
    from raw_provisioning import raw_sysv_service_cmd
    cmd = raw_sysv_service_cmd("otelcol-contrib")
    assert "systemctl" not in cmd
    assert 'chkconfig --list otelcol-contrib 2>/dev/null | grep -q "3:on"' in cmd
    assert "chkconfig --add otelcol-contrib && chkconfig otelcol-contrib on" in cmd
    assert "service otelcol-contrib status" in cmd and "service otelcol-contrib start" in cmd


def test_deploy_installs_init_script_enables_with_chkconfig_and_is_idempotent(tmp_path):
    res = _run_mon(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    init = tmp_path / "etc" / "init.d" / "otelcol-contrib"
    assert oct(init.stat().st_mode & 0o777) == "0o755" and "chkconfig: 2345" in init.read_text()
    cfg = (tmp_path / "etc" / "otelcol" / "config.yaml").read_text()
    keys = yaml.safe_load(cfg)["exporters"]
    assert keys["otlphttp/security_logs"]["sending_queue"] == {
        "enabled": True, "storage": "file_storage", "queue_size": 64, "blocking": True}
    assert keys["otlphttp/metrics"]["sending_queue"] == {"enabled": True, "blocking": False}
    assert "s3cr3t-token" not in res.stdout + res.stderr
    log = (tmp_path / "sysv.log").read_text().splitlines()
    assert "chkconfig --add otelcol-contrib" in log and "chkconfig otelcol-contrib on" in log
    assert "service otelcol-contrib restart" in log                  # first install restarts through the handler
    assert not (tmp_path / "systemctl.log").exists()
    (tmp_path / "sysv.log").unlink()
    (tmp_path / "scp.log").unlink()
    res2 = _run_mon(tmp_path)
    assert res2.returncode == 0, res2.stdout + res2.stderr
    assert "changed=0" in res2.stdout, res2.stdout
    assert not (tmp_path / "scp.log").exists()
    assert not (tmp_path / "sysv.log").exists() or "restart" not in (tmp_path / "sysv.log").read_text()


def test_chkconfig_sentinel_reenables_a_service_switched_off_out_of_band(tmp_path):
    assert _run_mon(tmp_path).returncode == 0
    st = tmp_path / "sysv.state"
    st.write_text("".join(ln for ln in st.read_text().splitlines(True) if not ln.startswith("on ")))
    (tmp_path / "sysv.log").unlink()
    res = _run_mon(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "MON-121" in res.stdout and "chkconfig otelcol-contrib on" in (tmp_path / "sysv.log").read_text()
    assert "changed=1" in res.stdout, res.stdout


# --------------------------------------------------------------------------
# sending_queue compatibility with the real v0.119.0 (ADR-0006 §2.8 outcome)
# --------------------------------------------------------------------------

def _render_config(tmp_path, os_path):
    extra = _env_vars(tmp_path)
    extra["host_agents_os_path"] = os_path
    out = tmp_path / ("config-%s.yaml" % os_path)
    res = _play(tmp_path, [{"ansible.builtin.template": {"src": str(MON / "templates" / "otelcol-contrib.yaml.j2"),
                                                       "dest": str(out)}}], extra)
    assert res.returncode == 0, res.stdout + res.stderr
    return out


def test_modern_and_el7_keep_the_bytes_queue_with_block_on_overflow(tmp_path):
    for os_path in ("modern", "legacy_el7"):
        exporters = yaml.safe_load(_render_config(tmp_path, os_path).read_text())["exporters"]
        q = exporters["otlphttp/system_logs"]["sending_queue"]
        assert q["sizer"] == "bytes" and q["block_on_overflow"] is True and "blocking" not in q


@pytest.mark.skipif(not os.environ.get("OTELCOL_EL6_BIN"),
                    reason="set OTELCOL_EL6_BIN to an otelcol-contrib v0.119.0 binary")
def test_real_otelcol_0_119_0_validates_the_el6_config_and_rejects_the_modern_one(tmp_path):
    import subprocess
    binary = os.environ["OTELCOL_EL6_BIN"]
    assert "0.119.0" in subprocess.run([binary, "--version"], capture_output=True, text=True).stdout
    (tmp_path / "var" / "otelcol").mkdir(parents=True)                # file_storage requires the directory
    env = dict(os.environ, O2_BASIC_AUTH="dGVzdA==")
    el6 = subprocess.run([binary, "validate", "--config=%s" % _render_config(tmp_path, "legacy_el6")],
                         capture_output=True, text=True, env=env)
    assert el6.returncode == 0, el6.stdout + el6.stderr
    modern = subprocess.run([binary, "validate", "--config=%s" % _render_config(tmp_path, "modern")],
                            capture_output=True, text=True, env=env)
    assert modern.returncode != 0 and "invalid keys: block_on_overflow, sizer" in modern.stderr


# --------------------------------------------------------------------------
# Backup on CentOS 6 (BAK-1xx): legacy_el6 restic/resticprofile, cron.d
# --------------------------------------------------------------------------

def _derive(tmp_path, os_path):
    """Run the shared BAK-010..013 derivation (main.yml) for os_path and return the derived facts."""
    import json
    main = el7._tasks(BAK / "tasks" / "main.yml")
    tasks = [t for t in main if t.get("name", "").startswith(("[BAK-201]", "[BAK-202]", "[BAK-012]", "[BAK-013]"))]
    out = tmp_path / "derived.json"
    tasks.append({"ansible.builtin.copy": {"dest": str(out), "content":
                  "{{ {'bin': backup_restic_binary, 'cron': backup_use_cron | bool, "
                  "'cond': _backup_conditional.results | map(attribute='item') | list} | to_json }}"}})
    extra = _env_vars(tmp_path)
    for k in ("backup_restic_binary", "backup_sources", "backup_excludes", "backup_repository"):
        extra.pop(k)
    extra.update(host_agents_os_path=os_path, host_agents_install_root="/opt/host-agents",
                 host_agents_inputs={"backup_paths": ["/etc"], "backup_exclude_paths": [], "backup_pre_hooks": []})
    res = _play(tmp_path, tasks, extra)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(out.read_text())


def test_shared_backup_derivation_uses_the_legacy_el6_row_and_cron_on_centos6(tmp_path):
    d = _derive(tmp_path, "legacy_el6")
    assert d == {"bin": "/opt/host-agents/restic/0.17.3/restic", "cron": True, "cond": ["/opt/services"]}
    assert _derive(tmp_path, "legacy_el7")["bin"] == "/opt/host-agents/restic/0.19.1/restic"


def _run_bak(tmp_path, tags=None):
    extra = _env_vars(tmp_path)
    extra["backup_restic_binary"] = str(tmp_path / "opt" / "restic" / "0.17.3" / "restic")
    rtgz = tmp_path / "restic_0.17.3_linux_amd64.bz2"
    rtgz.write_bytes(bz2.compress(b"#!/bin/sh\necho restic-fixture\n"))
    # resticprofile validates the profile with "show": the fixture accepts it like the real 0.29.1 does.
    rp = _release_tar(tmp_path, "resticprofile_no_self_update_0.29.1_linux_amd64.tar.gz", "resticprofile",
                      b"#!/bin/sh\necho resticprofile-fixture\n")
    extra["host_agents_checksums"] = dict(extra["host_agents_checksums"],
                                         restic={"0.17.3": {"amd64": hashlib.sha256(rtgz.read_bytes()).hexdigest()}},
                                         resticprofile={"0.29.1": {"amd64": hashlib.sha256(rp.read_bytes()).hexdigest()}})
    for agent, ver, f in (("restic", "0.17.3", rtgz), ("resticprofile", "0.29.1", rp)):
        d = tmp_path / "cache" / agent / ver
        d.mkdir(parents=True, exist_ok=True)
        if not (d / f.name).exists():
            shutil.copy(f, d / f.name)
    (tmp_path / "bin").mkdir(exist_ok=True)
    tasks = [{"ansible.builtin.import_role": {"name": "backup", "tasks_from": "legacy_el6.yml"}}]
    handlers = [{"name": "Refresh backup tooling", "ansible.builtin.debug": {"msg": "refreshed"}}]
    return _play(tmp_path, tasks, extra, tags=tags, path_env=_fakebin(tmp_path), handlers=handlers)


def test_backup_el6_deploy_installs_el6_tools_writes_cron_and_is_idempotent(tmp_path):
    res = _run_bak(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    t = tmp_path
    assert (t / "bin" / "restic").readlink() == t / "opt" / "restic" / "0.17.3" / "restic"
    assert (t / "bin" / "resticprofile").readlink() == t / "opt" / "resticprofile" / "0.29.1" / "resticprofile"
    cron = (t / "etc" / "cron.d" / "host-agents-backup").read_text()
    assert cron.splitlines()[-1].startswith("7 2 * * * root set -a; . %s/etc/restic/env" % t)
    prof = yaml.safe_load((t / "etc" / "restic" / "profiles.yaml").read_text())
    assert prof["global"]["restic-binary"].endswith("/restic/0.17.3/restic")
    for p, mode in (("etc/restic/env", "0o600"), ("etc/restic/password", "0o600"), ("etc/restic/profiles.yaml", "0o600"),
                    ("sbin/host-agents-backup-event", "0o755"), ("etc/cron.d/host-agents-backup", "0o644")):
        assert oct((t / p).stat().st_mode & 0o777) == mode, p
    assert "AKIA-secret" not in res.stdout and "pw-secret" not in res.stdout and "S3-secret" not in res.stdout
    res2 = _run_bak(tmp_path)
    assert res2.returncode == 0, res2.stdout + res2.stderr
    assert "changed=0" in res2.stdout, res2.stdout


@pytest.mark.skipif(not (os.environ.get("RESTICPROFILE_EL6_BIN") and os.environ.get("RESTIC_EL6_BIN")),
                    reason="set RESTICPROFILE_EL6_BIN/RESTIC_EL6_BIN to resticprofile v0.29.1 / restic 0.17.3")
def test_real_resticprofile_0_29_1_accepts_the_profile_with_restic_0_17_3(tmp_path):
    import subprocess
    extra = _env_vars(tmp_path)
    extra["backup_restic_binary"] = os.environ["RESTIC_EL6_BIN"]
    out = tmp_path / "profiles.yaml"
    res = _play(tmp_path, [{"ansible.builtin.template": {"src": str(BAK / "templates" / "profiles.yaml.j2"),
                                                       "dest": str(out)}}], extra)
    assert res.returncode == 0, res.stdout + res.stderr
    rp = subprocess.run([os.environ["RESTICPROFILE_EL6_BIN"], "-f", "yaml", "-c", str(out), "-n", "default", "show"],
                        capture_output=True, text=True)
    assert rp.returncode == 0, rp.stdout + rp.stderr
    assert "0.17.3" in subprocess.run([os.environ["RESTIC_EL6_BIN"], "version"], capture_output=True, text=True).stdout
