"""Raw Provisioning Path helper contract (ADR-0005).

The rendered shell commands are executed with a local ``sh`` and only their
observable effects (files, modes, exit codes) are asserted.
"""
import getpass
import grp
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from raw_provisioning import (  # noqa: E402
    raw_probe_cmd, raw_push_changed, raw_push_cmd, raw_read_cmd,
    raw_parse_os_release, raw_classify_os_path, raw_read_extract, raw_set_directives,
    raw_changed, raw_group_cmd, raw_user_cmd, raw_authorized_key_cmd,
    raw_sysctl_directives, raw_limits_directives, raw_sudoers_line,
    raw_rm_cmd, raw_yum_cmd, raw_sysctl_live_cmd, raw_service_cmd,
    raw_iptables_cmd, raw_iptables_absent, raw_timezone_cmd, raw_selinux_cmd,
    raw_firewalld_cmd, raw_firewalld_present, raw_firewalld_absent, raw_firewalld_failed,
    raw_firewalld_masquerade_off_cmd, raw_firewalld_plan, raw_default_iface_cmd,
)

OWNER = getpass.getuser()
GROUP = grp.getgrgid(os.getgid()).gr_name
CONTENT = "Port 22\nPermitRootLogin no\n"


def sh(cmd):
    return subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)


def push(dest, content=CONTENT, mode="0640", validate="true"):
    return sh(raw_push_cmd(content, str(dest), OWNER, GROUP, mode, validate))


def test_failed_validation_preserves_original_and_removes_temp(tmp_path):
    dest = tmp_path / "sshd_config"
    dest.write_bytes(b"original\n")
    r = push(dest, validate="false")
    assert r.returncode != 0
    assert dest.read_bytes() == b"original\n"
    assert list(tmp_path.iterdir()) == [dest]


def test_successful_validation_replaces_content_and_mode(tmp_path):
    dest = tmp_path / "sshd_config"
    dest.write_bytes(b"original\n")
    r = push(dest, mode="0640")
    assert r.returncode == 0, r.stderr
    assert dest.read_text() == CONTENT
    assert stat.S_IMODE(dest.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [dest]


def test_creates_missing_dest(tmp_path):
    dest = tmp_path / "new"
    assert push(dest).returncode == 0
    assert dest.read_text() == CONTENT


def test_temp_file_is_0600_when_validated(tmp_path):
    dest = tmp_path / "sshd_config"
    record = tmp_path / "mode.txt"
    r = push(dest, mode="0644", validate="stat -c %%a %%s > %s" % record)
    assert r.returncode == 0, r.stderr
    assert record.read_text().strip() == "600"


def test_validator_receives_the_pushed_content(tmp_path):
    dest = tmp_path / "sshd_config"
    seen = tmp_path / "seen.txt"
    assert push(dest, validate="cp %%s %s" % seen).returncode == 0
    assert seen.read_text() == CONTENT


def test_content_with_shell_metacharacters_is_preserved(tmp_path):
    nasty = "a'b\"c $(echo x) `id` \\ ; | &\n\n  trailing  \n"
    dest = tmp_path / "f"
    assert push(dest, content=nasty).returncode == 0
    assert dest.read_text() == nasty


def test_restorecon_absent_or_failing_does_not_fail_task(tmp_path):
    dest = tmp_path / "f"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "restorecon"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    cmd = "PATH=%s:$PATH; %s" % (
        bindir, raw_push_cmd(CONTENT, str(dest), OWNER, GROUP, "0600", "true"))
    assert sh(cmd).returncode == 0
    assert dest.read_text() == CONTENT
    # absent: no restorecon anywhere on PATH
    dest2 = tmp_path / "g"
    cmd = "PATH=/usr/bin:/bin; %s" % raw_push_cmd(
        CONTENT, str(dest2), OWNER, GROUP, "0600", "true")
    assert sh(cmd).returncode == 0


def probe(dest):
    return sh(raw_probe_cmd(str(dest))).stdout


def test_sentinel_unchanged_when_content_and_mode_match(tmp_path):
    dest = tmp_path / "f"
    push(dest, mode="0640")
    assert raw_push_changed(probe(dest), CONTENT, "0640") is False


def test_sentinel_changed_on_content_mismatch(tmp_path):
    dest = tmp_path / "f"
    push(dest, mode="0640")
    assert raw_push_changed(probe(dest), CONTENT + "x\n", "0640") is True


def test_sentinel_changed_on_mode_mismatch(tmp_path):
    dest = tmp_path / "f"
    push(dest, mode="0640")
    assert raw_push_changed(probe(dest), CONTENT, "0600") is True


def test_sentinel_changed_when_dest_absent_without_error(tmp_path):
    r = sh(raw_probe_cmd(str(tmp_path / "missing")))
    assert r.returncode == 0
    assert raw_push_changed(r.stdout, CONTENT, "0640") is True
    assert raw_push_changed(None, CONTENT, "0640") is True


def test_set_directives_replaces_or_appends_like_lineinfile():
    current = "#Port 22\nUsePAM yes\nPermitRootLogin yes\n"
    out = raw_set_directives(current, [
        {"regexp": "^#?Port", "line": "Port 2222"},
        {"regexp": "^#?PermitRootLogin", "line": "PermitRootLogin no"},
        {"regexp": "^#?MaxAuthTries", "line": "MaxAuthTries 3"},
    ])
    assert out == "Port 2222\nUsePAM yes\nPermitRootLogin no\nMaxAuthTries 3\n"
    # applying again is a fixed point (idempotent)
    assert raw_set_directives(out, [
        {"regexp": "^#?Port", "line": "Port 2222"}]) == out


def test_sentinel_ignores_banner_noise_around_probe(tmp_path):
    dest = tmp_path / "f"
    push(dest, mode="0640")
    noisy = "Welcome to legacy host\r\n" + probe(dest).replace("\n", "\r\n") + "motd\r\n"
    assert raw_push_changed(noisy, CONTENT, "0640") is False


def test_read_roundtrips_content_despite_banner_noise(tmp_path):
    src = tmp_path / "sshd_config"
    src.write_text(CONTENT)
    out = sh(raw_read_cmd(str(src))).stdout
    noisy = "banner\r\n" + out.replace("\n", "\r\n") + "trailer\r\n"
    assert raw_read_extract(noisy).strip() == CONTENT.strip()


def test_read_of_missing_or_empty_file_is_none(tmp_path):
    assert raw_read_extract(sh(raw_read_cmd(str(tmp_path / "nope"))).stdout) is None
    empty = tmp_path / "empty"
    empty.write_text("")
    assert raw_read_extract(sh(raw_read_cmd(str(empty))).stdout) is None
    assert raw_read_extract(None) is None


def _walk_tasks(tasks):
    for t in tasks:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _walk_tasks(t.get(key, []) or [])


def test_raw_tasks_declare_change_control_and_no_lineinfile_directive_duplication():
    import yaml
    role = ROOT_DIR / "roles" / "security"
    tasks = list(_walk_tasks(yaml.safe_load((role / "tasks" / "main.yml").read_text())))
    raw = [t for t in tasks if "ansible.builtin.raw" in t]
    assert raw, "expected raw tasks in the security role"
    for t in raw:
        assert "changed_when" in t, t["name"]
        assert "failed_when" in t or t["name"].startswith("[SEC-022]"), t["name"]
    # both paths share one directive list
    assert "ssh_hardening_directives" in (role / "defaults" / "main.yml").read_text()


@pytest.mark.parametrize("stdout, distribution, major, version", [
    ("CentOS release 6.10 (Final)\n", "CentOS", "6", "6.10"),
    ("CentOS Linux release 7.9.2009 (Core)\n", "CentOS", "7", "7.9.2009"),
    ("Red Hat Enterprise Linux Server release 7.9 (Maipo)\r\n", "RedHat", "7", "7.9"),
    ("Welcome to legacy box\nCentOS release 6.5 (Final)\n", "CentOS", "6", "6.5"),
    ("Banner: policy release 1.0\nCentOS release 6.5 (Final)\n", "CentOS", "6", "6.5"),
])
def test_raw_os_release_yields_distribution_and_major_version(stdout, distribution, major, version):
    facts = raw_parse_os_release(stdout)
    assert facts == {"distribution": distribution, "major_version": major, "version": version}


@pytest.mark.parametrize("stdout", [
    "", "cat: /etc/redhat-release: No such file or directory\n", "Rocky Linux release\n",
])
def test_unparseable_raw_os_release_is_rejected(stdout):
    with pytest.raises(Exception):
        raw_parse_os_release(stdout)


@pytest.mark.parametrize("stdout, expected", [
    ("CentOS release 6.10 (Final)\n", "legacy_el6"),
    ("CentOS Linux release 7.9.2009 (Core)\n", "legacy_el7"),
    ("Red Hat Enterprise Linux Server release 7.9 (Maipo)\r\n", "legacy_el7"),
    ("Red Hat Enterprise Linux release 6.10 (Santiago)\n", "legacy_el6"),
    ("Welcome to legacy box\nCentOS release 6.5 (Final)\n", "legacy_el6"),
    ("Rocky Linux release 9.3 (Blue Onyx)\n", "modern"),
    ("Red Hat Enterprise Linux release 9.2 (Plow)\n", "modern"),
    ("CentOS Stream release 9\n", "modern"),
    ("cat: /etc/redhat-release: No such file or directory\n", "modern"),
    ("", "modern"),
    (None, "modern"),
])
def test_raw_classify_os_path(stdout, expected):
    assert raw_classify_os_path(stdout) == expected


def _render(expr, **ctx):
    from jinja2 import Environment
    env = Environment()
    env.filters["raw_classify_os_path"] = raw_classify_os_path
    env.filters["bool"] = lambda v: str(v).lower() in ("true", "1", "yes")
    return env.from_string(expr).render(**ctx)


EFFECTIVE_EXPR = (ROOT_DIR / "playbooks/common/detect_raw_path.yml").read_text()


def _effective_expr():
    import yaml
    task = next(t for t in yaml.safe_load(EFFECTIVE_EXPR) if "_raw_path_effective" in (t.get("ansible.builtin.set_fact") or {}))
    return task["ansible.builtin.set_fact"]["_raw_path_effective"]


@pytest.mark.parametrize("ctx, expected", [
    ({"raw_os_release": {"stdout": "CentOS release 6.10 (Final)"}}, "True"),
    ({"raw_os_release": {"stdout": "Rocky Linux release 9.3"}}, "False"),
    ({"raw_os_release": {"stdout": ""}}, "False"),
    ({"raw_os_release": {}}, "False"),
    ({"raw_provisioning_path": False, "raw_os_release": {"stdout": "CentOS Linux release 7.9.2009"}}, "False"),
    ({"raw_provisioning_path": True, "raw_os_release": {"stdout": "Rocky Linux release 9.3"}}, "True"),
    ({"raw_provisioning_path": None, "raw_os_release": {"stdout": "CentOS release 6.10"}}, "True"),
    ({"raw_provisioning_path": "", "raw_os_release": {"stdout": "Rocky Linux release 9.3"}}, "False"),
    ({"raw_provisioning_path": "false", "raw_os_release": {"stdout": "CentOS release 6.10"}}, "False"),
])
def test_effective_raw_path_precedence(ctx, expected):
    assert _render(_effective_expr(), **ctx).strip() == expected


# --- common role raw consumers (#31) ---------------------------------------

def test_sysctl_directives_replace_or_append_in_sysctl_conf():
    current = "kernel.sysrq = 0\nvm.swappiness = 60\n# net.core.rmem_max = 1\n"
    directives = raw_sysctl_directives({"vm.swappiness": 10, "net.core.rmem_max": 16777216,
                                        "net.ipv4.tcp_rmem": "4096 87380 16777216"})
    out = raw_set_directives(current, directives)
    assert out == ("kernel.sysrq = 0\nvm.swappiness = 10\n# net.core.rmem_max = 1\n"
                   "net.core.rmem_max = 16777216\nnet.ipv4.tcp_rmem = 4096 87380 16777216\n")
    assert raw_set_directives(out, directives) == out


def test_limits_preserve_foreign_lines_and_are_a_fixed_point():
    limits = [{"domain": "*", "limit_type": "soft", "limit_item": "nofile", "value": 65535},
              {"domain": "*", "limit_type": "hard", "limit_item": "nproc", "value": "65535"}]
    directives = raw_limits_directives(limits)
    current = "# custom\nbob\tsoft\tcore\t0\n*\tsoft\tnofile\t1024\n"
    out = raw_set_directives(current, directives)
    assert out == ("# custom\nbob\tsoft\tcore\t0\n*\tsoft\tnofile\t65535\n*\thard\tnproc\t65535\n")
    assert raw_set_directives(out, directives) == out


def test_sudoers_line_is_validated_by_visudo_and_newline_terminated():
    assert raw_sudoers_line("ppzxc") == "ppzxc ALL=(ALL) NOPASSWD:ALL\n"
    with pytest.raises(ValueError):
        raw_sudoers_line("bad name\nroot")


def test_sudoers_validation_failure_preserves_existing_file(tmp_path):
    dest = tmp_path / "90-ppzxc"
    dest.write_bytes(b"old\n")
    r = sh(raw_push_cmd(raw_sudoers_line("ppzxc"), str(dest), OWNER, GROUP, "0440", "false"))
    assert r.returncode != 0
    assert dest.read_bytes() == b"old\n"
    assert list(tmp_path.iterdir()) == [dest]


def test_raw_changed_reads_marker_line_only():
    assert raw_changed("banner\r\n__RAW_CHANGED__\r\n") is True
    assert raw_changed("nothing\n") is False
    assert raw_changed(None) is False
    assert raw_changed("echo __RAW_CHANGED__ in banner text\n") is False


def _stub_bin(tmp_path, scripts):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in scripts.items():
        f = bindir / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(0o755)
    return bindir


def _run(tmp_path, bindir, cmd):
    return sh("PATH=%s:$PATH; %s" % (bindir, cmd))


def test_group_created_only_when_missing(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {
        "getent": "exit 2",
        "groupadd": 'echo "groupadd $*" >> %s' % log,
    })
    r = _run(tmp_path, bindir, raw_group_cmd("ops", 1500))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().strip() == "groupadd -g 1500 ops"

    bindir = _stub_bin(tmp_path, {"getent": "echo ops:x:1500:"})
    r = _run(tmp_path, bindir, raw_group_cmd("ops", 1500))
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_group_gid_drift_is_corrected(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {
        "getent": "echo ops:x:999:",
        "groupmod": 'echo "groupmod $*" >> %s' % log,
    })
    r = _run(tmp_path, bindir, raw_group_cmd("ops", 1500))
    assert raw_changed(r.stdout)
    assert log.read_text().strip() == "groupmod -g 1500 ops"


def test_group_failure_is_propagated(tmp_path):
    bindir = _stub_bin(tmp_path, {"getent": "exit 2", "groupadd": "exit 9"})
    r = _run(tmp_path, bindir, raw_group_cmd("ops", None))
    assert r.returncode != 0 and not raw_changed(r.stdout)


USER_STUBS = {
    "id": 'case "$1" in -u) echo 1000;; -gn) echo dev;; -nG) echo "dev wheel";; esac',
}


def test_user_created_with_tier_options(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {
        "getent": "exit 2",
        "useradd": 'echo "useradd $*" >> %s' % log,
    })
    r = _run(tmp_path, bindir, raw_user_cmd("ppzxc", ["wheel", "docker"],
                                            "/bin/bash", "Ops", 1001, "present"))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().strip() == "useradd -m -g ppzxc -G wheel,docker -s /bin/bash -c Ops -u 1001 ppzxc"


def test_user_in_sync_is_unchanged(tmp_path):
    bindir = _stub_bin(tmp_path, dict(USER_STUBS, **{
        "getent": "echo dev:x:1000:1000:Ops:/home/dev:/bin/bash",
        "usermod": "exit 9",
    }))
    r = _run(tmp_path, bindir, raw_user_cmd("dev", ["wheel"], "/bin/bash", "Ops", 1000, "present"))
    assert r.returncode == 0, r.stderr
    assert not raw_changed(r.stdout)


def test_user_drift_is_fixed_with_a_single_usermod(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, dict(USER_STUBS, **{
        "getent": "echo dev:x:1000:1000:Ops:/home/dev:/bin/sh",
        "usermod": 'echo "usermod $*" >> %s' % log,
    }))
    r = _run(tmp_path, bindir, raw_user_cmd("dev", ["wheel", "docker"], "/bin/bash", None, None, "present"))
    assert raw_changed(r.stdout)
    assert log.read_text().splitlines() == ["usermod -s /bin/bash -a -G docker dev"]


def test_absent_user_is_removed_only_if_present(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {"getent": "echo x:x:1:1::/h:/s",
                                  "userdel": 'echo "userdel $*" >> %s' % log})
    r = _run(tmp_path, bindir, raw_user_cmd("old", [], "/bin/bash", None, None, "absent"))
    assert raw_changed(r.stdout)
    assert log.read_text().strip() == "userdel -r old"
    bindir = _stub_bin(tmp_path, {"getent": "exit 2"})
    r = _run(tmp_path, bindir, raw_user_cmd("old", [], "/bin/bash", None, None, "absent"))
    assert r.returncode == 0 and not raw_changed(r.stdout)


KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc user@host"


def _key_env(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    bindir = _stub_bin(tmp_path, {"getent": "echo %s:x:1:1::%s:/bin/sh" % (OWNER, home)})
    return home, bindir


def test_authorized_key_added_once(tmp_path):
    home, bindir = _key_env(tmp_path)
    cmd = raw_authorized_key_cmd(OWNER, KEY, "present")
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0, r.stderr
    assert raw_changed(r.stdout)
    f = home / ".ssh" / "authorized_keys"
    assert f.read_text() == KEY + "\n"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and not raw_changed(r.stdout)
    assert f.read_text() == KEY + "\n"


def test_authorized_key_appends_after_unterminated_line(tmp_path):
    home, bindir = _key_env(tmp_path)
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text("ssh-rsa AAAAother a@b")
    assert _run(tmp_path, bindir, raw_authorized_key_cmd(OWNER, KEY, "present")).returncode == 0
    assert (ssh / "authorized_keys").read_text() == "ssh-rsa AAAAother a@b\n" + KEY + "\n"


def test_authorized_key_revoked_only_when_present(tmp_path):
    home, bindir = _key_env(tmp_path)
    ssh = home / ".ssh"
    ssh.mkdir()
    keep = "ssh-rsa AAAAother a@b\n"
    (ssh / "authorized_keys").write_text(keep + KEY + "\n")
    cmd = raw_authorized_key_cmd(OWNER, KEY + " renamed-comment", "absent")
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert (ssh / "authorized_keys").read_text() == keep
    assert list(ssh.iterdir()) == [ssh / "authorized_keys"]
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_authorized_key_rejects_keys_without_blob_or_multiline():
    with pytest.raises(ValueError):
        raw_authorized_key_cmd("u", "not-a-key", "present")
    with pytest.raises(ValueError):
        raw_authorized_key_cmd("u", KEY + "\nssh-rsa AAAAx y", "present")


def test_common_raw_tasks_declare_change_control_and_gate_module_tasks():
    import yaml
    role = ROOT_DIR / "roles" / "common"
    tasks = list(_walk_tasks(yaml.safe_load((role / "tasks" / "main.yml").read_text())))
    raw = [t for t in tasks if "ansible.builtin.raw" in t]
    assert raw, "expected raw tasks in the common role"
    for t in raw:
        assert "changed_when" in t and "failed_when" in t, t["name"]
    gated = ["COMMON-002", "COMMON-005", "COMMON-007", "COMMON-011", "COMMON-012", "COMMON-013", "COMMON-014", "COMMON-015",
             "COMMON-016", "COMMON-022", "COMMON-023"]
    for t in tasks:
        if any(t.get("name", "").startswith("[%s]" % g) for g in gated):
            assert "_raw_path_effective" in str(t.get("when")), t["name"]
    assert "_raw_path_effective" in (role / "defaults" / "main.yml").read_text()


def test_authorized_key_with_changed_comment_replaces_the_line(tmp_path):
    home, bindir = _key_env(tmp_path)
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text("ssh-rsa AAAAother a@b\n" + KEY + "\n")
    new = KEY.replace("user@host", "renamed@host")
    r = _run(tmp_path, bindir, raw_authorized_key_cmd(OWNER, new, "present"))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert (ssh / "authorized_keys").read_text() == "ssh-rsa AAAAother a@b\n" + new + "\n"
    assert list(ssh.iterdir()) == [ssh / "authorized_keys"]
    assert not raw_changed(_run(tmp_path, bindir, raw_authorized_key_cmd(OWNER, new, "present")).stdout)


def test_authorized_key_corrects_mode_of_existing_files(tmp_path):
    home, bindir = _key_env(tmp_path)
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o755)
    ssh.chmod(0o755)
    f = ssh / "authorized_keys"
    f.write_text(KEY + "\n")
    f.chmod(0o644)
    r = _run(tmp_path, bindir, raw_authorized_key_cmd(OWNER, KEY, "present"))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(ssh.stat().st_mode) == 0o700


def test_sentinel_detects_owner_group_drift(tmp_path):
    dest = tmp_path / "f"
    push(dest, mode="0640")
    p = probe(dest)
    assert raw_push_changed(p, CONTENT, "0640", OWNER, GROUP) is False
    assert raw_push_changed(p, CONTENT, "0640", "someone-else", GROUP) is True
    assert raw_push_changed(p, CONTENT, "0640", OWNER, "other-group") is True


def test_read_allow_empty_treats_missing_and_empty_file_as_first_provisioning(tmp_path):
    missing = sh(raw_read_cmd(str(tmp_path / "nope"))).stdout
    assert raw_read_extract(missing) is None
    assert raw_read_extract(missing, True) == ""
    assert raw_read_extract(None, True) is None


def test_rm_cmd_reports_change_only_when_file_existed(tmp_path):
    f = tmp_path / "x"
    f.write_text("a")
    r = sh(raw_rm_cmd(str(f)))
    assert r.returncode == 0 and raw_changed(r.stdout) and not f.exists()
    r = sh(raw_rm_cmd(str(f)))
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_yum_installs_only_missing_packages(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {
        "rpm": 'case "$3" in curl) exit 0;; *) exit 1;; esac',
        "yum": 'echo "yum $*" >> %s' % log,
    })
    r = _run(tmp_path, bindir, raw_yum_cmd(["curl", "git", "nc"]))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().strip() == "yum -y install git nc"
    bindir = _stub_bin(tmp_path, {"rpm": "exit 0", "yum": "exit 9"})
    r = _run(tmp_path, bindir, raw_yum_cmd(["curl"]))
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_yum_failure_is_propagated_but_optional_is_tolerated(tmp_path):
    bindir = _stub_bin(tmp_path, {"rpm": "exit 1", "yum": "exit 1"})
    assert _run(tmp_path, bindir, raw_yum_cmd(["git"])).returncode != 0
    r = _run(tmp_path, bindir, raw_yum_cmd(["bat"], optional=True))
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_sysctl_live_values_are_aligned_when_drifted(tmp_path):
    log = tmp_path / "calls"
    (tmp_path / "state_vm.swappiness").write_text("60\n")
    (tmp_path / "state_net.ipv4.tcp_rmem").write_text("4096\t87380\t16777216\n")
    bindir = _stub_bin(tmp_path, {
        "sysctl": ('case "$1" in -n) cat %s/state_$2 2>/dev/null || exit 255;; '
                   '-w) echo "$2" >> %s; k=${2%%%%=*}; echo "${2#*=}" > %s/state_$k;; esac')
                  % (tmp_path, log, tmp_path),
    })
    settings = {"vm.swappiness": 10, "net.ipv4.tcp_rmem": "4096 87380 16777216", "net.ipv6.x": 1}
    r = _run(tmp_path, bindir, raw_sysctl_live_cmd(settings))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().splitlines() == ["vm.swappiness=10"]
    (tmp_path / "state_vm.swappiness").write_text("10\n")
    r = _run(tmp_path, bindir, raw_sysctl_live_cmd(settings))
    assert r.returncode == 0 and not raw_changed(r.stdout)


def _service_cmd(systemd):
    """The host running the tests may itself have systemctl; force the wanted branch."""
    cmd = raw_service_cmd("auditd")
    return cmd if systemd else cmd.replace("command -v systemctl", "false")


def _service_stubs(tmp_path, systemd, active, enabled):
    log = tmp_path / "calls"
    ok = lambda flag: "exit 0" if flag else "exit 1"
    scripts = {
        "service": 'if [ "$2" = status ]; then %s; fi; echo "service $*" >> %s' % (ok(active), log),
        "chkconfig": ('if [ "$1" = --list ]; then echo "$2 0:off 3:%s"; exit 0; fi; echo "chkconfig $*" >> %s'
                      % ("on" if enabled else "off", log)),
    }
    if systemd:
        scripts["systemctl"] = ('case "$1" in is-active) %s;; is-enabled) %s;; *) echo "systemctl $*" >> %s;; esac'
                                % (ok(active), ok(enabled), log))
    return _stub_bin(tmp_path, scripts), log


@pytest.mark.parametrize("systemd", [True, False])
def test_service_started_and_enabled_only_when_needed(tmp_path, systemd):
    bindir, log = _service_stubs(tmp_path, systemd, active=False, enabled=False)
    r = sh("PATH=%s:$PATH; %s" % (bindir, _service_cmd(systemd)))
    assert r.returncode == 0 and raw_changed(r.stdout)
    calls = log.read_text()
    assert "start" in calls and ("enable" in calls or "chkconfig auditd on" in calls)


@pytest.mark.parametrize("systemd", [True, False])
def test_service_in_desired_state_is_unchanged(tmp_path, systemd):
    bindir, log = _service_stubs(tmp_path, systemd, active=True, enabled=True)
    r = sh("PATH=%s:$PATH; %s" % (bindir, _service_cmd(systemd)))
    assert r.returncode == 0 and not raw_changed(r.stdout)
    assert not log.exists()


def test_service_start_failure_is_propagated(tmp_path):
    bindir = _stub_bin(tmp_path, {"systemctl": 'case "$1" in is-active) exit 1;; *) exit 1;; esac'})
    assert sh("PATH=%s:$PATH; %s" % (bindir, raw_service_cmd("auditd"))).returncode != 0


def test_security_raw_tasks_gate_module_tasks_and_restart_through_raw_handlers():
    import yaml
    role = ROOT_DIR / "roles" / "security"
    tasks = list(_walk_tasks(yaml.safe_load((role / "tasks" / "main.yml").read_text())))
    gated = ["SEC-009", "SEC-010", "SEC-012", "SEC-013", "SEC-014", "SEC-015"]
    for t in tasks:
        if any(t.get("name", "").startswith("[%s]" % g) for g in gated):
            assert "_raw_path_effective" in str(t.get("when")), t["name"]
    raw = {t["name"]: t for t in tasks if "ansible.builtin.raw" in t}
    for t in raw.values():
        assert "changed_when" in t and "failed_when" in t or t["name"].startswith("[SEC-022]"), t["name"]
    # sudoers is validated with visudo and mode stays 4-digit octal
    sudoers = next(t for n, t in raw.items() if n.startswith("[SEC-027]"))
    assert "visudo -cf %s" in sudoers["ansible.builtin.raw"] and "'0440'" in sudoers["ansible.builtin.raw"]
    # each raw content push notifies the shared restart handler
    for prefix, handler in (("[SEC-032]", "Restart fail2ban"), ("[SEC-035]", "Restart auditd")):
        assert next(t for n, t in raw.items() if n.startswith(prefix))["notify"] == handler
    handlers = yaml.safe_load((role / "handlers" / "main.yml").read_text())
    for name in ("Restart fail2ban", "Restart auditd"):
        module = next(h for h in handlers if h["name"] == name)
        assert "_raw_path_effective" in str(module["when"])
        rawh = next(h for h in handlers if h.get("listen") == name)
        assert "ansible.builtin.raw" in rawh
        assert "failed_when: false" not in str(rawh) and rawh["failed_when"] is not False


def test_sysv_service_enabled_at_boot_not_just_current_runlevel(tmp_path):
    bindir = _stub_bin(tmp_path, {
        "service": "exit 0",
        "chkconfig": 'if [ "$1" = --list ]; then echo "auditd 0:off 3:off"; exit 0; fi; '
                     'echo "chkconfig $*" >> %s' % (tmp_path / "calls"),
    })
    r = sh("PATH=%s:$PATH; %s" % (bindir, raw_service_cmd("auditd").replace("command -v systemctl", "false")))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert "chkconfig auditd on" in (tmp_path / "calls").read_text()


def test_sudoers_policy_rejected_by_visudo_keeps_existing_file(tmp_path):
    bindir = _stub_bin(tmp_path, {"visudo": "exit 1"})
    dest = tmp_path / "99-security-policy"
    dest.write_bytes(b"Defaults timestamp_timeout=15\n")
    cmd = raw_push_cmd("Defaults bogus\n", str(dest), OWNER, GROUP, "0440", "visudo -cf %s")
    r = sh("PATH=%s:$PATH; %s" % (bindir, cmd))
    assert r.returncode != 0
    assert dest.read_bytes() == b"Defaults timestamp_timeout=15\n"
    assert list(tmp_path.iterdir()) == [dest, tmp_path / "bin"] or set(tmp_path.iterdir()) == {dest, tmp_path / "bin"}


def _iptables_stub(tmp_path, listing, list_rc=0):
    log = tmp_path / "calls"
    return _stub_bin(tmp_path, {
        "iptables": ('case "$1" in -S) printf "%%s\\n" %s; exit %d;; *) echo "iptables $*" >> %s;; esac'
                     % (" ".join("'%s'" % ln for ln in listing), list_rc, log)),
    }), log


def test_iptables_probe_reports_present_absent_and_error(tmp_path):
    bindir, _ = _iptables_stub(tmp_path, ["-P INPUT ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"])
    present = _run(tmp_path, bindir, raw_iptables_cmd(22, "tcp", None, "probe"))
    absent = _run(tmp_path, bindir, raw_iptables_cmd(80, "tcp", None, "probe"))
    assert not raw_iptables_absent(present.stdout) and "present" in present.stdout
    assert raw_iptables_absent(absent.stdout)
    bindir, _ = _iptables_stub(tmp_path, [], list_rc=1)
    broken = _run(tmp_path, bindir, raw_iptables_cmd(22, "tcp", None, "probe"))
    assert raw_iptables_absent(broken.stdout) is False and "error" in broken.stdout


def test_iptables_probe_matches_normalized_source_rule(tmp_path):
    bindir, _ = _iptables_stub(tmp_path, ["-A INPUT -s 10.1.2.3/32 -p tcp -m tcp --dport 22 -j ACCEPT",
                                          "-A INPUT -s 10.0.0.0/24 -p udp -m udp --dport 53 -j ACCEPT"])
    for src, port, proto, absent in (("10.1.2.3", 22, "tcp", False), ("10.1.2.3/32", 22, "tcp", False),
                                     ("10.0.0.5/24", 53, "udp", False), ("10.1.2.4", 22, "tcp", True),
                                     (None, 22, "tcp", True)):
        r = _run(tmp_path, bindir, raw_iptables_cmd(port, proto, src, "probe"))
        assert raw_iptables_absent(r.stdout) is absent, (src, port, proto, r.stdout)


def test_iptables_insert_puts_rule_at_top_and_failure_propagates(tmp_path):
    bindir, log = _iptables_stub(tmp_path, [])
    r = _run(tmp_path, bindir, raw_iptables_cmd(8080, "tcp", "192.168.0.0/16", "insert"))
    assert r.returncode == 0
    assert log.read_text().strip() == "iptables -I INPUT 1 -s 192.168.0.0/16 -p tcp -m tcp --dport 8080 -j ACCEPT"
    bindir = _stub_bin(tmp_path, {"iptables": "exit 3"})
    assert _run(tmp_path, bindir, raw_iptables_cmd(8080, "tcp", None, "insert")).returncode != 0


def test_iptables_rejects_unsafe_input():
    for args in ((22, "icmp", None), ("22; rm -rf /", "tcp", None), (22, "tcp", "1.2.3.4; id"), (70000, "tcp", None)):
        with pytest.raises(ValueError):
            raw_iptables_cmd(*args, "probe")


def _blocks_containing(tasks, prefixes):
    return [t for t in tasks if any(str(c.get("name", "")).startswith(prefixes) for c in t.get("block", []) or [])]


def test_centos6_ntp_and_iptables_tasks_are_raw_only_and_controlled():
    import yaml
    sec = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/security/tasks/main.yml").read_text())))
    com = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/common/tasks/main.yml").read_text())))
    for tasks, gated in ((sec, ("[SEC-008]", "[SEC-021]")), (com, ("[COMMON-010]",))):
        mod = [t for t in tasks if t.get("name", "").startswith(gated)]
        assert len(mod) == len(gated)
        assert all("_raw_path_effective" in str(t.get("when")) for t in mod)
    for tasks, prefixes in ((sec, ("[SEC-037]", "[SEC-038]", "[SEC-039]", "[SEC-040]")),
                            (com, ("[COMMON-041]", "[COMMON-042]", "[COMMON-043]", "[COMMON-044]"))):
        blocks = _blocks_containing(tasks, prefixes)
        assert len(blocks) == 1 and "== 6" in str(blocks[0]["when"]) and "_raw_path_effective" in str(blocks[0]["when"])
        inner = [c for c in blocks[0]["block"] if c["name"].startswith(prefixes)]
        assert len(inner) == 4
        for c in inner:
            assert "ansible.builtin.raw" in c and "changed_when" in c and "failed_when" in c, c["name"]
    handlers = yaml.safe_load((ROOT_DIR / "roles/common/handlers/main.yml").read_text())
    rawh = next(h for h in handlers if h.get("listen") == "Restart ntpd")
    assert "ansible.builtin.raw" in rawh and rawh["failed_when"] is not False


def _tz_env(tmp_path, current):
    zone = tmp_path / "zoneinfo"
    (zone / "Asia").mkdir(parents=True)
    (zone / "Asia" / "Seoul").write_text("seoul")
    (zone / "UTC").write_text("utc")
    local = tmp_path / "localtime"
    local.symlink_to(zone / current)
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {"timedatectl": 'echo "timedatectl $*" >> %s' % log})
    return zone, local, bindir, log


def test_timezone_set_only_when_it_differs(tmp_path):
    zone, local, bindir, log = _tz_env(tmp_path, "UTC")
    cmd = raw_timezone_cmd("Asia/Seoul", str(zone), str(local))
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().strip() == "timedatectl set-timezone Asia/Seoul"
    log.unlink()
    local.unlink()
    local.symlink_to(zone / "Asia" / "Seoul")
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and not raw_changed(r.stdout) and not log.exists()


def test_timezone_unknown_zone_fails_and_unsafe_name_is_rejected(tmp_path):
    zone, local, bindir, log = _tz_env(tmp_path, "UTC")
    r = _run(tmp_path, bindir, raw_timezone_cmd("Mars/Base", str(zone), str(local)))
    assert r.returncode != 0 and not log.exists()
    with pytest.raises(ValueError):
        raw_timezone_cmd("UTC; reboot")
    with pytest.raises(ValueError):
        raw_timezone_cmd("../etc/passwd")


def _selinux_env(tmp_path, config_mode, running):
    cfg = tmp_path / "selinux_config"
    cfg.write_text("# comment\nSELINUX=%s\nSELINUXTYPE=targeted\n" % config_mode)
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {"setenforce": 'echo "setenforce $*" >> %s' % log,
                                  "getenforce": "echo %s" % running})
    return cfg, bindir, log


def test_selinux_config_and_runtime_are_aligned_to_permissive(tmp_path):
    cfg, bindir, log = _selinux_env(tmp_path, "enforcing", "Enforcing")
    cmd = raw_selinux_cmd("permissive", "targeted", str(cfg))
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert cfg.read_text() == "# comment\nSELINUX=permissive\nSELINUXTYPE=targeted\n"
    assert log.read_text().strip() == "setenforce 0"
    log.unlink()
    bindir = _stub_bin(tmp_path, {"getenforce": "echo Permissive", "setenforce": "echo x >> %s" % log})
    r = _run(tmp_path, bindir, cmd)
    assert r.returncode == 0 and not raw_changed(r.stdout) and not log.exists()


def test_selinux_appends_missing_keys_and_tolerates_absent_subsystem(tmp_path):
    cfg = tmp_path / "selinux_config"
    cfg.write_text("SELINUX=permissive\n")
    bindir = _stub_bin(tmp_path, {})
    no_rt = lambda c: c.replace("command -v getenforce", "false")
    r = _run(tmp_path, bindir, no_rt(raw_selinux_cmd("permissive", "targeted", str(cfg))))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert cfg.read_text() == "SELINUX=permissive\nSELINUXTYPE=targeted\n"
    missing = tmp_path / "nope"
    r = _run(tmp_path, bindir, no_rt(raw_selinux_cmd("permissive", "targeted", str(missing))))
    assert r.returncode == 0 and not raw_changed(r.stdout) and not missing.exists()


def test_selinux_rejects_unsafe_input():
    with pytest.raises(ValueError):
        raw_selinux_cmd("bogus", "targeted")
    with pytest.raises(ValueError):
        raw_selinux_cmd("permissive", "targeted; reboot")


def test_centos7_only_tasks_are_raw_gated_and_controlled():
    import yaml
    sec = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/security/tasks/main.yml").read_text())))
    com = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/common/tasks/main.yml").read_text())))
    for tasks, gated in ((com, ("[COMMON-001]", "[COMMON-004]", "[COMMON-008]", "[COMMON-009]", "[COMMON-017]")),
                         (sec, ("[SEC-011]",))):
        mod = [t for t in tasks if t.get("name", "").startswith(gated)]
        assert len(mod) == len(gated)
        assert all("_raw_path_effective" in str(t.get("when")) for t in mod)
    for tasks, prefixes in ((com, tuple("[COMMON-%03d]" % n for n in range(45, 52))), (sec, ("[SEC-041]",))):
        blocks = _blocks_containing(tasks, prefixes)
        assert len(blocks) == 1 and "== 7" in str(blocks[0]["when"]) and "_raw_path_effective" in str(blocks[0]["when"])
        inner = [c for c in blocks[0]["block"] if c["name"].startswith(prefixes)]
        assert len(inner) == len(prefixes)
        for c in inner:
            assert "ansible.builtin.raw" in c and "changed_when" in c and "failed_when" in c, c["name"]
    handlers = yaml.safe_load((ROOT_DIR / "roles/common/handlers/main.yml").read_text())
    module = next(h for h in handlers if h["name"] == "Restart chrony")
    assert "_raw_path_effective" in str(module["when"])
    rawh = next(h for h in handlers if h.get("listen") == "Restart chrony")
    assert "ansible.builtin.raw" in rawh and rawh["failed_when"] is not False


FWD_STUB = r"""#!/bin/sh
# stateful firewall-cmd stub: state file holds one "zone|kind|value" per line
db="$FWD_DB"; zone=""; act=""; kind=""; val=""
for a in "$@"; do case "$a" in
  --permanent) ;;
  --zone=*) zone="${a#--zone=}" ;;
  --get-zones) echo "public work external dmz"; exit 0 ;;
  --get-zone-of-interface=*) v="${a#*=}"; z=$(grep "|interface|$v$" "$db" | cut -d'|' -f1); echo "${z:-no zone}"; [ -n "$FWD_ERR" ] && exit 5; exit 0 ;;
  --query-*|--add-*|--remove-*|--change-*) act="${a%%-*}"; rest="${a#--}"; act="${rest%%-*}"; rest="${rest#*-}"; kind="${rest%%=*}"; val="${a#*=}" ;;
esac; done
[ -n "$FWD_ERR" ] && exit 5
case "$act" in
  query) if [ "$kind" = masquerade ]; then grep -qx "$zone|masquerade|" "$db"; exit $?; fi
         grep -qxF "$zone|$kind|$val" "$db"; exit $? ;;
  add) grep -qxF "$zone|$kind|$val" "$db" || echo "$zone|$kind|$val" >> "$db" ;;
  change) grep -v "|interface|$val$" "$db" > "$db.n"; mv "$db.n" "$db"; echo "$zone|interface|$val" >> "$db" ;;
  remove) grep -vxF "$zone|$kind|$val" "$db" > "$db.n"; mv "$db.n" "$db"; [ "$kind" = masquerade ] && { grep -vx "$zone|masquerade|" "$db" > "$db.n"; mv "$db.n" "$db"; } ;;
esac
exit 0
"""


def _fwd_env(tmp_path, state=""):
    db = tmp_path / "fwd.db"
    db.write_text(state)
    bindir = _stub_bin(tmp_path, {})
    stub = bindir / "firewall-cmd"
    stub.write_text(FWD_STUB)
    stub.chmod(0o755)
    return db, bindir


def _fwd_run(tmp_path, bindir, db, cmd, err=False):
    return sh("PATH=%s:$PATH; FWD_DB=%s; export FWD_DB; %s%s" % (bindir, db, "FWD_ERR=1; export FWD_ERR; " if err else "", cmd))


def test_firewalld_probe_reports_present_absent_and_error(tmp_path):
    db, bindir = _fwd_env(tmp_path, "work|source|10.0.0.0/8\npublic|interface|eth0\n")
    for rule, present in (({"kind": "source", "zone": "work", "value": "10.0.0.0/8"}, True),
                          ({"kind": "source", "zone": "work", "value": "10.1.0.0/16"}, False),
                          ({"kind": "interface", "zone": "public", "value": "eth0"}, True),
                          ({"kind": "interface", "zone": "drop", "value": "eth0"}, False),
                          ({"kind": "interface", "zone": "drop", "value": "eth9"}, False)):
        r = _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe"))
        assert r.returncode == 0
        assert raw_firewalld_present(r.stdout) is present and raw_firewalld_absent(r.stdout) is (not present)
    rule = {"kind": "service", "zone": "public", "value": "http"}
    r = _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe"), err=True)
    assert r.returncode == 0 and raw_firewalld_failed(r.stdout)
    assert raw_firewalld_failed("") and raw_firewalld_failed(None) and not raw_firewalld_present("")


def test_firewalld_runtime_probe_and_masquerade_runtime(tmp_path):
    db, bindir = _fwd_env(tmp_path, "public|service|http\n")
    rule = {"kind": "service", "zone": "public", "value": "http"}
    r = _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe-runtime"))
    assert raw_firewalld_present(r.stdout)
    assert "--permanent" not in raw_firewalld_cmd(rule, "probe-runtime")
    assert "--permanent" in raw_firewalld_cmd(rule, "probe")
    r = _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(dict(rule, value="https"), "probe-runtime"))
    assert raw_firewalld_absent(r.stdout)


def test_firewalld_add_remove_round_trip_and_rich_rule(tmp_path):
    db, bindir = _fwd_env(tmp_path)
    for rule in ({"kind": "port", "zone": "dmz", "value": "9100/tcp"},
                 {"kind": "service", "zone": "public", "value": "https"},
                 {"kind": "source", "zone": "work", "value": "203.0.113.0/24"}):
        assert _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "add")).returncode == 0
        assert raw_firewalld_present(_fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe")).stdout)
        assert _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "remove")).returncode == 0
        assert raw_firewalld_absent(_fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe")).stdout)
    rich = {"kind": "rich-rule", "zone": "public", "value": "203.0.113.5", "port": 22}
    cmd = raw_firewalld_cmd(rich, "remove")
    assert 'rule family="ipv4" source address="203.0.113.5" port port="22" protocol="tcp" accept' in cmd.replace("'", "")
    assert _fwd_run(tmp_path, bindir, db, cmd).returncode == 0


def test_firewalld_rejects_unsafe_input():
    bad = ({"kind": "service", "zone": "public", "value": "http; reboot"},
           {"kind": "service", "zone": "pub lic", "value": "http"},
           {"kind": "port", "zone": "dmz", "value": "70000/tcp"},
           {"kind": "port", "zone": "dmz", "value": "80/icmp"},
           {"kind": "source", "zone": "work", "value": "1.2.3.4; id"},
           {"kind": "rich-rule", "zone": "public", "value": "1.2.3.4", "port": "22; id"},
           {"kind": "rich-rule", "zone": "public", "value": "1.2.3.4", "port": 22, "proto": "icmp"},
           {"kind": "rich-rule", "zone": "public", "value": "2001:db8::/32", "port": 22},
           {"kind": "interface", "zone": "public", "value": "eth0 && id"},
           {"kind": "bogus", "zone": "public", "value": "x"})
    for rule in bad:
        with pytest.raises(ValueError):
            raw_firewalld_cmd(rule, "probe")
    with pytest.raises(ValueError):
        raw_firewalld_cmd({"kind": "service", "zone": "public", "value": "http"}, "flush")


def _plan(**over):
    cfg = {"interface": "eth0", "interface_zone": "public", "source_zone": "work", "ssh_port": 22,
           "ssh_allowed_source_ips": [], "stale_source_ips": [], "allowed_services": ["http", "https"],
           "allowed_tcp_ports": ["22", "8080"], "monitoring_subnets": [], "dmz_ports": ["9100/tcp"],
           "internal_subnets": ["10.0.0.0/8"], "internal_ports": []}
    cfg.update(over)
    return raw_firewalld_plan(cfg)


def test_firewalld_plan_orders_removals_first_and_mirrors_module_conditions():
    plan = _plan(ssh_allowed_source_ips=["203.0.113.1"], stale_source_ips=["198.51.100.7"])
    states = [r["state"] for r in plan]
    assert states == sorted(states, key=lambda s: s != "disabled")
    keyset = {(r["state"], r["kind"], r["zone"], r["value"]) for r in plan}
    assert ("disabled", "service", "public", "cockpit") in keyset
    assert ("disabled", "source", "trusted", "198.51.100.7") in keyset
    assert ("enabled", "source", "work", "203.0.113.1") in keyset
    assert ("enabled", "service", "work", "ssh") in keyset
    assert ("enabled", "port", "work", "8080/tcp") in keyset
    assert ("enabled", "port", "work", "22/tcp") not in keyset
    assert ("disabled", "interface", "drop", "eth0") in keyset and ("enabled", "interface", "public", "eth0") in keyset
    ing = _plan(ssh_allowed_source_ips=["203.0.113.1"], ingress_rules=[{"port": 53, "proto": "udp", "sources": ["198.51.100.0/24"]}])
    assert any(r["kind"] == "rich-rule" and r["zone"] == "work" and r["proto"] == "udp" and r["state"] == "enabled" for r in ing)
    plain = {(r["state"], r["kind"], r["zone"], r["value"]) for r in _plan()}
    assert ("enabled", "port", "public", "8080/tcp") in plain
    assert not any(k[2] == "public" and k[1] == "service" and k[0] == "disabled" for k in plain)
    assert ("enabled", "source", "internal", "10.0.0.0/8") in plain and ("enabled", "port", "dmz", "9100/tcp") in plain
    assert not any(r["state"] == "disabled" for r in _plan(interface_zone="drop") if r["kind"] == "interface")


def test_firewalld_plan_applies_then_second_run_is_unchanged(tmp_path):
    db, bindir = _fwd_env(tmp_path, "drop|interface|eth0\ntrusted|source|203.0.113.1\n")
    plan = _plan(ssh_allowed_source_ips=["203.0.113.1"], stale_source_ips=["203.0.113.1"])

    def one_pass():
        changed = 0
        for rule in plan:
            probe = _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, "probe")).stdout
            if (rule["state"] == "enabled" and raw_firewalld_absent(probe)) or \
                    (rule["state"] == "disabled" and raw_firewalld_present(probe)):
                mode = "add" if rule["state"] == "enabled" else "remove"
                assert _fwd_run(tmp_path, bindir, db, raw_firewalld_cmd(rule, mode)).returncode == 0
                changed += 1
        return changed

    assert one_pass() > 0
    lines = set(db.read_text().split())
    assert "work|source|203.0.113.1" in lines and "public|interface|eth0" in lines
    assert "trusted|source|203.0.113.1" not in lines and "drop|interface|eth0" not in lines
    assert one_pass() == 0


def test_firewalld_masquerade_removed_only_outside_external(tmp_path):
    db, bindir = _fwd_env(tmp_path, "public|masquerade|\nexternal|masquerade|\n")
    cmd = raw_firewalld_masquerade_off_cmd()
    r = _fwd_run(tmp_path, bindir, db, cmd)
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert db.read_text().split() == ["external|masquerade|"]
    r = _fwd_run(tmp_path, bindir, db, cmd)
    assert r.returncode == 0 and not raw_changed(r.stdout)


def test_default_iface_cmd_reads_route(tmp_path):
    bindir = _stub_bin(tmp_path, {"ip": "echo 'default via 10.0.0.1 dev ens192 proto static metric 100'"})
    assert _run(tmp_path, bindir, raw_default_iface_cmd()).stdout.strip() == "ens192"
    bindir = _stub_bin(tmp_path, {"ip": "exit 0"})
    assert _run(tmp_path, bindir, raw_default_iface_cmd()).stdout.strip() == ""


def test_centos7_firewalld_tasks_are_raw_gated_and_controlled():
    import yaml
    tasks = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/security/tasks/main.yml").read_text())))
    fw = [t for t in tasks if any(k in t for k in ("ansible.posix.firewalld",))
          or "firewall-cmd" in str(t.get("ansible.builtin.command", "")) or "firewall-cmd" in str(t.get("ansible.builtin.shell", ""))
          or t.get("name", "").startswith(("[SEC-005]", "[SEC-006"))]
    assert len(fw) >= 30
    for t in fw:
        assert "_raw_path_effective" in str(t.get("when")), t["name"]
    prefixes = tuple("[SEC-%03d]" % n for n in range(42, 51))
    blocks = _blocks_containing(tasks, prefixes)
    assert len(blocks) == 1 and "== 7" in str(blocks[0]["when"]) and "_raw_path_effective" in str(blocks[0]["when"])
    inner = [c for c in blocks[0]["block"] if c["name"].startswith(prefixes)]
    assert len(inner) == len(prefixes)
    for c in inner:
        if "ansible.builtin.set_fact" in c:
            continue
        assert "ansible.builtin.raw" in c and "changed_when" in c and "failed_when" in c, c["name"]
    handlers = yaml.safe_load((ROOT_DIR / "roles/security/handlers/main.yml").read_text())
    module = next(h for h in handlers if h["name"] == "Reload firewalld")
    assert "_raw_path_effective" in str(module["when"])
    rawh = next(h for h in handlers if h.get("listen") == "Reload firewalld")
    assert "ansible.builtin.raw" in rawh and rawh["failed_when"] is not False


def test_raw_tasks_never_override_check_mode_and_are_skipped_under_check(tmp_path):
    """ADR-0005 Option A: raw has no check-mode support, so it is skipped under --check.

    No raw task may opt back in with ``check_mode: false``, and a raw task run
    with ``--check`` must be skipped without touching the target.
    """
    import yaml
    for role in ("common", "security"):
        tasks = _walk_tasks(yaml.safe_load((ROOT_DIR / f"roles/{role}/tasks/main.yml").read_text()))
        raws = [t for t in tasks if "ansible.builtin.raw" in t]
        assert raws, role
        for t in raws:
            assert t.get("check_mode") is not False, t["name"]
        handlers = yaml.safe_load((ROOT_DIR / f"roles/{role}/handlers/main.yml").read_text())
        for h in handlers:
            if "ansible.builtin.raw" in h:
                assert h.get("check_mode") is not False, h["name"]

    marker = tmp_path / "touched"
    play = tmp_path / "play.yml"
    play.write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n"
        f"    - ansible.builtin.raw: touch {marker}\n"
    )
    ansible = shutil.which("ansible-playbook")
    if ansible is None:
        pytest.skip("ansible-playbook not installed")
    res = subprocess.run([ansible, "-i", "localhost,", "--check", str(play)],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "skipped=1" in res.stdout
    assert not marker.exists()


def test_detect_probe_is_read_only_and_tolerant():
    import yaml
    probe = next(t for t in yaml.safe_load(EFFECTIVE_EXPR) if "ansible.builtin.raw" in t)
    assert probe["check_mode"] is False
    assert probe["failed_when"] is False
    assert probe["become"] is False
    assert probe["changed_when"] is False


def test_detect_file_gathers_facts_only_off_raw_path():
    import yaml
    setup = next(t for t in yaml.safe_load(EFFECTIVE_EXPR) if "ansible.builtin.setup" in t)
    assert setup["when"] == "not (_raw_path_effective | bool)"


@pytest.mark.parametrize("playbook", ["site.yml", "maintenance.yml"])
def test_target_plays_import_detection_with_always_tag(playbook):
    import yaml
    plays = yaml.safe_load((ROOT_DIR / "playbooks" / playbook).read_text())
    targets = [p for p in plays if p.get("roles") and p.get("hosts") != "overseer"]
    assert targets
    for play in targets:
        imp = [t for t in play["pre_tasks"] if t.get("ansible.builtin.import_tasks") == "common/detect_raw_path.yml"]
        assert len(imp) == 1 and imp[0]["tags"] == ["always"]
        assert play["gather_facts"] is False


def test_common_profile_and_environment_templates_have_raw_equivalents():
    """COMMON-018/019/020 use ansible.builtin.template (AnsiballZ), so on the raw
    path they must be skipped and replaced by probe + push raw tasks."""
    import yaml
    tasks = list(_walk_tasks(yaml.safe_load((ROOT_DIR / "roles/common/tasks/main.yml").read_text())))
    for prefix in ("[COMMON-018]", "[COMMON-019]", "[COMMON-020]"):
        mod = next(t for t in tasks if t.get("name", "").startswith(prefix))
        assert "_raw_path_effective" in str(mod.get("when")), prefix
    raw = [t for t in tasks if "ansible.builtin.raw" in t]
    for tpl in ("aliases.sh.j2", "node-env.sh.j2", "environment.j2"):
        push = [t for t in raw if tpl in str(t.get("vars", ""))]
        assert len(push) == 1, tpl
        assert "changed_when" in push[0] and "failed_when" in push[0], tpl
    for dest in ("/etc/profile.d/99-aliases.sh", "/etc/profile.d/98-node-env.sh", "/etc/environment"):
        assert any(dest in str(t.get("ansible.builtin.raw")) for t in raw), dest


def test_default_route_facts_are_parsed_for_raw_hosts(tmp_path):
    """Raw hosts gather no facts, so ansible_default_ipv4 must come from the route probe."""
    from raw_provisioning import raw_default_route_cmd, raw_parse_default_route
    bindir = _stub_bin(tmp_path, {"ip": 'echo "1.1.1.1 via 39.116.31.254 dev enp2s0  src 39.116.31.59"'})
    out = _run(tmp_path, bindir, raw_default_route_cmd()).stdout
    assert raw_parse_default_route(out) == {
        "interface": "enp2s0", "gateway": "39.116.31.254", "address": "39.116.31.59"}
    assert raw_parse_default_route("") == {}
    assert raw_parse_default_route("garbage\n") == {}


def test_detect_raw_path_publishes_default_route_before_common_templates():
    text = (ROOT_DIR / "playbooks/common/detect_raw_path.yml").read_text()
    assert "raw_default_route_cmd" in text and "ansible_default_ipv4" in text


def test_firewalld_plan_unbinds_drop_zone_interfaces_from_the_shared_list():
    plan = _plan(interface="enp2s0", drop_unbind_interfaces=["bond0", "eno1", "eno2", "enp2s0"])
    unbound = [r["value"] for r in plan if (r["state"], r["kind"], r["zone"]) == ("disabled", "interface", "drop")]
    assert unbound == ["enp2s0", "bond0", "eno1", "eno2"]
    custom = _plan(interface="eth0", drop_unbind_interfaces=["em1"])
    assert [r["value"] for r in custom if (r["state"], r["kind"], r["zone"]) == ("disabled", "interface", "drop")] == ["eth0", "em1"]


def test_security_role_shares_drop_unbind_interfaces_with_module_path():
    text = (ROOT_DIR / "roles/security/tasks/main.yml").read_text()
    assert text.count("firewall_drop_unbind_interfaces") >= 3
    assert '- "bond0"' not in text and '- "eno1"' not in text


def test_argless_command_filters_accept_the_jinja_piped_value():
    """`{{ '' | raw_xxx_cmd }}` passes the piped value as the first argument."""
    import yaml
    from raw_provisioning import FilterModule, raw_default_route_cmd
    filters = FilterModule().filters()
    for name in ("raw_default_iface_cmd", "raw_firewalld_masquerade_off_cmd", "raw_default_route_cmd"):
        assert filters[name]("")
    assert raw_default_route_cmd() and raw_default_iface_cmd()


def test_raw_gate_precedes_fact_dependent_conditions():
    """Raw hosts gather no facts; `when` items short-circuit in order, so the raw gate must come first."""
    import yaml
    for role in ("common", "security"):
        tasks = _walk_tasks(yaml.safe_load((ROOT_DIR / "roles" / role / "tasks" / "main.yml").read_text()))
        for t in tasks:
            when = t.get("when")
            if not isinstance(when, list) or not any("_raw_path_effective" in str(c) for c in when):
                continue
            gate = next(i for i, c in enumerate(when) if "_raw_path_effective" in str(c))
            for i, cond in enumerate(when[:gate]):
                # detect_raw_path.yml sets os_family/distribution*; other facts stay undefined.
                assert not any(f in str(cond) for f in ("ansible_service_mgr", "ansible_pkg_mgr", "ansible_facts")), (
                    t.get("name"), cond)


# --------------------------------------------------------------------------
# Host Agents subset (#46): scp upload, hash-pinned sentinel, check-mode diff
# --------------------------------------------------------------------------
import hashlib  # noqa: E402

from raw_provisioning import (  # noqa: E402
    raw_scp_argv, raw_upload_changed, raw_upload_finalize_cmd, raw_check_diff, raw_secret_notice,
)

BIN = b"\x7fELF-fake-binary\x00" * 64
BIN_SHA = hashlib.sha256(BIN).hexdigest()


def test_scp_argv_uses_resolved_connection_values():
    argv = raw_scp_argv("/cache/otelcol", "/var/tmp/otelcol.raw.upload", "10.0.0.5", "2222", "ops", "/tmp/k")
    assert argv[0] == "scp" and argv[-1] == "ops@10.0.0.5:/var/tmp/otelcol.raw.upload"
    assert argv[argv.index("-P") + 1] == "2222"
    assert argv[argv.index("-i") + 1] == "/tmp/k"
    assert argv[-2] == "/cache/otelcol" and "BatchMode=yes" in argv


def test_scp_argv_brackets_ipv6():
    argv = raw_scp_argv("/c/x", "/var/tmp/x", "fe80::1", 22, "ops", "/k")
    assert argv[-1] == "ops@[fe80::1]:/var/tmp/x"


@pytest.mark.parametrize("key", [None, ""])
def test_scp_argv_requires_a_key_because_batchmode_cannot_prompt(key):
    with pytest.raises(ValueError, match="private key"):
        raw_scp_argv("/c/x", "/var/tmp/x", "h", 22, "ops", key)


@pytest.mark.parametrize("key", [None, ""])
def test_scp_argv_password_mode_uses_sshpass_with_env_and_never_carries_the_password(key):
    argv = raw_scp_argv("/cache/otelcol", "/var/tmp/otelcol.raw.upload", "10.0.0.5", "2222", "ops", key, True)
    assert argv[:3] == ["sshpass", "-e", "scp"]
    assert argv[-1] == "ops@10.0.0.5:/var/tmp/otelcol.raw.upload" and argv[-2] == "/cache/otelcol"
    assert argv[argv.index("-P") + 1] == "2222"
    assert "BatchMode=yes" not in argv and "-i" not in argv
    assert "PubkeyAuthentication=no" in argv and "PreferredAuthentications=password" in argv
    assert "NumberOfPasswordPrompts=1" in argv


def test_scp_argv_key_wins_over_password_mode():
    argv = raw_scp_argv("/c/x", "/var/tmp/x", "h", 22, "ops", "/k", True)
    assert argv[0] == "scp" and "-i" in argv and "BatchMode=yes" in argv


def test_scp_argv_password_mode_keeps_the_path_and_ipv6_guards():
    assert raw_scp_argv("/c/x", "/var/tmp/x", "fe80::1", 22, "ops", None, True)[-1] == "ops@[fe80::1]:/var/tmp/x"
    with pytest.raises(ValueError):
        raw_scp_argv("/c/x", "/a;rm -rf /", "h", 22, "u", None, True)


@pytest.mark.parametrize("dest", ["relative/x", "/a b", "/a;rm -rf /", "/a/../b", "/a$(x)"])
def test_scp_argv_rejects_unsafe_remote_path(dest):
    with pytest.raises(ValueError):
        raw_scp_argv("/c/x", dest, "h", 22, "u", "/k")


def test_upload_sentinel_pins_hash_and_mode():
    probe = "banner\n__RAW_PROBE__ %s 755 root:root\n" % BIN_SHA
    assert raw_upload_changed(probe, BIN_SHA, "0755", "root", "root") is False
    assert raw_upload_changed(probe, BIN_SHA, "0700", "root", "root") is True
    assert raw_upload_changed(probe, "0" * 64, "0755", "root", "root") is True
    assert raw_upload_changed("__RAW_PROBE__   \n", BIN_SHA, "0755") is True
    assert raw_upload_changed("", BIN_SHA, "0755") is True


def test_finalize_installs_only_when_hash_matches(tmp_path):
    stage, dest = tmp_path / "stage", tmp_path / "bin"
    stage.write_bytes(BIN)
    cmd = raw_upload_finalize_cmd(str(stage), str(dest), OWNER, GROUP, "0755", BIN_SHA)
    assert sh(cmd).returncode == 0
    assert dest.read_bytes() == BIN and stat.S_IMODE(dest.stat().st_mode) == 0o755
    assert not stage.exists() and not (tmp_path / "bin.raw.tmp").exists()


def test_finalize_hash_mismatch_fails_and_leaves_dest_untouched(tmp_path):
    stage, dest = tmp_path / "stage", tmp_path / "bin"
    dest.write_bytes(b"old")
    stage.write_bytes(BIN + b"tampered")
    res = sh(raw_upload_finalize_cmd(str(stage), str(dest), OWNER, GROUP, "0755", BIN_SHA))
    assert res.returncode != 0
    assert dest.read_bytes() == b"old"
    assert not stage.exists() and not (tmp_path / "bin.raw.tmp").exists()


def test_finalize_missing_stage_fails(tmp_path):
    res = sh(raw_upload_finalize_cmd(str(tmp_path / "nope"), str(tmp_path / "bin"), OWNER, GROUP, "0755", BIN_SHA))
    assert res.returncode != 0 and not (tmp_path / "bin").exists()


def test_check_diff_shows_changes_and_hides_secrets():
    out = raw_check_diff("a=1\n", "a=2\n", "/etc/x.conf")
    assert "-a=1" in out and "+a=2" in out and "/etc/x.conf" in out
    assert raw_check_diff("a=1", "a=1", "/etc/x.conf").endswith("no content difference")


def test_secret_notice_reports_change_state_without_content():
    assert raw_secret_notice("/etc/s.env", True).endswith("would change")
    assert raw_secret_notice("/etc/s.env", False).endswith("would stay unchanged")
    assert "TOKEN" not in raw_secret_notice("/etc/s.env", True)


# --------------------------------------------------------------------------
# Host Agents legacy_el7 helpers (#47): the rendered commands are executed for real.
# --------------------------------------------------------------------------

def _sh(cmd):
    import subprocess
    return subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True)


def test_raw_dir_cmd_creates_then_is_idempotent_and_fixes_mode(tmp_path):
    import getpass
    import grp
    import os
    from raw_provisioning import raw_changed, raw_dir_cmd
    own, grp_ = getpass.getuser(), grp.getgrgid(os.getgid()).gr_name
    d = tmp_path / "a" / "b"
    cmd = raw_dir_cmd(str(d), own, grp_, "0750")
    first = _sh(cmd)
    assert first.returncode == 0 and raw_changed(first.stdout) and oct(d.stat().st_mode & 0o777) == "0o750"
    assert not raw_changed(_sh(cmd).stdout)
    d.chmod(0o755)
    assert raw_changed(_sh(cmd).stdout) and oct(d.stat().st_mode & 0o777) == "0o750"


def _agent_tree(tmp_path, versions):
    agent = tmp_path / "opt" / "agent"
    for i, v in enumerate(versions):
        (agent / v).mkdir(parents=True)
        (agent / v / "agent").write_text(v)
        os.utime(agent / v, (1000 + i, 1000 + i))
    (tmp_path / "bin").mkdir()
    return agent, tmp_path / "bin" / "agent"


def test_raw_switch_binary_switches_prunes_to_current_plus_previous_and_notifies_once(tmp_path):
    from raw_provisioning import raw_changed, raw_switch_binary_cmd
    agent, link = _agent_tree(tmp_path, ["1.0", "1.1", "1.2"])
    link.symlink_to(agent / "1.1" / "agent")
    cmd = raw_switch_binary_cmd(str(link), str(agent / "1.2" / "agent"), str(agent), "agent")
    res = _sh(cmd)
    assert res.returncode == 0 and raw_changed(res.stdout)
    assert link.readlink() == agent / "1.2" / "agent"
    assert sorted(p.name for p in agent.iterdir()) == ["1.1", "1.2"]           # 1.0 pruned, previous kept
    again = _sh(cmd)
    assert again.returncode == 0 and not raw_changed(again.stdout)             # idempotent
    assert sorted(p.name for p in agent.iterdir()) == ["1.1", "1.2"]           # re-run keeps the previous one


def test_raw_switch_binary_preserves_a_regular_file_binary_before_the_first_switch(tmp_path):
    from raw_provisioning import raw_changed, raw_switch_binary_cmd
    agent, link = _agent_tree(tmp_path, ["1.0"])
    link.write_text("old-0.108.0")
    res = _sh(raw_switch_binary_cmd(str(link), str(agent / "1.0" / "agent"), str(agent), "agent"))
    assert res.returncode == 0 and raw_changed(res.stdout)
    assert link.is_symlink() and (agent / "legacy-agent").read_text() == "old-0.108.0"


def test_raw_exists_helpers_round_trip(tmp_path):
    from raw_provisioning import raw_exists_cmd, raw_exists_results
    (tmp_path / "yes").write_text("x")
    paths = [str(tmp_path / "yes"), str(tmp_path / "no space")]
    res = _sh(raw_exists_cmd(paths))
    assert res.returncode == 0
    assert raw_exists_results(res.stdout, paths) == [
        {"item": paths[0], "stat": {"exists": True}}, {"item": paths[1], "stat": {"exists": False}}]


@pytest.mark.parametrize("key,password_auth", [("/k", False), (None, True)])
def test_scp_argv_accepts_legacy_ssh_rsa_host_keys_of_centos6_openssh(key, password_auth):
    # CentOS 6 sshd (OpenSSH 5.3) offers only ssh-rsa/ssh-dss; OpenSSH 9.x disables ssh-rsa by default.
    argv = raw_scp_argv("/c/x", "/var/tmp/x", "h", 22, "ops", key, password_auth)
    assert "HostKeyAlgorithms=+ssh-rsa" in argv
    assert "PubkeyAcceptedAlgorithms=+ssh-rsa" in argv
