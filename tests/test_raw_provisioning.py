"""Raw Provisioning Path helper contract (ADR-0005).

The rendered shell commands are executed with a local ``sh`` and only their
observable effects (files, modes, exit codes) are asserted.
"""
import getpass
import grp
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from raw_provisioning import (  # noqa: E402
    raw_probe_cmd, raw_push_changed, raw_push_cmd, raw_read_cmd,
    raw_parse_os_release, raw_read_extract, raw_set_directives,
    raw_changed, raw_group_cmd, raw_user_cmd, raw_authorized_key_cmd,
    raw_sysctl_directives, raw_limits_content, raw_sudoers_line,
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


# --- common role raw consumers (#31) ---------------------------------------

def test_sysctl_directives_replace_or_append_in_sysctl_conf():
    current = "kernel.sysrq = 0\nvm.swappiness = 60\n# net.core.rmem_max = 1\n"
    directives = raw_sysctl_directives({"vm.swappiness": 10, "net.core.rmem_max": 16777216,
                                        "net.ipv4.tcp_rmem": "4096 87380 16777216"})
    out = raw_set_directives(current, directives)
    assert out == ("kernel.sysrq = 0\nvm.swappiness = 10\n# net.core.rmem_max = 1\n"
                   "net.core.rmem_max = 16777216\nnet.ipv4.tcp_rmem = 4096 87380 16777216\n")
    assert raw_set_directives(out, directives) == out


def test_limits_content_lists_every_limit_and_is_stable():
    limits = [{"domain": "*", "limit_type": "soft", "limit_item": "nofile", "value": 65535},
              {"domain": "*", "limit_type": "hard", "limit_item": "nproc", "value": "65535"}]
    out = raw_limits_content(limits)
    assert out == raw_limits_content(limits)
    rows = [ln.split() for ln in out.splitlines() if not ln.startswith("#")]
    assert rows == [["*", "soft", "nofile", "65535"], ["*", "hard", "nproc", "65535"]]
    assert out.endswith("\n")


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
    r = _run(tmp_path, bindir, raw_user_cmd("ppzxc", "ppzxc", ["wheel", "docker"],
                                            "/bin/bash", "Ops", 1001, "present"))
    assert r.returncode == 0 and raw_changed(r.stdout)
    assert log.read_text().strip() == "useradd -m -g ppzxc -G wheel,docker -s /bin/bash -c Ops -u 1001 ppzxc"


def test_user_in_sync_is_unchanged(tmp_path):
    bindir = _stub_bin(tmp_path, dict(USER_STUBS, **{
        "getent": "echo dev:x:1000:1000:Ops:/home/dev:/bin/bash",
        "usermod": "exit 9",
    }))
    r = _run(tmp_path, bindir, raw_user_cmd("dev", "dev", ["wheel"], "/bin/bash", "Ops", 1000, "present"))
    assert r.returncode == 0, r.stderr
    assert not raw_changed(r.stdout)


def test_user_drift_is_fixed_with_a_single_usermod(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, dict(USER_STUBS, **{
        "getent": "echo dev:x:1000:1000:Ops:/home/dev:/bin/sh",
        "usermod": 'echo "usermod $*" >> %s' % log,
    }))
    r = _run(tmp_path, bindir, raw_user_cmd("dev", "dev", ["wheel", "docker"], "/bin/bash", None, None, "present"))
    assert raw_changed(r.stdout)
    assert log.read_text().splitlines() == ["usermod -s /bin/bash -a -G docker dev"]


def test_absent_user_is_removed_only_if_present(tmp_path):
    log = tmp_path / "calls"
    bindir = _stub_bin(tmp_path, {"getent": "echo x:x:1:1::/h:/s",
                                  "userdel": 'echo "userdel $*" >> %s' % log})
    r = _run(tmp_path, bindir, raw_user_cmd("old", "old", [], "/bin/bash", None, None, "absent"))
    assert raw_changed(r.stdout)
    assert log.read_text().strip() == "userdel -r old"
    bindir = _stub_bin(tmp_path, {"getent": "exit 2"})
    r = _run(tmp_path, bindir, raw_user_cmd("old", "old", [], "/bin/bash", None, None, "absent"))
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
    gated = ["COMMON-011", "COMMON-012", "COMMON-013", "COMMON-014", "COMMON-015",
             "COMMON-016", "COMMON-022", "COMMON-023"]
    for t in tasks:
        if any(t.get("name", "").startswith("[%s]" % g) for g in gated):
            assert "raw_provisioning_path" in str(t.get("when")), t["name"]
    assert "raw_provisioning_path" in (role / "defaults" / "main.yml").read_text()
