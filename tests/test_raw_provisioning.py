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
    raw_probe_cmd, raw_push_changed, raw_push_cmd, raw_set_directives,
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
