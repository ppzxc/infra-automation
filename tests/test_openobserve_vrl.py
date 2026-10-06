"""OpenObserve VRL ingest function (ADR-0008, Spec #93 / Ticket-2, seam 2).

The VRL program is run through a real ``vrl`` CLI (https://github.com/vectordotdev/vrl, ``cargo install vrl
--features cli``) against sample ``security_logs`` records and the resulting record is asserted: the extracted
fields, "no match leaves the record untouched" and "body is never modified".

Set ``VRL_BIN`` (or put ``vrl`` on PATH); the tests skip without it.

Records are what OpenObserve hands the function after flattening: OTel attribute dots become underscores
(``process.executable.name`` -> ``process_executable_name``), ``body`` is the original log line.
"""

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
VRL_FILE = ROOT_DIR / "roles" / "openobserve_config" / "files" / "vrl" / "security_semantics.vrl"
VRL_BIN = os.environ.get("VRL_BIN") or shutil.which("vrl")

pytestmark = pytest.mark.skipif(not VRL_BIN, reason="vrl CLI not available (set VRL_BIN)")

SSHD = "Mar  5 10:11:12 host1 sshd[1234]: "
SUDO = "Mar  5 10:11:12 host1 sudo[99]: "


def _apply(tmp_path, record):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(record) + "\n")
    res = subprocess.run([VRL_BIN, "--input", str(src), "--program", str(VRL_FILE), "--print-object", "--quiet"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def _rec(program, body, **extra):
    return {"process_executable_name": program, "body": body, "host_name": "ns0001", **extra}


def _added(before, after):
    return {k: v for k, v in after.items() if before.get(k) != v}


@pytest.mark.parametrize("line, expected", [
    ("Accepted publickey for root from 10.0.0.1 port 51234 ssh2: RSA SHA256:abc",
     {"user_name": "root", "source_address": "10.0.0.1", "source_port": 51234,
      "event_action": "ssh_login", "event_outcome": "success"}),
    ("Accepted password for alice from 2001:db8::1 port 22 ssh2",
     {"user_name": "alice", "source_address": "2001:db8::1", "source_port": 22,
      "event_action": "ssh_login", "event_outcome": "success"}),
    ("Failed password for bob from 203.0.113.9 port 40000 ssh2",
     {"user_name": "bob", "source_address": "203.0.113.9", "source_port": 40000,
      "event_action": "ssh_login", "event_outcome": "failure", "event_reason": "failed password"}),
    ("Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2",
     {"user_name": "admin", "source_address": "203.0.113.9", "source_port": 40001,
      "event_action": "ssh_login", "event_outcome": "failure", "event_reason": "invalid user"}),
    ("Invalid user oracle from 198.51.100.7 port 3333",
     {"user_name": "oracle", "source_address": "198.51.100.7", "source_port": 3333,
      "event_action": "ssh_login", "event_outcome": "failure", "event_reason": "invalid user"}),
    ("Invalid user guest from 198.51.100.7",
     {"user_name": "guest", "source_address": "198.51.100.7",
      "event_action": "ssh_login", "event_outcome": "failure", "event_reason": "invalid user"}),
])
def test_sshd_login_lines_become_user_address_port_and_outcome(tmp_path, line, expected):
    rec = _rec("sshd", SSHD + line)
    out = _apply(tmp_path, rec)
    assert _added(rec, out) == expected


@pytest.mark.parametrize("line, expected", [
    ("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
     {"user_name": "alice", "user_effective_name": "root", "process_command_line": "/usr/bin/systemctl restart nginx",
      "event_action": "sudo", "event_outcome": "success"}),
    ("bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow",
     {"user_name": "bob", "user_effective_name": "root", "process_command_line": "/bin/cat /etc/shadow",
      "event_action": "sudo", "event_outcome": "failure", "event_reason": "NOT in sudoers"}),
    ("carol : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
     {"user_name": "carol", "user_effective_name": "root", "process_command_line": "/bin/ls",
      "event_action": "sudo", "event_outcome": "failure", "event_reason": "authentication failure"}),
    ("pam_unix(sudo:auth): authentication failure; logname=dave uid=1000 euid=0 tty=/dev/pts/0 ruser=dave rhost=  user=dave",
     {"user_name": "dave", "event_action": "sudo", "event_outcome": "failure",
      "event_reason": "authentication failure"}),
])
def test_sudo_lines_become_user_command_and_outcome(tmp_path, line, expected):
    rec = _rec("sudo", SUDO + line)
    out = _apply(tmp_path, rec)
    assert _added(rec, out) == expected


@pytest.mark.parametrize("rec", [
    _rec("sshd", SSHD + "Connection closed by 10.0.0.1 port 22 [preauth]"),
    _rec("sshd", SSHD + "pam_unix(sshd:session): session opened for user root by (uid=0)"),
    _rec("sudo", SUDO + "pam_unix(sudo:session): session opened for user root by alice(uid=0)"),
    _rec("kernel", "Out of memory: Killed process 1234 (java)"),
    # another program that merely quotes the text must not be interpreted
    _rec("logger", "Accepted publickey for root from 10.0.0.1 port 22 ssh2"),
    {"body": "no program field at all, Failed password for x from 1.2.3.4 port 1"},
    {"process_executable_name": "sshd"},
    {"process_executable_name": "sshd", "body": 12345},
])
def test_other_records_pass_through_unchanged(tmp_path, rec):
    assert _apply(tmp_path, copy.deepcopy(rec)) == rec


def test_body_and_existing_fields_are_never_modified(tmp_path):
    rec = _rec("sshd", SSHD + "Accepted publickey for root from 10.0.0.1 port 22 ssh2", custom="keep", host_ip="10.9.9.9")
    out = _apply(tmp_path, rec)
    assert out["body"] == rec["body"] and out["custom"] == "keep" and out["host_ip"] == "10.9.9.9"
    assert out["process_executable_name"] == "sshd"
