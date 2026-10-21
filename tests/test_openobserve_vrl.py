"""OpenObserve VRL ingest functions (ADR-0008, Spec #93 / Ticket-2 and Spec #277, seam 2).

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


def _apply(tmp_path, record, program=VRL_FILE):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(record) + "\n")
    res = subprocess.run([VRL_BIN, "--input", str(src), "--program", str(program), "--print-object", "--quiet"],
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
      "event_action": "ssh_login", "event_reason": "invalid user"}),
    ("Invalid user guest from 198.51.100.7",
     {"user_name": "guest", "source_address": "198.51.100.7",
      "event_action": "ssh_login", "event_reason": "invalid user"}),
])
def test_sshd_login_lines_become_user_address_port_and_outcome(tmp_path, line, expected):
    rec = _rec("sshd", SSHD + line)
    out = _apply(tmp_path, rec)
    assert _added(rec, out) == expected


@pytest.mark.parametrize("line", [
    "Invalid user oracle from 198.51.100.7 port 3333",
    "Invalid user guest from 198.51.100.7",
])
def test_invalid_user_probe_line_is_not_counted_as_a_second_failure(tmp_path, line):
    # sshd logs both "Invalid user X from" and "Failed password for invalid user X" for one attempt; alerts count outcomes
    out = _apply(tmp_path, _rec("sshd", SSHD + line))
    assert "event_outcome" not in out and out["event_reason"] == "invalid user"


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
    {"body": "no program field at all, Failed password for x from 192.0.2.4 port 1"},
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


SU = "Mar  5 10:11:12 host1 su[77]: "


@pytest.mark.parametrize("line, expected", [
    # EL6 / EL7+ / Ubuntu: PAM이 남기는 인증 실패 줄 (user=는 대상 계정, ruser가 실행한 사람)
    ("pam_unix(su:auth): authentication failure; logname=alice uid=500 euid=0 tty=pts/0 ruser=alice rhost=  user=root",
     {"user_name": "alice", "user_effective_name": "root", "event_action": "su", "event_outcome": "failure",
      "event_reason": "authentication failure"}),
    ("pam_unix(su-l:auth): authentication failure; logname=bob uid=1000 euid=1000 tty=/dev/pts/1 ruser=bob rhost=  user=root",
     {"user_name": "bob", "user_effective_name": "root", "event_action": "su", "event_outcome": "failure",
      "event_reason": "authentication failure"}),
    # Ubuntu가 같은 시도에 한 번 더 남기는 줄은 두 번 세지 않도록 결과(event_outcome) 없이 su로만 표시한다
    ("FAILED SU (to root) alice on pts/0",
     {"user_name": "alice", "user_effective_name": "root", "event_action": "su", "event_reason": "authentication failure"}),
])
def test_su_authentication_failures_become_su_failure(tmp_path, line, expected):
    rec = _rec("su", SU + line)
    assert _added(rec, _apply(tmp_path, rec)) == expected


@pytest.mark.parametrize("line", [
    "pam_unix(su:session): session opened for user root by alice(uid=1000)",
    "(to root) alice on pts/0",
    "Successful su for root by alice",
])
def test_successful_su_is_not_a_failure(tmp_path, line):
    rec = _rec("su", SU + line)
    out = _apply(tmp_path, rec)
    assert out.get("event_outcome") != "failure" and out["body"] == rec["body"]


# --- 스위치 syslog (Spec #277): switch_syslog_semantics ----------------------------------------------------------------------
SWITCH_VRL_FILE = ROOT_DIR / "roles" / "openobserve_config" / "files" / "vrl" / "switch_syslog_semantics.vrl"
ADJ = ("Oct 20 17:48:40 203.0.113.5 ns0250-3750X: Oct 20 17:48:39.443 KST: %ADJ-3-RESOLVE_REQ: "
       "Adj resolve request: Failed to resolve 203.0.113.9 Vlan7")
FLAP = ("Oct 20 17:50:01 203.0.113.6 NS0347-3560X: Oct 20 17:50:00.001 KST: %SW_MATM-4-MACFLAP_NOTIF: "
        "Host 0011.2233.4455 in vlan 7 is flapping between port Gi0/13 and port Gi0/14")


def _switch(body, **extra):
    # what the pipeline hands over: host_name is the collection server (not the switch) and severity is always 0
    return {"service_name": "switch-syslog", "host_name": "collector01", "severity": 0, "log_file_path": "/var/log/switch.log",
            "body": body, **extra}


def _apply_switch(tmp_path, record):
    return _apply(tmp_path, record, program=SWITCH_VRL_FILE)


@pytest.mark.parametrize("body, expected", [
    (ADJ, {"device_name": "ns0250-3750x", "device_id": "ns0250", "cisco_facility": "ADJ", "cisco_mnemonic": "RESOLVE_REQ",
           "event_name": "ADJ-3-RESOLVE_REQ", "log_syslog_severity_code": 3, "log_syslog_severity_name": "error"}),
    (FLAP, {"device_name": "ns0347-3560x", "device_id": "ns0347", "cisco_facility": "SW_MATM", "cisco_mnemonic": "MACFLAP_NOTIF",
            "event_name": "SW_MATM-4-MACFLAP_NOTIF", "log_syslog_severity_code": 4, "log_syslog_severity_name": "warning"}),
    # Cisco의 순번과 시계 표시(*)가 붙은 형식
    ("Oct 20 17:50:01 203.0.113.6 ns0347-3560X: 000123: *Oct 20 17:50:00.001 KST: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (203.0.113.7)",
     {"device_name": "ns0347-3560x", "device_id": "ns0347", "cisco_facility": "SYS", "cisco_mnemonic": "CONFIG_I",
      "event_name": "SYS-5-CONFIG_I", "log_syslog_severity_code": 5, "log_syslog_severity_name": "notice"}),
])
def test_cisco_message_becomes_device_facility_severity_and_mnemonic_fields(tmp_path, body, expected):
    rec = _switch(body)
    assert _added(rec, _apply_switch(tmp_path, rec)) == expected


@pytest.mark.parametrize("severity, name", list(enumerate(
    ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"])))
def test_severity_number_and_name_follow_the_message_code(tmp_path, severity, name):
    rec = _switch(f"Oct 20 17:50:01 203.0.113.6 ns0347: Oct 20 17:50:00.001 KST: %TEST-{severity}-SAMPLE: x")
    out = _apply_switch(tmp_path, rec)
    assert (out["log_syslog_severity_code"], out["log_syslog_severity_name"]) == (severity, name)


@pytest.mark.parametrize("device", ["ns0347-3560X", "NS0347-3560X", "ns0347-3560x.corp.example", "Ns0347-3560X.Corp.Example.Net"])
def test_name_case_and_domain_differences_collapse_into_one_device(tmp_path, device):
    out = _apply_switch(tmp_path, _switch(f"Oct 20 17:50:01 203.0.113.6 {device}: Oct 20 17:50:00.001 KST: %SW_MATM-4-MACFLAP_NOTIF: x"))
    assert (out["device_name"], out["device_id"]) == ("ns0347-3560x", "ns0347")


@pytest.mark.parametrize("device, name", [("core-sw1", "core-sw1"), ("Core-SW1.corp.example", "core-sw1"), ("203.0.113.40", "203.0.113.40")])
def test_a_name_without_a_management_number_keeps_only_the_normalized_name(tmp_path, device, name):
    rec = _switch(f"Oct 20 17:50:01 203.0.113.6 {device}: Oct 20 17:50:00.001 KST: %SYS-5-CONFIG_I: x")
    out = _apply_switch(tmp_path, rec)
    assert out["device_name"] == name and "device_id" not in out and out["event_name"] == "SYS-5-CONFIG_I"


@pytest.mark.parametrize("body", [
    "garbage that is not a log line",
    "Oct 20 17:50:01 203.0.113.6 ns0347: Oct 20 17:50:00.001 KST: no cisco message code in this line",
    "Oct 20 17:50:01 203.0.113.6 ns0347: Oct 20 17:50:00.001 KST: %SW_MATM-9-BAD_SEVERITY: severity must be 0..7",
    "Oct 20 17:50:01 203.0.113.6 ns0347: Oct 20 17:50:00.001 KST: %NOSEVERITY: not facility-severity-mnemonic",
    "",
])
def test_lines_that_are_not_cisco_messages_pass_through_unchanged(tmp_path, body):
    rec = _switch(body)
    assert _apply_switch(tmp_path, copy.deepcopy(rec)) == rec


def test_body_and_existing_fields_are_never_modified(tmp_path):
    rec = _switch(FLAP, custom="keep")
    out = _apply_switch(tmp_path, rec)
    for key, value in rec.items():
        assert out[key] == value, key   # host_name stays the collection server, severity stays 0, body stays byte for byte
    assert out["severity"] == 0 and out["host_name"] == "collector01"


@pytest.mark.parametrize("rec", [
    # same Cisco-looking text, but it is a server log or another service: not touched
    {"service_name": "sshd", "host_name": "ns0001", "body": FLAP},
    {"service_name": "syslog", "host_name": "ns0001", "severity": "info", "body": ADJ},
    {"host_name": "ns0001", "body": ADJ},
    {"service_name": "switch-syslog"},
    {"service_name": "switch-syslog", "body": 12345},
    {"service_name": 7, "body": ADJ},
])
def test_server_logs_and_other_services_are_not_affected(tmp_path, rec):
    assert _apply_switch(tmp_path, copy.deepcopy(rec)) == rec


# --------------------------------------------------------------------------
# 방화벽 syslog(Spec #282): security_logs의 fortigate-syslog 레코드는 security_semantics를 그대로 통과한다
@pytest.mark.parametrize("rec", [
    {"service_name": "fortigate-syslog", "host_name": "ns0266",
     "body": 'date=2026-10-21 time=10:00:00 devname="FW-A" type="event" subtype="system" action="login" status="failed" user="admin"'},
    {"service_name": "fortigate-syslog", "host_name": "ns0266",
     "body": 'type="utm" subtype="ips" action="dropped" msg="Failed password for x from 192.0.2.4 port 1"'},
])
def test_fortigate_records_on_security_logs_pass_the_security_function_unchanged(tmp_path, rec):
    assert _apply(tmp_path, copy.deepcopy(rec)) == rec


# --------------------------------------------------------------------------
# 방화벽 필드 추출(Spec #282 / Ticket-2): fortigate_semantics
#
# 주의: 아래 입력은 합성이다. 실제 장비 로그 샘플이 아직 없어(장비 syslog 미설정) FortiOS 7.2/7.4 Log Message Reference의 기본
# key=value 형식(date, time, devname, devid, type, subtype, action, srcip, user, policyid, ui, remip)을 근거로 만들었다.
# 키 이름·값 모양은 실장비 샘플로 재검증해야 한다(런북 docs/runbooks/fortigate-syslog.md 5절). IP는 문서용 예약 대역만 쓴다.
FORTIGATE_VRL_FILE = ROOT_DIR / "roles" / "openobserve_config" / "files" / "vrl" / "fortigate_semantics.vrl"
FGT_HEAD = 'date=2026-10-21 time=10:00:00 devname="{dev}" devid="FGT60F0000000000" '


def _fgt(rest, dev="NS0399", **extra):
    # what the pipeline hands over: host_name is the collection server, severity is always 0, body is the line as received
    return {"service_name": "fortigate-syslog", "host_name": "collector01", "severity": 0,
            "body": FGT_HEAD.format(dev=dev) + rest, **extra}


def _apply_fgt(tmp_path, record):
    return _apply(tmp_path, record, program=FORTIGATE_VRL_FILE)


FGT_CASES = {
    "admin_login": ('logid="0100032001" type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" '
                    'action="login" status="success" user="admin" ui="https(192.0.2.10)" msg="Administrator admin logged in successfully"',
                    {"event_action": "login", "user_name": "admin", "source_address": "192.0.2.10", "fortigate_log_type": "event",
                     "fortigate_log_subtype": "system"}),
    "admin_login_failed": ('logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" '
                           'action="login" status="failed" user="admin" ui="ssh(192.0.2.11)" reason="passwd_invalid"',
                           {"event_action": "login", "user_name": "admin", "source_address": "192.0.2.11",
                            "fortigate_log_type": "event", "fortigate_log_subtype": "system"}),
    "config_change": ('logid="0100044546" type="event" subtype="system" level="information" vd="root" logdesc="Attribute configured" '
                      'action="Edit" user="admin" ui="GUI(192.0.2.10)" cfgpath="firewall.policy" cfgobj="7" msg="Edit firewall.policy 7"',
                      {"event_action": "edit", "user_name": "admin", "source_address": "192.0.2.10", "fortigate_log_type": "event",
                       "fortigate_log_subtype": "system"}),
    "vpn": ('logid="0101039424" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel up" '
            'action="tunnel-up" remip=192.0.2.20 user="vpnuser" reason="login successfully"',
            {"event_action": "tunnel-up", "user_name": "vpnuser", "source_address": "192.0.2.20", "fortigate_log_type": "event",
             "fortigate_log_subtype": "vpn"}),
    "utm_ips": ('logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" srcip=192.0.2.30 '
                'dstip=198.51.100.5 policyid=12 action="dropped" attack="Example.Attack" severity="high"',
                {"event_action": "dropped", "source_address": "192.0.2.30", "fortigate_policy_id": 12, "fortigate_log_type": "utm",
                 "fortigate_log_subtype": "ips"}),
    "policy_deny": ('logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.40 dstip=198.51.100.6 '
                    'policyid=0 action="deny" service="HTTPS"',
                    {"event_action": "deny", "source_address": "192.0.2.40", "fortigate_policy_id": 0, "fortigate_log_type": "traffic",
                     "fortigate_log_subtype": "forward"}),
    "ha": ('logid="0104035001" type="event" subtype="ha" level="critical" vd="root" logdesc="HA state changed" '
           'msg="Virtual cluster 1 member state changed from standby to primary"',
           {"fortigate_log_type": "event", "fortigate_log_subtype": "ha"}),
}


@pytest.mark.parametrize("case", sorted(FGT_CASES))
def test_firewall_line_gets_device_type_subtype_action_source_user_and_policy_fields(tmp_path, case):
    rest, expected = FGT_CASES[case]
    rec = _fgt(rest)
    expected = {"device_name": "ns0399", "device_id": "ns0399", **expected}
    assert _added(rec, _apply_fgt(tmp_path, rec)) == expected


@pytest.mark.parametrize("dev, name, ident", [("NS0380", "ns0380", "ns0380"), ("ns0381", "ns0381", "ns0381"), ("Ns0399", "ns0399", "ns0399"),
                                              ("NS0399.corp.example", "ns0399", "ns0399"), ("lab-fw", "lab-fw", None)])
def test_device_name_is_normalized_and_the_management_number_comes_from_it(tmp_path, dev, name, ident):
    out = _apply_fgt(tmp_path, _fgt('type="event" subtype="ha" msg="x"', dev=dev))
    assert out["device_name"] == name and out.get("device_id") == ident


def test_syslog_header_and_priority_before_the_key_values_do_not_matter(tmp_path):
    rec = _fgt('type="traffic" subtype="forward" srcip=192.0.2.40 action="deny"')
    rec["body"] = "<189>Oct 21 10:00:00 ns0399 " + rec["body"]
    assert _apply_fgt(tmp_path, rec)["source_address"] == "192.0.2.40"


def test_quoted_values_with_spaces_and_embedded_key_names_are_not_mistaken_for_fields(tmp_path):
    rec = _fgt('type="event" subtype="system" action="login" user="john doe" msg="user=intruder srcip=198.51.100.99 action=deny" ui="https(192.0.2.10)"')
    out = _apply_fgt(tmp_path, rec)
    assert (out["user_name"], out["source_address"], out["event_action"]) == ("john doe", "192.0.2.10", "login")


@pytest.mark.parametrize("unset", ['user="N/A"', 'user=""', "user=N/A"])
def test_unset_user_is_left_out_instead_of_stored_as_a_value(tmp_path, unset):
    out = _apply_fgt(tmp_path, _fgt(f'type="traffic" subtype="forward" srcip=192.0.2.40 {unset}'))
    assert "user_name" not in out


def test_firewall_body_and_existing_fields_are_never_modified(tmp_path):
    rec = _fgt(FGT_CASES["admin_login"][0], custom="keep")
    out = _apply_fgt(tmp_path, rec)
    for key, value in rec.items():
        assert out[key] == value, key   # body byte for byte, host_name stays the collection server, severity stays 0


@pytest.mark.parametrize("body", [
    "garbage that is not a log line",
    "date=2026-10-21 time=10:00:00 devname=\"ns0399\" no type key here",
    "Oct 21 10:00:00 ns0399 something=else",
    "",
])
def test_firewall_lines_that_cannot_be_interpreted_pass_through_unchanged(tmp_path, body):
    rec = {"service_name": "fortigate-syslog", "host_name": "collector01", "body": body}
    assert _apply_fgt(tmp_path, copy.deepcopy(rec)) == rec


@pytest.mark.parametrize("rec", [
    # same FortiGate-looking text, but a server log, a switch line or another service: not touched
    {"service_name": "sshd", "host_name": "ns0001", "body": FGT_HEAD.format(dev="ns0399") + FGT_CASES["utm_ips"][0]},
    {"service_name": "switch-syslog", "host_name": "collector01", "body": FGT_HEAD.format(dev="ns0399") + FGT_CASES["utm_ips"][0]},
    {"host_name": "ns0001", "body": FGT_HEAD.format(dev="ns0399") + FGT_CASES["utm_ips"][0]},
    {"service_name": "fortigate-syslog"},
    {"service_name": "fortigate-syslog", "body": 12345},
    {"service_name": 7, "body": FGT_HEAD.format(dev="ns0399") + FGT_CASES["utm_ips"][0]},
])
def test_server_switch_and_other_service_records_are_not_affected_by_the_firewall_function(tmp_path, rec):
    assert _apply_fgt(tmp_path, copy.deepcopy(rec)) == rec


# 장비 이름 별칭(Spec #282): 원래 이름을 그대로 쓰는 장비는 별칭표로 관리번호를 얻는다. 이름은 가짜다.
def _apply_fgt_with_aliases(tmp_path, record, aliases):
    import sys
    sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
    from openobserve_config import o2c_fortigate_vrl
    program = tmp_path / "fortigate_aliased.vrl"
    program.write_text(o2c_fortigate_vrl(FORTIGATE_VRL_FILE.read_text(), aliases))
    return _apply(tmp_path, record, program=program)


@pytest.mark.parametrize("dev", ["Example_Branch_FW", "EXAMPLE_BRANCH_FW", "example_branch_fw.corp.example"])
def test_aliased_device_name_gets_the_management_number_and_keeps_the_normalized_name(tmp_path, dev):
    out = _apply_fgt_with_aliases(tmp_path, _fgt('type="event" subtype="ha" msg="x"', dev=dev), {"example_branch_fw": "ns0000"})
    assert out["device_id"] == "ns0000" and out["device_name"] == "example_branch_fw"


def test_names_missing_from_the_alias_table_still_use_the_ns_number_and_an_empty_table_changes_nothing(tmp_path):
    aliases = {"example_branch_fw": "ns0000"}
    out = _apply_fgt_with_aliases(tmp_path, _fgt('type="event" subtype="ha" msg="x"', dev="NS0380"), aliases)
    assert out["device_id"] == "ns0380"
    out = _apply_fgt_with_aliases(tmp_path, _fgt('type="event" subtype="ha" msg="x"', dev="Example_Branch_FW"), {})
    assert out["device_name"] == "example_branch_fw" and "device_id" not in out


# 실로그 샘플 검증(Spec #282): 실제 FortiOS 줄을 가짜 값으로 치환한 tests/fixtures/fortigate_real_lines.tsv
# 검증 범위: 관리자 로그인 성공/실패, 정책·로그 설정 변경(GUI·jsconsole·ha_daemon), 로컬·포워드 트래픽(정책 0 포함), IPsec 터널 통계,
# UTM(ips·virus·dlp·anomaly), HA 인터페이스 실패, FSSO, 엔드포인트. 검증되지 않은 종류: HA 전환(상태 변경) 실제 줄, SSL VPN 사용자 로그인/로그아웃,
# 웹필터·앱제어의 실제 장비 줄(장비 테스트 생성 줄만 있음), IPv6 주소.
REAL_LINES_FILE = ROOT_DIR / "tests" / "fixtures" / "fortigate_real_lines.tsv"


def _real_line(name):
    for raw in REAL_LINES_FILE.read_text(encoding="utf-8").splitlines():
        if raw and not raw.startswith("#"):
            key, _tag, line = raw.split("\t", 2)
            if key == name:
                return line
    raise KeyError(name)


def _real_rec(name):
    return {"service_name": "fortigate-syslog", "host_name": "collector01", "severity": 0, "body": _real_line(name)}


OFFICE = {"device_name": "example_branch_fw", "device_id": "ns0001"}   # 관리번호 없는 장비는 별칭표로 관리번호를 얻는다
IDC1 = {"device_name": "ns0001", "device_id": "ns0001"}
REAL_CASES = {
    "login_failed": (OFFICE, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "login",
                              "source_address": "192.0.2.11", "user_name": "example-admin"}),
    "login_success": (OFFICE, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "login",
                               "source_address": "192.0.2.11", "user_name": "example-admin"}),
    "policy_edit_gui": (OFFICE, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "edit",
                                 "source_address": "192.0.2.11", "user_name": "example-admin"}),
    "syslogd_filter_edit": (OFFICE, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "edit",
                                     "source_address": "192.0.2.11", "user_name": "example-admin"}),
    "local_in_deny": (OFFICE, {"fortigate_log_type": "traffic", "fortigate_log_subtype": "local", "event_action": "deny",
                               "source_address": "192.0.2.12", "fortigate_policy_id": 0}),
    "forward_accept": (OFFICE, {"fortigate_log_type": "traffic", "fortigate_log_subtype": "forward", "event_action": "accept",
                                "source_address": "192.0.2.13", "fortigate_policy_id": 8}),
    "forward_deny_policy0": (IDC1, {"fortigate_log_type": "traffic", "fortigate_log_subtype": "forward", "event_action": "deny",
                                    "source_address": "192.0.2.16", "fortigate_policy_id": 0}),
    # user="<상대 장비 IP>" 는 사용자가 아니다: user_name을 만들지 않는다
    "vpn_tunnel_stats": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "vpn", "event_action": "tunnel-stats",
                                "source_address": "192.0.2.10"}),
    # ui="ha_daemon" 에는 주소가 없다: source_address를 만들지 않는다
    "policy_edit_ha_daemon": ({"device_name": "ns0002", "device_id": "ns0002"},
                              {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "edit",
                               "user_name": "example-admin"}),
    "policy_edit_jsconsole": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "edit",
                                     "source_address": "192.0.2.10", "user_name": "example-admin"}),
    "log_setting_edit": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "system", "event_action": "edit",
                                "source_address": "192.0.2.10", "user_name": "example-admin"}),
    "ips_high": (IDC1, {"fortigate_log_type": "utm", "fortigate_log_subtype": "ips", "event_action": "detected",
                        "source_address": "192.0.2.61", "user_name": "user5", "fortigate_policy_id": 0}),
    "virus_infected": (IDC1, {"fortigate_log_type": "utm", "fortigate_log_subtype": "virus", "event_action": "passthrough",
                              "source_address": "192.0.2.61", "user_name": "user", "fortigate_policy_id": 1}),
    "dlp_info": (IDC1, {"fortigate_log_type": "utm", "fortigate_log_subtype": "dlp", "event_action": "block",
                        "source_address": "192.0.2.61", "user_name": "user4", "fortigate_policy_id": 1}),
    "anomaly_critical": (IDC1, {"fortigate_log_type": "utm", "fortigate_log_subtype": "anomaly", "event_action": "clear_session",
                                "source_address": "192.0.2.61", "fortigate_policy_id": 0}),
    "ha_interface_failed": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "ha"}),   # action 키가 없다
    "fsso_logon": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "user", "event_action": "fss0-logon",
                          "source_address": "192.0.2.66", "user_name": "user"}),
    "endpoint_license": (IDC1, {"fortigate_log_type": "event", "fortigate_log_subtype": "endpoint", "event_action": "add"}),
}


@pytest.mark.parametrize("name", sorted(REAL_CASES))
def test_real_firewall_lines_get_the_expected_fields(tmp_path, name):
    ident, expected = REAL_CASES[name]
    rec = _real_rec(name)
    out = _apply_fgt_with_aliases(tmp_path, copy.deepcopy(rec), {"example_branch_fw": "ns0001"})
    assert _added(rec, out) == {**ident, **expected}
    assert all(out[k] == v for k, v in rec.items())   # 원문과 기존 필드는 그대로
