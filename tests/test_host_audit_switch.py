"""Host Audit 스위치 단계 판정 필터 (Spec #568 / Ticket-3·4): KISA-2026 N-01~N-38.

합성 running-config만 쓴다(장비 주소·모델·실제 결과 없음). 판정 규칙의 기준은 docs/host_audit_switch.md 적용 표다.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

import host_audit_switch as hs  # noqa: E402
from host_audit_kisa import EXCEPTION, GOOD, MANUAL, NOT_APPLICABLE, VULNERABLE  # noqa: E402

TODAY = "2026-11-19"
VERSION = "Cisco IOS Software, C0000 Software (C0000-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"

GOOD_CONFIG = """\
Building configuration...

Current configuration : 2000 bytes
!
version 15.0
service timestamps log datetime msec localtime
service password-encryption
!
hostname swtest
!
security passwords min-length 8
login block-for 120 attempts 5 within 60
enable secret 9 $9$fakehashvalue
username admin privilege 15 secret 9 $9$fakehash1
username viewer privilege 1 secret 9 $9$fakehash2
!
logging buffered 32768 informational
logging host 192.0.2.50
logging trap informational
ntp server 192.0.2.60
!
ip ssh version 2
service tcp-keepalives-in
service tcp-keepalives-out
no ip http server
no ip http secure-server
no ip bootp server
no cdp run
no ip source-route
no ip domain-lookup
no service pad
!
access-list 10 permit 192.0.2.0 0.0.0.255
ip access-list standard VTY_ACL
 permit 192.0.2.0 0.0.0.255
!
interface Vlan1
 no ip address
!
banner login ^C
Authorized users only.
^C
!
line con 0
 exec-timeout 5 0
 login local
line aux 0
 exec-timeout 5 0
 no exec
 transport input none
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 login local
 transport input ssh
line vty 5 15
 access-class VTY_ACL in
 exec-timeout 5 0
 login local
 transport input ssh
!
end
"""


def edit(config=GOOD_CONFIG, *, drop=(), sub=(), add=()):
    """합성 설정에서 줄을 지우고(정규식), 바꾸고, 문자열을 덧붙인다."""
    for pattern in drop:
        config, n = re.subn(pattern, "", config, flags=re.M)
        assert n, "drop pattern matched nothing: %s" % pattern
    for old, new in sub:
        assert old in config, old
        config = config.replace(old, new)
    for line in add:
        config = config.replace("\nend\n", "\n" + line + "\nend\n")
    return config


def judge(config=GOOD_CONFIG, version=VERSION, access="ssh", register=None, host="sw0001"):
    result = hs.host_audit_switch_result(
        {"rc": 0, "stdout": hs_json(config, version), "stderr": ""}, access, register or [], host, ["cisco_switches"], TODAY)
    return result


def hs_json(config, version):
    import json
    return json.dumps({"running_config": config, "version": version})


def verdict(result, code):
    return next(r for r in result["results"] if r["code"] == "KISA-2026:" + code)


def v(result):
    return {r["code"].split(":")[1]: r["verdict"] for r in result["results"]}


L2_NOT_APPLICABLE = ["N-22", "N-23", "N-31", "N-32", "N-33", "N-34", "N-38"]
ALL_CODES = ["N-%02d" % n for n in range(1, 39)]

# ------------------------------------------------------------ 기준선과 구조


def test_good_config_is_good_for_every_item_except_the_fixed_manual_one():
    result = judge()
    verdicts = v(result)
    assert result["status"] == "ok" and result["edition"] == "KISA-2026"
    assert sorted(verdicts) == sorted(hs.CHECKS)
    # 이 합성 설정은 L2이고 AUX 포트가 있다. N-12·N-24는 항상 점검불가(수동 확인), L2 해당없음 7개는 판정하지 않는다.
    assert {c: x for c, x in verdicts.items() if x != GOOD} == dict(
        {"N-12": MANUAL, "N-24": MANUAL}, **{c: NOT_APPLICABLE for c in L2_NOT_APPLICABLE})


def test_only_registered_items_are_reported_and_unimplemented_ones_are_left_out():
    assert set(hs.CHECKS) <= set(_table_rows())
    assert sorted(r["code"].split(":")[1] for r in judge()["results"]) == sorted(hs.CHECKS)


def test_result_rows_have_the_server_record_shape():
    row = verdict(judge(), "N-01")
    assert set(row) == {"code", "result", "verdict", "evidence", "exception"}
    assert row["code"] == "KISA-2026:N-01" and row["result"] == "GOOD" and row["exception"] is None


# ------------------------------------------------------------ 항목별 취약/양호


CASES = [
    # (코드, 이름, 설정 변경, 기대 판정)
    ("N-01", "enable 비밀번호 없음", dict(drop=[r"^enable secret.*\n"]), VULNERABLE),
    ("N-01", "enable password만 있음도 설정 있음", dict(sub=[("enable secret 9 $9$fakehashvalue", "enable password fakepw")]), GOOD),
    ("N-01", "vty no login", dict(sub=[("line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n login local", "line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n no login")]), VULNERABLE),
    ("N-01", "con 인증 줄 없음", dict(sub=[("line con 0\n exec-timeout 5 0\n login local", "line con 0\n exec-timeout 5 0")]), VULNERABLE),
    ("N-01", "con 인증 줄 없어도 aaa login이 있으면 양호",
     dict(sub=[("line con 0\n exec-timeout 5 0\n login local", "line con 0\n exec-timeout 5 0")], add=["aaa authentication login default local"]), GOOD),
    ("N-01", "con login authentication", dict(sub=[("line con 0\n exec-timeout 5 0\n login local", "line con 0\n exec-timeout 5 0\n login authentication CONSOLE")]), GOOD),
    ("N-02", "min-length 없음", dict(drop=[r"^security passwords.*\n"]), VULNERABLE),
    ("N-02", "min-length 7", dict(sub=[("min-length 8", "min-length 7")]), VULNERABLE),
    ("N-02", "min-length 12", dict(sub=[("min-length 8", "min-length 12")]), GOOD),
    ("N-03", "password-encryption 없음", dict(drop=[r"^service password-encryption\n"]), VULNERABLE),
    ("N-03", "no service password-encryption", dict(sub=[("service password-encryption", "no service password-encryption")]), VULNERABLE),
    ("N-03", "enable secret 없음(password만)", dict(sub=[("enable secret 9 $9$fakehashvalue", "enable password fakepw")]), VULNERABLE),
    ("N-03", "enable secret 평문(0)", dict(sub=[("enable secret 9 $9$fakehashvalue", "enable secret 0 plainpw")]), VULNERABLE),
    ("N-03", "enable secret 유형 표기 없음", dict(sub=[("enable secret 9 $9$fakehashvalue", "enable secret plainpw")]), VULNERABLE),
    ("N-03", "username 평문 password", dict(add=["username tmp password plainpw"]), VULNERABLE),
    ("N-03", "username password 7은 암호화 표기", dict(add=["username tmp password 7 0822455D0A16"]), GOOD),
    ("N-03", "username secret 평문(0)", dict(add=["username tmp secret 0 plainpw"]), VULNERABLE),
    ("N-04", "block-for 없음", dict(drop=[r"^login block-for.*\n"]), VULNERABLE),
    ("N-04", "attempts 6", dict(sub=[("attempts 5", "attempts 6")]), VULNERABLE),
    ("N-04", "attempts 3", dict(sub=[("attempts 5", "attempts 3")]), GOOD),
    ("N-05", "계정이 전부 15", dict(sub=[("username viewer privilege 1", "username viewer privilege 15")]), VULNERABLE),
    ("N-05", "계정이 15와 권한 미지정뿐", dict(sub=[("username viewer privilege 1", "username viewer")]), VULNERABLE),
    ("N-05", "계정 하나는 가이드 예외로 양호", dict(drop=[r"^username viewer.*\n"]), GOOD),
    ("N-05", "계정도 aaa authorization exec도 없음", dict(drop=[r"^username .*\n"]), VULNERABLE),
    ("N-05", "계정 없고 aaa authorization exec 있음", dict(drop=[r"^username .*\n"], add=["aaa authorization exec default group tacacs+ local"]), GOOD),
    ("N-06", "vty 한 블록에 access-class 없음", dict(sub=[("line vty 0 4\n access-class 10 in\n", "line vty 0 4\n")]), VULNERABLE),
    ("N-06", "ACL이 설정에 없음", dict(sub=[("access-class 10 in", "access-class 77 in")]), VULNERABLE),
    ("N-06", "ACL이 전체 허용(번호 표준)", dict(sub=[("access-list 10 permit 192.0.2.0 0.0.0.255", "access-list 10 permit any")]), VULNERABLE),
    ("N-06", "ACL이 전체 허용(이름 확장)", dict(sub=[("ip access-list standard VTY_ACL\n permit 192.0.2.0 0.0.0.255", "ip access-list extended VTY_ACL\n permit tcp any any eq 22")]), VULNERABLE),
    ("N-06", "transport input none 블록은 제외", dict(sub=[("line vty 5 15\n access-class VTY_ACL in\n exec-timeout 5 0\n login local\n transport input ssh",
                                                         "line vty 5 15\n exec-timeout 5 0\n login local\n transport input none")]), GOOD),
    ("N-07", "vty exec-timeout 없음", dict(sub=[("line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n", "line vty 0 4\n access-class 10 in\n")]), VULNERABLE),
    ("N-07", "exec-timeout 0 0", dict(sub=[("line con 0\n exec-timeout 5 0", "line con 0\n exec-timeout 0 0")]), VULNERABLE),
    ("N-07", "exec-timeout 11분", dict(sub=[("line con 0\n exec-timeout 5 0", "line con 0\n exec-timeout 11 0")]), VULNERABLE),
    ("N-07", "exec-timeout 10분 0초는 양호", dict(sub=[("line con 0\n exec-timeout 5 0", "line con 0\n exec-timeout 10 0")]), GOOD),
    ("N-07", "exec-timeout 10분 1초", dict(sub=[("line con 0\n exec-timeout 5 0", "line con 0\n exec-timeout 10 1")]), VULNERABLE),
    ("N-07", "exec-timeout 분만 적음", dict(sub=[("line con 0\n exec-timeout 5 0", "line con 0\n exec-timeout 5")]), GOOD),
    ("N-08", "transport input 줄 없음", dict(sub=[("line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n login local\n transport input ssh",
                                                  "line vty 0 4\n access-class 10 in\n exec-timeout 5 0\n login local")]), VULNERABLE),
    ("N-08", "transport input telnet ssh", dict(sub=[("transport input ssh\nline vty 5", "transport input telnet ssh\nline vty 5")]), VULNERABLE),
    ("N-08", "transport input all", dict(sub=[("transport input ssh\n!\nend", "transport input all\n!\nend")]), VULNERABLE),
    ("N-08", "ip ssh version 2 없음", dict(drop=[r"^ip ssh version 2\n"]), VULNERABLE),
    ("N-09", "aux 블록에 차단 줄 없음", dict(sub=[("line aux 0\n exec-timeout 5 0\n no exec\n transport input none", "line aux 0\n exec-timeout 5 0")]), VULNERABLE),
    ("N-09", "aux에 transport input none만 있어도 양호", dict(sub=[("line aux 0\n exec-timeout 5 0\n no exec\n transport input none", "line aux 0\n exec-timeout 5 0\n transport input none")]), GOOD),
    ("N-09", "aux 블록 없음은 해당없음", dict(drop=[r"^line aux 0\n(?: .*\n)+"]), NOT_APPLICABLE),
    ("N-10", "배너 없음", dict(drop=[r"^banner login \^C\nAuthorized users only\.\n\^C\n"]), VULNERABLE),
    ("N-10", "motd만 있어도 양호", dict(sub=[("banner login ^C", "banner motd ^C")]), GOOD),
    ("N-10", "배너에 변수", dict(sub=[("Authorized users only.", "Welcome to $(hostname)")]), VULNERABLE),
    ("N-10", "배너에 장비 호스트명", dict(sub=[("Authorized users only.", "This is swtest, authorized only")]), VULNERABLE),
    ("N-10", "배너에 Cisco 문구", dict(sub=[("Authorized users only.", "Cisco IOS router")]), VULNERABLE),
    ("N-10", "한 줄 배너", dict(sub=[("banner login ^C\nAuthorized users only.\n^C", "banner login ^CAuthorized only^C")]), GOOD),
    ("N-11", "원격 로그 서버 없음", dict(drop=[r"^logging host.*\n"]), VULNERABLE),
    ("N-11", "구형 표기 logging <주소>", dict(sub=[("logging host 192.0.2.50", "logging 192.0.2.50")]), GOOD),
    ("N-11", "no logging on", dict(add=["no logging on"]), VULNERABLE),
    ("N-13", "logging buffered 없음", dict(drop=[r"^logging buffered.*\n"]), VULNERABLE),
    ("N-13", "크기 미지정", dict(sub=[("logging buffered 32768 informational", "logging buffered informational")]), VULNERABLE),
    ("N-13", "크기 15999", dict(sub=[("32768", "15999")]), VULNERABLE),
    ("N-13", "크기 16000", dict(sub=[("32768", "16000")]), GOOD),
    ("N-13", "no logging buffered", dict(sub=[("logging buffered 32768 informational", "no logging buffered")]), VULNERABLE),
    ("N-14", "no logging on", dict(add=["no logging on"]), VULNERABLE),
    ("N-14", "trap warnings", dict(sub=[("logging trap informational", "logging trap warnings")]), VULNERABLE),
    ("N-14", "trap 숫자 3", dict(sub=[("logging trap informational", "logging trap 3")]), VULNERABLE),
    ("N-14", "trap debugging", dict(sub=[("logging trap informational", "logging trap debugging")]), GOOD),
    ("N-14", "trap 줄 없음은 기본 informational", dict(drop=[r"^logging trap.*\n"]), GOOD),
    ("N-14", "trap 잘못된 수준", dict(sub=[("logging trap informational", "logging trap loud")]), VULNERABLE),
    ("N-15", "ntp 줄 없음", dict(drop=[r"^ntp server.*\n"]), VULNERABLE),
    ("N-15", "ntp peer", dict(sub=[("ntp server 192.0.2.60", "ntp peer 192.0.2.60")]), GOOD),
    ("N-16", "timestamps 줄 없음", dict(drop=[r"^service timestamps log.*\n"]), VULNERABLE),
    ("N-16", "uptime 방식", dict(sub=[("service timestamps log datetime msec localtime", "service timestamps log uptime")]), VULNERABLE),
    ("N-16", "no service timestamps log", dict(sub=[("service timestamps log datetime msec localtime", "no service timestamps log")]), VULNERABLE),
    ("N-16", "옵션 없는 datetime", dict(sub=[("service timestamps log datetime msec localtime", "service timestamps log datetime")]), GOOD),
]


@pytest.mark.parametrize("code,name,change,expected", CASES, ids=["%s %s" % (c[0], c[1]) for c in CASES])
def test_item_verdict_on_synthetic_config(code, name, change, expected):
    assert verdict(judge(edit(**change)), code)["verdict"] == expected


def test_evidence_never_carries_secret_or_address_values():
    config = edit(add=["username leak secret 0 leak-plain-pw", "snmp-server community leak-community RO"])
    text = str(judge(config))
    for value in ("leak-plain-pw", "leak-community", "fakehash", "192.0.2.50", "192.0.2.60"):
        assert value not in text, value


# ------------------------------------------------------------ N-08 접속 방식, N-12, N-15 버전


def test_telnet_session_is_vulnerable_for_n08_even_when_the_config_is_clean():
    assert verdict(judge(access="ssh"), "N-08")["verdict"] == GOOD
    row = verdict(judge(access="telnet"), "N-08")
    assert row["verdict"] == VULNERABLE and "Telnet" in row["evidence"]


def test_n08_vulnerable_without_a_k9_image_when_not_connected_by_ssh():
    no_k9 = VERSION.replace("LANBASEK9", "LANBASE")
    assert verdict(judge(version=no_k9, access="telnet"), "N-08")["verdict"] == VULNERABLE
    assert verdict(judge(version=no_k9, access="ssh"), "N-08")["verdict"] == GOOD


def test_n12_records_only_the_version_and_is_always_manual():
    row = verdict(judge(), "N-12")
    assert row["verdict"] == MANUAL and "15.0(2)SE11" in row["evidence"] and "수동 확인" in row["evidence"]
    assert verdict(judge(version=""), "N-12")["verdict"] == MANUAL


def test_n15_without_access_group_is_manual_only_for_old_ios_or_unknown_version():
    old = "Cisco IOS Software, C0000, Version 12.1(22)EA14, RELEASE\n"
    new = "Cisco IOS Software, C0000, Version 12.2(55)SE12, RELEASE\n"
    assert verdict(judge(version=old), "N-15")["verdict"] == MANUAL
    assert verdict(judge(version=""), "N-15")["verdict"] == MANUAL
    assert verdict(judge(version=new), "N-15")["verdict"] == GOOD
    with_acl = edit(add=["ntp access-group peer 10"])
    assert verdict(judge(with_acl, version=old), "N-15")["verdict"] == GOOD
    # ntp 줄이 없으면 버전과 무관하게 취약
    assert verdict(judge(edit(drop=[r"^ntp server.*\n"]), version=old), "N-15")["verdict"] == VULNERABLE


# ------------------------------------------------------------ L2/L3 판정


L3_CONFIGS = {
    "ip routing": "ip routing",
    "SVI 주소": "interface Vlan10\n ip address 192.0.2.1 255.255.255.0",
    "라우티드 포트": "interface GigabitEthernet1/0/1\n no switchport\n ip address 192.0.2.5 255.255.255.252",
    "Loopback 주소": "interface Loopback0\n ip address 192.0.2.9 255.255.255.255",
    "Tunnel 주소": "interface Tunnel0\n ip address 192.0.2.13 255.255.255.252",
}


@pytest.mark.parametrize("name", sorted(L3_CONFIGS))
def test_l3_is_detected_by_the_table_rules(name):
    assert hs.device_role(edit(add=[L3_CONFIGS[name]])) == "L3"


def test_l2_when_nothing_routes():
    assert hs.device_role(GOOD_CONFIG) == "L2"
    assert hs.device_role(edit(add=["no ip routing", "interface Vlan20\n no ip address"])) == "L2"
    assert hs.device_role(edit(add=["interface GigabitEthernet1/0/2\n switchport mode access"])) == "L2"


def test_role_is_recorded_on_the_result():
    assert judge()["role"] == "L2" and judge(edit(add=["ip routing"]))["role"] == "L3"


# ------------------------------------------------------------ 예외 레지스터 (서버와 같은 경로)


def _exc(code, **kw):
    entry = {"code": code, "reason": "사유", "risk": "위험", "mitigation": "보완", "approver": "정보보호 책임자",
             "approved_on": "2026-09-01", "expires_on": "2026-12-31"}
    entry.update(kw)
    return entry


def test_approved_exception_turns_vulnerable_and_manual_into_exception_like_servers():
    config = edit(drop=[r"^ntp server.*\n"])
    result = judge(config, register=[_exc("KISA-2026:N-15"), _exc("KISA-2026:N-12")])
    assert verdict(result, "N-15")["verdict"] == EXCEPTION and verdict(result, "N-15")["exception"]["state"] == "유효"
    assert verdict(result, "N-12")["verdict"] == EXCEPTION


def test_expired_exception_reverts_and_pending_exception_changes_nothing():
    config = edit(drop=[r"^ntp server.*\n"])
    expired = judge(config, register=[_exc("KISA-2026:N-15", expires_on="2026-11-01")])
    assert verdict(expired, "N-15")["verdict"] == VULNERABLE and verdict(expired, "N-15")["exception"]["state"] == "만료"
    pending = judge(config, register=[_exc("KISA-2026:N-15", approver="", approved_on="")])
    assert verdict(pending, "N-15")["verdict"] == VULNERABLE and verdict(pending, "N-15")["exception"]["state"] == "승인 대기"


def test_exception_scope_can_name_a_switch_or_the_switch_group():
    config = edit(drop=[r"^ntp server.*\n"])
    assert verdict(judge(config, register=[_exc("KISA-2026:N-15", hosts=["sw0002"])]), "N-15")["verdict"] == VULNERABLE
    assert verdict(judge(config, register=[_exc("KISA-2026:N-15", hosts=["sw0001"])]), "N-15")["verdict"] == EXCEPTION
    assert verdict(judge(config, register=[_exc("KISA-2026:N-15", groups=["cisco_switches"])]), "N-15")["verdict"] == EXCEPTION


def test_exception_does_not_touch_good_or_not_applicable():
    result = judge(edit(drop=[r"^line aux 0\n(?: .*\n)+"]), register=[_exc("KISA-2026:N-09"), _exc("KISA-2026:N-01")])
    assert verdict(result, "N-09")["verdict"] == NOT_APPLICABLE and verdict(result, "N-01")["verdict"] == GOOD


# ------------------------------------------------------------ 접속 실패와 수집기 종료 코드


@pytest.mark.parametrize("probe,expect", [
    ({"rc": 3, "stdout": "", "stderr": "Authentication failed for 192.0.2.1 pw=secret-word"}, "접속"),
    ({"rc": 2, "stdout": "", "stderr": ""}, "설정"),
    ({"rc": 0, "stdout": "not json", "stderr": ""}, "형식"),
    ({"rc": 0, "stdout": '{"running_config": "", "version": "x"}', "stderr": ""}, "설정"),
    ({"skipped": True}, "건너뜀"),
    ({"resolve_failed": True}, "접속 정보"),
    ({"failed": True, "msg": "template error", "rc": 1}, "수집"),
    (None, "수집"),
])
def test_collection_failures_make_the_switch_unavailable_without_leaking_output(probe, expect):
    result = hs.host_audit_switch_result(probe, "ssh", [], "sw0001", ["cisco_switches"], TODAY)
    assert result["status"] == "failed" and expect in result["reason"] and result["results"] == []
    assert "secret-word" not in str(result) and "192.0.2.1" not in str(result)


def test_record_for_a_switch_that_could_not_be_inspected():
    declared = {"fqdn": "", "ip": "", "environment": "production", "groups": ["cisco_switches"]}
    rec = hs.host_audit_switch_record({"rc": 3, "stdout": ""}, "sw0001", declared, "2026-11-19T00:00:00Z", "ssh", [], TODAY)
    assert rec["device_type"] == "SWITCH" and rec["status"] == "unreachable" and rec["inventory_hostname"] == "sw0001"
    assert rec["reason"] and rec["identity"] is None and rec["os"] is None
    assert rec["config_vulnerability"]["status"] == "failed"
    ok = hs.host_audit_switch_record({"rc": 0, "stdout": hs_json(GOOD_CONFIG, VERSION)}, "sw0001", declared,
                                     "2026-11-19T00:00:00Z", "telnet", [], TODAY)
    assert ok["status"] == "ok" and ok["switch"] == {"access": "telnet", "role": "L2", "version": "15.0(2)SE11"}
    assert ok["config_vulnerability"]["status"] == "ok" and len(ok["config_vulnerability"]["results"]) == len(hs.CHECKS)
    assert "running_config" not in str(ok) and "swtest" not in str(ok)
    from host_audit import RECORD_SCHEMA_VERSION
    assert ok["schema_version"] == RECORD_SCHEMA_VERSION
    assert set(ok) >= {"schema_version", "inventory_hostname", "collected_at", "status", "reason", "declared",
                       "identity", "os", "config_vulnerability"}


# ------------------------------------------------------------ 적용 표와 레지스트리 대조


TABLE = ROOT_DIR / "docs" / "host_audit_switch.md"


def _table_rows():
    rows = {}
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*(N-\d\d)\s*\|", line)
        if m:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            rows[cells[0]] = {"title": cells[1], "severity": cells[2], "category": cells[3], "l2": cells[4], "l3": cells[5]}
    return rows


def test_every_registered_check_matches_its_row_in_the_application_table():
    table = _table_rows()
    assert set(hs.CHECKS) <= set(table)
    for code, meta in hs.CHECKS.items():
        row = table[code]
        assert (meta["title"], meta["severity"], meta["category"], meta["l2"], meta["l3"]) == \
            (row["title"], row["severity"], row["category"], row["l2"], row["l3"]), code


def test_n01_to_n16_are_all_registered_and_nothing_beyond_the_table_is():
    table = _table_rows()
    assert {c for c in table if int(c[2:]) <= 16} <= set(hs.CHECKS)


def test_not_applicable_rows_in_the_table_carry_the_reason_text():
    # L2/L3 열이 해당없음이면 레지스트리 사유가 표의 사유 열과 같아야 한다(N-17 이후는 Ticket-4가 등록할 때 같은 시험이 잡는다).
    text = {}
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*(N-\d\d)\s*\|", line)
        if m:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            text[cells[0]] = cells[7]
    for code, meta in hs.CHECKS.items():
        if "해당없음" in (meta["l2"], meta["l3"]) or "점검불가" in (meta["l2"], meta["l3"]):
            assert meta["reason"] and meta["reason"] in text[code], code


def test_registering_a_new_check_is_one_decorator_and_shows_up_in_results():
    @hs.switch_check("N-99", title="가짜", severity="하", category="기능", l2="적용", l3="적용")
    def _fake(ctx):
        return "GOOD", "등록 시험"
    try:
        assert verdict(judge(), "N-99")["verdict"] == GOOD
    finally:
        del hs.CHECKS["N-99"]


def test_a_check_marked_not_applicable_for_the_role_is_not_called():
    called = []

    @hs.switch_check("N-98", title="가짜", severity="하", category="기능", l2="해당없음", l3="적용", reason="L2 시험 사유")
    def _fake(ctx):
        called.append(ctx["role"])
        return "VULN", "x"
    try:
        l2 = verdict(judge(), "N-98")
        l3 = verdict(judge(edit(add=["ip routing"])), "N-98")
    finally:
        del hs.CHECKS["N-98"]
    assert l2["verdict"] == NOT_APPLICABLE and "L2 시험 사유" in l2["evidence"] and called == ["L3"]
    assert l3["verdict"] == VULNERABLE


def test_a_crashing_check_becomes_manual_instead_of_stopping_the_switch():
    @hs.switch_check("N-97", title="가짜", severity="하", category="기능", l2="적용", l3="적용")
    def _boom(ctx):
        raise ValueError("secret-word in message")
    try:
        result = judge()
    finally:
        del hs.CHECKS["N-97"]
    row = verdict(result, "N-97")
    assert row["verdict"] == MANUAL and "secret-word" not in str(row)
    assert verdict(result, "N-01")["verdict"] == GOOD


def test_the_filters_are_exported_for_ansible():
    names = hs.FilterModule().filters()
    assert {"host_audit_switch_result", "host_audit_switch_record"} <= set(names)


# ------------------------------------------------------------ 서버 보고서 모델 불변


def test_server_report_model_is_unchanged_by_switch_records_in_the_same_directory():
    from host_audit import host_audit_report_model, host_audit_host_record
    declared = {"fqdn": "a.example", "ip": "192.0.2.5", "environment": "production", "groups": ["servers"]}
    server = host_audit_host_record({"rc": 1, "stdout": "", "stderr": "x"}, "ns0001", declared, "2026-11-19T00:00:00Z")
    switch = hs.host_audit_switch_record({"rc": 3}, "sw0001", declared, "2026-11-19T00:00:00Z", "ssh", [], TODAY)
    meta = {"run_id": "ha-1", "run_kind": "on_demand", "started_at": "2026-11-19T00:00:00Z", "targets": ["ns0001"]}
    assert host_audit_report_model([server, switch], meta) == host_audit_report_model([server], meta)


# ------------------------------------------------------------ N-17 ~ N-38 (Ticket-4)

SPOOF_ACL = """\
ip access-list extended SPOOF
 deny ip 10.0.0.0 0.255.255.255 any
 deny ip 127.0.0.0 0.255.255.255 any
 deny ip 172.16.0.0 0.15.255.255 any
 deny ip 192.168.0.0 0.0.255.255 any
 permit ip any any"""
L3_INTERFACE = """\
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 no ip proxy-arp
 no ip unreachables
 no ip redirects
 ip access-group SPOOF in"""
# L3 기준선: GOOD_CONFIG(L2 기준선)에 라우팅과 위 인터페이스를 더한다.
L3_GOOD = edit(add=["ip routing", SPOOF_ACL, L3_INTERFACE])
OLD_IOS = "Cisco IOS Software, C0000, Version 12.1(22)EA14, RELEASE\n"
STRONG = "Str0ng!Communit"


def l3(**change):
    return edit(L3_GOOD, **change)


def community(extra, name=STRONG):
    return edit(add=["snmp-server community %s %s" % (name, extra)])


FUNCTION_CASES = [
    ("N-17", "snmp 줄 없음은 양호", edit(), GOOD),
    ("N-17", "snmp community 있음", community("RO 10"), VULNERABLE),
    ("N-17", "snmp v3 user만 있어도", edit(add=["snmp-server user admin grp v3"]), VULNERABLE),
    ("N-17", "snmp host만 있어도", edit(add=["snmp-server host 192.0.2.70 version 2c x"]), VULNERABLE),
    ("N-18", "community 없음은 양호", edit(), GOOD),
    ("N-18", "강한 community", community("RO 10"), GOOD),
    ("N-18", "public", community("RO 10", "public"), VULNERABLE),
    ("N-18", "private", community("RW 10", "private"), VULNERABLE),
    ("N-18", "8자 미만", community("RO 10", "Ab1!x"), VULNERABLE),
    ("N-18", "문자 종류 2가지(영소문자+숫자)", community("RO 10", "abcdefgh1234"), VULNERABLE),
    ("N-18", "문자 종류 3가지(대소문자+숫자)", community("RO 10", "Abcdefgh1234"), GOOD),
    ("N-18", "강한 것 하나와 약한 것 하나", edit(add=["snmp-server community %s RO 10" % STRONG, "snmp-server community public RO 10"]), VULNERABLE),
    ("N-19", "snmp 줄 없음은 양호", edit(), GOOD),
    ("N-19", "community에 ACL 번호", community("RO 10"), GOOD),
    ("N-19", "community에 이름 ACL", community("RO VTY_ACL"), GOOD),
    ("N-19", "ACL 없는 community", community("RO"), VULNERABLE),
    ("N-19", "view와 RO 뒤의 ACL", community("view v1 RO 10"), GOOD),
    ("N-19", "ACL이 설정에 없음", community("RO 77"), VULNERABLE),
    ("N-19", "v3 group에 access 없음", edit(add=["snmp-server group grp v3 priv"]), VULNERABLE),
    ("N-19", "v3 group에 access 있음", edit(add=["snmp-server group grp v3 priv access 10"]), GOOD),
    ("N-20", "community 없음은 양호", edit(), GOOD),
    ("N-20", "RO만", community("RO 10"), GOOD),
    ("N-20", "RW 있음", community("RW 10"), VULNERABLE),
    ("N-20", "소문자 rw", community("rw 10"), VULNERABLE),
    ("N-20", "문자열이 RW여도 권한은 RO", community("RO 10", "RW"), GOOD),
    ("N-21", "tftp-server 없음", edit(), GOOD),
    ("N-21", "tftp-server 있음", edit(add=["tftp-server flash:image.bin"]), VULNERABLE),
    ("N-21", "tftp-server에 ACL", edit(add=["tftp-server flash:image.bin 10"]), GOOD),
    ("N-25", "tcp-keepalives in·out 둘 다", edit(), GOOD),
    ("N-25", "in 없음", edit(drop=[r"^service tcp-keepalives-in\n"]), VULNERABLE),
    ("N-25", "out 없음", edit(drop=[r"^service tcp-keepalives-out\n"]), VULNERABLE),
    ("N-26", "ip finger 줄 없음(12.2 이상)", edit(), GOOD),
    ("N-26", "ip finger 켜짐", edit(add=["ip finger"]), VULNERABLE),
    ("N-26", "service finger 켜짐", edit(add=["service finger"]), VULNERABLE),
    ("N-26", "no ip finger", edit(add=["no ip finger"]), GOOD),
    ("N-27", "http 둘 다 no", edit(), GOOD),
    ("N-27", "http server 켜짐", edit(sub=[("no ip http server", "ip http server")]), VULNERABLE),
    ("N-27", "secure-server 켜짐", edit(sub=[("no ip http secure-server", "ip http secure-server")]), VULNERABLE),
    ("N-27", "켜졌어도 access-class 있음", edit(sub=[("no ip http server", "ip http server")], add=["ip http access-class 10"]), GOOD),
    ("N-27", "http 줄이 아예 없음", edit(drop=[r"^no ip http .*\n"]), GOOD),
    ("N-28", "small-servers 줄 없음(12.2 이상)", edit(), GOOD),
    ("N-28", "tcp-small-servers 켜짐", edit(add=["service tcp-small-servers"]), VULNERABLE),
    ("N-28", "udp-small-servers 켜짐", edit(add=["service udp-small-servers"]), VULNERABLE),
    ("N-28", "no service 둘 다", edit(add=["no service tcp-small-servers", "no service udp-small-servers"]), GOOD),
    ("N-29", "no ip bootp server", edit(), GOOD),
    ("N-29", "ip dhcp bootp ignore", edit(drop=[r"^no ip bootp server\n"], add=["ip dhcp bootp ignore"]), GOOD),
    ("N-29", "둘 다 없음", edit(drop=[r"^no ip bootp server\n"]), VULNERABLE),
    ("N-30", "no cdp run", edit(), GOOD),
    ("N-30", "no cdp run 없음", edit(drop=[r"^no cdp run\n"]), VULNERABLE),
    ("N-30", "일부 인터페이스에만 no cdp enable", edit(drop=[r"^no cdp run\n"], add=["interface Gi1/0/1\n no cdp enable"]), VULNERABLE),
    ("N-35", "ip identd 줄 없음(12.2 이상)", edit(), GOOD),
    ("N-35", "ip identd 켜짐", edit(add=["ip identd"]), VULNERABLE),
    ("N-35", "no ip identd", edit(add=["no ip identd"]), GOOD),
    ("N-36", "no ip domain-lookup", edit(), GOOD),
    ("N-36", "no ip domain lookup 표기", edit(sub=[("no ip domain-lookup", "no ip domain lookup")]), GOOD),
    ("N-36", "줄 없음", edit(drop=[r"^no ip domain-lookup\n"]), VULNERABLE),
    ("N-37", "no service pad", edit(), GOOD),
    ("N-37", "줄 없음", edit(drop=[r"^no service pad\n"]), VULNERABLE),
    # L3 전용 항목
    ("N-22", "ACL과 uRPF 없음", l3(drop=[r"^ ip access-group SPOOF in\n"]), VULNERABLE),
    ("N-22", "특수 대역 deny ACL을 입력 방향으로", l3(), GOOD),
    ("N-22", "uRPF만 있어도", l3(sub=[(" ip access-group SPOOF in", " ip verify unicast source reachable-via rx")]), GOOD),
    ("N-22", "ACL을 출력 방향으로 걸면 인정 안 함", l3(sub=[(" ip access-group SPOOF in", " ip access-group SPOOF out")]), VULNERABLE),
    ("N-22", "ACL에 사설 대역 deny 빠짐", l3(sub=[(" deny ip 10.0.0.0 0.255.255.255 any\n", "")]), VULNERABLE),
    ("N-22", "ACL에 루프백 deny 빠짐", l3(sub=[(" deny ip 127.0.0.0 0.255.255.255 any\n", "")]), VULNERABLE),
    ("N-22", "ACL이 설정에 없음", l3(sub=[("ip access-list extended SPOOF", "ip access-list extended OTHER")]), VULNERABLE),
    ("N-22", "번호 ACL", l3(sub=[(" ip access-group SPOOF in", " ip access-group 150 in")],
                         add=["access-list 150 deny ip 10.0.0.0 0.255.255.255 any", "access-list 150 deny ip 127.0.0.0 0.255.255.255 any",
                              "access-list 150 deny ip 172.16.0.0 0.15.255.255 any", "access-list 150 deny ip 192.168.0.0 0.0.255.255 any",
                              "access-list 150 permit ip any any"]), GOOD),
    ("N-22", "라우팅 인터페이스가 없음", edit(add=["ip routing"]), VULNERABLE),
    ("N-23", "L3는 항상 점검불가(수동 확인)", l3(), MANUAL),
    ("N-24", "항상 점검불가(수동 확인)", edit(), MANUAL),
    ("N-31", "directed-broadcast 없음", l3(), GOOD),
    ("N-31", "directed-broadcast 켜짐", l3(sub=[(" no ip redirects", " no ip redirects\n ip directed-broadcast")]), VULNERABLE),
    ("N-31", "no ip directed-broadcast", l3(sub=[(" no ip redirects", " no ip redirects\n no ip directed-broadcast")]), GOOD),
    ("N-32", "no ip source-route", l3(), GOOD),
    ("N-32", "줄 없음", l3(drop=[r"^no ip source-route\n"]), VULNERABLE),
    ("N-33", "모든 L3 인터페이스에 no ip proxy-arp", l3(), GOOD),
    ("N-33", "한 인터페이스에 없음", l3(add=["interface Vlan20\n ip address 192.0.2.17 255.255.255.240"]), VULNERABLE),
    ("N-33", "주소 없는 SVI는 세지 않음", l3(add=["interface Vlan20\n no ip address"]), GOOD),
    ("N-34", "no ip unreachables·redirects", l3(), GOOD),
    ("N-34", "unreachables 없음", l3(drop=[r"^ no ip unreachables\n"]), VULNERABLE),
    ("N-34", "redirects 없음", l3(drop=[r"^ no ip redirects\n"]), VULNERABLE),
    ("N-34", "Null0은 unreachables만 요구", l3(add=["interface Null0\n no ip unreachables"]), GOOD),
    ("N-34", "Null0에 unreachables 없음", l3(add=["interface Null0\n description sink"]), VULNERABLE),
    ("N-38", "mask-reply 없음", l3(), GOOD),
    ("N-38", "mask-reply 켜짐", l3(sub=[(" no ip redirects", " no ip redirects\n ip mask-reply")]), VULNERABLE),
]


@pytest.mark.parametrize("code,name,config,expected", FUNCTION_CASES, ids=["%s %s" % (c[0], c[1]) for c in FUNCTION_CASES])
def test_function_item_verdict_on_synthetic_config(code, name, config, expected):
    assert verdict(judge(config), code)["verdict"] == expected


@pytest.mark.parametrize("code,off,on", [
    ("N-26", ["no ip finger"], "ip finger"),
    ("N-28", ["no service tcp-small-servers", "no service udp-small-servers"], "service tcp-small-servers"),
    ("N-35", ["no ip identd"], "ip identd"),
])
def test_default_dependent_items_are_manual_before_ios_12_2_unless_explicitly_off(code, off, on):
    assert verdict(judge(edit(), version=OLD_IOS), code)["verdict"] == MANUAL
    assert verdict(judge(edit(), version=""), code)["verdict"] == MANUAL
    assert verdict(judge(edit(add=off), version=OLD_IOS), code)["verdict"] == GOOD
    assert verdict(judge(edit(add=[on]), version=OLD_IOS), code)["verdict"] == VULNERABLE


def test_l3_baseline_is_good_for_every_item_except_the_fixed_manual_ones():
    result = judge(L3_GOOD)
    assert result["role"] == "L3"
    assert {c: x for c, x in v(result).items() if x != GOOD} == {"N-12": MANUAL, "N-23": MANUAL, "N-24": MANUAL}


def test_all_38_items_are_registered_and_each_matches_the_table_for_l2_and_l3():
    assert sorted(hs.CHECKS) == ALL_CODES
    table = _table_rows()
    for role, config in (("L2", GOOD_CONFIG), ("L3", L3_GOOD)):
        result = judge(config)
        assert result["role"] == role and sorted(v(result)) == ALL_CODES
        for code in ALL_CODES:
            state = table[code]["l2" if role == "L2" else "l3"]
            row = verdict(result, code)
            assert (state == "해당없음") == (row["verdict"] == NOT_APPLICABLE), (role, code)
            if state == "점검불가":
                assert row["verdict"] == MANUAL, (role, code)


def _table_reasons():
    reasons = {}
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*(N-\d\d)\s*\|", line)
        if m:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            reasons[cells[0]] = cells[7]
    return reasons


def test_l2_not_applicable_items_are_the_seven_of_the_table_and_keep_the_table_reason_in_the_json():
    reasons = _table_reasons()
    assert sorted(c for c, m in hs.CHECKS.items() if m["l2"] == "해당없음") == L2_NOT_APPLICABLE
    result = judge(GOOD_CONFIG)
    for code in L2_NOT_APPLICABLE:
        row = verdict(result, code)
        assert row["verdict"] == NOT_APPLICABLE and row["evidence"] == reasons[code] == hs.CHECKS[code]["reason"], code


def test_unverifiable_items_keep_a_reason_in_the_json_for_both_roles():
    reasons = _table_reasons()
    for config in (GOOD_CONFIG, L3_GOOD):
        for code in ("N-12", "N-24"):
            row = verdict(judge(config), code)
            assert row["verdict"] == MANUAL and "수동 확인" in row["evidence"], code
    row = verdict(judge(L3_GOOD), "N-23")
    assert row["verdict"] == MANUAL and "수동 확인" in row["evidence"]
    for code in ("N-23", "N-24"):
        assert hs.CHECKS[code]["reason"] == reasons[code]


def test_n23_and_n24_evidence_is_reference_only_and_carries_no_names():
    config = l3(add=["interface GigabitEthernet1/0/1\n description secret-uplink-name\n shutdown",
                     "interface GigabitEthernet1/0/2\n switchport mode access", "ip tcp intercept mode watch"])
    result = judge(config)
    text = str(result)
    assert "secret-uplink-name" not in text and "GigabitEthernet1/0/2" not in text
    assert verdict(result, "N-24")["verdict"] == MANUAL


def test_function_evidence_never_carries_snmp_or_acl_values():
    config = l3(add=["snmp-server community Leak!Communit1 RW 77", "snmp-server host 192.0.2.77 version 2c Leak!Communit1",
                     "snmp-server user leakuser leakgroup v3", "tftp-server flash:leakimage.bin"])
    text = str(judge(config))
    for value in ("Leak!Communit1", "leakuser", "leakgroup", "192.0.2.77", "192.0.2.1", "leakimage"):
        assert value not in text, value


def test_no_command_other_than_the_collected_texts_is_available_to_the_checks():
    source = (ROOT_DIR / "filter_plugins" / "host_audit_switch.py").read_text(encoding="utf-8")
    for banned in ("subprocess", "socket", "paramiko", "open(", "os.system"):
        assert banned not in source, banned


def test_n10_one_line_banner_is_judged_without_the_control_c_delimiter_leaking_into_the_body():
    one_line = "banner login ^C%s^C"
    base = "banner login ^C\nAuthorized users only.\n^C"
    assert verdict(judge(edit(sub=[(base, one_line % "Cisco IOS router")])), "N-10")["verdict"] == VULNERABLE
    assert verdict(judge(edit(sub=[(base, one_line % "swtest authorized only")])), "N-10")["verdict"] == VULNERABLE
    assert verdict(judge(edit(sub=[(base, "banner motd ^C^C")])), "N-10")["verdict"] == VULNERABLE
