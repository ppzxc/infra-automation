"""Host Audit 스위치 단계 판정 필터 (Spec #568 / Ticket-3): KISA-2026 N-01~N-16.

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


# ------------------------------------------------------------ 기준선과 구조


def test_good_config_is_good_for_every_item_except_the_fixed_manual_one():
    result = judge()
    verdicts = v(result)
    assert result["status"] == "ok" and result["edition"] == "KISA-2026"
    assert sorted(verdicts) == ["N-%02d" % n for n in range(1, 17)]
    # 이 합성 설정은 AUX 포트가 있고, N-12는 항상 점검불가(수동 확인)다.
    assert {c: x for c, x in verdicts.items() if x != GOOD} == {"N-12": MANUAL}


def test_only_registered_items_are_reported_and_unimplemented_ones_are_left_out():
    assert sorted(hs.CHECKS) == ["N-%02d" % n for n in range(1, 17)]
    assert not any(r["code"].endswith(("N-17", "N-38")) for r in judge()["results"])


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
    assert ok["config_vulnerability"]["status"] == "ok" and len(ok["config_vulnerability"]["results"]) == 16
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
