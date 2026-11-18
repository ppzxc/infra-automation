"""Log Review Report 1부 13번과 장비 관리자 로그인 적용 (Spec #544 / Ticket-7 #562, ADR-0015).

필터 직접 테스트(ADR-0013 다수 층): 보고서 모델 필터에 fixture 조회 결과·기준 설정을 넣고 항목 상태·판정·표만 본다.
쿼리 문자열과 내부 함수 구성은 시험하지 않는다(#544 Testing Decisions). 장비·계정 이름과 주소는 가짜 값(RFC 5737)이다.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import host_audit_log_review_model, host_audit_log_review_period  # noqa: E402

TZ = "Asia/Seoul"
STARTED = "2026-10-31T22:00:05Z"  # KST 11-01 07:00 -> 2026-10 점검
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
HOSTS = ("ns0001", "ns0002")
FW = ("ns0901",)
SW = ("ns0902",)
HOLIDAYS = {2026: ["2026-10-03", "2026-10-05", "2026-10-09"]}
OFFICE = "203.0.113.10"
OUTSIDE = "192.0.2.77"
# 2026-10-15(목) 10:00:00 KST
T0 = 1792026000 * 1000000
MIN = 60 * 1000000


def _ok(hits):
    return {"ok": True, "hits": hits, "error": ""}


def _fail(error="HTTP 503"):
    return {"ok": False, "hits": [], "error": error}


def _every_day(names):
    return [{"name": n, "day": d, "records": 3} for n in names for d in OCT]


def _results(**override):
    out = {
        "collection_hosts_daily": _ok(_every_day(HOSTS)),
        "collection_switch_daily": _ok(_every_day(SW)),
        "collection_fortigate_daily": _ok(_every_day(FW)),
        "accounts_ssh_success_hourly": _ok([]),
        "accounts_ssh_failure_minutely": _ok([]),
        "accounts_ssh_invalid_user": _ok([]),
        "accounts_privilege_hourly": _ok([]),
        "accounts_account_change_hourly": _ok([]),
        "source_logins": _ok([]),
        "source_login_minutes": _ok([]),
        "command_burst_sudo_minutely": _ok([]),
        "device_fortigate_logins": _ok([]),
        "device_fortigate_changes": _ok([]),
        "device_switch_login_failures": _ok([]),
        "device_switch_config_changes": _ok([]),
    }
    out.update(override)
    return out


PARSING = {
    "fortigate": {"part1.unauthorized_account": "auto", "part1.login_failures": "auto", "part1.off_hours_login": "auto",
                  "part1.off_hours_privilege": "auto", "part1.unauthorized_source": "auto",
                  "part1.multi_source_login": "auto"},
    "switch": {"part1.login_failures": "partial", "part1.off_hours_privilege": "partial"},
}


def _settings(devices="default", admin_accounts="default", burst=None):
    host = {"declared": ["alice"], "bootstrap": "", "agents_only": False, "inventory_accounts": None}
    s = {
        "collection_targets": {"hosts": list(HOSTS), "devices": list(FW + SW)},
        "accounts": {"hosts": {h: dict(host) for h in HOSTS}, "business_hours": {"start": 8, "end": 20},
                     "holidays": HOLIDAYS, "failure_threshold": 5, "failure_window_minutes": 10},
        "sources": {"reference": {"normal_sources": [{"address": OFFICE, "name": "사무실"}]}, "managed_addresses": {},
                    "window_seconds": 120, "min_sources": 2},
        "command_burst": burst if burst is not None else {"threshold": 30, "window_minutes": 2},
    }
    if devices == "default":
        devices = {"fortigate": list(FW), "switch": list(SW), "parsing": PARSING,
                   "admin_accounts": [{"device": "ns0901", "accounts": ["fwadmin"]}] if admin_accounts == "default" else admin_accounts}
    if devices is not None:
        s["devices"] = devices
    return s


def _model(results=None, settings=None):
    meta = {"run_id": "ha-x", "run_kind": "scheduled", "started_at": STARTED, "generated_at": STARTED,
            "timezone": TZ, "period": host_audit_log_review_period(STARTED, TZ),
            "settings": settings if settings is not None else _settings()}
    return host_audit_log_review_model(results if results is not None else _results(), meta)


def _item(model, no):
    return next(i for i in model["part1"] if i["no"] == no)


def _section(item, kind):
    return next(s for s in item["sections"] if s["kind"] == kind)


def _sudo(minute, runs, user="alice", host="ns0001"):
    return {"host": host, "user": user, "minute": minute, "runs": runs}


# ------------------------------------------------------------------ 13번: 같은 계정의 2분 내 sudo 집중

def test_29_sudo_runs_within_two_minutes_is_no_finding_and_the_limit_is_printed():
    m = _model(_results(command_burst_sudo_minutely=_ok([_sudo("2026-10-15 10:00", 20), _sudo("2026-10-15 10:01", 9)])))
    item = _item(m, 13)
    assert (item["status"], item["verdict"]) == ("auto", "이상 없음")
    assert "2분" in item["criterion"] and "30회" in item["criterion"]
    assert "sudo 명령만 본다" in item["criterion"]


def test_30_sudo_runs_within_two_minutes_across_hosts_of_one_account_is_listed():
    hits = [_sudo("2026-10-15 10:00", 20), _sudo("2026-10-15 10:01", 10, host="ns0002"), _sudo("2026-10-15 10:02", 25)]
    m = _model(_results(command_burst_sudo_minutely=_ok(hits)))
    item = _item(m, 13)
    assert (item["status"], item["verdict"]) == ("auto", "확인 필요")
    assert len(item["rows"]) == 1
    row = dict(zip(item["columns"], item["rows"][0]))
    assert row["계정"] == "alice" and row["2분 내 최대 sudo"] == 35 and row["처음 시각(KST)"] == "2026-10-15 10:01"
    assert row["호스트"] == "ns0001, ns0002"


def test_runs_three_minutes_apart_are_not_one_window_and_thresholds_come_from_the_settings():
    hits = [_sudo("2026-10-15 10:00", 20), _sudo("2026-10-15 10:02", 20)]
    m = _model(_results(command_burst_sudo_minutely=_ok(hits)))
    assert _item(m, 13)["verdict"] == "이상 없음"
    m = _model(_results(command_burst_sudo_minutely=_ok(hits)), _settings(burst={"threshold": 20, "window_minutes": 1}))
    item = _item(m, 13)
    assert item["verdict"] == "확인 필요" and "1분" in item["criterion"] and "20회" in item["criterion"]


def test_a_failed_sudo_search_is_a_query_failure_of_item_13():
    m = _model(_results(command_burst_sudo_minutely=_fail()))
    assert _item(m, 13)["status_label"] == "조회 실패(HTTP 503)"


# ------------------------------------------------------------------ 장비 관리자 로그인(1·2·3·4·7·12번)

def _fgt(minute, user="fwadmin", source=OFFICE, outcome="success", logins=1, device="ns0901", first=None):
    first = T0 if first is None else first
    return {"device": device, "user": user, "source": source, "minute": minute, "outcome": outcome, "logins": logins,
            "first_us": first, "last_us": first}


def test_without_device_settings_the_items_have_no_device_sections():
    m = _model(settings=_settings(devices=None))
    for no in (1, 2, 3, 4, 7, 12):
        assert _item(m, no)["sections"] == []
    assert _item(m, 1)["status"] == "auto" and _item(m, 1)["verdict"] == "이상 없음"


def test_a_switch_without_parsing_is_unavailable_per_item_and_the_item_is_partial_not_dropped():
    m = _model()
    for no in (1, 3, 7, 12):
        item = _item(m, no)
        sw = _section(item, "switch")
        assert sw["status_label"] == "점검 불가(파싱 없음)" and sw["rows"] == []
        assert item["status"] == "partial", no
        assert "스위치: 점검 불가(파싱 없음)" in item["summary"]
    # 파싱이 있는 FortiGate는 같은 항목에서 자동 판정이다
    assert _section(_item(m, 1), "fortigate")["status"] == "auto"
    assert _item(m, 1)["verdict"] == "이상 없음"


def test_with_parsing_switched_off_for_every_kind_each_item_says_so_per_device_kind():
    s = _settings()
    s["devices"]["parsing"] = {}
    m = _model(settings=s)
    for no in (1, 2, 3, 4, 7, 12):
        labels = {sec["kind"]: sec["status_label"] for sec in _item(m, no)["sections"]}
        assert labels == {"fortigate": "점검 불가(파싱 없음)", "switch": "점검 불가(파싱 없음)"}


def test_a_fortigate_admin_login_by_an_account_outside_the_device_list_is_listed_under_item_1():
    hits = [_fgt("2026-10-15 10:00"), _fgt("2026-10-15 10:05", user="intruder", logins=2)]
    m = _model(_results(device_fortigate_logins=_ok(hits)))
    item = _item(m, 1)
    fw = _section(item, "fortigate")
    assert (fw["status"], fw["verdict"]) == ("auto", "확인 필요")
    assert fw["rows"] == [["ns0901", "intruder", 2, ""]]
    assert item["verdict"] == "확인 필요"


def test_without_a_device_admin_list_every_fortigate_login_account_is_listed_as_no_list():
    m = _model(_results(device_fortigate_logins=_ok([_fgt("2026-10-15 10:00")])), _settings(admin_accounts=None))
    fw = _section(_item(m, 1), "fortigate")
    assert fw["rows"] == [["ns0901", "fwadmin", 1, "장비 관리자 허용 목록 없음"]]
    assert fw["verdict"] == "확인 필요"


def test_a_device_missing_from_the_admin_list_has_its_login_accounts_listed_as_no_list():
    hits = [_fgt("2026-10-15 10:00"), _fgt("2026-10-15 10:00", device="ns0903")]
    s = _settings()
    s["devices"]["fortigate"] = ["ns0901", "ns0903"]
    s["collection_targets"]["devices"].append("ns0903")
    res = _results(device_fortigate_logins=_ok(hits),
                   collection_fortigate_daily=_ok(_every_day(("ns0901", "ns0903"))))
    fw = _section(_item(_model(res, s), 1), "fortigate")
    assert fw["rows"] == [["ns0903", "fwadmin", 1, "장비 관리자 허용 목록 없음"]]


def test_fortigate_failures_4_in_10_minutes_is_no_finding_and_5_is_listed_under_item_2():
    four = [_fgt("2026-10-15 10:0%d" % i, outcome="failure") for i in range(4)]
    m = _model(_results(device_fortigate_logins=_ok(four)))
    assert _section(_item(m, 2), "fortigate")["verdict"] == "이상 없음"
    five = four + [_fgt("2026-10-15 10:09", outcome="failure")]
    m = _model(_results(device_fortigate_logins=_ok(five)))
    fw = _section(_item(m, 2), "fortigate")
    assert fw["verdict"] == "확인 필요"
    assert fw["rows"] == [["ns0901", "fwadmin", 5, "2026-10-15 10:00", 5]]


def test_switch_login_failures_are_judged_per_device_only_and_partial_under_item_2():
    hits = [{"device": "ns0902", "minute": "2026-10-15 10:0%d" % i, "failures": 1} for i in range(5)]
    m = _model(_results(device_switch_login_failures=_ok(hits)))
    sw = _section(_item(m, 2), "switch")
    assert (sw["status"], sw["verdict"]) == ("partial", "확인 필요")
    assert sw["rows"] == [["ns0902", 5, "2026-10-15 10:00", 5]]
    assert "계정" in sw["summary"]  # 계정이 구조화되지 않았다는 한계


def test_fortigate_logins_whose_result_is_unknown_are_not_counted_as_no_finding():
    m = _model(_results(device_fortigate_logins=_ok([_fgt("2026-10-15 10:00", outcome="")])))
    for no in (1, 2, 3, 7, 12):
        fw = _section(_item(m, no), "fortigate")
        assert (fw["status"], fw["verdict"]) == ("partial", "확인 필요"), no
        assert "결과를 알 수 없는 로그인 1건" in fw["summary"]


def test_a_fortigate_admin_login_off_hours_is_listed_under_item_3_and_19_59_is_business_hours():
    hits = [_fgt("2026-10-15 19:59"), _fgt("2026-10-15 20:00"), _fgt("2026-10-17 11:00")]
    m = _model(_results(device_fortigate_logins=_ok(hits)))
    fw = _section(_item(m, 3), "fortigate")
    assert fw["verdict"] == "확인 필요"
    assert fw["rows"] == [["ns0901", "fwadmin", "주말·야간", 2, "2026-10-15 20시, 2026-10-17 11시"]]


def test_off_hours_admin_account_changes_are_findings_other_config_and_ha_sync_are_reference_under_item_4():
    changes = [
        {"device": "ns0901", "user": "fwadmin", "hour": "2026-10-15 22", "target": "config", "via": "", "changes": 3},
        {"device": "ns0901", "user": "fwadmin", "hour": "2026-10-15 22", "target": "admin", "via": "ha", "changes": 2},
    ]
    m = _model(_results(device_fortigate_changes=_ok(changes)))
    fw = _section(_item(m, 4), "fortigate")
    assert fw["verdict"] == "이상 없음" and len(fw["rows"]) == 2
    changes.append({"device": "ns0901", "user": "fwadmin", "hour": "2026-10-17 09", "target": "admin", "via": "",
                    "changes": 1})
    m = _model(_results(device_fortigate_changes=_ok(changes)))
    fw = _section(_item(m, 4), "fortigate")
    assert fw["verdict"] == "확인 필요"
    assert [r[2] for r in fw["rows"]] == ["HA 동기화(참고)", "관리자 계정·권한 변경", "설정 변경(참고)"]


def test_off_hours_switch_config_changes_are_partial_findings_under_item_4():
    hits = [{"device": "ns0902", "hour": "2026-10-15 23", "changes": 1}, {"device": "ns0902", "hour": "2026-10-15 10", "changes": 4}]
    m = _model(_results(device_switch_config_changes=_ok(hits)))
    sw = _section(_item(m, 4), "switch")
    assert (sw["status"], sw["verdict"]) == ("partial", "확인 필요")
    assert sw["rows"] == [["ns0902", "설정 변경(SYS-5-CONFIG_I)", "야간", 1, "2026-10-15 23시"]]


def test_a_fortigate_admin_login_from_outside_the_normal_sources_is_listed_under_item_7():
    hits = [_fgt("2026-10-15 10:00"), _fgt("2026-10-15 10:30", source=OUTSIDE)]
    m = _model(_results(device_fortigate_logins=_ok(hits)))
    fw = _section(_item(m, 7), "fortigate")
    assert fw["verdict"] == "확인 필요"
    assert [r[:4] for r in fw["rows"]] == [[OUTSIDE, "ns0901", "fwadmin", 1]]


def test_a_fortigate_admin_login_from_a_managed_host_is_shown_but_not_a_finding_under_item_7():
    s = _settings()
    s["sources"]["managed_addresses"] = {"10.20.0.5": "ns0001"}
    m = _model(_results(device_fortigate_logins=_ok([_fgt("2026-10-15 10:00", source="10.20.0.5")])), s)
    fw = _section(_item(m, 7), "fortigate")
    assert fw["verdict"] == "이상 없음"
    assert fw["rows"][0][-1] == "관리 호스트 ns0001"


def test_the_same_fortigate_admin_from_two_sources_within_two_minutes_is_listed_under_item_12():
    hits = [_fgt("2026-10-15 10:00"), _fgt("2026-10-15 10:02", source=OUTSIDE, first=T0 + 2 * MIN)]
    m = _model(_results(device_fortigate_logins=_ok(hits)))
    fw = _section(_item(m, 12), "fortigate")
    assert fw["verdict"] == "확인 필요" and fw["rows"][0][0] == "fwadmin"
    hits[1] = _fgt("2026-10-15 10:03", source=OUTSIDE, first=T0 + 3 * MIN)
    m = _model(_results(device_fortigate_logins=_ok(hits)))
    assert _section(_item(m, 12), "fortigate")["verdict"] == "이상 없음"


def test_a_failed_device_search_is_a_query_failure_of_that_section_and_the_item_is_partial_check():
    m = _model(_results(device_fortigate_logins=_fail()))
    item = _item(m, 1)
    assert _section(item, "fortigate")["status_label"] == "조회 실패(HTTP 503)"
    assert (item["status"], item["verdict"]) == ("partial", "확인 필요")


def test_a_failed_server_search_stays_a_query_failure_with_the_device_sections_attached():
    m = _model(_results(accounts_ssh_success_hourly=_fail()))
    item = _item(m, 1)
    assert item["status_label"] == "조회 실패(HTTP 503)" and item["verdict"] == ""
    assert {s["kind"] for s in item["sections"]} == {"fortigate", "switch"}


def test_a_device_with_a_collection_gap_is_not_judged_as_no_finding():
    days = [d for d in OCT if d != "2026-10-20"]
    res = _results(collection_fortigate_daily=_ok([{"name": "ns0901", "day": d, "records": 1} for d in days]))
    fw = _section(_item(_model(res), 1), "fortigate")
    assert (fw["status"], fw["verdict"]) == ("partial", "확인 필요")
    assert "ns0901" in fw["summary"]
