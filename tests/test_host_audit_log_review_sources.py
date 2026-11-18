"""Log Review Report 1부 출발지 항목 6·7·12번 (Spec #544 / Ticket-5 #560, ADR-0015).

필터 직접 테스트(ADR-0013 다수 층): fixture 조회 결과와 fixture 기준 목록(RFC 5737 문서용 주소, example 호스트명)으로
보고서 모델의 항목 상태·사유·행만 본다. 쿼리 문자열과 내부 함수 구성은 시험하지 않는다(#544 Testing Decisions).
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import host_audit_log_review_model, host_audit_log_review_period  # noqa: E402
from host_audit_log_review_sources import host_audit_log_review_managed_addresses  # noqa: E402

TZ = "Asia/Seoul"
STARTED = "2026-10-31T22:00:05Z"
PERIOD = host_audit_log_review_period(STARTED, TZ)
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
# 2026-10-15 10:00:00 KST = 2026-10-15T01:00:00Z
T0 = 1792026000 * 1000000

OFFICE = "203.0.113.10"
SNAT = "198.51.100.0/28"
OUTSIDE = "192.0.2.77"
RELAY = "10.20.0.5"       # 관리 호스트 h-relay의 내부 주소(인벤토리 ip)
NAT_ONLY = "10.99.0.9"    # 인벤토리로 계산되지 않아 문서에 둔 내부 주소(h-gw)

REFERENCE = {
    "normal_sources": [{"address": OFFICE, "name": "사무실"}, {"address": SNAT, "name": "사무실 SNAT"}],
    "internal_addresses": [{"address": NAT_ONLY, "host": "h-gw"}],
    "personal_info_systems": ["h-db"],
}
MANAGED = {RELAY: "h-relay"}

ITEMS = ("part1.relogin_from_managed_host", "part1.unauthorized_source", "part1.multi_source_login")


def _ok(hits):
    return {"ok": True, "hits": hits, "error": ""}


def _login(host, user, source, logins=1, first=T0, last=None):
    return {"host_name": host, "user_name": user, "source_address": source, "logins": logins,
            "first_us": first, "last_us": first if last is None else last}


def _minute(user, source, first, last=None, logins=1):
    return {"user_name": user, "source_address": source, "first_us": first, "last_us": first if last is None else last,
            "logins": logins}


def _collected(hosts):
    return _ok([{"name": h, "day": d, "records": 3} for h in hosts for d in OCT])


def _model(logins=(), minutes=(), reference=REFERENCE, managed=None, gap_free=("h-web", "h-db"), results=None,
           window=120, min_sources=2):
    res = {"collection_hosts_daily": _collected(gap_free), "collection_switch_daily": _ok([]),
           "collection_fortigate_daily": _ok([]),
           "source_logins": _ok(list(logins)), "source_login_minutes": _ok(list(minutes))}
    res.update(results or {})
    settings = {
        "collection_targets": {"hosts": ["h-web", "h-db"], "devices": []},
        "sources": {"reference": reference, "managed_addresses": MANAGED if managed is None else managed,
                    "window_seconds": window, "min_sources": min_sources},
    }
    return host_audit_log_review_model(res, {"run_id": "r", "started_at": STARTED, "timezone": TZ, "period": PERIOD,
                                             "settings": settings})


def _item(model, key):
    return next(i for i in model["part1"] if i["key"] == key)


# ------------------------------------------------------------------ 내부 주소 대응: 인벤토리에서 계산하는 몫

def test_managed_addresses_come_from_the_inventory_values_and_the_collected_host_addresses():
    records = [
        {"inventory_hostname": "h-web", "declared": {"ip": "10.20.0.11"}, "identity": {"ips": ["10.20.0.11", "10.30.0.11"]}},
        {"inventory_hostname": "h-db", "declared": {"ip": ""}, "identity": None},      # 수집 실패: 선언 값만
        {"inventory_hostname": "h-a", "identity": {"ips": ["172.17.0.1"]}},             # 여러 호스트가 같은 주소(도커 브리지)
        {"inventory_hostname": "h-b", "identity": {"ips": ["172.17.0.1", "127.0.0.1"]}},
    ]
    declared = {"h-db": ["10.20.0.12", "h-db.example.test", ""], "h-relay": ["10.20.0.5", "198.51.100.40"]}
    assert host_audit_log_review_managed_addresses(records, declared) == {
        "10.20.0.11": "h-web", "10.30.0.11": "h-web", "10.20.0.12": "h-db", "10.20.0.5": "h-relay", "198.51.100.40": "h-relay",
    }
    assert host_audit_log_review_managed_addresses([], None) == {}


# ------------------------------------------------------------------ 기준 목록 문서가 없거나 읽지 못함

def test_without_the_reference_document_the_three_source_items_are_a_reference_list_failure():
    for reference in (None, {}, "garbage"):
        m = _model(logins=[_login("h-web", "alice", OUTSIDE)], reference=reference)
        for key in ITEMS:
            item = _item(m, key)
            assert item["status"] == "failed", (reference, key)
            assert item["status_label"] == "조회 실패(기준 목록)", (reference, key)
        assert m["errors"] == []


def test_a_reference_document_with_a_malformed_address_is_a_reference_list_failure():
    bad = dict(REFERENCE, normal_sources=[{"address": "not-an-address", "name": "x"}])
    for key in ITEMS:
        assert _item(_model(reference=bad), key)["status_label"] == "조회 실패(기준 목록)"


# ------------------------------------------------------------------ 6번: 관리 호스트에서 온 재로그인

RELOGIN = "part1.relogin_from_managed_host"


def test_a_login_whose_source_is_a_managed_host_address_is_listed_under_item_6():
    m = _model(logins=[
        _login("h-web", "alice", RELAY, logins=3, first=T0, last=T0 + 3600 * 1000000),
        _login("h-db", "bob", NAT_ONLY),
        _login("h-web", "carol", OFFICE),          # 정상 출발지(관리 호스트 아님): 6번 아님
        _login("h-relay", "dave", RELAY),          # 자기 자신에게 로그인: 다른 시스템이 아니다
    ])
    item = _item(m, RELOGIN)
    assert item["status"] == "auto" and item["verdict"] == "확인 필요"
    rows = [dict(zip(item["columns"], r)) for r in item["rows"]]
    assert [(r["출발 호스트"], r["출발지"], r["대상 호스트"], r["계정"], r["건수"]) for r in rows] == [
        ("h-gw", NAT_ONLY, "h-db", "bob", 1),
        ("h-relay", RELAY, "h-web", "alice", 3),
    ]
    assert rows[0]["개인정보처리시스템"] == "예" and rows[1]["개인정보처리시스템"] == "아니오"
    assert rows[1]["처음"] == "2026-10-15 10:00" and rows[1]["마지막"] == "2026-10-15 11:00"


def test_no_login_from_a_managed_host_is_no_finding():
    item = _item(_model(logins=[_login("h-web", "carol", OFFICE)]), RELOGIN)
    assert item["status"] == "auto" and item["verdict"] == "이상 없음" and item["rows"] == []


# ------------------------------------------------------------------ 7번: 정상 출발지 목록 밖 로그인 성공

UNAUTHORIZED = "part1.unauthorized_source"


def test_a_login_from_outside_the_normal_sources_is_listed_under_item_7_and_cidr_ranges_count_as_normal():
    m = _model(logins=[
        _login("h-db", "alice", OUTSIDE, logins=2),
        _login("h-web", "bob", "198.51.100.5"),     # SNAT /28 안: 정상
        _login("h-web", "bob", "198.51.100.20"),    # /28 밖
        _login("h-web", "carol", OFFICE),           # 정상
        _login("h-web", "dave", RELAY),             # 관리 호스트 주소는 6번에서 본다
        _login("h-web", "erin", "2001:db8::7"),
        _login("h-web", "frank", ""),
    ])
    item = _item(m, UNAUTHORIZED)
    assert item["status"] == "auto" and item["verdict"] == "확인 필요"
    rows = [dict(zip(item["columns"], r)) for r in item["rows"]]
    assert [(r["출발지"], r["대상 호스트"], r["계정"], r["건수"], r["개인정보처리시스템"]) for r in rows] == [
        ("(출발지 없음)", "h-web", "frank", 1, "아니오"),
        ("192.0.2.77", "h-db", "alice", 2, "예"),
        ("198.51.100.20", "h-web", "bob", 1, "아니오"),
        ("2001:db8::7", "h-web", "erin", 1, "아니오"),
    ]
    # 개인정보처리시스템 목록이 문서에 없으면 1~5번과 같이 '미지정'이다
    no_pii = {k: v for k, v in REFERENCE.items() if k != "personal_info_systems"}
    item = _item(_model(logins=[_login("h-db", "alice", OUTSIDE)], reference=no_pii), UNAUTHORIZED)
    assert [dict(zip(item["columns"], r))["개인정보처리시스템"] for r in item["rows"]] == ["미지정"]


def test_logins_only_from_normal_sources_are_no_finding_under_item_7():
    item = _item(_model(logins=[_login("h-web", "carol", OFFICE), _login("h-db", "bob", "198.51.100.1")]), UNAUTHORIZED)
    assert item["status"] == "auto" and item["verdict"] == "이상 없음"


def test_a_host_with_a_collection_gap_makes_items_6_7_12_partial_not_a_plain_no_finding():
    m = _model(logins=[_login("h-web", "carol", OFFICE)], gap_free=("h-web",))   # h-db는 전월 로그 없음
    for key in ITEMS:
        item = _item(m, key)
        assert item["status"] == "partial" and item["verdict"] == "이상 없음", key
        assert "h-db" in item["summary"], key


# ------------------------------------------------------------------ 12번: 2분 안에 출발지 2개 이상

MULTI = "part1.multi_source_login"
S = 1000000


def _multi_rows(minutes, **kw):
    item = _item(_model(minutes=minutes, **kw), MULTI)
    return item, [dict(zip(item["columns"], r)) for r in item["rows"]]


def test_the_same_account_from_two_sources_within_two_minutes_is_listed_and_the_boundary_is_inclusive():
    item, rows = _multi_rows([
        _minute("alice", OFFICE, T0), _minute("alice", OUTSIDE, T0 + 119 * S),         # 119초: 해당
        _minute("bob", OFFICE, T0), _minute("bob", OUTSIDE, T0 + 120 * S),             # 120초: 해당(2분 이내)
        _minute("carol", OFFICE, T0), _minute("carol", OUTSIDE, T0 + 121 * S),         # 121초: 아님
        _minute("dave", OFFICE, T0, T0 + 50 * S, logins=4), _minute("dave", OFFICE, T0 + 60 * S),  # 출발지 하나: 아님
    ])
    assert item["status"] == "auto" and item["verdict"] == "확인 필요"
    assert [r["계정"] for r in rows] == ["alice", "bob"]
    assert rows[0]["출발지"] == "192.0.2.77, 203.0.113.10(사무실)"
    assert rows[0]["시작"] == "2026-10-15 10:00" and rows[0]["끝"] == "2026-10-15 10:01" and rows[0]["건수"] == 2


def test_the_gap_is_measured_from_the_last_login_of_the_earlier_minute():
    # 사무실 로그인이 10:00:00~10:00:50 사이에 있었고 다른 출발지가 10:02:40(마지막에서 110초)에 왔다
    _, rows = _multi_rows([_minute("alice", OFFICE, T0, T0 + 50 * S, logins=3), _minute("alice", OUTSIDE, T0 + 160 * S)])
    assert [r["계정"] for r in rows] == ["alice"]


def test_overlapping_hits_of_one_account_are_one_row_and_the_thresholds_come_from_the_settings():
    minutes = [_minute("alice", OFFICE, T0), _minute("alice", OUTSIDE, T0 + 60 * S), _minute("alice", RELAY, T0 + 100 * S)]
    _, rows = _multi_rows(minutes)
    assert len(rows) == 1 and rows[0]["건수"] == 3
    assert rows[0]["출발지"] == "10.20.0.5(h-relay), 192.0.2.77, 203.0.113.10(사무실)"
    _, rows = _multi_rows(minutes[:2], min_sources=3)
    assert rows == []
    _, rows = _multi_rows([_minute("alice", OFFICE, T0), _minute("alice", OUTSIDE, T0 + 200 * S)], window=300)
    assert len(rows) == 1


def test_a_failed_minute_search_is_a_query_failure_of_item_12_only():
    m = _model(results={"source_login_minutes": {"ok": False, "hits": [], "error": "결과가 조회 한도(50000행)에 닿음"}})
    assert _item(m, MULTI)["status_label"] == "조회 실패(결과가 조회 한도(50000행)에 닿음)"
    assert _item(m, RELOGIN)["status"] == "auto"


def test_a_failed_login_search_is_a_query_failure_of_items_6_and_7():
    m = _model(results={"source_logins": {"ok": False, "hits": [], "error": "HTTP 401(인증·권한)"}})
    for key in (RELOGIN, "part1.unauthorized_source"):
        assert _item(m, key)["status_label"] == "조회 실패(HTTP 401(인증·권한))"
