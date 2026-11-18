"""Log Review Report 보고서 모델 필터 (Spec #544 / Ticket-3 #558, ADR-0015).

필터 직접 테스트(ADR-0013 두 층 중 다수 층): 같은 입력이면 같은 보고서 모델이 나오는지, 항목 상태와 사유가 맞는지만 본다.
쿼리 문자열과 내부 함수 구성은 시험하지 않는다(#544 Testing Decisions).
"""
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import (  # noqa: E402
    host_audit_log_review_file_name,
    host_audit_log_review_model,
    host_audit_log_review_period,
    host_audit_log_review_queries,
    host_audit_log_review_results,
)

TZ = "Asia/Seoul"


# ------------------------------------------------------------------ 점검 기간

def test_the_scheduled_run_on_the_first_at_07_kst_reviews_the_whole_previous_month():
    p = host_audit_log_review_period("2026-10-31T22:00:05Z", TZ)  # KST 11-01 07:00
    assert p["month"] == "2026-10"
    assert p["label"] == "2026-10-01 00:00 ~ 2026-10-31 24:00 (KST)"
    assert p["start_us"] == 1790780400 * 1000000  # 2026-10-01T00:00+09:00
    assert p["end_us"] == 1793458800 * 1000000    # 2026-11-01T00:00+09:00 (끝은 포함하지 않는다)
    assert p["days"][0] == "2026-10-01" and p["days"][-1] == "2026-10-31" and len(p["days"]) == 31


def test_the_month_is_the_kst_month_not_the_utc_month():
    # UTC로는 아직 11월 30일이지만 KST로는 12월 1일이다 -> 11월을 점검한다
    assert host_audit_log_review_period("2026-11-30T15:00:00Z", TZ)["month"] == "2026-11"
    # UTC 11-30 14:59:59는 KST 11-30 23:59:59 -> 10월을 점검한다
    assert host_audit_log_review_period("2026-11-30T14:59:59Z", TZ)["month"] == "2026-10"


def test_january_reviews_december_of_the_previous_year_and_leap_february_has_29_days():
    jan = host_audit_log_review_period("2027-01-05T01:00:00Z", TZ)
    assert jan["month"] == "2026-12" and jan["label"].startswith("2026-12-01 00:00 ~ 2026-12-31 24:00")
    feb = host_audit_log_review_period("2028-03-01T00:00:00Z", TZ)
    assert feb["month"] == "2028-02" and len(feb["days"]) == 29


def test_a_malformed_start_time_is_an_error_not_a_silent_period():
    with pytest.raises(Exception):
        host_audit_log_review_period("not-a-time", TZ)


# ------------------------------------------------------------------ 보고서 모델: 골격

RUN_ID = "ha-20261031T220000Z"
STARTED = "2026-10-31T22:00:05Z"
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
NOT_COLLECTED = "점검 불가(애플리케이션 접속기록·업무 기록 미수집)"


def _daily(name, days, records=5):
    return [{"name": name, "day": d, "records": records} for d in days]


def _ok(hits):
    return {"ok": True, "hits": hits, "error": ""}


def _fail(error="HTTP 401(인증·권한)"):
    return {"ok": False, "hits": [], "error": error}


def _results(hosts=None, switch=None, fortigate=None):
    return {"collection_hosts_daily": hosts if hosts is not None else _ok([]),
            "collection_switch_daily": switch if switch is not None else _ok([]),
            "collection_fortigate_daily": fortigate if fortigate is not None else _ok([])}


def _model(results=None, hosts=("ns0001", "ns0002"), devices=()):
    meta = {"run_id": RUN_ID, "run_kind": "scheduled", "started_at": STARTED, "generated_at": "2026-10-31T22:10:00Z",
            "timezone": TZ, "period": host_audit_log_review_period(STARTED, TZ),
            "settings": {"collection_targets": {"hosts": list(hosts), "devices": list(devices)}}}
    return host_audit_log_review_model(results if results is not None else _results(), meta)


def _part3(model, key="part3.collection_gap"):
    return next(i for i in model["part3"] if i["key"] == key)


def test_part1_has_the_19_ak034_log_review_items_in_form_order():
    m = _model()
    assert [i["no"] for i in m["part1"]] == list(range(1, 20))
    assert m["part1"][0]["title"] == "접근권한이 부여되지 않은 계정으로 접속한 행위"
    assert m["part1"][2]["title"].endswith("업무시간 외 접속한 경우")
    assert m["part1"][3]["title"].endswith("업무시간 외 권한변경한 경우")
    assert m["part1"][18]["title"] == "수행업무 중 적합하지 않은 파일을 첨부하여 진행한 경우"


def test_part2_has_the_9_security_policy_items_in_form_order_as_an_empty_table_for_people():
    m = _model()
    assert [i["no"] for i in m["part2"]] == list(range(1, 10))
    assert m["part2"][0]["title"] == "장기간 사용하지 않는 정책(Hit-Count가 0 등) 존재"
    assert m["part2"][8]["title"] == "불필요한 목적지 정책 존재"
    assert {i["status_label"] for i in m["part2"]} == {"사람 대조"}
    assert all(i["rows"] == [] and i["verdict"] == "" for i in m["part2"])


def test_items_8_to_11_and_14_to_19_say_every_month_that_application_records_are_not_collected():
    m = _model()
    not_collected = {i["no"] for i in m["part1"] if i["status_label"] == NOT_COLLECTED}
    assert not_collected == {8, 9, 10, 11, 14, 15, 16, 17, 18, 19}


def test_every_item_now_has_a_judge_and_a_missing_search_is_a_query_failure_never_not_implemented_or_ok():
    m = _model()
    labels = [i["status_label"] for i in m["part1"] + m["part3"]]
    assert "점검 불가(미구현)" not in labels
    item13 = next(i for i in m["part1"] if i["no"] == 13)
    assert item13["status_label"] == "조회 실패(조회하지 않음)" and item13["verdict"] == ""


def test_the_people_columns_are_always_empty_and_the_approval_has_three_signers():
    m = _model(_results(hosts=_ok(_daily("ns0001", ["2026-10-01"]))))
    for item in m["part1"] + m["part2"] + m["part3"]:
        assert (item["final_verdict"], item["remarks"], item["action"]) == ("", "", "")
    assert [a["role"] for a in m["approvals"]] == ["점검자", "정보보호관리자", "정보보호책임자(CISO)"]
    assert all(a["name"] == a["signature"] == a["date"] == "" for a in m["approvals"])


def test_the_header_names_the_period_and_the_run():
    m = _model()
    assert m["period"]["label"] == "2026-10-01 00:00 ~ 2026-10-31 24:00 (KST)"
    assert m["run_id"] == RUN_ID and m["started_at"] == "2026-11-01 07:00"


def test_the_status_counts_cover_every_item_once():
    m = _model()
    assert sum(c["count"] for c in m["counts"]) == 19 + 9 + len(m["part3"])
    assert [c["label"] for c in m["counts"]] == ["자동 판정", "일부 자동", "사람 대조", "점검 불가", "조회 실패"]


# ------------------------------------------------------------------ 3부 수집 공백

def test_hosts_with_logs_every_day_have_no_gap():
    m = _model(_results(hosts=_ok(_daily("ns0001", OCT) + _daily("ns0002", OCT))))
    gap = _part3(m)
    assert gap["status_label"] == "자동 판정" and gap["verdict"] == "이상 없음" and gap["rows"] == []


def test_a_host_without_any_log_in_the_month_is_a_gap():
    m = _model(_results(hosts=_ok(_daily("ns0001", OCT))))
    gap = _part3(m)
    assert gap["verdict"] == "확인 필요"
    assert gap["rows"] == [["호스트", "ns0002", "전월 로그 없음", "전체", 31]]


def test_a_host_whose_logs_stop_for_some_days_is_a_broken_gap_with_the_missing_ranges():
    days = [d for d in OCT if d not in ("2026-10-03", "2026-10-04", "2026-10-05", "2026-10-20")]
    m = _model(_results(hosts=_ok(_daily("ns0001", OCT) + _daily("ns0002", days))))
    assert _part3(m)["rows"] == [["호스트", "ns0002", "끊김", "10-03~10-05, 10-20", 4]]


def test_zero_record_rows_and_hosts_outside_the_targets_do_not_count():
    hits = _daily("ns0001", OCT) + _daily("ns0002", OCT[:30]) + _daily("ns0002", ["2026-10-31"], records=0) \
        + _daily("stranger", OCT)
    rows = _part3(_model(_results(hosts=_ok(hits))))["rows"]
    assert rows == [["호스트", "ns0002", "끊김", "10-31", 1]]


def test_a_device_counts_as_collected_on_a_day_seen_in_either_device_stream():
    sw = _ok(_daily("ns0900", OCT[:15]))
    fg = _ok(_daily("ns0900", OCT[15:]) + _daily("ns0901", OCT))
    m = _model(_results(hosts=_ok(_daily("ns0001", OCT) + _daily("ns0002", OCT)), switch=sw, fortigate=fg),
               devices=("ns0900", "ns0901", "ns0902"))
    assert _part3(m)["rows"] == [["장비", "ns0902", "전월 로그 없음", "전체", 31]]


def test_a_failed_query_is_query_failure_not_no_gap():
    gap = _part3(_model(_results(hosts=_fail())))
    assert gap["status_label"] == "조회 실패(호스트 로그 HTTP 401(인증·권한))"
    assert gap["verdict"] == ""


def test_a_failed_device_query_keeps_the_host_gaps_found_but_stays_a_query_failure():
    m = _model(_results(hosts=_ok(_daily("ns0001", OCT)), fortigate=_fail("연결 불가·시간 초과")), devices=("ns0900",))
    gap = _part3(m)
    assert gap["status"] == "failed" and "장비 로그 연결 불가" in gap["status_label"]
    assert gap["rows"] == [["호스트", "ns0002", "전월 로그 없음", "전체", 31]]


def test_no_collection_targets_is_unavailable_not_ok():
    gap = _part3(_model(hosts=()))
    assert gap["status_label"] == "점검 불가(수집 대상 목록 없음)"


def test_the_collection_gap_states_its_method_and_criterion():
    gap = _part3(_model(_results(hosts=_ok(_daily("ns0001", OCT)))))
    assert "system_logs" in gap["method"] and "끊김" in gap["criterion"]


# ------------------------------------------------------------------ 조회 결과 정리 (uri 반복 결과 -> 항목 입력)

def _uri(name, status=200, hits=None, size=100, json_body=None):
    r = {"item": {"name": name, "size": size}, "status": status}
    if status == 200:
        r["json"] = json_body if json_body is not None else {"hits": hits or []}
    return r


def test_uri_results_become_ok_or_failed_per_query_with_status_only_reasons():
    out = host_audit_log_review_results({"results": [
        _uri("a", hits=[{"x": 1}]), _uri("b", status=401), _uri("c", status=-1), _uri("d", status=500),
        _uri("e", json_body={"error": "x"})]})
    assert out["a"] == {"ok": True, "hits": [{"x": 1}], "error": ""}
    assert out["b"]["error"] == "HTTP 401(인증·권한)" and not out["b"]["ok"]
    assert out["c"]["error"] == "연결 불가·시간 초과"
    assert out["d"]["error"] == "HTTP 500"
    assert out["e"]["error"] == "응답 형식 오류"


def test_a_result_that_reaches_the_requested_size_may_be_truncated_and_is_a_failure():
    out = host_audit_log_review_results([_uri("a", hits=[{"x": i} for i in range(3)], size=3)])
    assert out["a"] == {"ok": False, "hits": [], "error": "결과가 조회 한도(3행)에 닿음"}


def test_a_credential_problem_fails_every_query_with_that_reason():
    out = host_audit_log_review_results([{"item": {"name": "a"}, "skipped": True}], "자격증명 문서를 읽지 못함")
    assert out == {"a": {"ok": False, "hits": [], "error": "자격증명 문서를 읽지 못함"}}


def test_queries_cover_the_month_in_microseconds_and_every_name_is_unique():
    period = host_audit_log_review_period(STARTED, TZ)
    qs = host_audit_log_review_queries(period)
    assert {"collection_hosts_daily", "collection_switch_daily", "collection_fortigate_daily"} <= {q["name"] for q in qs}
    assert len({q["name"] for q in qs}) == len(qs)
    for q in qs:
        assert q["body"]["query"]["start_time"] == period["start_us"]
        assert q["body"]["query"]["end_time"] == period["end_us"]
        assert q["body"]["query"]["size"] == q["size"]


def test_every_item_key_is_unique_so_judge_modules_can_register_by_key():
    m = _model()
    keys = [i["key"] for i in m["part1"] + m["part2"] + m["part3"]]
    assert len(keys) == len(set(keys))


def test_a_judge_that_raises_marks_only_its_item_and_records_the_error(monkeypatch):
    import host_audit_log_review as core

    def boom(ctx):
        raise KeyError("x")

    monkeypatch.setattr(core._collection, "JUDGES", {"part3.collection_gap": boom})
    m = _model()
    assert _part3(m)["status_label"] == "조회 실패(판정 오류 KeyError)"
    assert m["errors"] == ["part3.collection_gap: KeyError"]
    assert len(m["part1"]) == 19


# ------------------------------------------------------------------ 첨부 이름

def test_the_attachment_name_is_ascii_and_derived_from_the_run_id():
    assert host_audit_log_review_file_name(RUN_ID) == "host-audit-ha-20261031T220000Z-log-review.html"
    assert host_audit_log_review_file_name("../x y") == "host-audit-x-y-log-review.html"
