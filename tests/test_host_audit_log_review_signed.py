"""Log Review Report 서명본: 전월 서명본 확인과 등록 검증 (Spec #544 / Ticket-9 #564, ADR-0015).

필터 직접 테스트(ADR-0013 두 층 중 다수 층). 전월 서명본 항목은 보고서 모델(host_audit_log_review_model)로 보고,
조회·등록 판단은 그 필터를 직접 부른다. 값은 모두 fixture(example 주소·가짜 해시)다.
"""
import json
import sys
from pathlib import Path

import jinja2
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT_DIR / "roles" / "host_audit" / "templates"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import host_audit_log_review_model, host_audit_log_review_period  # noqa: E402
from host_audit_log_review_signed import (  # noqa: E402
    host_audit_log_review_signed_file_problems,
    host_audit_log_review_signed_keys,
    host_audit_log_review_signed_lookup,
    host_audit_log_review_signed_record,
    host_audit_log_review_signed_request,
    host_audit_log_review_signed_target,
)

TZ = "Asia/Seoul"
RUN_ID = "ha-20261130T220000Z"          # 12월 1일 07:00 KST 정기 실행 -> 11월 점검
STARTED = "2026-11-30T22:00:05Z"
PREV_ID = "ha-20261031T220000Z"          # 직전 정기 실행(11월 1일 07:00 KST) -> 10월 점검, 그 서명본이 '전월 서명본'
PREV_STARTED = "2026-10-31T22:00:05Z"
SHA = "a" * 64
ITEM = "part3.previous_signed_copy"
RUN = {"run_id": RUN_ID, "run_kind": "scheduled", "started_at": STARTED}
POINTERS = [
    {"run_id": "ha-20260930T220000Z", "run_kind": "scheduled", "started_at": "2026-09-30T22:00:04Z"},
    {"run_id": PREV_ID, "run_kind": "scheduled", "started_at": PREV_STARTED},
]


def _record(**over):
    rec = {"schema_version": 1, "run_id": PREV_ID, "review_month": "2026-10",
           "file_key": "2026-11/%s/signed/host-audit-%s-log-review-signed.pdf" % (PREV_ID, PREV_ID),
           "sha256": SHA, "size": 123456, "registered_at": "2026-11-05T05:30:00Z"}
    rec.update(over)
    return rec


def _model(signed):
    meta = {"run_id": RUN_ID, "run_kind": "scheduled", "started_at": STARTED, "generated_at": STARTED,
            "timezone": TZ, "period": host_audit_log_review_period(STARTED, TZ),
            "settings": {"collection_targets": {"hosts": [], "devices": []}, "previous_signed_copy": signed}}
    m = host_audit_log_review_model({}, meta)
    assert m["errors"] == []
    return next(i for i in m["part3"] if i["key"] == ITEM)


def _render(signed):
    meta = {"run_id": RUN_ID, "run_kind": "scheduled", "started_at": STARTED, "generated_at": STARTED,
            "timezone": TZ, "period": host_audit_log_review_period(STARTED, TZ),
            "settings": {"collection_targets": {"hosts": [], "devices": []}, "previous_signed_copy": signed}}
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=False,
                             undefined=jinja2.StrictUndefined)
    html = env.get_template("log_review.html.j2").render(host_audit_log_review_model=host_audit_log_review_model({}, meta))
    return html.split('<section class="approval', 1)[1]


def _lookup(response, history=None):
    history = {"state": "ok", "reason": "", "pointers": POINTERS} if history is None else history
    return host_audit_log_review_signed_lookup(history, RUN, response, TZ)


def _ok(doc):
    return {"status": 200, "content": json.dumps(doc)}


# ------------------------------------------------------------------ 보고서: 전월 서명본 있음/없음/전월 실행 없음

def test_a_registered_previous_copy_is_there_with_its_kst_time_and_hash():
    item = _model(_lookup(_ok(_record())))
    assert item["status"] == "auto" and item["verdict"] == "이상 없음"
    assert item["summary"] == "전월 서명본: 있음(2026-11-05 14:30 KST · SHA-256 %s)" % SHA
    assert any(PREV_ID in str(c) for row in item["rows"] for c in row)


def test_no_record_in_the_previous_run_is_none_and_needs_a_look():
    item = _model(_lookup({"status": 404, "content": ""}))
    assert item["status"] == "auto" and item["verdict"] == "확인 필요"
    assert item["summary"].startswith("전월 서명본: 없음") and PREV_ID in item["summary"]


def test_without_a_previous_scheduled_run_the_item_cannot_be_checked():
    item = _model(_lookup(None, {"state": "ok", "reason": "", "pointers": []}))
    assert item["status"] == "unavailable" and item["status_label"] == "점검 불가(전월 정기 실행 없음)"
    assert item["summary"] == "전월 서명본: 전월 정기 실행 없음"


def test_a_failed_pointer_lookup_or_record_read_is_a_query_failure_not_none():
    item = _model(_lookup(None, {"state": "failed", "reason": "baseline/ 목록 조회 실패(status=403)", "pointers": []}))
    assert item["status"] == "failed" and "baseline/ 목록 조회 실패" in item["status_label"]
    assert item["summary"] == "전월 서명본: 확인 실패"
    item = _model(_lookup({"status": 403, "content": ""}))
    assert item["status"] == "failed" and item["status_label"] == "조회 실패(서명본 기록 HTTP 403)"
    item = _model(_lookup({"status": -1, "content": ""}))
    assert item["status"] == "failed" and "연결 불가" in item["status_label"]


def test_a_damaged_record_is_a_failure_not_a_signed_copy():
    for content in ("{not json", json.dumps(_record(sha256="xyz")), json.dumps(_record(run_id="ha-other"))):
        item = _model(_lookup({"status": 200, "content": content}))
        assert item["status"] == "failed" and "서명본 기록 형식 오류" in item["status_label"], content


def test_storage_off_or_no_lookup_is_unavailable():
    item = _model(_lookup(None, {"state": "disabled", "reason": "보관 비활성(host_audit_storage_enabled=false)"}))
    assert item["status"] == "unavailable" and "보관 비활성" in item["status_label"]
    assert _model(None)["status"] == "unavailable"


def test_a_previous_run_that_is_not_last_months_is_flagged_even_with_a_copy():
    """직전 정기 실행이 실패해 포인터가 없으면 그 전 실행이 고른다: 전월 서명본이 아니므로 확인 필요."""
    history = {"state": "ok", "reason": "", "pointers": POINTERS[:1]}
    rec = _record(run_id="ha-20260930T220000Z", review_month="2026-09")
    item = _model(_lookup(_ok(rec), history))
    assert item["verdict"] == "확인 필요" and "직전 정기 실행이 2026-11 실행이 아님" in item["summary"]


def test_the_approval_page_says_whether_last_months_copy_was_registered():
    present = _render(_lookup(_ok(_record())))
    assert "전월 서명본: 있음(2026-11-05 14:30 KST · SHA-256 %s)" % SHA in present
    assert "전월 서명본: 없음" in _render(_lookup({"status": 404, "content": ""}))
    assert "전월 서명본: 전월 정기 실행 없음" in _render(_lookup(None, {"state": "ok", "reason": "", "pointers": []}))


def test_the_lookup_reads_the_record_of_the_baseline_run():
    keys = host_audit_log_review_signed_keys({"run_id": PREV_ID, "started_at": PREV_STARTED}, TZ)
    assert keys["prefix"] == "2026-11/%s/" % PREV_ID
    assert keys["record_key"] == "2026-11/%s/signed/registration.json" % PREV_ID
    assert keys["pdf_key"] == "2026-11/%s/signed/host-audit-%s-log-review-signed.pdf" % (PREV_ID, PREV_ID)


# ------------------------------------------------------------------ 등록: 입력·파일·버킷 검증 (잘못 올리면 지울 수 없다)

INTAKE = "/srv/host_audit/_signed_intake"


def _request(**over):
    args = dict(run_id=PREV_ID, sha256=SHA.upper(), intake_dir=INTAKE + "/")
    args.update(over)
    return host_audit_log_review_signed_request(**args)


def test_the_request_takes_only_a_run_id_and_a_hash_and_names_the_intake_file():
    req = _request()
    assert req == {"run_id": PREV_ID, "sha256": SHA, "src": INTAKE + "/%s.pdf" % PREV_ID,
                   "pointer_key": "baseline/%s.json" % PREV_ID}


@pytest.mark.parametrize("over", [
    {"run_id": ""}, {"run_id": "../ha-1"}, {"run_id": "ha 1"}, {"run_id": "-ha"},
    {"sha256": ""}, {"sha256": "a" * 63}, {"sha256": "g" * 64}, {"sha256": SHA + " x"},
    {"intake_dir": ""}, {"intake_dir": "relative/dir"},
])
def test_a_malformed_request_stops_before_anything_is_read(over):
    with pytest.raises(Exception):
        _request(**over)


def _stat(**over):
    st = {"exists": True, "isreg": True, "islnk": False, "size": 2048, "checksum": SHA}
    st.update(over)
    return st


def test_a_matching_pdf_has_no_file_problem():
    assert host_audit_log_review_signed_file_problems(_stat(), "%PDF-", SHA, 20 * 1024 * 1024) == []


@pytest.mark.parametrize("stat,head,needle", [
    ({"exists": False}, "", "없음"),
    ({"islnk": True, "isreg": False}, "%PDF-", "심볼릭 링크"),
    ({"isreg": False}, "%PDF-", "일반 파일이 아님"),
    ({"size": 0}, "%PDF-", "비어 있음"),
    ({"size": 30 * 1024 * 1024}, "%PDF-", "상한"),
    ({"checksum": "b" * 64}, "%PDF-", "SHA-256 불일치"),
    ({}, "PK\x03\x04", "PDF 파일이 아님"),
])
def test_every_bad_file_is_refused(stat, head, needle):
    problems = host_audit_log_review_signed_file_problems(_stat(**stat), head, SHA, 20 * 1024 * 1024)
    assert any(needle in p for p in problems), problems


POINTER = {"run_id": PREV_ID, "run_kind": "scheduled", "started_at": PREV_STARTED, "findings_key": "x"}
SUMMARY = {"log_review": {"file_name": "host-audit-%s-log-review.html" % PREV_ID, "sha256": "c" * 64, "period": "2026-10"}}


def _target(pointer=None, summary=None, record=None):
    pointer = _ok(POINTER) if pointer is None else pointer
    summary = _ok(SUMMARY) if summary is None else summary
    record = {"status": 404, "content": ""} if record is None else record
    return host_audit_log_review_signed_target(_request(), pointer, summary, record, TZ)


def test_a_finished_scheduled_run_with_a_report_and_no_copy_yet_is_the_target():
    t = _target()
    assert t["problems"] == []
    assert t["pdf_key"] == "2026-11/%s/signed/host-audit-%s-log-review-signed.pdf" % (PREV_ID, PREV_ID)
    assert t["record_key"] == "2026-11/%s/signed/registration.json" % PREV_ID
    assert t["review_month"] == "2026-10"


@pytest.mark.parametrize("kw,needle", [
    ({"pointer": {"status": 404, "content": ""}}, "정기 실행 기록(baseline/%s.json)이 없음" % PREV_ID),
    ({"pointer": {"status": 403, "content": ""}}, "정기 실행 기록 HTTP 403"),
    ({"pointer": {"status": -1, "content": ""}}, "연결 불가"),
    ({"pointer": _ok(dict(POINTER, run_kind="on_demand"))}, "형식이 맞지 않음"),
    ({"pointer": _ok(dict(POINTER, run_id="ha-other"))}, "형식이 맞지 않음"),
    ({"summary": {"status": 404, "content": ""}}, "메일 요약(mail_summary.json) HTTP 404"),
    ({"summary": _ok({"report": {}})}, "Log Review Report를 보내지 않았음"),
    ({"record": _ok(_record())}, "이미 등록된 서명본이 있음(등록 일시 2026-11-05 14:30 KST"),
    ({"record": {"status": 500, "content": ""}}, "서명본 등록 기록 HTTP 500"),
])
def test_every_bucket_side_mismatch_is_refused(kw, needle):
    problems = _target(**kw)["problems"]
    assert any(needle in p for p in problems), problems


def test_the_record_carries_the_verified_hash_size_and_time():
    t = _target()
    rec = host_audit_log_review_signed_record(_request(), t, 2048, "2026-11-05T05:30:00Z")
    assert rec == {"schema_version": 1, "run_id": PREV_ID, "review_month": "2026-10", "file_key": t["pdf_key"],
                   "sha256": SHA, "size": 2048, "registered_at": "2026-11-05T05:30:00Z"}
    # 다음 달 보고서가 이 기록을 그대로 '있음'으로 읽는다(등록과 확인이 같은 형식을 쓴다)
    item = _model(_lookup(_ok(rec)))
    assert item["verdict"] == "이상 없음" and SHA in item["summary"]
