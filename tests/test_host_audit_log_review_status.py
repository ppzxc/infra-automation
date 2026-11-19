"""Log Review Report 3부 로그 관리 상태 나머지 (Spec #544 / Ticket-8 #563, ADR-0015).

보존·시각 동기·백업·알림 이력·GitHub 감사 로그 수집 상태. 필터 직접 테스트(ADR-0013 다수 층)로 보고서 모델의 3부 항목만 본다.
쿼리 문자열은 시험하지 않는다(#544 Testing Decisions). 호스트 이름은 fixture 값이다.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import (  # noqa: E402
    host_audit_log_review_model,
    host_audit_log_review_period,
    host_audit_log_review_queries,
)

TZ = "Asia/Seoul"
STARTED = "2026-10-31T22:00:05Z"
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
HOSTS = ("ns0001", "ns0002")


def _ok(hits):
    return {"ok": True, "hits": hits, "error": ""}


def _fail(error="HTTP 401(인증·권한)"):
    return {"ok": False, "hits": [], "error": error}


def _daily(name, days):
    return [{"name": name, "day": d, "records": 3} for d in days]


def _model(results=None, hosts=HOSTS, log_management=None):
    base = {"collection_hosts_daily": _ok(sum((_daily(h, OCT) for h in hosts), [])),
            "collection_switch_daily": _ok([]), "collection_fortigate_daily": _ok([])}
    base.update(results or {})
    settings = {"collection_targets": {"hosts": list(hosts), "devices": []}}
    if log_management is not None:
        settings["log_management"] = log_management
    meta = {"run_id": "ha-20261031T220000Z", "run_kind": "scheduled", "started_at": STARTED,
            "generated_at": "2026-10-31T22:10:00Z", "timezone": TZ,
            "period": host_audit_log_review_period(STARTED, TZ), "settings": settings}
    return host_audit_log_review_model(base, meta)


def _item(model, key):
    return next(i for i in model["part3"] if i["key"] == "part3." + key)


# ------------------------------------------------------------------ 시각 동기

def _sync(name, status="synced", readings=8000, max_offset_ms=3):
    return {"name": name, "sync_status": status, "readings": readings, "max_offset_ms": max_offset_ms}


def test_every_host_synced_within_one_second_is_ok():
    m = _model({"status_time_sync": _ok([_sync("ns0001"), _sync("ns0002", max_offset_ms=None)])})
    item = _item(m, "time_sync")
    assert item["status_label"] == "자동 점검" and item["verdict"] == "이상 없음"
    assert [r[0] for r in item["rows"]] == ["ns0001", "ns0002"]
    assert item["rows"][0][-1] == "이상 없음"


def test_unsynced_readings_or_an_offset_over_one_second_need_a_check():
    m = _model({"status_time_sync": _ok([_sync("ns0001", readings=7990), _sync("ns0001", "unsynced", readings=10),
                                         _sync("ns0002", max_offset_ms="-1500.5")])})
    item = _item(m, "time_sync")
    assert item["verdict"] == "확인 필요"
    rows = {r[0]: r for r in item["rows"]}
    assert rows["ns0001"][-1] == "확인 필요" and rows["ns0002"][-1] == "확인 필요"


def test_a_host_without_time_sync_readings_or_without_a_tool_is_unverifiable_not_ok():
    m = _model({"status_time_sync": _ok([_sync("ns0001", "no_tool")])})
    item = _item(m, "time_sync")
    rows = {r[0]: r[-1] for r in item["rows"]}
    assert rows == {"ns0001": "확인 불가(동기 도구 없음)", "ns0002": "확인 불가(판독 없음)"}
    assert item["status_label"] == "일부 자동" and item["verdict"] == "확인 필요"


def test_a_host_in_the_collection_gap_is_marked_as_such_in_time_sync():
    results = {"collection_hosts_daily": _ok(_daily("ns0001", OCT)), "status_time_sync": _ok([_sync("ns0001")])}
    rows = {r[0]: r[-1] for r in _item(_model(results), "time_sync")["rows"]}
    assert rows["ns0002"] == "확인 불가(로그가 없는 날)"


def test_a_failed_time_sync_query_is_a_query_failure():
    item = _item(_model({"status_time_sync": _fail()}), "time_sync")
    assert item["status_label"] == "조회 실패(HTTP 401(인증·권한))" and item["verdict"] == ""


# ------------------------------------------------------------------ 전월 백업 결과

def _runs(name, days, success=True, runs=1):
    return [{"name": name, "day": d, "success": success, "runs": runs} for d in days]


def _backup(daily, others=None):
    return {"status_backup_daily": _ok(daily), "status_backup_other_failures": _ok(others or [])}


def test_daily_successful_backups_on_every_target_are_ok():
    item = _item(_model(_backup(_runs("ns0001", OCT) + _runs("ns0002", OCT))), "backup")
    assert item["status_label"] == "자동 점검" and item["verdict"] == "이상 없음"
    assert {r[0]: r[-1] for r in item["rows"]} == {"ns0001": "이상 없음", "ns0002": "이상 없음"}


def test_a_failure_missing_days_and_a_host_without_success_are_reported_per_host():
    daily = _runs("ns0001", OCT) + _runs("ns0001", ["2026-10-07"], success="false", runs=2) \
        + _runs("ns0002", OCT[:28]) + _runs("ns0003", ["2026-10-02"], success=False)
    item = _item(_model(_backup(daily), hosts=("ns0001", "ns0002", "ns0003")), "backup")
    assert item["verdict"] == "확인 필요"
    rows = {r[0]: r for r in item["rows"]}
    assert rows["ns0001"][1:] == [31, 2, "", "실패 2회"]
    assert rows["ns0002"][1:] == [28, 0, "10-29~10-31", "누락 3일"]
    assert rows["ns0003"][1:] == [0, 1, "전체", "성공 없음"]


def test_a_host_in_the_collection_gap_without_backups_says_so():
    results = dict(_backup(_runs("ns0001", OCT)), collection_hosts_daily=_ok(_daily("ns0001", OCT)))
    rows = {r[0]: r[-1] for r in _item(_model(results), "backup")["rows"]}
    assert rows["ns0002"] == "성공 없음(로그가 없는 날)"


def test_maintenance_and_integrity_check_failures_need_a_check():
    item = _item(_model(_backup(_runs("ns0001", OCT) + _runs("ns0002", OCT),
                                [{"job": "maintenance", "command": "check", "failures": 1}])), "backup")
    assert item["verdict"] == "확인 필요"
    assert ["maintenance/check", "-", 1, "", "실패 1회"] in item["rows"]


def test_a_failed_backup_query_is_a_query_failure():
    item = _item(_model({"status_backup_daily": _fail("연결 불가·시간 초과"),
                         "status_backup_other_failures": _ok([])}), "backup")
    assert item["status_label"] == "조회 실패(연결 불가·시간 초과)"


# ------------------------------------------------------------------ GitHub 감사 로그 수집 상태

def _beat(days, result="ok", hook_status="ok", checks=4, expired=0, failed=0):
    return [{"day": d, "result": result, "hook_status": hook_status, "checks": checks, "expired": expired,
             "failed": failed} for d in days]


def _github(beats, events=12):
    return {"status_github_heartbeats": _ok(beats), "status_github_events": _ok([{"records": events}])}


def test_a_heartbeat_every_day_with_a_healthy_hook_is_ok_even_without_org_events():
    item = _item(_model(_github(_beat(OCT), events=0)), "github_audit")
    assert item["status_label"] == "자동 점검" and item["verdict"] == "이상 없음" and item["rows"] == []
    assert "수신 이벤트 0건" in item["summary"] and "로그인" in item["method"]


def test_days_without_a_heartbeat_an_unhealthy_hook_and_expired_failures_need_a_check():
    beats = _beat([d for d in OCT if d not in ("2026-10-09", "2026-10-10")]) \
        + _beat(["2026-10-15"], hook_status="inactive", checks=2) + _beat(["2026-10-20"], result="error", hook_status="unknown",
                                                                         checks=1) \
        + _beat(["2026-10-21"], expired=3)
    item = _item(_model(_github(beats)), "github_audit")
    assert item["verdict"] == "확인 필요"
    assert ["전달 점검 기록 없는 날", "10-09~10-10", 2] in item["rows"]
    assert ["훅 상태 inactive", "10-15", 2] in item["rows"]
    assert ["점검 오류(result=error)", "10-20", 1] in item["rows"]
    assert ["재전송 기간을 넘긴 실패 전달(최대)", "10-21", 3] in item["rows"]


def test_no_heartbeat_at_all_means_the_collection_state_is_unknown_for_the_whole_month():
    item = _item(_model(_github([])), "github_audit")
    assert item["verdict"] == "확인 필요" and ["전달 점검 기록 없는 날", "전체", 31] in item["rows"]


def test_a_failed_github_query_is_a_query_failure():
    item = _item(_model({"status_github_heartbeats": _fail("HTTP 400"), "status_github_events": _ok([])}), "github_audit")
    assert item["status_label"] == "조회 실패(전달 점검 기록 HTTP 400)"


# ------------------------------------------------------------------ 보존 기간

RETENTION = {"security_logs": 365, "system_logs": 365, "backup_logs": 365}


def test_declared_retention_of_one_year_meets_the_standard_but_the_server_value_is_for_people():
    item = _item(_model(log_management={"retention_days": RETENTION}), "retention")
    assert item["status_label"] == "일부 자동" and item["verdict"] == "이상 없음"
    assert ["security_logs", 365, 365, "이상 없음"] in item["rows"]
    assert "_search" in item["summary"] or "_search" in item["method"]


def test_a_log_type_kept_shorter_than_one_year_needs_a_check():
    item = _item(_model(log_management={"retention_days": dict(RETENTION, system_logs=180)}), "retention")
    assert item["verdict"] == "확인 필요"
    assert ["system_logs", 180, 365, "기준 미달"] in item["rows"]


def test_a_personal_information_system_in_scope_raises_the_standard_to_two_years():
    item = _item(_model(log_management={"retention_days": RETENTION, "personal_info_system": True}), "retention")
    assert item["verdict"] == "확인 필요"
    assert ["security_logs", 365, 730, "기준 미달"] in item["rows"]


def test_no_declared_retention_is_unavailable_not_ok():
    assert _item(_model(), "retention")["status_label"] == "점검 불가(보존 기간 설정 없음)"


# ------------------------------------------------------------------ 알림 이력

def test_alert_history_is_a_manual_check_because_search_cannot_read_it():
    item = _item(_model(), "alert_history")
    assert item["status_label"] == "사람 대조" and item["verdict"] == ""
    assert "알림" in item["method"] and "_search" in item["summary"]


# ------------------------------------------------------------------ 조회 목록

def test_the_status_queries_are_registered_and_stay_inside_the_review_period():
    period = host_audit_log_review_period(STARTED, TZ)
    qs = {q["name"]: q for q in host_audit_log_review_queries(period)}
    assert {"status_time_sync", "status_backup_daily", "status_backup_other_failures", "status_github_heartbeats",
            "status_github_events"} <= set(qs)
    for name, q in qs.items():
        if name.startswith("status_"):
            assert (q["body"]["query"]["start_time"], q["body"]["query"]["end_time"]) == (period["start_us"], period["end_us"])
