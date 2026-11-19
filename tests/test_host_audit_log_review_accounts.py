"""Log Review Report 1부 계정·시간 항목 1·2·3·4·5번 (Spec #544 / Ticket-4 #559, ADR-0015).

필터 직접 테스트(ADR-0013 다수 층): 보고서 모델 필터에 fixture 조회 결과·기준 설정을 넣고 항목 상태·판정·표만 본다.
쿼리 문자열과 내부 함수 구성은 시험하지 않는다(#544 Testing Decisions). 계정·호스트 이름은 모두 가짜 값이다.
"""
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import host_audit_log_review_model, host_audit_log_review_period  # noqa: E402
from host_audit_log_review_accounts import host_audit_log_review_account_hosts  # noqa: E402

TZ = "Asia/Seoul"
STARTED = "2026-10-31T22:00:05Z"  # KST 11-01 07:00 -> 2026-10 점검
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
HOSTS = ("ns0001", "ns0002")
# 2026-10: 03(토)·04(일), 05(월, 개천절 대체공휴일), 09(금, 한글날), 12(월)~16(금) 평일
HOLIDAYS = {2026: ["2026-10-03", "2026-10-05", "2026-10-09"]}


def _ok(hits):
    return {"ok": True, "hits": hits, "error": ""}


def _fail(error="HTTP 401(인증·권한)"):
    return {"ok": False, "hits": [], "error": error}


def _every_day(names):
    return [{"name": n, "day": d, "records": 3} for n in names for d in OCT]


def _results(success=(), failures=(), invalid=(), privilege=(), changes=(), collection=None, **override):
    out = {
        "collection_hosts_daily": collection if collection is not None else _ok(_every_day(HOSTS)),
        "collection_switch_daily": _ok([]),
        "collection_fortigate_daily": _ok([]),
        "accounts_ssh_success_hourly": _ok(list(success)),
        "accounts_ssh_failure_minutely": _ok(list(failures)),
        "accounts_ssh_invalid_user": _ok(list(invalid)),
        "accounts_privilege_hourly": _ok(list(privilege)),
        "accounts_account_change_hourly": _ok(list(changes)),
    }
    out.update(override)
    return out


def _host(declared=("alice",), bootstrap="", agents_only=False, inventory_accounts=None):
    return {"declared": list(declared), "bootstrap": bootstrap, "agents_only": agents_only,
            "inventory_accounts": inventory_accounts}


def _settings(hosts=None, holidays=None, pii="unset", **extra):
    accounts = {"hosts": hosts if hosts is not None else {"ns0001": _host(), "ns0002": _host()},
                "business_hours": {"start": 8, "end": 20},
                "holidays": HOLIDAYS if holidays is None else holidays,
                "failure_threshold": 5, "failure_window_minutes": 10}
    accounts.update(extra)
    s = {"collection_targets": {"hosts": list(HOSTS), "devices": []}, "accounts": accounts}
    if pii != "unset":
        s["personal_info_systems"] = pii
    return s


def _model(results=None, settings=None):
    meta = {"run_id": "ha-x", "run_kind": "scheduled", "started_at": STARTED, "generated_at": STARTED,
            "timezone": TZ, "period": host_audit_log_review_period(STARTED, TZ),
            "settings": settings if settings is not None else _settings()}
    return host_audit_log_review_model(results if results is not None else _results(), meta)


def _item(model, no):
    return next(i for i in model["part1"] if i["no"] == no)


def _col(item, name):
    return [r[item["columns"].index(name)] for r in item["rows"]]


def _login(host, user, hour, logins=1):
    return {"host": host, "user": user, "hour": hour, "logins": logins}


# ------------------------------------------------------------------ 1번 허용 계정 밖 로그인 성공

def test_item1_logins_by_declared_accounts_bootstrap_and_root_are_no_finding():
    hosts = {"ns0001": _host(declared=("alice",), bootstrap="boot"), "ns0002": _host(declared=("alice",))}
    m = _model(_results(success=[_login("ns0001", "alice", "2026-10-12 10"), _login("ns0001", "boot", "2026-10-12 10"),
                                 _login("ns0002", "root", "2026-10-12 11")]), _settings(hosts=hosts))
    i = _item(m, 1)
    assert i["status"] == "auto" and i["verdict"] == "이상 없음"
    assert i["rows"] == []


def test_item1_a_successful_login_by_an_account_outside_the_allowed_list_is_a_finding():
    m = _model(_results(success=[_login("ns0001", "mallory", "2026-10-12 10", 2), _login("ns0001", "mallory", "2026-10-13 09"),
                                 _login("ns0002", "alice", "2026-10-12 10")]))
    i = _item(m, 1)
    assert i["status"] == "auto" and i["verdict"] == "확인 필요"
    assert _col(i, "호스트") == ["ns0001"] and _col(i, "계정") == ["mallory"] and _col(i, "로그인 수") == [3]


def test_item1_the_bootstrap_account_is_allowed_only_on_its_own_host():
    hosts = {"ns0001": _host(bootstrap="boot"), "ns0002": _host()}
    m = _model(_results(success=[_login("ns0002", "boot", "2026-10-12 10")]), _settings(hosts=hosts))
    assert _col(_item(m, 1), "계정") == ["boot"]


def test_item1_agents_only_hosts_use_the_asset_inventory_accounts():
    hosts = {"ns0001": _host(declared=(), agents_only=True, inventory_accounts=["legacy"]), "ns0002": _host()}
    m = _model(_results(success=[_login("ns0001", "legacy", "2026-10-12 10"), _login("ns0001", "alice", "2026-10-12 10")]),
               _settings(hosts=hosts))
    assert _col(_item(m, 1), "계정") == ["alice"]


def test_item1_a_host_without_an_allowed_list_is_named_not_judged_ok():
    hosts = {"ns0001": _host(declared=(), agents_only=True, inventory_accounts=None), "ns0002": _host()}
    m = _model(_results(success=[_login("ns0001", "anyone", "2026-10-12 10"), _login("ns0009", "alice", "2026-10-12 10")]),
               _settings(hosts=hosts))
    i = _item(m, 1)
    assert i["verdict"] == "확인 필요"
    notes = dict(zip(_col(i, "호스트"), _col(i, "비고")))
    assert "허용 계정 목록 없음" in notes["ns0001"] and "허용 계정 목록 없음" in notes["ns0009"]


def test_item1_invalid_user_attempts_are_a_separate_statistic_not_a_finding():
    invalid = [{"host": "ns0001", "attempts": 120, "users": 30, "sources": 4},
               {"host": "ns0002", "attempts": 5, "users": 2, "sources": 1}]
    i = _item(_model(_results(invalid=invalid)), 1)
    assert i["verdict"] == "이상 없음" and i["rows"] == []
    assert "존재하지 않는 계정 시도 125건" in i["summary"] and "호스트 2대" in i["summary"]


def test_item1_a_failed_success_query_is_query_failure():
    i = _item(_model(_results(accounts_ssh_success_hourly=_fail())), 1)
    assert i["status_label"] == "조회 실패(HTTP 401(인증·권한))" and i["verdict"] == ""


def test_item1_states_the_allowed_account_rule_as_its_criterion():
    i = _item(_model(), 1)
    assert "root" in i["criterion"] and "bootstrap" in i["criterion"] and "Asset Inventory" in i["criterion"]
    assert i["method"]


# ------------------------------------------------------------------ 수집 공백·개인정보처리시스템 (1~4번 공통)

def test_a_host_with_a_collection_gap_is_shown_on_the_item_and_never_judged_ok():
    gap = _ok([{"name": "ns0001", "day": d, "records": 3} for d in OCT])  # ns0002는 전월 로그 없음
    i = _item(_model(_results(collection=gap)), 1)
    assert i["status"] == "partial" and i["verdict"] == "확인 필요"
    assert _col(i, "호스트") == ["ns0002"] and "수집 공백" in _col(i, "비고")[0]
    assert "수집 공백 호스트 1대(ns0002)" in i["summary"]


def test_when_the_collection_gap_is_unknown_the_item_does_not_say_ok():
    i = _item(_model(_results(collection=_fail())), 1)
    assert i["status"] == "partial" and i["verdict"] == "확인 필요"
    assert "수집 공백을 확인하지 못함" in i["summary"]


def test_personal_information_systems_are_marked_on_rows_or_unset_when_not_given():
    res = _results(success=[_login("ns0001", "mallory", "2026-10-12 10"), _login("ns0002", "eve", "2026-10-12 10")])
    unset = _item(_model(res), 1)
    assert _col(unset, "개인정보처리시스템") == ["미지정", "미지정"]
    assert "개인정보처리시스템 표시: 미지정" in unset["summary"]
    marked = _item(_model(res, _settings(pii=["ns0002"])), 1)
    assert _col(marked, "개인정보처리시스템") == ["아니오", "예"]
    assert "개인정보처리시스템 해당 행 1(호스트 ns0002)" in marked["summary"]


# ------------------------------------------------------------------ 2번 연속 실패

def _fails(host, user, minutes, each=1):
    return [{"host": host, "user": user, "minute": m, "failures": each} for m in minutes]


def test_item2_five_failures_within_nine_minutes_is_a_finding():
    minutes = ["2026-10-12 10:00", "2026-10-12 10:02", "2026-10-12 10:04", "2026-10-12 10:07", "2026-10-12 10:09"]
    i = _item(_model(_results(failures=_fails("ns0001", "alice", minutes))), 2)
    assert i["status"] == "auto" and i["verdict"] == "확인 필요"
    assert _col(i, "계정") == ["alice"] and _col(i, "10분 내 최대 실패") == [5]
    assert _col(i, "처음 시각(KST)") == ["2026-10-12 10:00"]


def test_item2_five_failures_spread_over_eleven_minutes_is_not_a_finding():
    minutes = ["2026-10-12 10:00", "2026-10-12 10:03", "2026-10-12 10:06", "2026-10-12 10:09", "2026-10-12 10:11"]
    i = _item(_model(_results(failures=_fails("ns0001", "alice", minutes))), 2)
    assert i["verdict"] == "이상 없음" and i["rows"] == []


def test_item2_four_failures_is_below_the_threshold_and_five_reaches_it():
    four = _item(_model(_results(failures=_fails("ns0001", "alice", ["2026-10-12 10:00"], each=4))), 2)
    five = _item(_model(_results(failures=_fails("ns0001", "alice", ["2026-10-12 10:00"], each=5))), 2)
    assert four["rows"] == [] and five["verdict"] == "확인 필요"


def test_item2_failures_count_per_account_and_host_separately():
    res = _results(failures=_fails("ns0001", "alice", ["2026-10-12 10:00"], each=3)
                   + _fails("ns0002", "alice", ["2026-10-12 10:01"], each=3)
                   + _fails("ns0001", "bob", ["2026-10-12 10:02"], each=3))
    assert _item(_model(res), 2)["rows"] == []


def test_item2_states_the_threshold_from_the_settings_and_fails_on_query_failure():
    i = _item(_model(_results(), _settings(failure_threshold=7, failure_window_minutes=15)), 2)
    assert "15분" in i["criterion"] and "7회" in i["criterion"]
    assert _item(_model(_results(accounts_ssh_failure_minutely=_fail("연결 불가·시간 초과"))), 2)["status"] == "failed"


# ------------------------------------------------------------------ 3번 업무시간 외 접속

def test_item3_a_login_at_19_59_on_a_weekday_is_business_hours_and_20_00_is_not():
    # 시 단위로 받는다: 19:59는 19시 버킷, 20:00은 20시 버킷
    inside = _item(_model(_results(success=[_login("ns0001", "alice", "2026-10-12 19")])), 3)
    outside = _item(_model(_results(success=[_login("ns0001", "alice", "2026-10-12 20")])), 3)
    assert inside["status"] == "auto" and inside["verdict"] == "이상 없음" and inside["rows"] == []
    assert outside["verdict"] == "확인 필요" and _col(outside, "구분") == ["야간"]


def test_item3_the_business_day_starts_at_08_00():
    early = _item(_model(_results(success=[_login("ns0001", "alice", "2026-10-12 07")])), 3)
    start = _item(_model(_results(success=[_login("ns0001", "alice", "2026-10-12 08")])), 3)
    assert _col(early, "구분") == ["야간"] and start["rows"] == []


def test_item3_weekends_and_listed_holidays_are_off_hours_all_day():
    res = _results(success=[_login("ns0001", "alice", "2026-10-03 10"),   # 토요일·개천절
                            _login("ns0001", "bob", "2026-10-04 11"),     # 일요일
                            _login("ns0002", "alice", "2026-10-09 14", 2),  # 한글날(금)
                            _login("ns0002", "bob", "2026-10-13 14")])    # 평일 낮
    i = _item(_model(res), 3)
    assert list(zip(_col(i, "호스트"), _col(i, "계정"), _col(i, "구분"), _col(i, "접속 수"))) == [
        ("ns0001", "alice", "주말", 1), ("ns0001", "bob", "주말", 1), ("ns0002", "alice", "공휴일", 2)]
    assert "2026-10-09 14시" in _col(i, "일시(KST)")[2]


def test_item3_a_year_without_a_holiday_list_says_so_and_judges_only_weekends_and_nights():
    res = _results(success=[_login("ns0001", "alice", "2026-10-09 14")])  # 한글날이지만 목록이 없다
    i = _item(_model(res, _settings(holidays={2025: ["2025-10-09"]})), 3)
    assert i["status"] == "partial" and i["rows"] == []
    assert "공휴일 목록 없음" in i["criterion"]


def test_item3_an_empty_holiday_list_for_the_year_is_a_list_not_a_missing_one():
    i = _item(_model(_results(), _settings(holidays={"2026": []})), 3)
    assert i["status"] == "auto" and "공휴일 목록 없음" not in i["criterion"]


def test_item3_business_hours_must_be_whole_hours_or_the_item_is_a_judge_error_not_a_silent_midnight():
    ok = _item(_model(_results(), _settings(business_hours={"start": "09:00", "end": "18"})), 3)
    assert "평일 09:00~18:00 KST" in ok["criterion"]
    m = _model(_results(), _settings(business_hours={"start": "08:30", "end": 20}))
    assert _item(m, 3)["status"] == "failed" and any(e.startswith("part1.off_hours_login") for e in m["errors"])


def test_item3_the_criterion_states_the_business_hours_and_the_holiday_count():
    i = _item(_model(), 3)
    assert "평일 08:00~20:00 KST" in i["criterion"] and "2026년 공휴일 3일" in i["criterion"]


# ------------------------------------------------------------------ 4번 업무시간 외 sudo·su·계정·권한 변경

def _priv(host, user, action, hour, runs=1, automation=0):
    return {"host": host, "user": user, "action": action, "hour": hour, "runs": runs, "automation": automation}


def _change(host, kind, actor, hour, changes=1):
    return {"host": host, "kind": kind, "actor": actor, "hour": hour, "changes": changes}


def test_item4_sudo_su_and_account_changes_outside_business_hours_are_listed():
    res = _results(privilege=[_priv("ns0001", "alice", "sudo", "2026-10-12 21", 3),
                              _priv("ns0001", "alice", "su", "2026-10-12 19"),          # 업무시간
                              _priv("ns0002", "bob", "su", "2026-10-04 10")],          # 일요일
                   changes=[_change("ns0002", "ADD_USER", "alice", "2026-10-09 15")])   # 한글날
    i = _item(_model(res), 4)
    assert i["status"] == "auto" and i["verdict"] == "확인 필요"
    assert list(zip(_col(i, "호스트"), _col(i, "계정"), _col(i, "종류"), _col(i, "구분"), _col(i, "건수"))) == [
        ("ns0001", "alice", "sudo", "야간", 3), ("ns0002", "alice", "계정 변경 ADD_USER", "공휴일", 1),
        ("ns0002", "bob", "su", "주말", 1)]


def test_item4_ansible_automation_sudo_is_counted_apart_and_alone_is_not_a_finding():
    res = _results(privilege=[_priv("ns0001", "deploy", "sudo", "2026-10-12 23", 40, automation=40)])
    i = _item(_model(res), 4)
    assert i["verdict"] == "이상 없음"
    assert _col(i, "자동화(Ansible)") == [40] and _col(i, "건수") == [40]


def test_item4_business_hours_only_activity_is_no_finding():
    res = _results(privilege=[_priv("ns0001", "alice", "sudo", "2026-10-12 08", 9)],
                   changes=[_change("ns0001", "USER_MGMT", "alice", "2026-10-12 19")])
    i = _item(_model(res), 4)
    assert i["verdict"] == "이상 없음" and i["rows"] == []


def test_account_change_query_filters_by_audit_type_not_body_like():
    """#577: 본문 LIKE로 거르면 한 달 범위가 Caddy 쓰기 제한(30초)을 넘는다. 종류는 audit_type 필드로 거른다."""
    import host_audit_log_review_accounts as accounts
    sql = accounts._ACCOUNT_CHANGE_QUERY["sql"]
    where = sql.split("WHERE", 1)[1].split("GROUP BY", 1)[0]
    assert "audit_type IN (" in where and "'USER_MGMT'" in where and "'ACCT_UNLOCK'" in where
    assert "body LIKE 'type=" not in where


def test_item4_either_query_failing_is_query_failure():
    assert _item(_model(_results(accounts_account_change_hourly=_fail())), 4)["status"] == "failed"
    assert _item(_model(_results(accounts_privilege_hourly=_fail())), 4)["status"] == "failed"


# ------------------------------------------------------------------ 5번 계정별 접속일 목록(사람 대조)

def test_item5_lists_login_days_per_account_for_people_to_check_against_leave_records():
    res = _results(success=[_login("ns0001", "alice", "2026-10-12 10"), _login("ns0002", "alice", "2026-10-12 21"),
                            _login("ns0001", "alice", "2026-10-14 09", 3), _login("ns0002", "bob", "2026-10-13 10")])
    i = _item(_model(res), 5)
    assert i["status"] == "manual" and i["verdict"] == ""
    assert _col(i, "계정") == ["alice", "bob"]
    assert _col(i, "접속일 수") == [2, 1]
    assert _col(i, "접속일") == ["10-12, 10-14", "10-13"]
    assert _col(i, "호스트") == ["ns0001, ns0002", "ns0002"]


def test_item5_query_failure_is_query_failure_and_gaps_are_named():
    assert _item(_model(_results(accounts_ssh_success_hourly=_fail())), 5)["status"] == "failed"
    gap = _ok([{"name": "ns0001", "day": d, "records": 3} for d in OCT])
    assert "수집 공백 호스트 1대(ns0002)" in _item(_model(_results(collection=gap)), 5)["summary"]


# ------------------------------------------------------------------ 허용 계정 입력(태스크가 넘기는 값)

def test_account_hosts_are_built_from_declared_accounts_bootstrap_and_asset_inventory():
    sources = {"ns0001": {"accounts": [{"name": "alice"}, {"name": "gone", "state": "absent"}], "admin_users": ["ops"],
                          "bootstrap": "boot", "agents_only": False},
               "ns0002": {"accounts": [], "admin_users": [], "bootstrap": "", "agents_only": True},
               "ns0003": {"agents_only": True}}
    inventory = [{"host": "ns0002", "collected": True, "accounts": [{"name": "legacy"}, {"name": "root"}]},
                 {"host": "ns0003", "collected": False}]
    out = host_audit_log_review_account_hosts(sources, inventory)
    assert out["ns0001"] == {"declared": ["alice", "ops"], "bootstrap": "boot", "agents_only": False,
                             "inventory_accounts": None}
    assert out["ns0002"]["inventory_accounts"] == ["legacy", "root"]
    assert out["ns0003"]["inventory_accounts"] is None  # 수집하지 못한 호스트는 목록을 알 수 없다


def test_a_host_whose_connection_was_not_resolved_has_no_allowed_list_not_root_only():
    out = host_audit_log_review_account_hosts({"ns0001": {"resolved": False, "accounts": [], "admin_users": [],
                                                          "bootstrap": "", "agents_only": False}})
    assert out["ns0001"]["declared"] is None
    i = _item(_model(_results(success=[_login("ns0001", "alice", "2026-10-12 10")]), _settings(hosts=out)), 1)
    assert _col(i, "계정") == ["alice"] and "허용 계정 목록 없음" in _col(i, "비고")[0]


def test_missing_account_settings_and_results_never_raise():
    meta = {"run_id": "ha-x", "run_kind": "scheduled", "started_at": STARTED, "generated_at": STARTED, "timezone": TZ,
            "period": host_audit_log_review_period(STARTED, TZ), "settings": {}}
    m = host_audit_log_review_model({}, meta)
    assert m["errors"] == []
    assert {_item(m, n)["status"] for n in (1, 2, 3, 4, 5)} == {"failed"}


# ------------------------------------------------------------------ 통합(소수): 실제 AUD-804가 호스트 변수에서 허용 계정을 만든다

class _O2(object):
    """security_logs SSH 로그인 성공 조회에만 가짜 행을 돌려주는 OpenObserve."""

    def __init__(self):
        rows = [{"host": "ns0001", "user": u, "hour": "2026-10-12 10", "logins": 1} for u in ("alice", "boot", "intruder")]
        rows += [{"host": "ns0002", "user": u, "hour": "2026-10-12 10", "logins": 1} for u in ("legacy", "alice")]
        rows += [{"host": "ns0003", "user": "alice", "hour": "2026-10-12 10", "logins": 1}]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                sql = body["query"]["sql"]
                hits = rows if ("event_outcome = 'success'" in sql and "ssh_login" in sql) else []
                payload = json.dumps({"hits": hits}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]


@pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")
def test_the_report_task_builds_the_allowed_accounts_from_resolved_host_variables(tmp_path):
    o2 = _O2()
    try:
        inventory = {"all": {"children": {
            "host_audit_targets": {"hosts": {
                "ns0001": {"accounts": [{"name": "alice", "keys": ["ssh-ed25519 AAAA fake"]}, {"name": "gone", "state": "absent"}],
                           "_normalized_admin_users": ["alice"], "_boot_summary": {"username": "boot", "address": "192.0.2.1"}},
                "ns0002": {},
                "ns0003": {}}},  # 접속 해석을 거치지 못한 호스트(선언 계정 변수가 없다)
            "agents_only": {"hosts": {"ns0002": {}}}}}}
        (tmp_path / "inv.yml").write_text(yaml.safe_dump(inventory))
        model = {"asset_inventory": {"hosts": [{"host": "ns0002", "collected": True, "accounts": [{"name": "legacy"}]}]}}
        play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
                "tasks": [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "log_review"}},
                          {"ansible.builtin.debug": {"msg": "{{ host_audit_log_review_model.part1[0] }}"}}]}
        (tmp_path / "pb.yml").write_text(yaml.safe_dump([play], allow_unicode=True))
        ev = {"openbao_fixture": {"inventory/services/openobserve": {"url": o2.url, "org": "acme"},
                                  "secrets/services/openobserve/readonly": {"username": "reader", "password": "pw"}},
              "host_audit_run": {"run_id": "ha-x", "run_kind": "scheduled", "started_at": STARTED,
                                 "output_dir": str(tmp_path / "run"), "timezone": TZ, "target_hosts": ""},
              "host_audit_model": model, "host_audit_log_review_collect_hosts": ["ns0001", "ns0002"],
              "host_audit_log_review_devices": [], "host_audit_storage_enabled": False, "_host_audit_records": []}
        (tmp_path / "vars.json").write_text(json.dumps(ev))
        (tmp_path / "run").mkdir()
        env = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json",
                   ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"), ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"))
        res = subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "pb.yml"),
                              "-e", "@%s" % (tmp_path / "vars.json")], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
        assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
        tasks = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
        item = tasks[-1]["hosts"]["localhost"]["msg"]
    finally:
        o2.server.shutdown()
        o2.server.server_close()
    # ns0001: 선언 계정 alice·bootstrap boot은 허용, intruder만 발견. ns0002(에이전트만): Asset Inventory 계정 legacy만 허용
    # ns0003: 해석되지 않은 호스트는 root만 허용이 아니라 '허용 계정 목록 없음'
    assert [(r[0], r[1]) for r in item["rows"]] == [("ns0001", "intruder"), ("ns0002", "alice"), ("ns0003", "alice")]
    assert "허용 계정 목록 없음" in item["rows"][2][-1] and "허용 계정 목록 없음" not in item["rows"][0][-1]
    assert item["verdict"] == "확인 필요"


# ------------------------------------------------------------------ role 기본값의 공휴일 목록(#574)

def _default_holidays():
    import yaml
    path = ROOT_DIR / "roles" / "host_audit" / "defaults" / "main.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["host_audit_log_review_holidays"]


def test_default_holidays_are_well_formed_per_year():
    holidays = _default_holidays()
    assert {"2026", "2027"} <= set(holidays)
    for year, days in holidays.items():
        assert days == sorted(set(days)), year
        assert all(d.startswith(year + "-") and len(d) == 10 for d in days), year


def test_default_2026_holidays_include_labour_day_and_constitution_day():
    """2026년부터 노동절(5/1)·제헌절(7/17)이 공휴일이다(공휴일에 관한 법률 개정, 인사혁신처 2026-04-28 보도자료)."""
    days = _default_holidays()["2026"]
    assert "2026-05-01" in days and "2026-07-17" in days


def test_default_2027_holidays_match_the_2027_calendar():
    """2027 월력요항(우주항공청, 2026-06-29 공표) 관공서 공휴일 24일: 대체공휴일 7일 포함."""
    assert _default_holidays()["2027"] == [
        "2027-01-01", "2027-02-06", "2027-02-07", "2027-02-08", "2027-02-09", "2027-03-01", "2027-05-01", "2027-05-03",
        "2027-05-05", "2027-05-13", "2027-06-06", "2027-07-17", "2027-07-19", "2027-08-15", "2027-08-16", "2027-09-14",
        "2027-09-15", "2027-09-16", "2027-10-03", "2027-10-04", "2027-10-09", "2027-10-11", "2027-12-25", "2027-12-27"]
