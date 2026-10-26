"""Host Audit 월간 악화 알림 (Spec #322 / Ticket-9, #331).

지난 정기 점검(Audit Baseline)에서 KISA 취약이 아니던 항목이 이번 점검에서 취약이면 알린다. 비교는 실패 개수가 아니라 항목 단위이고,
지난 결과가 없는 호스트는 알리지 않는다. 알림은 사내 알림 webhook(text/plain)으로 가며 악화된 항목 목록이 본문에 들어간다.
관찰 가능한 동작만 본다: 보고서 모델이 내놓는 악화 목록, 통지 본문, 그리고 webhook으로 실제 나가는 요청.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_baseline import host_audit_kisa_alert, host_audit_kisa_worsened  # noqa: E402

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
RUN = {"run_id": "ha-20261101T000000Z", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z"}
CODE = "KISA-2026:U-%02d"


def _row(n, verdict="취약"):
    return {"code": CODE % n, "title": "항목 %d" % n, "verdict": verdict}


def _model(**hosts):
    """A report model with only the KISA appendix the baseline reads: host -> rows."""
    return {"cover": {"baseline": ""}, "config_vulnerability": {"appendix": hosts, "findings": []}}


def _baseline(**hosts):
    """The stored findings document of the previous scheduled run: host -> finding ids (hosts = every host inspected)."""
    return {"run_id": "ha-20261001T000000Z", "run_kind": "scheduled", "started_at": "2026-10-01T00:00:00Z",
            "sections": {"config_vulnerability": {"hosts": sorted(hosts), "ids": {h: [CODE % n for n in ids] for h, ids in hosts.items()}}}}


def _worsened(model, baseline):
    return [(w["host"], w["id"]) for w in host_audit_kisa_worsened(model, baseline)]


# --- 항목 단위 비교 -------------------------------------------------------------------------------------------

def test_a_different_item_failing_is_worse_even_when_the_failure_count_is_the_same():
    """Last month U-01 failed, this month U-02 fails: one failure each, but U-02 passed before."""
    assert _worsened(_model(ns1=[_row(1, "양호"), _row(2)]), _baseline(ns1=[1])) == [("ns1", CODE % 2)]


def test_an_item_that_failed_last_month_too_is_not_worse():
    assert _worsened(_model(ns1=[_row(1), _row(2, "양호")]), _baseline(ns1=[1])) == []


def test_only_failures_count_not_manual_exception_not_applicable_or_good_items():
    rows = [_row(1, "점검불가(수동)"), _row(2, "예외(승인)"), _row(3, "해당없음"), _row(4, "양호")]
    assert _worsened(_model(ns1=rows), _baseline(ns1=[])) == []


def test_every_newly_failing_item_of_every_host_is_listed_sorted_by_host_then_item():
    model = _model(ns2=[_row(7)], ns1=[_row(5), _row(3), _row(9)])
    assert _worsened(model, _baseline(ns1=[5], ns2=[])) == [("ns1", CODE % 3), ("ns1", CODE % 9), ("ns2", CODE % 7)]


def test_a_host_without_last_months_result_is_not_alerted():
    """ns9 is new to Host Audit: its failures have no 'passed last month' to compare with."""
    assert _worsened(_model(ns1=[_row(1)], ns9=[_row(2), _row(3)]), _baseline(ns1=[])) == [("ns1", CODE % 1)]


def test_without_a_baseline_nothing_is_alerted():
    assert _worsened(_model(ns1=[_row(1)]), None) == []


def test_a_baseline_without_the_kisa_section_alerts_nothing():
    assert _worsened(_model(ns1=[_row(1)]), {"run_id": "ha-x", "sections": {}}) == []


def test_the_worsened_items_carry_the_label_the_report_shows():
    (item,) = host_audit_kisa_worsened(_model(ns1=[_row(2)]), _baseline(ns1=[]))
    assert item == {"host": "ns1", "id": CODE % 2, "label": "%s 항목 2" % (CODE % 2)}


# --- 통지 계획과 본문 -----------------------------------------------------------------------------------------

def _compared(**hosts):
    """(model, history) of a run whose hosts all failed these items and whose baseline (inspected the same hosts) had no failure."""
    model = _model(**{h: [_row(n) for n in ns] for h, ns in hosts.items()})
    return model, {"state": "ok", "baseline": _baseline(**{h: [] for h in hosts}), "pointers": []}


def _plan(compared, run=RUN):
    return host_audit_kisa_alert(compared[0], run, compared[1])


def test_a_scheduled_run_with_worsened_items_sends_one_notification_listing_every_item():
    plan = _plan(_compared(ns1=[1, 2], ns2=[3]))
    assert plan["send"] is True and plan["count"] == 3 and plan["hosts"] == 2
    for host, n in (("ns1", 1), ("ns1", 2), ("ns2", 3)):
        assert "• %s: %s 항목 %d" % (host, CODE % n, n) in plan["text"]
    assert "Host Audit" in plan["text"] and "지난달" in plan["text"] and RUN["run_id"] in plan["text"]
    assert "ha-20261001T000000Z" in plan["text"]                 # 비교 기준 실행


def test_nothing_is_sent_for_an_on_demand_run_or_when_nothing_got_worse():
    assert _plan(_compared(ns1=[1]), dict(RUN, run_kind="on_demand"))["send"] is False
    plan = host_audit_kisa_alert(_model(ns1=[_row(1, "양호")]), RUN, {"state": "ok", "baseline": _baseline(ns1=[])})
    assert plan["send"] is False and plan["count"] == 0 and plan["text"] == ""
    model = _model(ns1=[_row(1)])
    for history in ({"state": "ok", "baseline": None}, {"state": "failed", "baseline": _baseline(ns1=[])},
                    {"state": "disabled"}, None):    # 첫 정기 실행, 기준선 조회 실패, 보관 꺼짐
        assert host_audit_kisa_alert(model, RUN, history)["send"] is False, history


def test_a_long_list_is_cut_to_fit_the_platform_limit_and_says_how_many_were_left_out():
    hosts = {"ns%03d" % i: list(range(1, 68)) for i in range(1, 8)}          # 7 hosts x 67 items
    plan = _plan(_compared(**hosts))
    assert plan["count"] == 7 * 67 and len(plan["text"]) <= 5000
    assert "외 " in plan["text"] and "건" in plan["text"]
    assert plan["text"].count("• ") < plan["count"]


def test_the_notification_text_carries_no_address_or_secret():
    text = _plan(_compared(ns1=[1]))["text"]
    assert "http" not in text and "@" not in text


# --- 태스크: webhook으로 실제로 나가는 요청 ---------------------------------------------------------------------

class _Hook(BaseHTTPRequestHandler):
    seen = []
    reply = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
        type(self).seen.append((self.path, self.headers.get("Content-Type"), self.headers.get("X-Test-Auth"), body))
        self.send_response(type(self).reply)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def hook():
    handler = type("H", (_Hook,), {"seen": [], "reply": 200})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, handler
    server.shutdown()


def _kisa_tasks():
    """AUD-640·621 (decide and send, right after the mail) and AUD-642 (judge, after every other judgement of the run)."""
    tasks = []
    for name in ("kisa_alert.yml", "kisa_alert_result.yml"):
        tasks += yaml.safe_load((ROLE_DIR / "tasks" / name).read_text(encoding="utf-8"))
    return {t["name"][:9]: t for t in tasks}


def _run_alert_tasks(tmp_path, server, *, compared, run=RUN, target=None, check=False, enabled=True, drop_target=False):
    tasks = _kisa_tasks()
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    vars_ = {"host_audit_alert_validate_certs": defaults["host_audit_alert_validate_certs"],
             "host_audit_model": compared[0], "host_audit_baseline_history": compared[1], "host_audit_run": run, "host_audit_kisa_alert_enabled": enabled,
             "_host_audit_alert_target": {} if drop_target else (target or {
                 "url": "http://127.0.0.1:%d/hook" % server.server_port, "header": "X-Test-Auth", "token": "tok-123"})}
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
                                   "vars": vars_, "tasks": [dict(tasks["[AUD-640]"]), dict(tasks["[AUD-641]"]), dict(tasks["[AUD-642]"])]}],
                                 allow_unicode=True))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check"] if check else [])
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300,
                          env=dict(os.environ, ANSIBLE_NOCOLOR="1"))


def test_the_notification_is_posted_as_plain_text_with_the_auth_header_and_the_item_list(tmp_path, hook):
    server, handler = hook
    res = _run_alert_tasks(tmp_path, server, compared=_compared(ns1=[2], ns2=[3]))
    assert res.returncode == 0, res.stdout + res.stderr
    ((path, ctype, auth, body),) = handler.seen
    assert path == "/hook" and ctype.startswith("text/plain") and auth == "tok-123"
    assert "• ns1: %s 항목 2" % (CODE % 2) in body and "• ns2: %s 항목 3" % (CODE % 3) in body
    assert "tok-123" not in res.stdout + res.stderr and "127.0.0.1:%d" % server.server_port not in res.stdout + res.stderr


def test_nothing_is_posted_when_nothing_got_worse_or_the_run_is_on_demand_or_it_is_a_check_run_or_disabled(tmp_path, hook):
    server, handler = hook
    clean = (_model(ns1=[_row(1, "양호")]), {"state": "ok", "baseline": _baseline(ns1=[]), "pointers": []})
    cases = {"clean": dict(compared=clean), "on_demand": dict(compared=_compared(ns1=[1]), run=dict(RUN, run_kind="on_demand")),
             "check": dict(compared=_compared(ns1=[1]), check=True), "disabled": dict(compared=_compared(ns1=[1]), enabled=False)}
    for name, kwargs in cases.items():
        (tmp_path / name).mkdir()
        res = _run_alert_tasks(tmp_path / name, server, **kwargs)
        assert res.returncode == 0, (name, res.stdout + res.stderr)
    assert handler.seen == []


def test_the_run_fails_loudly_when_the_notification_cannot_be_delivered(tmp_path, hook):
    server, handler = hook
    handler.reply = 500
    (tmp_path / "rejected").mkdir()
    rejected = _run_alert_tasks(tmp_path / "rejected", server, compared=_compared(ns1=[1]))
    assert rejected.returncode != 0 and "알림" in rejected.stdout + rejected.stderr
    (tmp_path / "missing").mkdir()
    missing = _run_alert_tasks(tmp_path / "missing", server, compared=_compared(ns1=[1]), drop_target=True)
    assert missing.returncode != 0 and "webhook" in missing.stdout + missing.stderr
    assert "tok-123" not in rejected.stdout + rejected.stderr + missing.stdout + missing.stderr


# --- 입력과 배선 ------------------------------------------------------------------------------------------------

def _flat(items):
    for t in items:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _flat(t.get(key) or [])


def test_the_webhook_comes_from_the_alert_kv_and_stays_out_of_logs():
    tasks = list(_flat(yaml.safe_load((ROLE_DIR / "tasks" / "storage_credentials.yml").read_text(encoding="utf-8"))))
    fetch = next(t for t in tasks if t["name"].startswith("[AUD-501]"))
    assert "agents/openobserve" in fetch["loop"]
    resolve = next(t for t in tasks if t["name"].startswith("[AUD-502]"))
    facts = resolve["ansible.builtin.set_fact"]
    assert "_host_audit_alert_target" in facts and resolve["no_log"] is True
    text = (ROLE_DIR / "tasks" / "storage_credentials.yml").read_text(encoding="utf-8")
    for key in ("alert_webhook_plain_url", "alert_webhook_auth_header", "alert_webhook_token"):
        assert key in text, key


def test_the_alert_is_sent_after_the_mail_and_judged_after_every_other_judgement_of_the_run():
    report = list(_flat(yaml.safe_load((ROLE_DIR / "tasks" / "report.yml").read_text(encoding="utf-8"))))
    includes = [t.get("ansible.builtin.include_tasks") for t in report]
    mail, send = includes.index("mail.yml"), includes.index("kisa_alert.yml")
    storage, mail_judge, alert_judge = (includes.index(n) for n in ("storage_result.yml", "mail_result.yml", "kisa_alert_result.yml"))
    assert mail < send < storage < mail_judge < alert_judge        # a failed notification must not hide the archive or mail verdicts


def test_every_alert_task_that_touches_the_webhook_hides_its_values():
    for task in _kisa_tasks().values():
        if "ansible.builtin.uri" in task or task["name"].startswith("[AUD-640]"):
            assert task.get("no_log") is True, task["name"]


# --- 운영 경로: 실제 로더를 거친 기준선, 알림 webhook을 못 읽어도 보관은 막히지 않음 ---------------------------------------

def test_a_baseline_that_went_through_the_real_loader_still_gives_the_same_worsened_items(tmp_path):
    """AUD-505·508 split the Package ids into files; the KISA section must reach the comparison unchanged."""
    import importlib.util

    import ansible.module_utils
    ansible.module_utils.__path__.append(str(ROLE_DIR / "module_utils"))
    spec = importlib.util.spec_from_file_location("host_audit_baseline_load", ROLE_DIR / "library" / "host_audit_baseline_load.py")
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    stored = _baseline(ns1=[1])
    stored["sections"]["package_vulnerability"] = {"hosts": ["ns1"], "ids": {"ns1": ["CVE-1|openssl"]}}
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(stored))
    document, _hosts, _ids = loader.load(str(src), str(tmp_path / "previous"))
    model = _model(ns1=[_row(1), _row(2)])
    assert _worsened(model, document) == _worsened(model, stored) == [("ns1", CODE % 2)]
    assert host_audit_kisa_alert(model, RUN, {"state": "ok", "baseline": document})["send"] is True


def _resolve_storage_target(tmp_path, statuses):
    """Run AUD-502 alone on KV lookup results with the given status per path (host_audit, rustfs, openobserve)."""
    tasks = list(_flat(yaml.safe_load((ROLE_DIR / "tasks" / "storage_credentials.yml").read_text(encoding="utf-8"))))
    resolve = next(t for t in tasks if t["name"].startswith("[AUD-502]"))
    data = {"agents/host_audit": {"storage_access_key": "ak", "storage_secret_key": "sk"},
            "agents/rustfs": {"rustfs_endpoint": "https://rustfs.example:9000"},
            "agents/openobserve": {"alert_webhook_plain_url": "https://hooks.example/x", "alert_webhook_token": "tok"}}
    results = [{"item": path, "status": statuses[path], "json": {"data": {"data": data[path] if statuses[path] == 200 else {}}}}
               for path in data]
    vars_ = {"_host_audit_storage_active": True, "host_audit_storage": {}, "host_audit_storage_bucket": "host-audit",
             "host_audit_alert_webhook": {}, "_host_audit_storage_kv": {"results": results}}
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out.json"
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "vars": vars_,
                                   "tasks": [dict(resolve), {"ansible.builtin.copy": {"dest": str(out), "content":
                                            "{{ {'problem': _host_audit_storage_problem, 'alert': _host_audit_alert_target} | to_json }}"}}]}]))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                         cwd=ROOT_DIR, timeout=300, env=dict(os.environ, ANSIBLE_NOCOLOR="1"))
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(out.read_text())


def test_not_being_allowed_to_read_the_alert_webhook_does_not_stop_the_archive_and_baseline(tmp_path):
    """A 403 on agents/openobserve must cost only the notification, never the monthly archive and report mail."""
    ok = _resolve_storage_target(tmp_path / "ok", {"agents/host_audit": 200, "agents/rustfs": 200, "agents/openobserve": 200})
    assert ok["problem"] == "" and ok["alert"]["url"] == "https://hooks.example/x" and ok["alert"]["token"] == "tok"
    denied = _resolve_storage_target(tmp_path / "denied", {"agents/host_audit": 200, "agents/rustfs": 200, "agents/openobserve": 403})
    assert denied["problem"] == "" and denied["alert"]["url"] == ""
    # a failure on the storage paths is still a storage problem
    broken = _resolve_storage_target(tmp_path / "broken", {"agents/host_audit": 403, "agents/rustfs": 200, "agents/openobserve": 200})
    assert "OpenBao 조회 실패" in broken["problem"]
