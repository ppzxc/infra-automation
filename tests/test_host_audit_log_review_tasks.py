"""Log Review Report 조회·작성 태스크 (Spec #544 / Ticket-3 #558, ADR-0015).

OpenObserve 오픈소스 빌드는 서버가 조회 전용을 강제하지 못한다(#556). 그래서 이 역할이 OpenObserve에 `POST /api/<org>/_search`
외의 호출을 하지 않는다는 것을 여기서 지킨다: 정적 검사(태스크 정의)와, 실제 log_review.yml을 가짜 OpenObserve(127.0.0.1)에 돌려
받은 요청 전부를 기록하는 통합 테스트(소수, ADR-0013). 비밀·실주소는 없다(openbao_fixture 우회).
"""
import base64
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
TASKS = ROLE_DIR / "tasks"

RUN_ID = "ha-20261031T220000Z"
STARTED = "2026-10-31T22:00:05Z"
OCT = ["2026-10-%02d" % d for d in range(1, 32)]
FILE = "host-audit-%s-log-review.html" % RUN_ID

needs_ansible = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")


def _flat(tasks):
    for task in tasks or []:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _flat(task.get(key))


def _all_tasks():
    for path in sorted(TASKS.glob("*.yml")):
        for task in _flat(yaml.safe_load(path.read_text(encoding="utf-8"))):
            if "block" not in task:  # 블록 자체가 아니라 그 안의 태스크를 하나씩 본다
                yield path.name, task


# ------------------------------------------------------------------ 정적 검사: OpenObserve에는 POST _search뿐

def test_the_only_task_that_talks_to_openobserve_is_a_post_to_search():
    o2_calls = []
    for file, task in _all_tasks():
        text = json.dumps(task, ensure_ascii=False)
        http = {k: v for k, v in task.items() if k in ("ansible.builtin.uri", "uri", "ansible.builtin.get_url", "get_url")}
        if "_host_audit_log_review_o2" in text and http:
            o2_calls.append((file, task["name"], http))
    assert len(o2_calls) == 1, o2_calls
    file, name, http = o2_calls[0]
    uri = http["ansible.builtin.uri"]
    assert file == "log_review.yml" and name.startswith("[AUD-803]")
    assert uri["method"] == "POST"
    assert uri["url"].endswith("/_search") and uri["url"].count("/api/") == 1


def test_the_search_account_is_used_only_by_the_search_task_and_never_by_a_shell():
    users = []
    for file, task in _all_tasks():
        text = json.dumps(task, ensure_ascii=False)
        if "_host_audit_log_review_o2.username" in text or "_host_audit_log_review_o2.password" in text:
            users.append(task["name"])
        for mod in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
            assert "_host_audit_log_review_o2" not in json.dumps(task.get(mod, ""), ensure_ascii=False), task["name"]
    assert len(users) == 1 and users[0].startswith("[AUD-803]")


def test_the_role_never_reads_the_openobserve_admin_or_ingest_accounts_and_its_modules_do_not_call_openobserve():
    text = "".join(p.read_text(encoding="utf-8") for p in sorted(ROLE_DIR.rglob("*")) if p.is_file() and p.suffix in (".yml", ".py", ".j2"))
    assert "openobserve/admin" not in text and "openobserve/ingest" not in text
    for p in sorted((ROLE_DIR / "library").glob("*.py")):
        body = p.read_text(encoding="utf-8").lower()
        assert "openobserve" not in body and "_search" not in body, p.name


def test_the_search_task_hides_its_results_and_takes_failures_as_values():
    task = next(t for _, t in _all_tasks() if t.get("name", "").startswith("[AUD-803]"))
    assert task["no_log"] is True and task["changed_when"] is False
    assert -1 in task["ansible.builtin.uri"]["status_code"] and 401 in task["ansible.builtin.uri"]["status_code"]


def test_the_switches_checked_for_collection_gaps_are_the_ones_the_silent_switch_alert_watches():
    """cisco_switches 전체가 아니라 syslog 전송이 확인된 스위치만 본다. OpenObserve Config의 목록과 어긋나면 매달 허위 공백이 나온다."""
    ours = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    o2c = yaml.safe_load((ROOT_DIR / "roles" / "openobserve_config" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert ours["host_audit_log_review_switch_syslog_devices"] == o2c["o2c_switch_syslog_roster"]


def test_the_draft_is_included_before_the_hashes_summary_upload_and_mail():
    block = next(t for t in yaml.safe_load((TASKS / "report.yml").read_text(encoding="utf-8")) if "always" in t)["block"]
    names = [json.dumps(t, ensure_ascii=False) if "include_tasks" in json.dumps(t) else t.get("name", "") for t in block]

    def at(needle):
        return next(i for i, n in enumerate(names) if needle in n)

    assert at("log_review.yml") < at("[AUD-806]") < at("[AUD-612]") < at("storage_upload.yml") < at("mail.yml") < at("[AUD-807]")


# ------------------------------------------------------------------ 통합: 실제 log_review.yml을 가짜 OpenObserve에

class _O2:
    def __init__(self, status=200):
        self.requests, self.status = [], status
        o2 = self

        class Handler(BaseHTTPRequestHandler):
            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                o2.requests.append((self.command, self.path, self.headers.get("Authorization", ""), body))
                hits = [{"name": "h1", "day": d, "records": 2} for d in OCT] if "system_logs" in json.dumps(body) else []
                payload = json.dumps({"hits": hits, "total": len(hits)}).encode() if o2.status == 200 else b'{"error":"x"}'
                self.send_response(o2.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _any

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]


@pytest.fixture
def o2():
    servers = []

    def make(status=200):
        s = _O2(status)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.server.shutdown()
        s.server.server_close()


def _run(tmp_path, o2_url, run_kind="scheduled", docs=True, extra=None):
    out = tmp_path / "run"
    out.mkdir(parents=True, exist_ok=True)
    fixture = {}
    if docs:
        fixture = {"inventory/services/openobserve": {"url": o2_url + "/", "org": "acme"},
                   "secrets/services/openobserve/readonly": {"username": "reader", "password": "pw-7f3a9c"}}
    show = {"ansible.builtin.debug": {"msg": {"made": "{{ _host_audit_log_review_made }}",
                                               "problem": "{{ _host_audit_log_review_problem }}"}}}
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
            "tasks": [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "log_review"}}, show]}
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([play], allow_unicode=True))
    ev = dict({"openbao_fixture": fixture,
               "host_audit_run": {"run_id": RUN_ID, "run_kind": run_kind, "started_at": STARTED, "output_dir": str(out),
                                  "timezone": "Asia/Seoul", "target_hosts": ""},
               "host_audit_log_review_collect_hosts": ["h1", "h2"], "host_audit_log_review_devices": [],
               "host_audit_storage_enabled": False}, **(extra or {}))
    evf = tmp_path / "vars.json"
    evf.write_text(json.dumps(ev))
    env = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json",
               ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"), ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb), "-e", "@%s" % evf], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    tasks = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    return out, tasks[-1]["hosts"]["localhost"]["msg"], res


@needs_ansible
def test_a_scheduled_run_posts_only_to_search_and_writes_the_report_with_the_collection_gap(tmp_path, o2):
    server = o2()
    out, state, res = _run(tmp_path, server.url)
    assert state["made"] in (True, "True") and state["problem"] == ""
    # 받은 요청 전부가 POST /api/<org>/_search다(쓰기 경로 없음). 기본 인증, 기간은 2026-10 KST.
    assert server.requests and {(m, p) for m, p, _, _ in server.requests} == {("POST", "/api/acme/_search")}
    assert all(a == "Basic " + base64.b64encode(b"reader:pw-7f3a9c").decode() for _, _, a, _ in server.requests)
    assert {b["query"]["start_time"] for *_, b in server.requests} == {1790780400 * 1000000}
    html = (out / "log_review" / FILE).read_text(encoding="utf-8")
    assert "2026-10-01 00:00 ~ 2026-10-31 24:00 (KST)" in html
    assert "h2" in html and "전월 로그 없음" in html
    # 기준 목록 문서(inventory/config/log_review)가 없으면 조회는 그대로 하고 1부 6·7·12번만 기준 목록 실패다(#560).
    assert html.count("조회 실패(기준 목록)") == 3
    assert oct((out / "log_review" / FILE).stat().st_mode & 0o777) == "0o600"
    # 계정·비밀번호는 출력에 나오지 않는다
    assert "pw-7f3a9c" not in res.stdout + res.stderr


@needs_ansible
def test_a_rejected_search_is_a_query_failure_in_the_report_not_a_failed_run(tmp_path, o2):
    server = o2(status=401)
    out, state, _ = _run(tmp_path, server.url)
    html = (out / "log_review" / FILE).read_text(encoding="utf-8")
    assert "조회 실패(호스트 로그 HTTP 401(인증·권한))" in html
    assert state["problem"] == ""  # 조회 실패는 실행 실패가 아니다(메일은 나간다)


@needs_ansible
def test_an_unreadable_account_calls_nothing_and_every_query_is_a_failure(tmp_path, o2):
    server = o2()
    out, state, _ = _run(tmp_path, server.url, docs=False)
    assert server.requests == []
    html = (out / "log_review" / FILE).read_text(encoding="utf-8")
    assert "조회 실패(호스트 로그 OpenBao 문서를 읽지 못함" in html


@needs_ansible
def test_an_on_demand_run_drafts_nothing_unless_the_flag_is_on_and_a_leftover_draft_is_removed(tmp_path, o2):
    server = o2()
    stale = tmp_path / "run" / "log_review" / FILE
    stale.parent.mkdir(parents=True)
    stale.write_text("old attempt")
    out, state, _ = _run(tmp_path, server.url, run_kind="on_demand")
    assert state["made"] in (False, "False") and server.requests == [] and not (out / "log_review").exists()
    out, state, _ = _run(tmp_path / "flag", server.url, run_kind="on_demand", extra={"host_audit_log_review_enabled": True})
    assert (out / "log_review" / FILE).is_file() and server.requests
