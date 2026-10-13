"""OpenObserve configuration as code (ADR-0008, Spec #93 / Ticket-2, seam 3).

``playbooks/openobserve_config.yml`` runs against a stateful fake OpenObserve HTTP server and the requests it receives
are asserted: first run creates everything, the second run changes nothing, a changed definition produces an update,
check mode writes nothing, and secrets never reach the output or the repository.
"""

import base64
import json
import os
import re
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "openobserve_config"
PLAYBOOK = ROOT_DIR / "playbooks" / "openobserve_config.yml"

WEBHOOK_URL = "https://hooks.example.internal/o2/SECRET-PATH-123"
KV = {"api_user": "cfg@example.com", "api_password": "API-PASSWORD-xyz", "alert_webhook_url": WEBHOOK_URL,
      "alert_webhook_token": "WEBHOOK-TOKEN-abc", "controller_ingest_token": "INGEST-TOKEN-qrs"}
EXPECTED_ALERTS = {
    "infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host", "infra-root-login-success",
    "infra-root-login-office-daily", "infra-sudo-escalation-failure", "infra-kernel-disk-errors",
    "infra-log-parse-errors-security-logs", "infra-log-parse-errors-system-logs",
}
SELFTEST = "infra-alert-selftest"   # 통지 경로 자가 시험 알림(Spec #184 / Ticket-2) — 검증 전용 스트림에 건다
SELFTEST_STREAM = "alert_selftest_alert_verify"


class FakeO2:
    """Minimal stateful stand-in for the OpenObserve config API (shapes taken from the v1.0.4 sources)."""

    def __init__(self):
        self.store = {k: {} for k in ("template", "destination", "function", "pipeline", "alert")}
        self.writes = []
        self.reads = []
        self.auth = set()
        self.ingests = []        # (path, auth header, records) of the verification step
        self.searches = []       # (stream, sql) of the verification step
        self.history = []        # alert evaluation history entries returned by GET alerts/history
        self.search_override = None   # fn(stream, sql, hits) -> hits, to simulate an engine that disagrees
        self.fixtures = yaml.safe_load((ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8"))
        outer = self

        class H(BaseHTTPRequestHandler):
            def _route(self):
                path = self.path.split("?")[0]
                m = re.fullmatch(r"/api/(?:v2/)?default/(alerts/templates|alerts/destinations|functions|pipelines|alerts)(?:/([^/]+))?", path)
                kind = {"alerts/templates": "template", "alerts/destinations": "destination", "functions": "function",
                        "pipelines": "pipeline", "alerts": "alert"}[m.group(1)] if m else None
                return kind, (m.group(2) if m else None)

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _fire(self, sql, stream):
                """What a correct engine returns: the hosts of the firing, non-known-failure cases of the alert owning this SQL."""
                run_hosts = {r["host_name"] for _, _, recs in outer.ingests for r in recs}
                for alert in outer.store["alert"].values():
                    prod = alert["stream_name"]
                    if stream != prod + "_alert_verify" or alert["query_condition"]["sql"].replace(f'"{prod}"', f'"{stream}"') != sql:
                        continue
                    cases = outer.fixtures[alert["name"]]["cases"]
                    return [{"host_name": h} for h in sorted(run_hosts)
                            for c in cases if h.startswith(c["host"] + "-") and c["fires"] and not c.get("known_failure")]
                return []

            def do_GET(self):  # noqa: N802
                outer.auth.add(self.headers.get("Authorization"))
                if self.path.split("?")[0] == "/api/v2/default/alerts/history":
                    return self._send(200, {"total": len(outer.history), "hits": outer.history})
                kind, key = self._route()
                outer.reads.append(self.path)
                if kind is None:
                    return self._send(404, {})
                items = outer.store[kind]
                if key is None:
                    lst = list(items.values())
                    if kind == "alert":   # the v2 list view carries no query/trigger settings
                        lst = [{"alert_id": v["alert_id"], "name": v["name"], "enabled": v["enabled"]} for v in lst]
                    return self._send(200, {"list": lst})
                return self._send(200, next(v for v in items.values() if v.get("alert_id") == key))

            def _write(self, method):
                outer.auth.add(self.headers.get("Authorization"))
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                path = self.path.split("?")[0]
                m = re.fullmatch(r"/api/default/([^/]+)/_json", path)
                if m and method == "POST":
                    outer.ingests.append((self.path, self.headers.get("Authorization"), body))
                    return self._send(200, {"code": 200})
                if path == "/api/default/_search" and method == "POST":
                    sql = body["query"]["sql"]
                    stream = re.search(r'FROM "([^"]+)"', sql).group(1)
                    hits = self._fire(sql, stream)
                    if outer.search_override:
                        hits = outer.search_override(stream, sql, hits)
                    outer.searches.append((stream, sql))
                    return self._send(200, {"hits": hits, "total": len(hits)})
                kind, key = self._route()
                outer.writes.append((method, self.path, body))
                if kind is None:
                    return self._send(404, {})
                items = outer.store[kind]
                if method == "POST":
                    rec = dict(body)
                    if kind == "alert":
                        rec["alert_id"] = uuid.uuid4().hex
                    if kind == "pipeline":
                        rec["pipeline_id"] = uuid.uuid4().hex
                    items[body["name"]] = rec
                else:
                    name = next(n for n, v in items.items() if key in (n, v.get("alert_id"), v.get("pipeline_id")))
                    items[name] = dict(items[name], **body)
                self._send(200, {"code": 200})

            def do_POST(self):  # noqa: N802
                self._write("POST")

            def do_PUT(self):  # noqa: N802
                self._write("PUT")

            def do_DELETE(self):  # noqa: N802
                outer.auth.add(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                kind, key = self._route()
                outer.writes.append(("DELETE", self.path, None))
                name = next((n for n, v in outer.store[kind].items() if v.get("alert_id") == key), None)
                if name is None:
                    return self._send(404, {})
                del outer.store[kind][name]
                self._send(200, {"code": 200})

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown()


@pytest.fixture()
def o2():
    srv = FakeO2()
    yield srv
    srv.close()


def _apply(o2, *args, kv=None, extra=None):
    extra = {"o2c_verify_retries": 1, "o2c_verify_delay": 0, **(extra or {})}
    env = dict(os.environ, ANSIBLE_NOCOLOR="1")
    cmd = ["ansible-playbook", "-i", "localhost,", str(PLAYBOOK), "-e", f"o2_endpoint={o2.url}",
           "-e", json.dumps({"o2c_kv_fixture": kv or KV, **extra}), *args]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    return res


def _changed(res):
    return int(re.search(r"changed=(\d+)", res.stdout).group(1))


def test_first_run_creates_template_destination_function_pipeline_and_every_alert_in_dependency_order(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert all(m == "POST" for m, _, _ in o2.writes)
    paths = [p for _, p, _ in o2.writes]
    assert paths[:4] == ["/api/default/alerts/templates", "/api/default/alerts/destinations", "/api/default/functions",
                         "/api/default/pipelines"]
    assert set(o2.store["alert"]) == EXPECTED_ALERTS | {SELFTEST}
    assert paths[4:] == ["/api/v2/default/alerts"] * (len(EXPECTED_ALERTS) + 1)


def test_template_body_is_a_naver_works_text_message(o2):
    """통지 본문은 네이버웍스 봇 형식 {"content": {"type": "text", "text": ...}} 이다."""
    assert _apply(o2).returncode == 0
    body = json.loads(o2.store["template"]["infra-automation-webhook"]["body"])
    assert body["content"]["type"] == "text"
    # 행동 가능한 알림: 심각도·제목·무슨 일·왜 중요·조치·런북·대상 행·대시보드 링크·발생 구간
    for var in ("{severity_icon}", "{severity}", "{title}", "{what}", "{why}", "{action}", "{runbook}",
                "{rows}", "{alert_url}", "{alert_start_time}", "{alert_end_time}", "{alert_name}"):
        assert var in body["content"]["text"], var
    assert "\n" in body["content"]["text"] and "\\n" not in body["content"]["text"]   # 실제 줄바꿈


RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "alerts.md"


def test_every_alert_is_actionable(o2):
    """모든 알림은 심각도·제목·무슨 일·왜 중요·조치·런북 링크와 대상 행 템플릿을 갖는다(PagerDuty/Google SRE 원칙)."""
    assert _apply(o2).returncode == 0
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for name, alert in o2.store["alert"].items():
        if name == SELFTEST:
            continue
        ctx = alert["context_attributes"]
        assert ctx["severity"] in ("P1 긴급", "P2 경고", "P3 주의"), name
        assert ctx["severity_icon"] in ("🔴", "🟠", "🟡"), name
        for key in ("title", "what", "why", "action"):
            assert ctx[key].strip() and '"' not in ctx[key] and "\n" not in ctx[key], (name, key)
        anchor = ctx["runbook"].split("#", 1)[1]
        assert ctx["runbook"].startswith("https://github.com/ppzxc/infra-automation/blob/main/docs/runbooks/alerts.md#")
        assert f'<a id="{anchor}"></a>' in runbook, (name, anchor)
        assert alert["row_template_type"] == "String" and alert["row_template"].startswith("• "), name
        # 행 템플릿의 {필드}는 모두 그 알림 SQL이 SELECT하는 컬럼이다
        import re as _re
        fields = set(_re.findall(r"\{(\w+)\}", alert["row_template"]))
        assert fields and all(f in alert["query_condition"]["sql"] for f in fields), (name, fields)


def test_severity_mapping_follows_impact(o2):
    assert _apply(o2).returncode == 0
    sev = {n: a["context_attributes"]["severity"] for n, a in o2.store["alert"].items()}
    assert sev["infra-root-login-success"] == sev["infra-kernel-disk-errors"] == "P1 긴급"
    assert sev["infra-ssh-login-failures-per-source"] == sev["infra-sudo-escalation-failure"] == "P2 경고"
    assert sev["infra-log-parse-errors-security-logs"] == "P3 주의"


def test_webhook_auth_header_name_comes_from_openbao(o2):
    kv = dict(KV, alert_webhook_auth_header="X-NANOIT-ACCESS")
    assert _apply(o2, kv=kv).returncode == 0
    assert o2.store["destination"]["infra-automation-webhook"]["headers"] == {
        "Content-Type": "application/json", "X-NANOIT-ACCESS": "WEBHOOK-TOKEN-abc"}


def test_function_pipeline_destination_and_alert_payloads_follow_the_definitions(o2):
    assert _apply(o2).returncode == 0
    fn = o2.store["function"]["security_semantics"]
    assert fn["function"] == (ROLE / "files" / "vrl" / "security_semantics.vrl").read_text().strip() and fn["params"] == "row"
    pl = o2.store["pipeline"]["security_semantics"]
    assert pl["source"]["stream_name"] == "security_logs" and pl["enabled"] is True
    func_node = next(n["data"] for n in pl["nodes"] if n["data"]["node_type"] == "function")
    assert func_node["name"] == "security_semantics" and func_node["after_flatten"] is True
    dest = o2.store["destination"]["infra-automation-webhook"]
    assert dest["url"] == WEBHOOK_URL and dest["type"] == "http"
    assert dest["headers"] == {"Content-Type": "application/json", "Authorization": "WEBHOOK-TOKEN-abc"}
    assert dest["template"] == "infra-automation-webhook"
    by = o2.store["alert"]
    assert all(a["destinations"] == ["infra-automation-webhook"] and a["enabled"] for a in by.values())
    assert SELFTEST in by
    assert by["infra-ssh-login-failures-per-source"]["query_condition"]["sql"].count("HAVING count(*) >= 10") == 1
    assert by["infra-ssh-login-failures-per-host"]["query_condition"]["sql"].count("HAVING count(*) >= 50") == 1
    assert by["infra-ssh-login-failures-per-source"]["trigger_condition"]["period"] == 5
    assert "user_name = 'root'" in by["infra-root-login-success"]["query_condition"]["sql"]
    assert by["infra-kernel-disk-errors"]["stream_name"] == "system_logs"
    for pattern in ("Out of memory: Killed process", "I/O error", "EXT4-fs error", "Corruption"):
        assert pattern in by["infra-kernel-disk-errors"]["query_condition"]["sql"]
    assert "log_parse_error" in by["infra-log-parse-errors-security-logs"]["query_condition"]["sql"]


def test_second_run_changes_nothing_and_sends_no_writes(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.writes == [] and _changed(res) == 0


def test_changed_definition_produces_exactly_one_update_to_the_existing_object(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2, extra={"o2c_ssh_fail_per_source_threshold": 20})
    assert res.returncode == 0, res.stdout + res.stderr
    ((method, path, body),) = o2.writes
    alert_id = o2.store["alert"]["infra-ssh-login-failures-per-source"]["alert_id"]
    assert method == "PUT" and path == f"/api/v2/default/alerts/{alert_id}"
    assert "HAVING count(*) >= 20" in body["query_condition"]["sql"]


def test_changed_vrl_updates_the_function_by_name(o2, tmp_path):
    assert _apply(o2).returncode == 0
    o2.store["function"]["security_semantics"]["function"] = "# stale\n."   # drift on the server
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    ((method, path, body),) = o2.writes
    assert (method, path) == ("PUT", "/api/default/functions/security_semantics") and body["function"].startswith("# OpenObserve VRL")


def test_pipeline_drift_is_repaired_with_its_id(o2):
    assert _apply(o2).returncode == 0
    pid = o2.store["pipeline"]["security_semantics"]["pipeline_id"]
    o2.store["pipeline"]["security_semantics"]["enabled"] = False
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    ((method, path, body),) = o2.writes
    assert (method, path) == ("PUT", f"/api/default/pipelines/{pid}") and body["pipeline_id"] == pid and body["enabled"] is True


def test_check_mode_reads_and_plans_but_writes_nothing(o2):
    res = _apply(o2, "--check")
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.writes == [] and o2.reads
    for expected in ("create template infra-automation-webhook", "create function security_semantics",
                     "create alert infra-root-login-success"):
        assert expected in res.stdout


def _seed_stale(o2):
    o2.store["alert"]["infra-old-renamed"] = {"alert_id": "stale1", "name": "infra-old-renamed", "enabled": True}
    o2.store["alert"]["team-custom-alert"] = {"alert_id": "other1", "name": "team-custom-alert", "enabled": True}


def test_infra_alert_missing_from_the_repository_is_deleted_and_others_are_kept(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert [(m, p) for m, p, _ in o2.writes] == [("DELETE", "/api/v2/default/alerts/stale1")]
    assert "infra-old-renamed" not in o2.store["alert"] and "team-custom-alert" in o2.store["alert"]
    o2.writes.clear()
    assert _apply(o2).returncode == 0 and o2.writes == []


def test_check_mode_lists_the_alerts_to_delete_without_writing(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.writes.clear()
    res = _apply(o2, "--check")
    assert res.returncode == 0 and o2.writes == []
    assert "delete alert infra-old-renamed" in res.stdout and "team-custom-alert" not in res.stdout


def test_check_mode_after_apply_reports_no_changes(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2, "--check")
    assert res.returncode == 0 and "변경 0건" in res.stdout and o2.writes == []


def test_secrets_never_reach_the_output(o2):
    res = _apply(o2, "-vvv")
    assert res.returncode == 0, res.stdout + res.stderr
    for secret in ("API-PASSWORD-xyz", "WEBHOOK-TOKEN-abc", "SECRET-PATH-123"):
        assert secret not in res.stdout + res.stderr
    assert o2.auth == {"Basic " + base64.b64encode(b"cfg@example.com:API-PASSWORD-xyz").decode(),
                       "Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()}   # 설정 API 계정 + 검증 주입 토큰


@pytest.mark.parametrize("missing", ["api_user", "api_password", "alert_webhook_url"])
def test_missing_inputs_fail_before_any_request(o2, missing):
    res = _apply(o2, kv={k: v for k, v in KV.items() if k != missing})
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []


def test_webhook_without_token_sends_no_auth_header(o2):
    res = _apply(o2, kv={k: v for k, v in KV.items() if k != "alert_webhook_token"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.store["destination"]["infra-automation-webhook"]["headers"] == {"Content-Type": "application/json"}


def test_every_api_task_is_no_log_and_writes_are_skipped_in_check_mode():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    uri_tasks = [t for t in tasks if "ansible.builtin.uri" in t]
    assert uri_tasks and all(t.get("no_log") is True for t in uri_tasks)
    apply = next(t for t in tasks if t["name"].startswith("[O2C-020]"))
    assert apply["when"] == "not ansible_check_mode" and apply["changed_when"] is True
    reads = [t for t in tasks if t["name"][:9] in ("[O2C-010]", "[O2C-011]")]
    assert all(t["check_mode"] is False and t["changed_when"] is False for t in reads)


def test_credential_facts_are_never_cacheable_and_reads_use_the_plan_path_table():
    import importlib.util
    spec = importlib.util.spec_from_file_location("o2c_filter", ROOT_DIR / "filter_plugins" / "openobserve_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    reqs = mod.o2c_read_requests("default")
    assert [r["kind"] for r in reqs] == list(mod.KINDS)
    assert all(r["path"] == mod.LIST_PATHS[r["kind"]].format(org="default") for r in reqs)
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    flat = [t for top in tasks for t in (top.get("block") or [top])]
    facts = [t for t in flat if "ansible.builtin.set_fact" in t
             and ({"o2c_kv", "o2c_auth_headers"} & set(t["ansible.builtin.set_fact"]))]
    assert len(facts) == 2 and all(t["ansible.builtin.set_fact"].get("cacheable") is False for t in facts)
    read = next(t for t in tasks if t["name"].startswith("[O2C-010]"))
    assert read["loop"] == "{{ o2c_org | o2c_read_requests }}"


def test_no_secret_value_is_committed_in_the_role_or_playbook():
    text = "".join(p.read_text(encoding="utf-8") for p in [PLAYBOOK, *ROLE.rglob("*") ] if p.is_file())
    assert not re.search(r"https?://[^\s'\"]*(hooks|webhook)[^\s'\"]*/[A-Za-z0-9_-]{16,}", text)
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert not any(k for k in defaults if "password" in k or "token" in k)


# --- 알림 검증 단계 (Spec #184 / Ticket-1) --------------------------------------------------------------------------------

FIXTURES = yaml.safe_load((ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8"))


def test_every_existing_alert_has_a_firing_and_a_non_firing_fixture_with_a_unique_host():
    assert set(FIXTURES) == EXPECTED_ALERTS
    hosts = [c["host"] for spec in FIXTURES.values() for c in spec["cases"]]
    assert len(hosts) == len(set(hosts))
    for name, spec in FIXTURES.items():
        assert {c["fires"] for c in spec["cases"]} == {True, False}, name


def test_verification_injects_synthetic_records_into_suffixed_streams_with_the_controller_token_and_searches_rewritten_sql(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    streams = {p.split("/")[3] for p, _, _ in o2.ingests}
    assert streams == {"security_logs_alert_verify", "system_logs_alert_verify"}
    assert {a for _, a, _ in o2.ingests} == {"Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()}
    assert len(o2.searches) == len(EXPECTED_ALERTS)
    for stream, sql in o2.searches:
        assert stream.endswith("_alert_verify") and 'FROM "security_logs"' not in sql and 'FROM "system_logs"' not in sql
    # 운영 스트림·운영 알림은 건드리지 않는다: 쓰기는 설정 객체뿐이고 합성 레코드는 검증 스트림에만 간다
    assert all("/_json" not in p for _, p, _ in o2.writes)
    hosts = {r["host_name"] for _, _, recs in o2.ingests for r in recs}
    assert any(h.startswith("verify-kernel-oom-upper-") for h in hosts)


def test_second_run_with_verification_still_changes_nothing_in_the_configuration(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and _changed(res) == 0


def test_job_fails_and_names_the_alert_and_case_when_an_alert_does_not_fire(o2):
    o2.search_override = lambda stream, sql, hits: [] if "Killed process" in sql else hits
    res = _apply(o2)
    assert res.returncode != 0
    assert "infra-kernel-disk-errors / 케이스 'OOM kill (대문자 Out of memory)': 발화해야 하는데 발화하지 않았습니다" in res.stdout


def test_job_fails_when_an_alert_fires_on_a_record_that_must_not_fire(o2):
    o2.search_override = lambda stream, sql, hits: hits + ([{"host_name": next(
        r["host_name"] for _, _, recs in o2.ingests for r in recs if r["host_name"].startswith("verify-root-other-user-"))}]
        if "user_name = 'root'" in sql else [])
    res = _apply(o2)
    assert res.returncode != 0
    assert "케이스 '일반 사용자 로그인 성공': 발화하면 안 되는데 발화했습니다" in res.stdout


def test_known_failure_case_is_reported_but_does_not_fail_the_job(o2):
    """OOM 소문자 사례는 현재 알림이 놓친다 — 엔진이 그렇게 답해도(발화 안 함) 알려진 실패로만 표시한다."""
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "infra-kernel-disk-errors / 케이스 '컨테이너 cgroup OOM kill (소문자 out of memory) — 실제로 놓친 사례'" in res.stdout
    assert "알려진 실패" in res.stdout


def test_known_failure_that_the_engine_now_catches_is_not_reported_as_failure(o2):
    o2.search_override = lambda stream, sql, hits: hits + ([{"host_name": next(
        r["host_name"] for _, _, recs in o2.ingests for r in recs if r["host_name"].startswith("verify-kernel-oom-cgroup-"))}]
        if "Killed process" in sql else [])
    res = _apply(o2)
    assert res.returncode == 0 and "알려진 실패" not in res.stdout


def test_job_fails_when_the_latest_evaluation_of_an_alert_is_an_error(o2):
    o2.history = [{"alert_name": "infra-root-login-success", "status": "ok", "timestamp": 100},
                  {"alert_name": "infra-root-login-success", "status": "error", "timestamp": 200, "error": "field missing"}]
    res = _apply(o2)
    assert res.returncode != 0 and "infra-root-login-success" in res.stdout


def test_an_old_evaluation_error_that_has_since_recovered_does_not_fail_the_job(o2):
    o2.history = [{"alert_name": "infra-root-login-success", "status": "error", "timestamp": 100},
                  {"alert_name": "infra-root-login-success", "status": "ok", "timestamp": 200}]
    assert _apply(o2).returncode == 0


def test_check_mode_sends_no_verification_requests(o2):
    res = _apply(o2, "--check")
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.ingests == [] and o2.searches == [] and not any("history" in r for r in o2.reads)


def test_missing_controller_ingest_token_fails_the_verification(o2):
    res = _apply(o2, kv={k: v for k, v in KV.items() if k != "controller_ingest_token"})
    assert res.returncode != 0 and o2.ingests == []


def test_verification_never_leaks_secrets_and_every_verify_uri_task_is_no_log():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    verify = [t for t in tasks if t["name"][:8] in ("[O2C-032", "[O2C-033", "[O2C-035")]
    assert len(verify) == 3 and all(t["no_log"] is True and t["when"] == "not ansible_check_mode" for t in verify)


def test_ingest_token_is_not_printed(o2):
    res = _apply(o2, "-vvv")
    assert "INGEST-TOKEN-qrs" not in res.stdout + res.stderr
    assert base64.b64encode(b"default:INGEST-TOKEN-qrs").decode() not in res.stdout + res.stderr


# --- root 로그인 정상 출발지 (Spec #184 / Ticket-8) ---------------------------------------------------------------------
# 정상 출발지 목록은 OpenBao(agents/openobserve)의 normal_sources에만 있다. 아래 주소는 문서용(TEST-NET-1) 가짜 값이다.
SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP = "192.0.2.10", "192.0.2.20", "192.0.2.21"
SOURCES = [{"address": SEMAPHORE_IP, "kind": "semaphore"}, {"address": OFFICE_IP, "kind": "office"},
           {"address": OFFICE_S2S_IP, "kind": "office"}]
KV_SOURCES = dict(KV, normal_sources=SOURCES)


def _sql(o2, name):
    return o2.store["alert"][name]["query_condition"]["sql"]


def test_external_root_login_alert_excludes_every_normal_source_and_stays_p1_event_alert(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    alert = o2.store["alert"]["infra-root-login-success"]
    sql = alert["query_condition"]["sql"]
    for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP):
        assert f"'{ip}'" in sql
    assert "NOT IN" in sql and "user_name = 'root'" in sql
    assert alert["context_attributes"]["severity"] == "P1 긴급"
    assert alert["trigger_condition"]["threshold"] == 1 and alert["trigger_condition"]["silence"] == 5


def test_office_root_login_alert_is_a_daily_p3_summary_of_office_sources_only(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    alert = o2.store["alert"]["infra-root-login-office-daily"]
    sql = alert["query_condition"]["sql"]
    assert f"'{OFFICE_IP}'" in sql and f"'{OFFICE_S2S_IP}'" in sql and SEMAPHORE_IP not in sql
    assert "user_name = 'root'" in sql and "NOT IN" not in sql
    assert alert["context_attributes"]["severity"] == "P3 주의"
    assert alert["trigger_condition"]["period"] == 1440 and alert["trigger_condition"]["silence"] == 1440


def test_ssh_failure_alerts_ignore_the_normal_source_list(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    for name in ("infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host"):
        assert not any(ip in _sql(o2, name) for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP)), name


def test_without_a_source_list_every_root_login_is_p1_and_the_office_alert_matches_nothing(o2):
    assert _apply(o2).returncode == 0
    assert "NOT IN" not in _sql(o2, "infra-root-login-success")
    assert "IN ('')" in _sql(o2, "infra-root-login-office-daily")


def test_changing_the_source_list_updates_only_the_root_alerts(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    o2.writes.clear()
    moved = dict(KV, normal_sources=[{"address": "192.0.2.99", "kind": "office"}])
    assert _apply(o2, kv=moved).returncode == 0
    ids = {o2.store["alert"][n]["alert_id"] for n in ("infra-root-login-success", "infra-root-login-office-daily")}
    assert {p.rsplit("/", 1)[1] for _, p, _ in o2.writes} == ids and all(m == "PUT" for m, _, _ in o2.writes)


def test_source_addresses_never_reach_the_output(o2):
    res = _apply(o2, "-vvv", kv=KV_SOURCES)
    assert res.returncode == 0, res.stdout + res.stderr
    for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP):
        assert ip not in res.stdout + res.stderr


@pytest.mark.parametrize("bad", [{"address": "1.2.3.4' OR '1'='1", "kind": "office"},
                                 {"address": "192.0.2.5", "kind": "partner"}, {"address": "", "kind": "office"}])
def test_invalid_source_entries_fail_before_any_request(o2, bad):
    res = _apply(o2, kv=dict(KV, normal_sources=[bad]))
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []
    assert "1' OR" not in res.stdout + res.stderr


def test_verification_places_normal_sources_in_the_synthetic_records_by_kind(o2):
    res = _apply(o2, kv=KV_SOURCES)
    assert res.returncode == 0, res.stdout + res.stderr
    recs = [r for _, _, rs in o2.ingests for r in rs if r.get("user_name") == "root"]
    by_host = {r["host_name"].rsplit("-", 1)[0]: r["source_address"] for r in recs}
    assert by_host["verify-root-semaphore"] == SEMAPHORE_IP and by_host["verify-root-office"] == OFFICE_IP
    assert by_host["verify-root-external"] not in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP)
    assert not any("@" in str(r.get("source_address", "")) for r in recs)


def test_verification_skips_kind_specific_cases_when_the_list_has_no_such_kind(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    hosts = {r["host_name"] for _, _, rs in o2.ingests for r in rs}
    assert not any(h.startswith(("verify-root-semaphore-", "verify-root-office-")) for h in hosts)
    assert any(h.startswith("verify-root-external-") for h in hosts)


def test_root_fixtures_cover_semaphore_office_and_external_for_both_root_alerts():
    cases = lambda n: {c["host"]: c["fires"] for c in FIXTURES[n]["cases"]}  # noqa: E731
    p1, p3 = cases("infra-root-login-success"), cases("infra-root-login-office-daily")
    assert p1["verify-root-external"] is True and p1["verify-root-semaphore"] is False and p1["verify-root-office"] is False
    assert p3["verify-office-p3-office"] is True and p3["verify-office-p3-semaphore"] is False and p3["verify-office-p3-external"] is False


def test_a_committed_file_never_holds_a_real_looking_internal_address():
    """가짜 OpenObserve 테스트와 픽스처는 문서용 대역(192.0.2/198.51.100/203.0.113)만 쓴다."""
    text = (ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8") + (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip


# --- 통지 경로 자가 시험 (Spec #184 / Ticket-2) -------------------------------------------------------------------------
def _selftest_ingests(o2):
    return [(p, a, recs) for p, a, recs in o2.ingests if p.split("/")[3] == SELFTEST_STREAM]


def test_standing_selftest_alert_is_managed_on_a_verification_only_stream_and_is_idempotent(o2):
    assert _apply(o2).returncode == 0
    alert = o2.store["alert"][SELFTEST]
    assert alert["stream_name"] == SELFTEST_STREAM and alert["destinations"] == ["infra-automation-webhook"]
    assert alert["enabled"] is True and alert["stream_type"] == "logs"
    # 운영 스트림을 보지 않으므로 운영 데이터로는 발화하지 않는다
    assert alert["stream_name"] not in ("security_logs", "system_logs")
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and _changed(res) == 0


def test_selftest_notification_is_clearly_marked_as_a_test(o2):
    assert _apply(o2).returncode == 0
    ctx = o2.store["alert"][SELFTEST]["context_attributes"]
    assert ctx["severity"] == "TEST"       # 통지 첫 줄이 "<아이콘> [TEST] <제목>"이 된다
    assert all(ctx[k].strip() and '"' not in ctx[k] and "\n" not in ctx[k] for k in ("title", "what", "why", "action", "runbook"))
    assert "시험" in ctx["title"] and o2.store["alert"][SELFTEST]["row_template"].startswith("• ")


def test_default_run_sends_no_selftest_record(o2):
    assert _apply(o2).returncode == 0
    assert _selftest_ingests(o2) == []


def test_verify_notify_injects_exactly_one_selftest_record_with_the_controller_token(o2):
    res = _apply(o2, extra={"o2c_verify_notify": True})
    assert res.returncode == 0, res.stdout + res.stderr
    sent = _selftest_ingests(o2)
    assert len(sent) == 1 and len(sent[0][2]) == 1
    assert sent[0][1] == "Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()
    assert sent[0][2][0]["host_name"].startswith("selftest")


def test_verify_notify_is_off_in_check_mode(o2):
    res = _apply(o2, "--check", extra={"o2c_verify_notify": True})
    assert res.returncode == 0 and o2.ingests == []


def test_selftest_ingest_task_is_no_log_and_not_run_in_check_mode():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    t = next(t for t in tasks if t["name"].startswith("[O2C-037"))
    assert t["no_log"] is True and "not ansible_check_mode" in str(t["when"]) and "o2c_verify_notify" in str(t["when"])
