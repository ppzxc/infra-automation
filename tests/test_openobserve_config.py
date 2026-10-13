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
    "infra-root-login-office-daily", "infra-sudo-escalation-failure", "infra-oom-kill", "infra-disk-fs-errors",
    "infra-log-parse-errors-security-logs", "infra-log-parse-errors-system-logs",
    "infra-disk-usage-p2", "infra-disk-usage-p1", "infra-inode-usage-p2", "infra-inode-usage-p1",
    "infra-memory-usage-p2", "infra-memory-usage-p1",
    "infra-silent-host-p2", "infra-silent-host-p1",
    "infra-backup-failure", "infra-integrity-check-failure", "infra-backup-missing", "infra-maintenance-missing",
}
RESOURCE_ALERTS = {  # name -> (severity, silence minutes, period minutes, stream)
    "infra-disk-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_usage"),
    "infra-disk-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_usage"),
    "infra-inode-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_inodes_usage"),
    "infra-inode-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_inodes_usage"),
    "infra-memory-usage-p2": ("P2 경고", 1440, 10, "system_memory_usage"),
    "infra-memory-usage-p1": ("P1 긴급", 60, 10, "system_memory_usage"),
}
SELFTEST = "infra-alert-selftest"   # 통지 경로 자가 시험 알림(Spec #184 / Ticket-2) — 검증 전용 스트림에 건다
SELFTEST_STREAM = "alert_selftest_alert_verify"


def _same_roster_alert(name, stored, sql):
    """Roster (absence) SQL of the same alert — the verification adds fake hosts to the roster, so the host names differ."""
    def is_roster(q):
        return "AS host_name, count(*) AS n FROM" in q or "AS host, count(*) AS n FROM" in q
    def shape(q):   # the roster hosts differ; the extra condition of each branch (e.g. job = 'backup' AND success = true) must match
        conds = (re.search(r"WHERE (?:(?:host|host_name) = '[^']*'(?: AND )?)?(.*?) HAVING", b) for b in q.split(" UNION ALL "))
        return {m.group(1) if m else "" for m in conds}
    return is_roster(stored) and is_roster(sql) and name.endswith("-p2") == ("count(*) >= 1" in sql) and shape(stored) == shape(sql)


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
                run_ids = {(r.get("host_name") or r["host"]).rsplit("-", 1)[1] for _, _, recs in outer.ingests for r in recs}
                for alert in outer.store["alert"].values():
                    prod = alert["stream_name"]
                    stored = alert["query_condition"]["sql"].replace(f'"{prod}"', f'"{stream}"')
                    if stream != prod + "_alert_verify" or not (stored == sql or _same_roster_alert(alert["name"], stored, sql)):
                        continue
                    cases = outer.fixtures[alert["name"]]["cases"]
                    key = outer.fixtures[alert["name"]].get("row_key", "host_name")
                    return [{key: f'{c["host"]}-{rid}'} for rid in sorted(run_ids)
                            for c in cases if c["fires"] and not c.get("known_failure")]
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


def _apply(o2, *args, kv=None, extra=None, inventory="localhost,"):
    extra = {"o2c_verify_retries": 1, "o2c_verify_delay": 0, **(extra or {})}
    env = dict(os.environ, ANSIBLE_NOCOLOR="1")
    cmd = ["ansible-playbook", "-i", str(inventory), str(PLAYBOOK), "-e", f"o2_endpoint={o2.url}",
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
    assert sev["infra-root-login-success"] == sev["infra-disk-fs-errors"] == "P1 긴급"
    assert sev["infra-ssh-login-failures-per-source"] == sev["infra-sudo-escalation-failure"] == sev["infra-oom-kill"] == "P2 경고"
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
    assert "infra-kernel-disk-errors" not in by
    oom, disk = by["infra-oom-kill"], by["infra-disk-fs-errors"]
    assert oom["stream_name"] == disk["stream_name"] == "system_logs"
    oom_sql, disk_sql = oom["query_condition"]["sql"].lower(), disk["query_condition"]["sql"].lower()
    assert "lower(body)" in oom_sql and "killed process" in oom_sql and "invoked oom-killer" in oom_sql
    for pattern in ("i/o error", "ext4-fs error", "corruption", "blk_update_request", "buffer i/o error"):
        assert pattern in disk_sql
    # Event Alert: 재통지(silence)는 조회 구간과 같다
    for a in (oom, disk):
        assert a["trigger_condition"]["silence"] == a["trigger_condition"]["period"] == 5
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
    assert streams == {"security_logs_alert_verify", "system_logs_alert_verify", "system_filesystem_usage_alert_verify",
                       "system_filesystem_inodes_usage_alert_verify", "system_memory_usage_alert_verify", "backup_logs_alert_verify"}
    assert {a for _, a, _ in o2.ingests} == {"Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()}
    assert len(o2.searches) == len(EXPECTED_ALERTS)
    for stream, sql in o2.searches:
        assert stream.endswith("_alert_verify") and 'FROM "security_logs"' not in sql and 'FROM "system_logs"' not in sql
    # 운영 스트림·운영 알림은 건드리지 않는다: 쓰기는 설정 객체뿐이고 합성 레코드는 검증 스트림에만 간다
    assert all("/_json" not in p for _, p, _ in o2.writes)
    hosts = {r.get("host_name") or r["host"] for _, _, recs in o2.ingests for r in recs}
    assert any(h.startswith("verify-oom-upper-") for h in hosts)


def test_second_run_with_verification_still_changes_nothing_in_the_configuration(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and _changed(res) == 0


def test_job_fails_and_names_the_alert_and_case_when_an_alert_does_not_fire(o2):
    o2.search_override = lambda stream, sql, hits: [] if "oom-killer" in sql else hits
    res = _apply(o2)
    assert res.returncode != 0
    assert "infra-oom-kill / 케이스 'OOM kill (대문자 Out of memory)': 발화해야 하는데 발화하지 않았습니다" in res.stdout


def test_job_fails_when_an_alert_fires_on_a_record_that_must_not_fire(o2):
    o2.search_override = lambda stream, sql, hits: hits + ([{"host_name": next(
        r["host_name"] for _, _, recs in o2.ingests for r in recs if r.get("host_name", "").startswith("verify-root-other-user-"))}]
        if "user_name = 'root'" in sql else [])
    res = _apply(o2)
    assert res.returncode != 0
    assert "케이스 '일반 사용자 로그인 성공': 발화하면 안 되는데 발화했습니다" in res.stdout


def test_no_fixture_is_marked_as_a_known_failure_any_more(o2):
    assert not [c for spec in FIXTURES.values() for c in spec["cases"] if "known_failure" in c]
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "알려진 실패" not in res.stdout


def test_oom_and_disk_fixtures_cover_case_and_os_variants():
    bodies = " ".join(r["body"] for c in FIXTURES["infra-oom-kill"]["cases"] for r in c["records"])
    assert "Memory cgroup out of memory: Killed process" in bodies and "Out of memory: Kill process" in bodies
    assert "invoked oom-killer" in bodies
    disk = " ".join(r["body"] for c in FIXTURES["infra-disk-fs-errors"]["cases"] for r in c["records"])
    assert "Buffer I/O error" in disk and "blk_update_request" in disk
    # 서로의 영역을 침범하지 않는다: OOM 로그는 디스크 알림에, 디스크 오류는 OOM 알림에 걸리지 않는다
    assert any(not c["fires"] and "Killed process" in c["records"][0]["body"] for c in FIXTURES["infra-disk-fs-errors"]["cases"])
    assert any(not c["fires"] and "I/O error" in c["records"][0]["body"] for c in FIXTURES["infra-oom-kill"]["cases"])


def test_replaced_kernel_disk_alert_is_deleted_from_the_server(o2):
    assert _apply(o2).returncode == 0
    o2.store["alert"]["infra-kernel-disk-errors"] = {"alert_id": "old-kernel", "name": "infra-kernel-disk-errors", "enabled": True}
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    assert ("DELETE", "/api/v2/default/alerts/old-kernel", None) in o2.writes
    assert "infra-kernel-disk-errors" not in o2.store["alert"]


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
    hosts = {r.get("host_name") or r["host"] for _, _, rs in o2.ingests for r in rs}
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


# --- 리소스 고갈 알림 (Spec #184 / Ticket-3) ------------------------------------------------------------

def test_resource_alerts_are_metric_state_alerts_with_grade_and_renotify_interval(o2):
    assert _apply(o2).returncode == 0
    for name, (sev, silence, period, stream) in RESOURCE_ALERTS.items():
        a = o2.store["alert"][name]
        assert a["stream_type"] == "metrics" and a["stream_name"] == stream, name
        assert a["context_attributes"]["severity"] == sev, name
        assert a["trigger_condition"]["silence"] == silence and a["trigger_condition"]["period"] == period, name
        assert a["query_condition"]["type"] == "sql"
        assert {"host_name", "usage_pct"} <= set(re.findall(r"\{(\w+)\}", a["row_template"])), name
    assert "mountpoint" in o2.store["alert"]["infra-disk-usage-p1"]["row_template"]


def test_existing_log_alerts_stay_logs(o2):
    assert _apply(o2).returncode == 0
    for name in EXPECTED_ALERTS - set(RESOURCE_ALERTS) - {"infra-silent-host-p2", "infra-silent-host-p1"}:
        assert o2.store["alert"][name]["stream_type"] == "logs", name


def test_resource_sql_groups_by_timestamp_uses_min_and_default_thresholds_and_fstype_exclusions(o2):
    assert _apply(o2).returncode == 0
    p2, p1 = _sql(o2, "infra-disk-usage-p2"), _sql(o2, "infra-disk-usage-p1")
    for sql in (p2, p1):
        assert "GROUP BY host_name, mountpoint, device, _timestamp" in sql and "min(" in sql
        for t in ("squashfs", "iso9660", "tmpfs", "devtmpfs", "overlay"):
            assert f"'{t}'" in sql
        assert "/boot" not in sql   # /boot, /boot/efi는 제외하지 않는다
    assert ">= 90" in p2 and "< 95" in p2 and ">= 95" in p1
    mem = _sql(o2, "infra-memory-usage-p1")
    assert "slab_unreclaimable" in mem and "GROUP BY host_name, _timestamp" in mem


def test_openbao_exclusions_and_threshold_overrides_reach_the_sql(o2):
    kv = dict(KV, alert_resource_exclusions=[{"host": "ns0297", "mount": "/data"}, {"host": "ns0288", "metric": "memory"}],
              alert_resource_thresholds=[{"host": "ns0300", "mount": "/var", "p2": 97, "p1": 99}])
    assert _apply(o2, kv=kv).returncode == 0
    disk = _sql(o2, "infra-disk-usage-p2")
    assert "NOT (host_name = 'ns0297' AND mountpoint = '/data')" in disk and "ns0288" not in disk
    assert "ns0288" in _sql(o2, "infra-memory-usage-p2")
    assert "host_name = 'ns0300' AND mountpoint = '/var' THEN 97" in disk
    assert "THEN 99" in _sql(o2, "infra-disk-usage-p1") and "ns0300" not in _sql(o2, "infra-memory-usage-p1")


def test_empty_openbao_resource_keys_work_and_second_run_changes_nothing_with_them(o2):
    kv = dict(KV, alert_resource_exclusions=[{"host": "ns0297", "mount": "/data"}])
    assert _apply(o2, kv=kv).returncode == 0
    o2.writes.clear()
    assert _apply(o2, kv=kv).returncode == 0 and o2.writes == []


def test_resource_fixtures_cover_the_ns0334_case_squashfs_and_below_threshold():
    cases = {c["name"]: c for spec in FIXTURES.values() for c in spec["cases"]}
    text = yaml.safe_dump(FIXTURES)
    assert "ns0334" in text and "squashfs" in text
    for name in RESOURCE_ALERTS:
        assert {c["fires"] for c in FIXTURES[name]["cases"]} == {True, False}, name
    assert cases

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


# --- Silent Host와 수집 로스터 (Spec #184 / Ticket-4) --------------------------------------------------------------------
def _inventory(tmp_path, servers, excluded=(), backup_only=()):
    groups = {"servers": {"hosts": {h: {} for h in servers}},
              "host_agents_excluded": {"hosts": {h: {} for h in excluded}},
              "host_agents_backup_only": {"hosts": {h: {} for h in backup_only}}}
    path = tmp_path / "hosts.yml"
    path.write_text(yaml.safe_dump({"all": {"children": groups}}), encoding="utf-8")
    return path


def _branch_hosts(sql):
    return set(re.findall(r"SELECT '([^']+)' AS host_name", sql))


SERVERS = ["ns0001", "ns0002", "ns0003", "ns0004", "ns0266", "ns0332"]


def test_silent_host_roster_is_servers_minus_exclusion_and_backup_only_and_keeps_ns0266_and_ns0332(o2, tmp_path):
    inv = _inventory(tmp_path, SERVERS, excluded=["ns0002"], backup_only=["ns0003"])
    res = _apply(o2, inventory=inv)
    assert res.returncode == 0, res.stdout + res.stderr
    for name in ("infra-silent-host-p2", "infra-silent-host-p1"):
        sql = _sql(o2, name)
        assert _branch_hosts(sql) == {"ns0001", "ns0004", "ns0266", "ns0332"}, name
        # 인라인 로스터 JOIN은 이 OpenObserve 버전에서 틀린 결과를 낸다 — UNION ALL 가지 방식만 쓴다
        assert "UNION ALL" in sql and "HAVING" in sql and "< 1" in sql
        for banned in ("VALUES", "unnest", "JOIN"):
            assert banned.lower() not in sql.lower(), (name, banned)


def test_silent_host_alerts_are_state_alerts_p2_and_p1_on_the_memory_heartbeat(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    p2, p1 = o2.store["alert"]["infra-silent-host-p2"], o2.store["alert"]["infra-silent-host-p1"]
    for a in (p2, p1):
        assert a["stream_type"] == "metrics" and a["stream_name"] == "system_memory_usage" and a["query_condition"]["type"] == "sql"
        assert a["trigger_condition"]["period"] == 180 and a["trigger_condition"]["frequency"] == 5
        assert "{host_name}" in a["row_template"]
        assert "같은 호스트의 서버 응답 없음 알림이 있으면 그쪽이 원인" in a["context_attributes"]["action"]
    assert p2["context_attributes"]["severity"] == "P2 경고" and p2["trigger_condition"]["silence"] == 1440
    assert p1["context_attributes"]["severity"] == "P1 긴급" and p1["trigger_condition"]["silence"] == 60
    # P2는 15분 없음(3시간 미만), P1은 3시간 없음 — 같은 호스트에 동시에 오지 않는다
    assert "900000000" in p2["query_condition"]["sql"] and "count(*) >= 1" in p2["query_condition"]["sql"]
    assert "count(*) >= 1" not in p1["query_condition"]["sql"]


def test_silent_host_p1_warns_that_the_log_gap_is_not_recoverable_after_about_5_hours(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    ctx = o2.store["alert"]["infra-silent-host-p1"]["context_attributes"]
    text = ctx["what"] + ctx["why"] + ctx["action"]
    assert "약 5시간" in text and "OpenObserve로 복구되지 않음" in text


def test_changing_the_inventory_changes_the_roster_sql_and_a_rerun_with_the_same_inventory_writes_nothing(o2, tmp_path):
    inv = _inventory(tmp_path, SERVERS)
    assert _apply(o2, inventory=inv).returncode == 0
    o2.writes.clear()
    assert _apply(o2, inventory=inv).returncode == 0 and o2.writes == []
    inv = _inventory(tmp_path, SERVERS + ["ns0500"], excluded=["ns0001"])
    assert _apply(o2, inventory=inv).returncode == 0
    updated = {p for m, p, _ in o2.writes if m == "PUT"}
    ids = {n: o2.store["alert"][n]["alert_id"] for n in ("infra-silent-host-p2", "infra-silent-host-p1",
                                                         "infra-backup-missing", "infra-maintenance-missing")}
    assert updated == {f"/api/v2/default/alerts/{i}" for i in ids.values()}
    hosts = _branch_hosts(_sql(o2, "infra-silent-host-p1"))
    assert "ns0500" in hosts and "ns0001" not in hosts


def test_expired_planned_stop_exception_is_ignored_and_a_valid_one_removes_the_host(o2, tmp_path):
    kv = dict(KV, silent_host_exceptions=[{"host": "ns0001", "expires": "2000-01-01"},
                                          {"host": "ns0004", "expires": "2999-12-31"}])
    assert _apply(o2, kv=kv, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    for name in ("infra-silent-host-p2", "infra-silent-host-p1"):
        hosts = _branch_hosts(_sql(o2, name))
        assert "ns0001" in hosts and "ns0004" not in hosts, name


@pytest.mark.parametrize("bad", [{"host": "ns0001"}, {"host": "ns0001", "expires": "soon"},
                                 {"expires": "2999-12-31"}, {"host": "ns0001' OR '1'='1", "expires": "2999-12-31"}])
def test_planned_stop_exception_without_a_valid_expiry_fails_before_any_request(o2, tmp_path, bad):
    res = _apply(o2, kv=dict(KV, silent_host_exceptions=[bad]), inventory=_inventory(tmp_path, SERVERS))
    assert res.returncode != 0 and o2.writes == [] and o2.reads == []


def test_verification_puts_fake_roster_hosts_into_the_searched_silent_host_sql(o2, tmp_path):
    res = _apply(o2, inventory=_inventory(tmp_path, SERVERS))
    assert res.returncode == 0, res.stdout + res.stderr
    for name in ("infra-silent-host-p2", "infra-silent-host-p1"):
        is_p2 = name.endswith("p2")
        searched = next(sql for stream, sql in o2.searches
                        if stream == "system_memory_usage_alert_verify" and "UNION ALL" in sql and ("count(*) >= 1" in sql) == is_p2)
        hosts = _branch_hosts(searched)
        for case in FIXTURES[name]["cases"]:
            assert any(h.startswith(case["host"] + "-") for h in hosts), (name, case["host"])
        assert "ns0266" in hosts


def test_silent_host_fixtures_cover_p2_p1_and_present_hosts():
    p2, p1 = FIXTURES["infra-silent-host-p2"]["cases"], FIXTURES["infra-silent-host-p1"]["cases"]
    assert {c["fires"] for c in p2} == {True, False} and {c["fires"] for c in p1} == {True, False}
    names = " ".join(c["name"] for c in p2 + p1)
    assert "3시간" in names and "15분" in names


def test_roster_follows_check_mode_without_writes(o2, tmp_path):
    res = _apply(o2, "--check", inventory=_inventory(tmp_path, SERVERS))
    assert res.returncode == 0 and o2.writes == [] and "infra-silent-host-p1" in res.stdout


def test_semaphore_docs_say_the_config_template_reads_the_servers_inventory():
    setup = (ROOT_DIR / "docs" / "semaphore-setup.md").read_text(encoding="utf-8")
    row = next(line for line in setup.splitlines() if line.startswith("| OpenObserve — Config |"))
    assert "servers" in row


# --- 백업 알림 (Spec #184 / Ticket-5) ---------------------------------------------------------------------------------
BACKUP_EVENTS = {"infra-backup-failure": ("backup", "success = false"),
                 "infra-integrity-check-failure": ("maintenance", "command = 'check' AND success = false")}
BACKUP_MISSING = {"infra-backup-missing": 1560, "infra-maintenance-missing": 11520}
BACKUP_ALERTS = {*BACKUP_EVENTS, *BACKUP_MISSING}


def _branch_hosts_as(sql):
    return set(re.findall(r"SELECT '([^']+)' AS host,", sql))


def test_backup_failure_and_integrity_failure_are_p2_event_alerts_on_backup_logs_keyed_by_host(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    for name, (job, cond) in BACKUP_EVENTS.items():
        a = o2.store["alert"][name]
        assert a["stream_name"] == "backup_logs" and a["context_attributes"]["severity"] == "P2 경고"
        sql = a["query_condition"]["sql"]
        assert f"job = '{job}'" in sql and cond in sql and "GROUP BY host" in sql and "host_name" not in sql, name
        assert a["trigger_condition"]["silence"] == a["trigger_condition"]["period"] == 5
        assert "{host}" in a["row_template"]


def test_backup_and_maintenance_missing_are_daily_p2_state_alerts_over_their_rosters(o2, tmp_path):
    inv = _inventory(tmp_path, SERVERS, excluded=["ns0002"], backup_only=["ns0003"])
    assert _apply(o2, inventory=inv).returncode == 0
    backup, maint = (o2.store["alert"][n] for n in ("infra-backup-missing", "infra-maintenance-missing"))
    for name, period in BACKUP_MISSING.items():
        a = o2.store["alert"][name]
        assert a["stream_name"] == "backup_logs" and a["context_attributes"]["severity"] == "P2 경고"
        assert a["trigger_condition"]["period"] == period and a["trigger_condition"]["silence"] == 1440
        sql = a["query_condition"]["sql"]
        assert "UNION ALL" in sql and "HAVING count(*) < 1" in sql and "AS host," in sql and "host_name" not in sql
        for banned in ("VALUES", "unnest", "JOIN"):
            assert banned.lower() not in sql.lower()
    assert "job = 'backup' AND success = true" in backup["query_condition"]["sql"]
    assert "command = 'check'" in maint["query_condition"]["sql"]
    # 수집 로스터는 Backup Only를 뺀다(이벤트를 안 보내 거짓 누락), 유지보수 로스터는 Backup Only를 포함한다
    assert _branch_hosts_as(backup["query_condition"]["sql"]) == {"ns0001", "ns0004", "ns0266", "ns0332"}
    assert _branch_hosts_as(maint["query_condition"]["sql"]) == {"ns0001", "ns0003", "ns0004", "ns0266", "ns0332"}


def test_backup_missing_action_starts_with_the_silent_host_check_and_runbook_anchors_exist(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    ctx = o2.store["alert"]["infra-backup-missing"]["context_attributes"]
    assert ctx["action"].startswith("① 같은 호스트의 Silent Host 알림이 있는지 먼저 확인")
    runbook = (ROOT_DIR / "docs" / "runbooks" / "alerts.md").read_text(encoding="utf-8")
    for name in BACKUP_ALERTS:
        anchor = o2.store["alert"][name]["context_attributes"]["runbook"].split("#")[1]
        assert f'<a id="{anchor}"></a>' in runbook, name


def test_verification_uses_the_host_field_for_backup_logs_and_fake_roster_hosts_for_missing_alerts(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    recs = [r for p, _, rs in o2.ingests if "backup_logs_alert_verify" in p for r in rs]
    assert recs and all("host" in r and "host_name" not in r for r in recs)
    searched = [sql for stream, sql in o2.searches if stream == "backup_logs_alert_verify" and "UNION ALL" in sql]
    hosts = set().union(*(_branch_hosts_as(q) for q in searched))
    for name in BACKUP_MISSING:
        for case in FIXTURES[name]["cases"]:
            assert any(h.startswith(case["host"] + "-") for h in hosts), (name, case["host"])


def test_backup_fixtures_cover_failed_events_and_fake_roster_host_missing():
    for name in BACKUP_ALERTS:
        assert {c["fires"] for c in FIXTURES[name]["cases"]} == {True, False}
        assert FIXTURES[name]["row_key"] == "host" and FIXTURES[name]["host_field"] == "host"
    assert any(c["records"] == [] and c["fires"] for c in FIXTURES["infra-backup-missing"]["cases"])


def test_adr_0006_alert_contract_has_grades_and_no_unexecuted_host_row():
    adr = next((ROOT_DIR / "docs" / "adr").glob("0006-*.md")).read_text(encoding="utf-8")
    table = adr[adr.index("표준 알림 계약"):adr.index("### 2.7")]
    assert "| 미실행 호스트" not in table and "P2" in table
