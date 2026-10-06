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
      "alert_webhook_token": "WEBHOOK-TOKEN-abc"}
EXPECTED_ALERTS = {
    "infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host", "infra-root-login-success",
    "infra-sudo-escalation-failure", "infra-kernel-disk-errors",
    "infra-log-parse-errors-security-logs", "infra-log-parse-errors-system-logs",
}


class FakeO2:
    """Minimal stateful stand-in for the OpenObserve config API (shapes taken from the v1.0.4 sources)."""

    def __init__(self):
        self.store = {k: {} for k in ("template", "destination", "function", "pipeline", "alert")}
        self.writes = []
        self.reads = []
        self.auth = set()
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

            def do_GET(self):  # noqa: N802
                outer.auth.add(self.headers.get("Authorization"))
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
    env = dict(os.environ, ANSIBLE_NOCOLOR="1")
    cmd = ["ansible-playbook", "-i", "localhost,", str(PLAYBOOK), "-e", f"o2_endpoint={o2.url}",
           "-e", json.dumps({"o2c_kv_fixture": kv or KV, **(extra or {})}), *args]
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
    assert set(o2.store["alert"]) == EXPECTED_ALERTS and paths[4:] == ["/api/v2/default/alerts"] * len(EXPECTED_ALERTS)


def test_function_pipeline_destination_and_alert_payloads_follow_the_definitions(o2):
    assert _apply(o2).returncode == 0
    fn = o2.store["function"]["security_semantics"]
    assert fn["function"] == (ROLE / "files" / "vrl" / "security_semantics.vrl").read_text().strip() and fn["params"] == "row"
    pl = o2.store["pipeline"]["security_semantics"]
    assert pl["source"]["stream_name"] == "security_logs" and pl["enabled"] is True
    func_node = next(n["data"] for n in pl["nodes"] if n["data"]["node_type"] == "function")
    assert func_node["name"] == "security_semantics" and func_node["after_flatten"] is True
    dest = o2.store["destination"]["infra-automation-webhook"]
    assert dest["url"] == WEBHOOK_URL and dest["headers"] == {"Authorization": "WEBHOOK-TOKEN-abc"} and dest["type"] == "http"
    assert dest["template"] == "infra-automation-webhook"
    by = o2.store["alert"]
    assert all(a["destinations"] == ["infra-automation-webhook"] and a["enabled"] for a in by.values())
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
    assert o2.auth == {"Basic " + base64.b64encode(b"cfg@example.com:API-PASSWORD-xyz").decode()}


@pytest.mark.parametrize("missing", ["api_user", "api_password", "alert_webhook_url"])
def test_missing_inputs_fail_before_any_request(o2, missing):
    res = _apply(o2, kv={k: v for k, v in KV.items() if k != missing})
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []


def test_webhook_without_token_sends_no_auth_header(o2):
    res = _apply(o2, kv={k: v for k, v in KV.items() if k != "alert_webhook_token"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.store["destination"]["infra-automation-webhook"]["headers"] == {}


def test_every_api_task_is_no_log_and_writes_are_skipped_in_check_mode():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    uri_tasks = [t for t in tasks if "ansible.builtin.uri" in t]
    assert uri_tasks and all(t.get("no_log") is True for t in uri_tasks)
    apply = next(t for t in tasks if t["name"].startswith("[O2C-020]"))
    assert apply["when"] == "not ansible_check_mode" and apply["changed_when"] is True
    reads = [t for t in tasks if t["name"][:9] in ("[O2C-010]", "[O2C-011]")]
    assert all(t["check_mode"] is False and t["changed_when"] is False for t in reads)


def test_no_secret_value_is_committed_in_the_role_or_playbook():
    text = "".join(p.read_text(encoding="utf-8") for p in [PLAYBOOK, *ROLE.rglob("*") ] if p.is_file())
    assert not re.search(r"https?://[^\s'\"]*(hooks|webhook)[^\s'\"]*/[A-Za-z0-9_-]{16,}", text)
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert not any(k for k in defaults if "password" in k or "token" in k)
