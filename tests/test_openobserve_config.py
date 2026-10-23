"""OpenObserve configuration as code (ADR-0008, Spec #93 / Ticket-2, seam 3).

``playbooks/openobserve_config.yml`` runs against a stateful fake OpenObserve HTTP server and the requests it receives
are asserted: first run creates everything, the second run changes nothing, a changed definition produces an update,
check mode writes nothing, and secrets never reach the output or the repository.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import subprocess
import threading
import time
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
    "infra-root-login-known", "infra-sudo-escalation-failure", "infra-oom-kill", "infra-disk-fs-errors",
    "infra-log-parse-errors-security-logs", "infra-log-parse-errors-system-logs",
    "infra-disk-usage-p2", "infra-disk-usage-p1", "infra-inode-usage-p2", "infra-inode-usage-p1",
    "infra-memory-usage-p2", "infra-memory-usage-p1",
    "infra-silent-host-p2", "infra-silent-host-p1", "infra-unreachable-host",
    "infra-backup-failure", "infra-integrity-check-failure", "infra-backup-missing", "infra-maintenance-missing",
    "infra-app-log-errors", "infra-app-telemetry-silent", "infra-keepalived-script-disabled",
    "infra-switch-config-change", "infra-switch-login-failures", "infra-switch-severity-critical",
    "infra-switch-mac-flap", "infra-switch-syslog-silent",   # 스위치 syslog(Spec #277)
    "infra-fortigate-admin-login-failures", "infra-fortigate-change-unapproved", "infra-fortigate-change-approved",
    "infra-fortigate-ha-failover", "infra-fortigate-critical-detection", "infra-fortigate-syslog-silent",   # 방화벽(Spec #282 / Ticket-3)
    "infra-ssh-bruteforce-success", "infra-account-change", "infra-sudo-risky-command", "infra-auditd-stopped",
    "infra-account-lockout",   # 보안 로그 알림(#318)
    "infra-raid-write-cache-disabled", "infra-raid-controller-fault", "infra-raid-logical-drive-degraded",
    "infra-raid-physical-drive-fault", "infra-raid-cache-battery-fault", "infra-raid-collection-error",
    "infra-host-status-silent",   # RAID 상태(#335)
}
# PromQL 알림 17개(#282 복원, #318 정비): name -> (severity, period, frequency, silence, operator, value, stream, pending minutes)
PROMQL_ALERTS = {
    "infra-cpu-usage-p1": ("P2 경고", 5, 5, 60, ">=", 90, "system_cpu_utilization", 15),
    "infra-cpu-usage-p2": ("P3 주의", 5, 5, 1440, ">=", 0, "system_cpu_utilization", 15),
    "infra-caddy-5xx-error-rate": ("P1 긴급", 10, 5, 60, ">=", 5, "caddy_http_request_duration_seconds_count", 0),
    "infra-caddy-4xx-error-rate": ("P3 주의", 10, 5, 1440, ">=", 5, "caddy_http_request_duration_seconds_count", 0),
    "infra-disk-fill-24h": ("P2 경고", 30, 30, 1440, ">=", 0, "system_filesystem_usage", 60),
    "infra-disk-fill-4h": ("P1 긴급", 10, 10, 60, ">=", 0, "system_filesystem_usage", 60),
    "infra-network-errors": ("P2 경고", 5, 5, 60, ">=", 0, "system_network_errors", 60),
    "infra-cpu-load-saturation": ("P2 경고", 5, 5, 60, ">=", 0, "system_cpu_load_average_1m", 15),
    "infra-cpu-iowait": ("P3 주의", 5, 5, 1440, ">", 10, "system_cpu_utilization", 15),
    "infra-cpu-steal": ("P3 주의", 5, 5, 1440, ">", 10, "system_cpu_utilization", 30),
    "infra-disk-io-saturation": ("P2 경고", 5, 5, 60, ">", 10, "system_disk_weighted_io_time", 30),
    "infra-disk-read-latency": ("P2 경고", 5, 5, 60, ">", 100, "system_disk_operation_time", 30),
    "infra-disk-write-latency": ("P2 경고", 5, 5, 60, ">", 100, "system_disk_operation_time", 30),
    "infra-inode-fill-24h": ("P2 경고", 30, 30, 1440, ">=", 0, "system_filesystem_inodes_usage", 60),
    "infra-conntrack-limit": ("P2 경고", 5, 5, 60, ">", 80, "system_network_conntrack_count", 0),
    "infra-swap-usage": ("P3 주의", 10, 5, 1440, ">", 80, "system_paging_utilization", 0),
    "infra-memory-pressure": ("P2 경고", 5, 5, 60, ">", 1000, "system_paging_faults", 15),
}
UPLINK_ALERT = "infra-switch-uplink-down"   # 업링크 목록(o2c_switch_uplinks)이 비어 있으면 만들어지지 않는다
UPLINKS = [{"device": "ns0250", "port": "Gi1/0/1"}]
RESOURCE_ALERTS = {  # name -> (severity, silence minutes, period minutes, stream)
    "infra-disk-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_usage"),
    "infra-disk-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_usage"),
    "infra-inode-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_inodes_usage"),
    "infra-inode-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_inodes_usage"),
    "infra-memory-usage-p2": ("P2 경고", 1440, 10, "system_linux_memory_available"),
    "infra-memory-usage-p1": ("P1 긴급", 60, 10, "system_linux_memory_available"),
}
SELFTEST = "infra-alert-selftest"   # 통지 경로 자가 시험 알림(Spec #184 / Ticket-2) — 검증 전용 스트림에 건다
SELFTEST_STREAM = "alert_selftest_alert_verify"


def _same_roster_alert(name, stored, sql):
    """Roster (absence) SQL of the same alert — the verification adds fake hosts to the roster, so the host names differ."""
    if name == UPLINK_ALERT:   # the verification adds the fake devices of the cases as watched ports — only that list differs
        pairs = lambda q: re.sub(r"AND \(\(device_id = .*\)\) GROUP BY", "AND (<pairs>) GROUP BY", q)   # noqa: E731
        return pairs(stored) == pairs(sql) != stored
    def is_roster(q):
        return any(f"AS {col}, count(*) AS n FROM" in q for col in ("host_name", "host", "device_id"))
    def shape(q):   # the roster hosts differ; the extra condition of each branch (e.g. job = 'backup' AND success = true) must match
        conds = (re.search(r"WHERE (?:(?:host|host_name|device_id) = '[^']*'(?: AND )?|\((?:(?:host|host_name|device_id) = '[^']*' OR )*(?:lower\(body\) LIKE '[^']*'(?: OR )?)*\) AND )?(.*?) HAVING", b) for b in q.split(" UNION ALL "))
        return {m.group(1) if m else "" for m in conds}
    return is_roster(stored) and is_roster(sql) and name.endswith("-p2") == ("count(*) >= 1" in sql) and shape(stored) == shape(sql)


def _case_host(rec):
    """The (fake) host of a synthetic record: backup_logs use host, switch syslog uses device_id, the others host_name."""
    return rec.get("host_name") or rec.get("host") or rec.get("device_id") or re.search(r'(?: |devname="?)(verify-\S+?)(?:-3560X:|"| )', rec["body"]).group(1)   # 변환 전 레코드는 원문에서


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
        self.trace_streams = {}   # 트레이스 스트림 이름 -> data_retention(일). 비어 있으면 아직 첫 span이 들어오지 않은 서버다
        self.missing_streams = {SELFTEST_STREAM}   # 아직 레코드가 없는 스트림 — 레코드가 들어오기 전에는 알림 생성이 404
        self.shorts = {}          # 단축 id -> 원본 URL (POST /api/default/short). 같은 원본이면 같은 id(멱등)
        self.short_collide = False   # 참이면 서버가 해시 충돌로 시각을 섞은 다른 id를 준다(실제 서버의 충돌 경로)
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
                run_ids = {_case_host(r).rsplit("-", 1)[1] for _, _, recs in outer.ingests for r in recs}
                for alert in outer.store["alert"].values():
                    prod = alert["stream_name"]
                    if alert["query_condition"]["type"] == "promql":
                        continue   # PromQL 알림은 합성 레코드 검증 대상이 아니다
                    stored = alert["query_condition"]["sql"].replace(f'"{prod}"', f'"{stream}"')
                    stored = re.sub(r'"(system_memory_limit)"', r'"\1_alert_verify"', stored)   # 두 번째 스트림(#259)
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
                if self.path.split("?")[0] == "/api/default/streams":
                    outer.reads.append(self.path)
                    assert self.path.endswith("type=traces")
                    return self._send(200, {"list": [{"name": n, "stream_type": "traces", "settings": {"data_retention": d}}
                                                     for n, d in outer.trace_streams.items()], "total": len(outer.trace_streams)})
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
                if path == "/api/default/short" and method == "POST":
                    original = body["original_url"]
                    digest = hashlib.md5((original + ("1792650000000000" if outer.short_collide else "")).encode()).hexdigest()
                    outer.shorts[digest[8:24]] = original
                    return self._send(200, {"short_url": "https://o2-server.example.test/web/short/%s?org_identifier=default" % digest[8:24]})
                m = re.fullmatch(r"/api/default/streams/([^/]+)/settings", path)
                if m and method == "PUT":
                    outer.writes.append((method, self.path, body))
                    outer.trace_streams[m.group(1)] = body["data_retention"]
                    return self._send(200, {"code": 200})
                kind, key = self._route()
                outer.writes.append((method, self.path, body))
                if kind is None:
                    return self._send(404, {})
                items = outer.store[kind]
                if method == "POST":
                    rec = dict(body)
                    if kind == "alert" and body["stream_name"] in outer.missing_streams and not any(
                            p.split("/")[3] == body["stream_name"] for p, _, _ in outer.ingests):
                        return self._send(404, {"code": 404, "message": "stream not found"})   # 실제 서버: 데이터 없는 스트림에는 알림을 못 만든다
                    if kind == "alert":
                        rec["alert_id"] = uuid.uuid4().hex
                    if kind == "pipeline":
                        rec["pipeline_id"] = uuid.uuid4().hex
                    items[body["name"]] = rec
                else:
                    if kind == "pipeline":
                        # 실제 서버: 갱신은 PUT /pipelines(본문의 pipeline_id). /pipelines/{id}는 조회·삭제 전용이라 PUT이 405다
                        if key is not None:
                            return self._send(405, {})
                        key = body["pipeline_id"]
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
    # 앱 텔레메트리 스위치는 OpenBao에서 읽고 토큰이 없으면 실패하므로, 기본은 "아무 호스트도 안 켬" 픽스처다(None이면 픽스처 없음).
    extra = {"o2c_verify_retries": 1, "o2c_verify_delay": 0, "o2c_app_telemetry_kv_fixture": {}, **(extra or {})}
    if extra["o2c_app_telemetry_kv_fixture"] is None:
        del extra["o2c_app_telemetry_kv_fixture"]
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
    assert paths[:7] == ["/api/default/alerts/templates", "/api/default/alerts/destinations", "/api/default/functions",
                         "/api/default/functions", "/api/default/functions", "/api/default/pipelines",
                         "/api/default/pipelines"]   # 함수 3개(보안·스위치·방화벽), 파이프라인 2개(보안 로그는 함수 둘을 잇는다)
    assert set(o2.store["alert"]) == EXPECTED_ALERTS | set(PROMQL_ALERTS) | {SELFTEST}
    assert paths[7:] == ["/api/v2/default/alerts"] * (len(EXPECTED_ALERTS) + len(PROMQL_ALERTS) + 1)


def test_template_body_is_a_naver_works_text_message(o2):
    """통지 본문은 네이버웍스 봇 형식 {"content": {"type": "text", "text": ...}} 이다."""
    assert _apply(o2).returncode == 0
    body = json.loads(o2.store["template"]["infra-automation-webhook"]["body"])
    assert body["content"]["type"] == "text"
    # 행동 가능한 알림: 심각도·제목·무슨 일·왜 중요·조치·런북·대상 행·대시보드 링크·발생 구간
    for var in ("{severity_icon}", "{severity}", "{title}", "{what}", "{why}", "{action}", "{runbook}",
                "{rows:10}", "{alert_count}", "{link_label}", "{alert_url}", "{alert_trigger_time_str}", "{alert_name}"):
        assert var in body["content"]["text"], var
    assert "\n" in body["content"]["text"] and "\\n" not in body["content"]["text"]   # 실제 줄바꿈
    # 시각 줄은 알림 평가 시각({alert_trigger_time_str})이고 KST다(OpenObserve 컨테이너가 호스트 /etc/localtime을 쓴다), 규칙은 다음 줄.
    # 결과 행 _timestamp 기반 변수는 최종 SELECT에 _timestamp가 없으면 비어 쓰지 않는다
    tpl = o2.store["template"]["infra-automation-webhook"]["body"]
    assert body["content"]["text"].endswith("\n⏱ 평가: {alert_trigger_time_str} KST\n📋 규칙: {alert_name}")
    assert "alert_start_time" not in tpl and "alert_end_time" not in tpl and "(UTC)" not in tpl


RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "alerts.md"
PROMQL_ROW_FIELDS = {"value", "host_name", "device", "mountpoint", "direction"}   # PromQL 행 템플릿이 쓸 수 있는 값(숫자 value와 안전한 레이블)


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
        for key in ("title", "what", "why"):
            assert ctx[key].strip() and '"' not in ctx[key] and "\n" not in ctx[key], (name, key)
        anchor = ctx["runbook"].split("#", 1)[1]
        assert ctx["runbook"].startswith("https://github.com/ppzxc/infra-automation/blob/main/docs/runbooks/alerts.md#")
        assert f'<a id="{anchor}"></a>' in runbook, (name, anchor)
        assert alert["row_template_type"] == "String" and alert["row_template"].startswith("• "), name
        # 행 템플릿의 {필드}는 모두 그 알림 SQL이 SELECT하는 컬럼이다
        import re as _re
        fields = set(_re.findall(r"\{(\w+)\}", alert["row_template"]))
        if alert["query_condition"]["type"] == "promql":   # 결과의 value와 시리즈 레이블
            assert fields and fields <= PROMQL_ROW_FIELDS and "value" in fields, (name, fields)
            continue
        assert fields and all(f in alert["query_condition"]["sql"] for f in fields), (name, fields)


def test_severity_mapping_follows_impact(o2):
    assert _apply(o2).returncode == 0
    sev = {n: a["context_attributes"]["severity"] for n, a in o2.store["alert"].items()}
    assert sev["infra-root-login-success"] == sev["infra-disk-fs-errors"] == "P1 긴급"
    assert sev["infra-ssh-login-failures-per-source"] == sev["infra-sudo-escalation-failure"] == sev["infra-oom-kill"] == "P2 경고"
    assert sev["infra-log-parse-errors-security-logs"] == "P3 주의"
    assert sev["infra-app-log-errors"] == "P2 경고"


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
    # 공격이 이어지면 5분이 아니라 15분마다 다시 알린다(2026-10-23, 대입 공격 하나에 하루 176통)
    for name in ("infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host"):
        assert by[name]["trigger_condition"]["silence"] == 15, name
    assert "count(DISTINCT source_address) >= 3" in by["infra-ssh-login-failures-per-host"]["query_condition"]["sql"]
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
    assert (method, path) == ("PUT", "/api/default/pipelines") and body["pipeline_id"] == pid and body["enabled"] is True


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


RETIRED = "infra-root-login-office-daily"   # 기본 폐기 목록의 한 건
UNMANAGED_LINE = "unmanaged infra- alert on server (kept): "


def test_only_alerts_on_the_retired_list_are_deleted_and_other_infra_alerts_are_kept_and_listed(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.store["alert"][RETIRED] = {"alert_id": "retired1", "name": RETIRED, "enabled": True}
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert [(m, p) for m, p, _ in o2.writes] == [("DELETE", "/api/v2/default/alerts/retired1")]
    assert RETIRED not in o2.store["alert"]
    assert "infra-old-renamed" in o2.store["alert"] and "team-custom-alert" in o2.store["alert"]
    assert UNMANAGED_LINE + "infra-old-renamed" in res.stdout and "team-custom-alert" not in res.stdout
    o2.writes.clear()
    assert _apply(o2).returncode == 0 and o2.writes == []


def test_check_mode_lists_the_retired_alert_to_delete_without_writing(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.store["alert"][RETIRED] = {"alert_id": "retired1", "name": RETIRED, "enabled": True}
    o2.writes.clear()
    res = _apply(o2, "--check")
    assert res.returncode == 0 and o2.writes == []
    assert f"delete alert {RETIRED}" in res.stdout and "delete alert infra-old-renamed" not in res.stdout
    assert UNMANAGED_LINE + "infra-old-renamed" in res.stdout


def test_a_name_added_to_the_retired_list_is_deleted(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.writes.clear()
    assert _apply(o2, extra={"o2c_retired_alerts": ["infra-old-renamed"]}).returncode == 0
    assert [(m, p) for m, p, _ in o2.writes] == [("DELETE", "/api/v2/default/alerts/stale1")]


@pytest.mark.parametrize("retired", [["Infra-Upper"], ["infra-"], ["other-alert"], ["infra-a", "infra-a"], ["infra-root-login-known"],
                                     ["infra x"], ["infra-a;drop"]])
def test_invalid_or_conflicting_retired_list_fails_before_any_request(o2, retired):
    res = _apply(o2, extra={"o2c_retired_alerts": retired})
    assert res.returncode != 0
    assert o2.reads == [] and o2.writes == [] and o2.ingests == []


def test_plan_only_reads_and_prints_the_plan_but_writes_and_injects_nothing(o2):
    assert _apply(o2).returncode == 0
    _seed_stale(o2)
    o2.store["alert"][RETIRED] = {"alert_id": "retired1", "name": RETIRED, "enabled": True}
    o2.store["function"]["security_semantics"]["function"] = "# drift\n."
    o2.writes.clear()
    o2.ingests.clear()
    o2.searches.clear()
    reads_before = len(o2.reads)
    res = _apply(o2, extra={"o2c_plan_only": True})
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(o2.reads) > reads_before
    assert o2.writes == [] and o2.ingests == [] and o2.searches == []
    assert f"delete alert {RETIRED}" in res.stdout and "update function security_semantics" in res.stdout
    assert UNMANAGED_LINE + "infra-old-renamed" in res.stdout
    assert "plan only: no changes were made" in res.stdout
    assert RETIRED in o2.store["alert"]


def test_plan_only_on_a_fresh_server_creates_nothing(o2):
    res = _apply(o2, extra={"o2c_plan_only": True})
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.writes == [] and o2.ingests == [] and o2.searches == []
    assert "create alert infra-root-login-success" in res.stdout and "plan only: no changes were made" in res.stdout
    assert all(not v for v in o2.store.values())


def test_plan_only_false_keeps_the_normal_apply(o2):
    res = _apply(o2, extra={"o2c_plan_only": False})
    assert res.returncode == 0, res.stdout + res.stderr
    assert o2.writes and o2.ingests and "plan only: no changes were made" not in res.stdout


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
    api_tasks = [t for t in tasks if "ansible.builtin.uri" in t or "o2c_http" in t]
    assert api_tasks and all(t.get("no_log") is True for t in api_tasks)
    apply = next(t for t in tasks if t["name"].startswith("[O2C-020]"))
    assert apply["when"] == "not ansible_check_mode" and apply["changed_when"] == "o2c_plan_actions | length > 0"
    assert "parallel" not in apply["o2c_http"]   # 쓰기는 계획된 순서(템플릿→대상→함수→파이프라인→알림)대로 하나씩 보낸다
    reads = [t for t in tasks if t["name"][:9] in ("[O2C-010]", "[O2C-011]")]
    assert all(t["check_mode"] is False and t["changed_when"] is False and t["o2c_http"]["parallel"] is True for t in reads)
    # 같은 모듈이 check 모드에서는 GET만 보내므로(모듈 테스트) 쓰기 태스크는 이중으로 막혀 있다
    assert all(t["o2c_http"].get("headers") for t in api_tasks if "o2c_http" in t)


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
    assert "o2c_org | o2c_read_requests" in read["o2c_http"]["requests"]


def test_no_secret_value_is_committed_in_the_role_or_playbook():
    text = "".join(p.read_text(encoding="utf-8") for p in [PLAYBOOK, *ROLE.rglob("*") ] if p.is_file())
    assert not re.search(r"https?://[^\s'\"]*(hooks|webhook)[^\s'\"]*/[A-Za-z0-9_-]{16,}", text)
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert not any(k for k in defaults if "password" in k or "token" in k)


# --- 알림 검증 단계 (Spec #184 / Ticket-1) --------------------------------------------------------------------------------

FIXTURES = yaml.safe_load((ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8"))


def test_every_existing_alert_has_a_firing_and_a_non_firing_fixture_with_a_unique_host():
    assert set(FIXTURES) == EXPECTED_ALERTS | {UPLINK_ALERT}
    hosts = [c["host"] for spec in FIXTURES.values() for c in spec["cases"]]
    assert len(hosts) == len(set(hosts))
    for name, spec in FIXTURES.items():
        assert {c["fires"] for c in spec["cases"]} == {True, False}, name


def test_verification_injects_synthetic_records_into_suffixed_streams_with_the_controller_token_and_searches_rewritten_sql(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    streams = {p.split("/")[3] for p, _, _ in o2.ingests}
    assert streams == {"security_logs_alert_verify", "system_logs_alert_verify", "system_filesystem_usage_alert_verify",
                       "system_filesystem_inodes_usage_alert_verify", "system_linux_memory_available_alert_verify", "system_memory_usage_alert_verify",   # Silent Host 하트비트
                       "system_memory_limit_alert_verify", "tcpcheck_status_alert_verify",
                       "backup_logs_alert_verify", "app_logs_alert_verify", "jvm_memory_used_alert_verify",
                       "host_status_logs_alert_verify", SELFTEST_STREAM}   # 마지막은 O2C-014가 빈 스트림을 만드는 시드
    assert {a for _, a, _ in o2.ingests} == {"Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()}
    assert len(o2.searches) == len(EXPECTED_ALERTS)
    for stream, sql in o2.searches:
        assert stream.endswith("_alert_verify") and 'FROM "security_logs"' not in sql and 'FROM "system_logs"' not in sql
        assert 'FROM "app_logs"' not in sql          # 운영 app_logs가 아니라 검증 스트림을 조회한다
    # 운영 스트림·운영 알림은 건드리지 않는다: 쓰기는 설정 객체뿐이고 합성 레코드는 검증 스트림에만 간다
    assert all("/_json" not in p for _, p, _ in o2.writes)
    hosts = {_case_host(r) for _, _, recs in o2.ingests for r in recs}
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


def test_replaced_kernel_disk_alert_is_kept_unless_it_is_retired(o2):
    assert _apply(o2).returncode == 0
    o2.store["alert"]["infra-kernel-disk-errors"] = {"alert_id": "old-kernel", "name": "infra-kernel-disk-errors", "enabled": True}
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    assert o2.writes == [] and "infra-kernel-disk-errors" in o2.store["alert"]
    assert _apply(o2, extra={"o2c_retired_alerts": ["infra-kernel-disk-errors"]}).returncode == 0
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


def test_known_root_login_alert_is_a_p2_event_alert_of_registered_and_private_sources(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    alert = o2.store["alert"]["infra-root-login-known"]
    sql = alert["query_condition"]["sql"]
    assert "infra-root-login-office-daily" not in o2.store["alert"]
    for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP):   # kind 무관: semaphore·office 모두 P2
        assert f"'{ip}'" in sql
    assert "user_name = 'root'" in sql and "NOT IN" not in sql and "source_address LIKE '10.%'" in sql
    assert alert["context_attributes"]["severity"] == "P2 경고"
    assert alert["context_attributes"]["runbook"].endswith("#root-login-known")
    trigger = alert["trigger_condition"]
    assert (trigger["period"], trigger["threshold"], trigger["silence"]) == (5, 1, 60)


def test_known_root_login_silence_comes_from_the_role_variable_and_must_be_an_integer(o2):
    assert _apply(o2, extra={"o2c_root_known_silence_minutes": 180}).returncode == 0
    assert o2.store["alert"]["infra-root-login-known"]["trigger_condition"]["silence"] == 180
    res = _apply(o2, extra={"o2c_root_known_silence_minutes": "1h"})
    assert res.returncode != 0


def test_private_ranges_are_plain_like_patterns_with_172_16_to_31_expanded(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    for name in ("infra-root-login-success", "infra-root-login-known"):
        sql = _sql(o2, name)
        for pat in ("10.%", "192.168.%", "127.%", "169.254.%", "172.16.%", "172.24.%", "172.31.%"):
            assert f"'{pat}'" in sql, (name, pat)
        assert "'172.15.%'" not in sql and "'172.32.%'" not in sql and "'172.%'" not in sql


def test_without_a_source_list_every_public_root_login_is_p1_and_private_ones_are_p2(o2):
    """normal_sources가 비어 있을 때: 공인 출발지는 모두 P1, 사설 대역은 P2, 등록 출발지 조건(IN)은 두지 않는다."""
    assert _apply(o2).returncode == 0
    assert "NOT IN" not in _sql(o2, "infra-root-login-success")
    known = _sql(o2, "infra-root-login-known")
    assert " IN (" not in known and "source_address LIKE '10.%'" in known and "IN ('')" not in known


def _root_rows(o2, kv, records):
    """Both root alert SQLs run on sqlite over the records; returns the sets of fired hosts (P1, P2)."""
    assert _apply(o2, kv=kv).returncode == 0
    fired = []
    for name in ("infra-root-login-success", "infra-root-login-known"):
        sql = _sql(o2, name).replace('"security_logs"', '"t"')
        fired.append({r["host_name"] for r in _run_alert_on_sqlite(sql, records, "t")})
    return fired


def _login(host, source, user="root", outcome="success"):
    return {"host_name": host, "event_action": "ssh_login", "event_outcome": outcome, "user_name": user, "source_address": source}


ROOT_CASES = [  # (host, source, user, outcome, P1, P2)
    ("public", "198.51.100.7", "root", "success", True, False),
    ("semaphore", SEMAPHORE_IP, "root", "success", False, True),
    ("office", OFFICE_IP, "root", "success", False, True),
    ("s2s", OFFICE_S2S_IP, "root", "success", False, True),
    ("private-10", "10.0.0.8", "root", "success", False, True),
    ("private-172-16", "172.16.0.8", "root", "success", False, True),
    ("private-172-31", "172.31.255.1", "root", "success", False, True),
    ("private-192-168", "192.168.0.8", "root", "success", False, True),
    ("loopback", "127.0.0.1", "root", "success", False, True),
    ("linklocal", "169.254.1.1", "root", "success", False, True),
    ("public-172-32", ".".join(("172", "32", "0", "1")), "root", "success", True, False),
    ("public-172-15", ".".join(("172", "15", "0", "1")), "root", "success", True, False),
    ("public-near-192", ".".join(("192", "169", "0", "1")), "root", "success", True, False),
    ("no-source", None, "root", "success", True, False),
    ("other-user-public", "198.51.100.7", "deploy", "success", False, False),
    ("other-user-private", "10.0.0.8", "deploy", "success", False, False),
    ("failed-public", "198.51.100.7", "root", "failure", False, False),
    ("failed-registered", SEMAPHORE_IP, "root", "failure", False, False),
]


def test_root_alert_sql_splits_logins_into_p1_external_and_p2_known_on_the_real_rows(o2):
    p1, p2 = _root_rows(o2, KV_SOURCES, [_login(h, src, u, o) for h, src, u, o, _, _ in ROOT_CASES])
    assert p1 == {h for h, _, _, _, a, _ in ROOT_CASES if a}
    assert p2 == {h for h, _, _, _, _, b in ROOT_CASES if b}
    assert not p1 & p2   # 한 로그인은 한 계층에만 걸린다


def test_root_alert_sql_with_an_empty_source_list_sends_public_to_p1_and_private_to_p2(o2):
    p1, p2 = _root_rows(o2, KV, [_login(h, src, u, o) for h, src, u, o, _, _ in ROOT_CASES])
    registered = {"semaphore", "office", "s2s"}   # 목록이 비면 192.0.2.x는 그냥 공인 출발지다
    assert registered <= p1 and not registered & p2
    assert {"private-10", "loopback", "linklocal", "private-172-16"} <= p2 and not {"private-10", "loopback"} & p1


def test_ssh_failure_alerts_ignore_the_normal_source_list(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    for name in ("infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host"):
        assert not any(ip in _sql(o2, name) for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP)), name


def test_changing_the_source_list_updates_only_the_root_alerts(o2):
    assert _apply(o2, kv=KV_SOURCES).returncode == 0
    o2.writes.clear()
    moved = dict(KV, normal_sources=[{"address": "192.0.2.99", "kind": "office"}])
    assert _apply(o2, kv=moved).returncode == 0
    ids = {o2.store["alert"][n]["alert_id"] for n in ("infra-root-login-success", "infra-root-login-known")}
    assert {p.rsplit("/", 1)[1] for _, p, _ in o2.writes} == ids and all(m == "PUT" for m, _, _ in o2.writes)


def test_source_addresses_never_reach_the_output(o2):
    res = _apply(o2, "-vvv", kv=KV_SOURCES)
    assert res.returncode == 0, res.stdout + res.stderr
    for ip in (SEMAPHORE_IP, OFFICE_IP, OFFICE_S2S_IP):
        assert ip not in res.stdout + res.stderr


@pytest.mark.parametrize("bad", [{"address": "192.0.2.4' OR '1'='1", "kind": "office"},
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
    hosts = {_case_host(r) for _, _, rs in o2.ingests for r in rs}
    assert not any(h.startswith(("verify-root-semaphore-", "verify-root-office-", "verify-known-semaphore-", "verify-known-office-")) for h in hosts)
    assert any(h.startswith("verify-root-external-") for h in hosts)


def test_root_fixtures_cover_every_tier_for_both_root_alerts():
    cases = lambda n: {c["host"]: c["fires"] for c in FIXTURES[n]["cases"]}  # noqa: E731
    p1, p2 = cases("infra-root-login-success"), cases("infra-root-login-known")
    assert p1["verify-root-external"] is True and p1["verify-root-semaphore"] is False and p1["verify-root-office"] is False
    assert p1["verify-root-private"] is False and p1["verify-root-failure"] is False and p1["verify-root-other-user"] is False
    assert p2["verify-known-semaphore"] is True and p2["verify-known-office"] is True and p2["verify-known-private"] is True
    assert p2["verify-known-external"] is False and p2["verify-known-other-user"] is False and p2["verify-known-failure"] is False


def test_a_committed_file_never_holds_a_real_looking_internal_address():
    """가짜 OpenObserve 테스트와 픽스처는 문서용 대역(192.0.2/198.51.100/203.0.113)만 쓴다."""
    text = (ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8") + (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "10.0.0.")), ip   # 10.0.0.x는 미등록 사설 대역 케이스용 가짜 값


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


def test_unreachable_host_is_a_p1_state_alert_on_tcpcheck_status_zero_for_5_minutes(o2):
    assert _apply(o2).returncode == 0
    a = o2.store["alert"]["infra-unreachable-host"]
    assert a["stream_type"] == "metrics" and a["stream_name"] == "tcpcheck_status"
    assert a["context_attributes"]["severity"] == "P1 긴급"
    assert a["trigger_condition"]["period"] == 5 and a["trigger_condition"]["silence"] == 60
    sql = a["query_condition"]["sql"]
    assert "max(value) = 0" in sql and "tcpcheck_endpoint" in sql
    assert "{tcpcheck_endpoint}" in a["row_template"]


def test_existing_log_alerts_stay_logs(o2):
    assert _apply(o2).returncode == 0
    for name in EXPECTED_ALERTS - set(RESOURCE_ALERTS) - {"infra-silent-host-p2", "infra-silent-host-p1", "infra-unreachable-host", "infra-app-telemetry-silent"}:
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
    assert "GROUP BY host_name, _timestamp" in mem and "min(pct)" in mem


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


def test_every_alert_carries_the_top_level_kst_tz_offset_and_converges(o2):
    """tz_offset은 trigger_condition이 아니라 알림 최상위 필드다. 로그·PromQL·자가 시험 알림 모두 540(KST)이고 2회차는 변경 0건이다."""
    assert _apply(o2).returncode == 0
    assert len(o2.store["alert"]) == len(EXPECTED_ALERTS) + len(PROMQL_ALERTS) + 1
    for name, a in o2.store["alert"].items():
        assert a["tz_offset"] == 540 and "tz_offset" not in a["trigger_condition"], name
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and _changed(res) == 0


def test_tz_offset_is_a_variable_and_a_changed_value_updates_every_alert_once(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2, extra={"o2c_tz_offset": 0})
    assert res.returncode == 0
    assert {w[0] for w in o2.writes} == {"PUT"} and len(o2.writes) == len(o2.store["alert"])
    assert {a["tz_offset"] for a in o2.store["alert"].values()} == {0}


def test_desired_alert_tz_offset_defaults_to_zero_without_the_spec_key():
    alert = dict(PROMQL_DEFS[0], action="① a ② b")
    assert _alert_bodies(_desired_spec([alert]))[alert["name"]]["tz_offset"] == 0
    assert _alert_bodies(dict(_desired_spec([alert]), tz_offset=540))[alert["name"]]["tz_offset"] == 540


def test_selftest_record_and_row_template_carry_a_quote_and_backslash_probe(o2):
    """행 값의 따옴표·역슬래시가 webhook JSON을 깨는지 통지에서 눈으로 확인할 수 있게 시험 레코드에 `a"b\\c`를 싣고 행 템플릿이 그것을 쓴다."""
    assert _apply(o2).returncode == 0
    o2.ingests.clear()
    assert _apply(o2, extra={"o2c_verify_notify": True}).returncode == 0
    (record,) = _selftest_ingests(o2)[0][2]
    assert record["probe"] == 'a"b\\c' and '"' in record["probe"] and "\\" in record["probe"]
    alert = o2.store["alert"][SELFTEST]
    assert "{probe}" in alert["row_template"] and "probe" in alert["query_condition"]["sql"]
    assert not re.search(r'["\\]', alert["row_template"])   # 템플릿 자체는 따옴표·역슬래시를 만들지 않는다


def test_selftest_notification_is_clearly_marked_as_a_test(o2):
    assert _apply(o2).returncode == 0
    ctx = o2.store["alert"][SELFTEST]["context_attributes"]
    assert ctx["severity"] == "TEST"       # 통지 첫 줄이 "<아이콘> [TEST] <제목>"이 된다
    assert all(ctx[k].strip() and '"' not in ctx[k] and "\n" not in ctx[k] for k in ("title", "what", "why", "runbook"))
    assert ctx["action"].startswith("\n1. ") and '"' not in ctx["action"]
    assert "시험" in ctx["title"] and o2.store["alert"][SELFTEST]["row_template"].startswith("• ")


def test_first_run_seeds_the_missing_selftest_stream_with_one_past_record_before_creating_its_alert(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    sent = _selftest_ingests(o2)
    assert len(sent) == 1 and len(sent[0][2]) == 1
    assert sent[0][1] == "Basic " + base64.b64encode(b"default:INGEST-TOKEN-qrs").decode()
    # 알림 조회 구간(5분)보다 오래된 시각이라 시드 레코드로는 통지가 나가지 않는다
    age_s = time.time() - sent[0][2][0]["_timestamp"] / 1_000_000
    assert age_s > o2.store["alert"][SELFTEST]["trigger_condition"]["period"] * 60 and age_s < 5 * 3600
    assert SELFTEST in o2.store["alert"]


def test_default_run_sends_no_selftest_record_once_the_selftest_alert_exists(o2):
    assert _apply(o2).returncode == 0
    o2.ingests.clear()
    assert _apply(o2).returncode == 0
    assert _selftest_ingests(o2) == []


def test_selftest_seed_is_skipped_in_check_mode(o2):
    res = _apply(o2, "--check")
    assert res.returncode == 0 and o2.ingests == []


def test_verify_notify_injects_exactly_one_selftest_record_with_the_controller_token(o2):
    assert _apply(o2).returncode == 0
    o2.ingests.clear()
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


SERVERS = ["ns0001", "ns0002", "ns0003", "ns0004", "ns0266", "ns0331"]


def test_silent_host_roster_is_servers_minus_exclusion_and_backup_only_and_keeps_ns0266_and_ns0331(o2, tmp_path):
    inv = _inventory(tmp_path, SERVERS, excluded=["ns0002"], backup_only=["ns0003"])
    res = _apply(o2, inventory=inv)
    assert res.returncode == 0, res.stdout + res.stderr
    for name in ("infra-silent-host-p2", "infra-silent-host-p1"):
        sql = _sql(o2, name)
        assert _branch_hosts(sql) == {"ns0001", "ns0004", "ns0266", "ns0331"}, name
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
                                                         "infra-backup-missing", "infra-maintenance-missing",
                                                         "infra-host-status-silent")}
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
    assert _branch_hosts_as(backup["query_condition"]["sql"]) == {"ns0001", "ns0004", "ns0266", "ns0331"}
    assert _branch_hosts_as(maint["query_condition"]["sql"]) == {"ns0001", "ns0003", "ns0004", "ns0266", "ns0331"}


def test_backup_missing_action_starts_with_the_silent_host_check_and_runbook_anchors_exist(o2, tmp_path):
    assert _apply(o2, inventory=_inventory(tmp_path, SERVERS)).returncode == 0
    ctx = o2.store["alert"]["infra-backup-missing"]["context_attributes"]
    assert ctx["action"].startswith("\n1. 같은 호스트의 Silent Host 알림이 있는지 먼저 확인")
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


# --- 요청 일괄 처리 모듈 o2c_http와 필터 (Issue #207: Config 속도) -----------------------------------------------------------
import sys  # noqa: E402

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from openobserve_config import o2c_as_requests, o2c_verify_pending  # noqa: E402


def test_as_requests_builds_path_body_label_and_keeps_the_original_item():
    items = [{"kind": "alert", "path": "/api/default/alerts", "op": "create", "name": "a", "body": {"x": 1}}]
    assert o2c_as_requests(items, method_key="method", default_method="POST", body_key="body", label="{op} {kind} {name}") == [
        {"path": "/api/default/alerts", "method": "POST", "body": {"x": 1}, "label": "create alert a", "item": items[0]}]
    alerts = [{"alert_id": "abc", "name": "n1"}]
    assert o2c_as_requests(alerts, path="/api/v2/default/alerts/{alert_id}", label="{name}") == [
        {"path": "/api/v2/default/alerts/abc", "method": "GET", "body": None, "label": "n1", "item": alerts[0]}]


def _search(alert, fires_host, hosts):
    return {"alert": alert, "row_key": "host_name",
            "hosts": {h: {"case": c, "fires": f, "known_failure": None} for h, (c, f) in hosts.items()}}


def test_verify_pending_lists_alerts_that_do_not_match_yet_or_whose_request_failed():
    ok = _search("a1", None, {"h1": ("fires", True), "h2": ("quiet", False)})
    pend = _search("a2", None, {"h3": ("fires", True)})
    down = _search("a3", None, {"h4": ("fires", True)})
    results = [{"item": ok, "status": 200, "json": {"hits": [{"host_name": "h1"}]}},
               {"item": pend, "status": 200, "json": {"hits": []}},
               {"item": down, "status": -1}]
    assert o2c_verify_pending(results) == ["a2", "a3"]
    assert o2c_verify_pending([results[0]]) == []


def _module_play(tmp_path, url, module_args, check=False):
    play = tmp_path / "m.yml"
    play.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "tasks": [
        {"name": "go", "o2c_http": module_args, "register": "r", "ignore_errors": True},
        {"copy": {"content": "{{ r | to_json }}", "dest": str(tmp_path / "out.json")}, "check_mode": False}]}]))
    cmd = ["ansible-playbook", "-i", "localhost,", str(play), "-M", str(ROLE / "library"), "-e", "ansible_python_interpreter=" + sys.executable]
    if check:
        cmd.append("--check")
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    return res, (json.loads((tmp_path / "out.json").read_text()) if (tmp_path / "out.json").exists() else None)


class _Echo(BaseHTTPRequestHandler):
    seen = []

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        _Echo.seen.append((self.command, self.path, body, self.headers.get("Authorization"), self.headers.get("Content-Type")))
        status = 404 if self.path.startswith("/missing") else 200
        data = json.dumps({"path": self.path, "echo": body}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _do  # noqa: N815

    def log_message(self, *a):
        pass


@pytest.fixture()
def echo():
    _Echo.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _reqs(*specs):
    return [{"path": p, "method": m, "body": b, "label": f"{m} {p}", "item": {"n": i}} for i, (m, p, b) in enumerate(specs)]


def test_module_returns_results_in_request_order_with_status_json_and_item(tmp_path, echo):
    reqs = _reqs(("GET", "/a", None), ("POST", "/b", {"k": "v"}), ("GET", "/c", None))
    res, out = _module_play(tmp_path, echo, {"base_url": echo, "requests": reqs, "headers": {"Authorization": "Basic SECRET"}, "parallel": True})
    assert res.returncode == 0, res.stdout + res.stderr
    assert [r["item"]["n"] for r in out["results"]] == [0, 1, 2]
    assert [r["status"] for r in out["results"]] == [200, 200, 200]
    assert out["results"][1]["json"]["path"] == "/b" and json.loads(out["results"][1]["json"]["echo"]) == {"k": "v"}
    sent = {(m, p): (a, c) for m, p, _, a, c in _Echo.seen}
    assert sent[("POST", "/b")] == ("Basic SECRET", "application/json")


def test_module_fails_on_a_status_outside_the_allowed_list_and_names_the_request_but_not_the_secret(tmp_path, echo):
    reqs = _reqs(("GET", "/a", None), ("GET", "/missing", None))
    res, out = _module_play(tmp_path, echo, {"base_url": echo, "requests": reqs, "headers": {"Authorization": "Basic SECRET"}})
    text = res.stdout + res.stderr
    assert out["failed"] is True and "404" in out["msg"] and "GET /missing" in out["msg"]
    assert "SECRET" not in text and "SECRET" not in json.dumps(out)


def test_module_records_the_status_without_failing_when_asked_and_runs_writes_in_order(tmp_path, echo):
    reqs = _reqs(("POST", "/1", {}), ("PUT", "/missing", {}), ("DELETE", "/3", {}))
    res, out = _module_play(tmp_path, echo, {"base_url": echo, "requests": reqs, "headers": {}, "fail_on_status": False})
    assert out.get("failed") is not True
    assert [r["status"] for r in out["results"]] == [200, 404, 200]
    assert [(m, p) for m, p, *_ in _Echo.seen] == [("POST", "/1"), ("PUT", "/missing"), ("DELETE", "/3")]   # 순서대로


def test_module_does_not_send_writes_in_check_mode_but_still_reads(tmp_path, echo):
    reqs = _reqs(("GET", "/r", None), ("POST", "/w", {}))
    res, out = _module_play(tmp_path, echo, {"base_url": echo, "requests": reqs, "headers": {}}, check=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert [(m, p) for m, p, *_ in _Echo.seen] == [("GET", "/r")]
    assert [r["status"] for r in out["results"]] == [200, None] and out["results"][1]["skipped"] is True


def test_module_reports_a_connection_failure_as_status_minus_one_when_not_failing(tmp_path):
    res, out = _module_play(tmp_path, "http://127.0.0.1:1", {"base_url": "http://127.0.0.1:1", "requests": _reqs(("GET", "/a", None)),
                                                              "headers": {}, "fail_on_status": False, "timeout": 2})
    assert out["results"][0]["status"] == -1


def test_app_log_error_alert_is_a_p2_event_alert_on_error_or_worse_per_host_and_container(o2):
    """컨테이너 로그 ERROR 알림(Spec #236): severity가 error 이상인 줄만, 호스트·컨테이너별 5분 1건부터. WARN 이하와 레벨 없는 줄은 알리지 않는다."""
    assert _apply(o2).returncode == 0
    alert = o2.store["alert"]["infra-app-log-errors"]
    sql = alert["query_condition"]["sql"]
    assert alert["stream_name"] == "app_logs" and alert["stream_type"] == "logs"
    assert "lower(severity) IN (" in sql and "GROUP BY host_name, container_name" in sql
    for level in ("'error'", "'fatal'", "'critical'", "'panic'", "'dpanic'"):
        assert level in sql, level
    assert "'warn'" not in sql and "'info'" not in sql and "body" not in sql      # 키워드가 아니라 파싱된 레벨만 본다
    assert alert["trigger_condition"]["period"] == 5 and alert["trigger_condition"]["silence"] == 5
    assert alert["context_attributes"]["severity"] == "P2 경고"


# --- app_traces 보존 기간과 앱 텔레메트리 무소식 알림 (Spec #253 / Ticket-8) ---------------------------------------------
SETTINGS_PATH = "/api/default/streams/app_traces/settings?type=traces"
APP_ALERT = "infra-app-telemetry-silent"


def _settings_writes(o2):
    return [w for w in o2.writes if "/settings" in w[1]]


def test_traces_retention_step_skips_when_the_stream_is_absent_and_does_not_fail(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert _settings_writes(o2) == [] and o2.trace_streams == {}
    assert any(r.endswith("/api/default/streams?type=traces") for r in o2.reads)   # 존재 여부는 읽어서 확인한다


def test_traces_retention_is_set_to_30_days_when_present_and_the_second_run_changes_nothing(o2):
    o2.trace_streams["app_traces"] = 0   # 0 = 서버 전역 값(365일)을 따름
    assert _apply(o2).returncode == 0
    assert _settings_writes(o2) == [("PUT", SETTINGS_PATH, {"data_retention": 30})]
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and _settings_writes(o2) == [] and o2.writes == []


def test_second_run_reports_changed_0_with_the_retention_already_in_place(o2):
    o2.trace_streams["app_traces"] = 0
    assert _apply(o2).returncode == 0
    res = _apply(o2)
    assert res.returncode == 0 and _changed(res) == 0, res.stdout


def test_only_the_app_traces_stream_is_touched(o2):
    o2.trace_streams.update({"app_traces": 30, "other_traces": 0})
    assert _apply(o2).returncode == 0 and _settings_writes(o2) == []


def test_check_mode_plans_the_retention_but_writes_nothing(o2):
    o2.trace_streams["app_traces"] = 365
    res = _apply(o2, "--check")
    assert res.returncode == 0 and o2.writes == [] and "update trace_stream app_traces" in res.stdout


def _app_kv(*hosts, off=()):
    return {h: {"otel_app_telemetry": True} for h in hosts} | {h: {"otel_app_telemetry": False} for h in off}


def _app_apply(o2, tmp_path, kv_by_host, **kw):
    extra = {"o2c_app_telemetry_kv_fixture": kv_by_host}
    return _apply(o2, inventory=_inventory(tmp_path, SERVERS, **kw), extra=extra)


def test_app_telemetry_silent_roster_holds_only_hosts_with_the_switch_on(o2, tmp_path):
    kv = _app_kv("ns0001", "ns0004", off=["ns0002"])   # ns0003은 키가 없다(꺼짐), ns0002는 명시적으로 꺼짐
    res = _app_apply(o2, tmp_path, kv)
    assert res.returncode == 0, res.stdout + res.stderr
    assert _branch_hosts(_sql(o2, APP_ALERT)) == {"ns0001", "ns0004"}


def test_app_telemetry_roster_ignores_hosts_outside_the_collect_roster_and_planned_stops(o2, tmp_path):
    kv = dict(KV, silent_host_exceptions=[{"host": "ns0004", "expires": "2999-12-31"}])
    fixture = _app_kv("ns0001", "ns0002", "ns0003", "ns0004", "ns0999")
    res = _apply(o2, kv=kv, inventory=_inventory(tmp_path, SERVERS, excluded=["ns0002"], backup_only=["ns0003"]),
                 extra={"o2c_app_telemetry_kv_fixture": fixture})
    assert res.returncode == 0, res.stdout + res.stderr
    assert _branch_hosts(_sql(o2, APP_ALERT)) == {"ns0001"}


def test_app_telemetry_roster_is_empty_when_no_host_has_the_switch_and_never_fires(o2, tmp_path):
    assert _app_apply(o2, tmp_path, {}).returncode == 0
    sql = _sql(o2, APP_ALERT)
    assert _branch_hosts(sql) == {"none"} and "HAVING count(*) < 0" in sql


def test_app_telemetry_silent_follows_the_state_alert_rules(o2, tmp_path):
    assert _app_apply(o2, tmp_path, _app_kv("ns0001", "ns0004")).returncode == 0
    a = o2.store["alert"][APP_ALERT]
    sql = a["query_condition"]["sql"]
    assert a["stream_type"] == "metrics" and a["stream_name"] == "jvm_memory_used" and a["query_condition"]["type"] == "sql"
    assert "service_name = 'funa'" in sql and "HAVING count(*) < 1" in sql and "UNION ALL" in sql
    assert a["trigger_condition"]["period"] == 15 and a["trigger_condition"]["frequency"] == 5
    assert a["trigger_condition"]["silence"] == 1440 and a["context_attributes"]["severity"] == "P2 경고"
    assert "{host_name}" in a["row_template"] and a["destinations"] == ["infra-automation-webhook"]
    for banned in ("VALUES", "unnest", "JOIN"):
        assert banned.lower() not in sql.lower()


def test_switching_a_host_on_changes_only_the_app_alert_and_a_rerun_writes_nothing(o2, tmp_path):
    inv = _inventory(tmp_path, SERVERS)
    on = {"o2c_app_telemetry_kv_fixture": _app_kv("ns0001")}
    assert _apply(o2, inventory=inv, extra=on).returncode == 0
    o2.writes.clear()
    assert _apply(o2, inventory=inv, extra=on).returncode == 0 and o2.writes == []
    assert _apply(o2, inventory=inv, extra={"o2c_app_telemetry_kv_fixture": _app_kv("ns0001", "ns0004")}).returncode == 0
    assert [(m, p) for m, p, _ in o2.writes] == [("PUT", f"/api/v2/default/alerts/{o2.store['alert'][APP_ALERT]['alert_id']}")]


def test_app_telemetry_fixtures_cover_firing_and_quiet_cases_and_verification_uses_the_roster_sql(o2, tmp_path):
    cases = FIXTURES[APP_ALERT]["cases"]
    assert {c["fires"] for c in cases} == {True, False}
    assert all(r.get("service_name") for c in cases for r in c["records"])
    res = _app_apply(o2, tmp_path, _app_kv("ns0001"))
    assert res.returncode == 0, res.stdout + res.stderr
    searched = next(sql for stream, sql in o2.searches if stream == "jvm_memory_used_alert_verify")
    for c in cases:
        assert any(h.startswith(c["host"] + "-") for h in _branch_hosts(searched)), c["host"]
    assert "ns0001" in _branch_hosts(searched)


def test_missing_openbao_token_fails_instead_of_emptying_the_app_telemetry_roster(o2, tmp_path, monkeypatch):
    for var in ("VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        monkeypatch.delenv(var, raising=False)
    res = _apply(o2, inventory=_inventory(tmp_path, SERVERS), extra={"o2c_app_telemetry_kv_fixture": None})   # roster has hosts, no switch fixture, no token
    assert res.returncode != 0
    assert "OpenBao" in res.stdout and "O2C-004" not in res.stderr
    assert o2.writes == []


def test_app_telemetry_roster_lookup_task_is_read_only_and_no_log():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    t = next(t for t in tasks if t["name"].startswith("[O2C-004]"))
    assert t["no_log"] is True and t["changed_when"] is False and t["check_mode"] is False
    assert "o2c_app_telemetry_kv_fixture is not defined" in str(t["when"])


# --- 메모리 사용률 알림: 1 - available / limit (Spec #253 / Ticket-6, #259) -------------------------------------------------
import sqlite3

MEM_ALERTS = ("infra-memory-usage-p2", "infra-memory-usage-p1")


def test_memory_alert_sql_uses_available_and_limit_streams_not_usage_states(o2):
    assert _apply(o2).returncode == 0
    for name in MEM_ALERTS:
        sql = _sql(o2, name)
        assert '"system_linux_memory_available"' in sql and '"system_memory_limit"' in sql, name
        assert "system_memory_usage" not in sql and "slab_unreclaimable" not in sql and "state" not in sql, name


def _run_memory_alert_on_sqlite(sql, case):
    """Execute the rendered alert SQL on the case's synthetic records (portable SQL subset) and return the firing hosts."""
    db = sqlite3.connect(":memory:")
    for stream in ("system_linux_memory_available", "system_memory_limit"):
        db.execute(f'CREATE TABLE "{stream}" (host_name TEXT, _timestamp INTEGER, value INTEGER)')   # 합성 레코드는 정수로 적재된다(나눗셈이 잘리면 안 된다)
    for rec in case["records"]:
        stream = rec.get("stream", "system_linux_memory_available")
        for t in (rec["ts"] if isinstance(rec["ts"], list) else [rec["ts"]]):
            db.execute(f'INSERT INTO "{stream}" VALUES (?, ?, ?)', (case["host"], t, rec["value"]))
    return {r[0] for r in db.execute(sql)}


@pytest.mark.parametrize("name", MEM_ALERTS)
def test_memory_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs(o2, name):
    assert _apply(o2).returncode == 0
    sql = _sql(o2, name)
    for case in FIXTURES[name]["cases"]:
        fired = _run_memory_alert_on_sqlite(sql, case)
        assert (case["host"] in fired) == case["fires"], (name, case["name"])


def test_memory_alert_fixtures_include_a_host_missing_either_stream(o2):
    for name in MEM_ALERTS:
        cases = FIXTURES[name]["cases"]
        only_avail = [c for c in cases if {r.get("stream", "system_linux_memory_available") for r in c["records"]} == {"system_linux_memory_available"}]
        only_limit = [c for c in cases if {r.get("stream", "system_linux_memory_available") for r in c["records"]} == {"system_memory_limit"}]
        assert only_avail and only_limit, name
        assert all(not c["fires"] for c in only_avail + only_limit), name


def test_memory_alert_keeps_thresholds_severity_and_silence_and_openbao_overrides(o2):
    kv = dict(KV, alert_resource_exclusions=[{"host": "ns0288", "metric": "memory"}],
              alert_resource_thresholds=[{"host": "ns0300", "metric": "memory", "p2": 97, "p1": 99}])
    assert _apply(o2, kv=kv).returncode == 0
    p2, p1 = _sql(o2, "infra-memory-usage-p2"), _sql(o2, "infra-memory-usage-p1")
    assert "THEN 97" in p2 and "THEN 99" in p1
    assert "ns0288" in p2 and "ns0288" in p1 and "THEN 99" in p1
    for name in MEM_ALERTS:
        sev, silence, period, _ = RESOURCE_ALERTS[name]
        a = o2.store["alert"][name]
        assert (a["trigger_condition"]["period"], a["trigger_condition"]["silence"]) == (period, silence)


# --- 스위치 syslog 필드 추출과 로그 알림 (Spec #277) ----------------------------------------------------------------------
from openobserve_config import (o2c_enabled_alerts, o2c_switch_noise_filter, o2c_switch_uplink_sql,  # noqa: E402
                                o2c_valid_switch_events, o2c_valid_switch_roster, o2c_valid_switch_uplinks)

SWITCH_ALERTS = {   # name -> (severity, period minutes, silence minutes)
    "infra-switch-config-change": ("P2 경고", 5, 5),
    "infra-switch-login-failures": ("P2 경고", 5, 5),
    "infra-switch-severity-critical": ("P1 긴급", 5, 5),
    "infra-switch-mac-flap": ("P2 경고", 10, 60),
    "infra-switch-syslog-silent": ("P2 경고", 1440, 1440),
}
SWITCH_FN = "switch_syslog_semantics"


def test_switch_alerts_are_created_on_system_logs_with_the_specified_grades_and_windows(o2):
    assert _apply(o2).returncode == 0
    for name, (sev, period, silence) in SWITCH_ALERTS.items():
        a = o2.store["alert"][name]
        assert a["stream_name"] == "system_logs" and a["stream_type"] == "logs", name
        assert a["context_attributes"]["severity"] == sev, name
        assert (a["trigger_condition"]["period"], a["trigger_condition"]["silence"]) == (period, silence), name
        assert a["destinations"] == ["infra-automation-webhook"] and a["enabled"], name
        assert "switch-syslog" in a["query_condition"]["sql"], name


def test_switch_function_and_pipeline_are_added_beside_the_security_ones_and_the_security_pipeline_is_untouched(o2):
    assert _apply(o2).returncode == 0
    assert set(o2.store["function"]) == {"security_semantics", SWITCH_FN, FORTIGATE_FN}
    fn = o2.store["function"][SWITCH_FN]
    assert fn["function"] == (ROLE / "files" / "vrl" / "switch_syslog_semantics.vrl").read_text().strip() and fn["params"] == "row"
    pl = o2.store["pipeline"][SWITCH_FN]
    assert pl["source"]["stream_name"] == "system_logs" and pl["source"]["source_type"] == "realtime" and pl["enabled"] is True
    node = next(n["data"] for n in pl["nodes"] if n["data"]["node_type"] == "function")
    assert node["name"] == SWITCH_FN and node["after_flatten"] is True
    # 서버 로그를 거르는 일은 함수 안의 service_name 검사가 한다(조건 노드는 쓰지 않는다)
    assert not [n for n in pl["nodes"] if n["data"]["node_type"] == "condition"]
    assert o2.store["pipeline"]["security_semantics"]["source"]["stream_name"] == "security_logs"


FORTIGATE_FN = "fortigate_semantics"


def test_firewall_function_runs_in_the_security_pipeline_right_after_the_security_function(o2):
    """Spec #282 / Ticket-2: one pipeline per source stream, so the firewall function is chained, not a second pipeline on security_logs."""
    assert _apply(o2).returncode == 0
    fn = o2.store["function"][FORTIGATE_FN]
    assert fn["function"] == (ROLE / "files" / "vrl" / "fortigate_semantics.vrl").read_text().strip() and fn["params"] == "row"
    assert set(o2.store["pipeline"]) == {"security_semantics", SWITCH_FN}
    pl = o2.store["pipeline"]["security_semantics"]
    assert pl["source"]["stream_name"] == "security_logs" and pl["enabled"] is True
    functions = [n for n in pl["nodes"] if n["data"]["node_type"] == "function"]
    assert [(n["data"]["name"], n["data"]["after_flatten"]) for n in functions] == [("security_semantics", True), (FORTIGATE_FN, True)]
    # input -> security_semantics -> fortigate_semantics -> output, and no condition node (the service check lives in the function)
    edges = {(e["source"], e["target"]) for e in pl["edges"]}
    ids = {n["data"].get("name") or n["io_type"]: n["id"] for n in pl["nodes"]}
    assert edges == {(next(n["id"] for n in pl["nodes"] if n["io_type"] == "input"), ids["security_semantics"]),
                     (ids["security_semantics"], ids[FORTIGATE_FN]),
                     (ids[FORTIGATE_FN], next(n["id"] for n in pl["nodes"] if n["io_type"] == "output"))}
    assert not [n for n in pl["nodes"] if n["data"]["node_type"] == "condition"]


def test_a_security_pipeline_deployed_before_the_firewall_function_is_extended_by_a_single_update(o2):
    assert _apply(o2).returncode == 0
    pl = o2.store["pipeline"]["security_semantics"]
    pl["nodes"] = [n for n in pl["nodes"] if n["data"].get("name") != FORTIGATE_FN]   # the old one-function shape
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    ((method, path, body),) = o2.writes
    assert (method, path) == ("PUT", "/api/default/pipelines")
    assert [n["data"]["name"] for n in body["nodes"] if n["data"]["node_type"] == "function"] == ["security_semantics", FORTIGATE_FN]


def test_firewall_function_drift_is_repaired_by_a_single_update(o2):
    assert _apply(o2).returncode == 0
    o2.store["function"][FORTIGATE_FN]["function"] = "# stale\n."
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    ((method, path, _),) = o2.writes
    assert (method, path) == ("PUT", f"/api/default/functions/{FORTIGATE_FN}")


def test_switch_function_drift_is_repaired_by_a_single_update(o2):
    assert _apply(o2).returncode == 0
    o2.store["function"][SWITCH_FN]["function"] = "# stale\n."
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    ((method, path, _),) = o2.writes
    assert (method, path) == ("PUT", f"/api/default/functions/{SWITCH_FN}")


def test_uplink_alert_is_not_created_while_the_port_list_is_empty(o2):
    assert _apply(o2).returncode == 0
    assert UPLINK_ALERT not in o2.store["alert"]
    assert all(UPLINK_ALERT not in sql for _, sql in o2.searches)


def test_uplink_alert_is_created_with_a_list_verified_and_only_removed_when_the_list_is_emptied_and_it_is_retired(o2):
    res = _apply(o2, extra={"o2c_switch_uplinks": UPLINKS})
    assert res.returncode == 0, res.stdout + res.stderr
    a = o2.store["alert"][UPLINK_ALERT]
    sql = a["query_condition"]["sql"]
    assert a["context_attributes"]["severity"] == "P1 긴급" and a["stream_name"] == "system_logs"
    assert "device_id = 'ns0250'" in sql and "interface gigabitethernet1/0/1, changed state to down" in sql   # 약어가 전체 이름으로 풀린다
    assert any("interface gigabitethernet1/0/49, changed state to down" in s for _, s in o2.searches)   # 검증은 케이스 장비를 목록에 더해 돌린다
    o2.writes.clear()
    res = _apply(o2)   # 목록이 비어도 폐기 목록에 없으면 지우지 않고 관리 밖으로 알려 준다
    assert res.returncode == 0 and o2.writes == [] and UPLINK_ALERT in o2.store["alert"]
    assert "unmanaged infra- alert on server (kept): " + UPLINK_ALERT in res.stdout
    assert _apply(o2, extra={"o2c_retired_alerts": [UPLINK_ALERT]}).returncode == 0
    assert [(m, p) for m, p, _ in o2.writes] == [("DELETE", f"/api/v2/default/alerts/{a['alert_id']}")]
    assert UPLINK_ALERT not in o2.store["alert"]


def test_every_switch_alert_has_a_runbook_entry_with_the_list_update_procedure():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for anchor in ("switch-config-change", "switch-login-failures", "switch-severity-critical", "switch-uplink-down",
                   "switch-mac-flap", "switch-syslog-silent"):
        assert f'<a id="{anchor}"></a>' in runbook, anchor
    for token in ("o2c_switch_uplinks", "o2c_switch_syslog_roster", "o2c_switch_noise_events"):
        assert token in runbook, token


def test_default_noise_list_holds_the_arp_resolution_failure_and_every_alert_excludes_it(o2):
    assert _apply(o2).returncode == 0
    for name in ("infra-switch-config-change", "infra-switch-login-failures", "infra-switch-severity-critical", "infra-switch-mac-flap"):
        assert "event_name NOT IN ('ADJ-3-RESOLVE_REQ')" in _sql(o2, name), name
    assert "NOT IN" not in _sql(o2, "infra-switch-syslog-silent")   # 잡음 줄도 수신으로 센다


def test_switch_thresholds_and_lists_come_from_role_variables(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    extra = {"o2c_switch_noise_events": ["ADJ-3-RESOLVE_REQ", "LINK-3-UPDOWN"], "o2c_switch_macflap_threshold": 7,
             "o2c_switch_login_fail_threshold": 9, "o2c_switch_syslog_roster": ["ns0250"], "o2c_switch_silent_hours": 48}
    assert _apply(o2, extra=extra).returncode == 0
    assert "HAVING count(*) >= 7" in _sql(o2, "infra-switch-mac-flap") and "HAVING count(*) >= 9" in _sql(o2, "infra-switch-login-failures")
    assert "'ADJ-3-RESOLVE_REQ', 'LINK-3-UPDOWN'" in _sql(o2, "infra-switch-severity-critical")
    silent = o2.store["alert"]["infra-switch-syslog-silent"]
    assert _branch_devices(silent["query_condition"]["sql"]) == {"ns0250"} and silent["trigger_condition"]["period"] == 2880


def _branch_devices(sql):
    return set(re.findall(r"SELECT '([^']+)' AS device_id", sql))


def test_default_silent_roster_is_the_explicit_list_of_confirmed_senders_and_the_default_window_is_24_hours(o2):
    assert _apply(o2).returncode == 0
    silent = o2.store["alert"]["infra-switch-syslog-silent"]
    assert _branch_devices(silent["query_condition"]["sql"]) == {"ns0250", "ns0347"}   # 인벤토리 전체가 아니라 명시 목록
    assert silent["trigger_condition"]["period"] == 24 * 60 and "HAVING count(*) < 1" in silent["query_condition"]["sql"]


@pytest.mark.parametrize("extra", [
    {"o2c_switch_noise_events": ["ADJ-3-RESOLVE_REQ' OR '1'='1"]},
    {"o2c_switch_macflap_events": ["SW_MATM-9-MACFLAP_NOTIF"]},   # 심각도는 0~7
    {"o2c_switch_syslog_roster": ["ns0250' OR '1'='1"]},
    {"o2c_switch_syslog_roster": ["server01"]},
    {"o2c_switch_uplinks": [{"device": "ns0250", "port": "Gi1/0/1' OR '1'='1"}]},
    {"o2c_switch_uplinks": [{"device": "core1", "port": "Gi1/0/1"}]},
])
def test_invalid_switch_lists_fail_before_any_request(o2, extra):
    res = _apply(o2, extra=extra)
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []
    assert "1' OR" not in res.stdout + res.stderr


def test_switch_filters_validate_and_build_safe_sql():
    assert o2c_valid_switch_events(["SW_MATM-4-MACFLAP_NOTIF", "ADJ-3-RESOLVE_REQ"]) and not o2c_valid_switch_events(["SW_MATM-8-X"])
    assert o2c_valid_switch_roster(["ns0250"]) and not o2c_valid_switch_roster(["NS0250", "ns0250 "])
    assert o2c_valid_switch_uplinks([{"device": "ns0250", "port": "Gi1/0/49"}, {"device": "ns0347", "port": "Port-channel1"}])
    assert not o2c_valid_switch_uplinks([{"device": "ns0250", "port": "Gi1/0/49%"}, {"device": "ns0250"}])
    assert o2c_switch_noise_filter([]) == "" and o2c_switch_noise_filter(["A-3-B"]) == " AND event_name NOT IN ('A-3-B')"
    sql = o2c_switch_uplink_sql([{"device": "ns0250", "port": "Gi1/0/4"}, {"device": "ns0250", "port": "Te1/1/1"}])
    assert "interface gigabitethernet1/0/4, changed state to down" in sql and "interface tengigabitethernet1/1/1, changed state to" in sql
    assert o2c_switch_uplink_sql([]).count("1 = 0") == 1   # 빈 목록은 어떤 줄도 잡지 않는다
    assert [a["name"] for a in o2c_enabled_alerts([{"name": "a"}, {"name": "b", "enabled": False}, {"name": "c", "enabled": "False"},
                                                   {"name": "d", "enabled": True}])] == ["a", "d"]


def _date_format(value, fmt, offset):
    """sqlite stand-in for OpenObserve's ``date_format(<µs or s>, <strftime format>, '+HH:MM')`` (same contract, independent of the SQL under test)."""
    if value is None:
        return None
    seconds = value / 1_000_000 if abs(value) >= 10**11 else value   # 10^11 s is year 5138, so a larger number is microseconds
    sign = -1 if offset[0] == "-" else 1
    hours, minutes = offset[1:].split(":")
    tz = timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
    return datetime.fromtimestamp(seconds, tz).strftime(fmt)


def _run_alert_on_sqlite(sql, records, stream="system_logs_alert_verify"):
    """Run a verification search on the injected synthetic records (portable SQL subset + regexp_replace) and return the rows."""
    db = sqlite3.connect(":memory:")
    db.create_function("regexp_replace", 3, lambda text, pattern, repl: re.sub(pattern, repl, text) if text is not None else None)
    db.create_function("date_format", 3, _date_format)
    records = [dict({"_timestamp": 1_792_767_302_000_000}, **r) for r in records]   # OpenObserve stamps every record on ingest
    columns = sorted({k for r in records for k in r})
    db.execute('CREATE TABLE "%s" (%s)' % (stream, ", ".join(f'"{c}"' for c in columns)))
    for r in records:
        db.execute('INSERT INTO "%s" VALUES (%s)' % (stream, ", ".join("?" * len(columns))), [r.get(c) for c in columns])
    cur = db.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body(o2):
    """Records written before the switch pipeline existed have no device_id; they must still count as "received"."""
    assert _apply(o2).returncode == 0
    sql = _sql(o2, "infra-switch-syslog-silent")
    for device in ("ns0250", "ns0347"):
        assert f"(device_id = '{device}' OR lower(body) LIKE '% {device}%')" in sql, device
    assert "HAVING count(*) < 1" in sql


def test_silent_alert_does_not_fire_right_after_the_pipeline_is_applied_when_old_logs_exist(o2):
    """The first evaluation after the pipeline change sees old records (raw body only) next to a few processed ones."""
    assert _apply(o2).returncode == 0
    sql = _sql(o2, "infra-switch-syslog-silent").replace('"system_logs"', '"system_logs_alert_verify"')
    other = {"service_name": "switch-syslog", "device_id": "ns0999", "body": "Oct 20 17:50:00 203.0.113.9 ns0999-3560X: x"}   # device_id 컬럼이 있는 스키마
    old = [{"service_name": "switch-syslog", "body": "Oct 20 17:48:40 203.0.113.9 NS0347-3560X: Oct 20 17:48:39.702 KST: %SW_MATM-4-MACFLAP_NOTIF: x"},
           {"service_name": "switch-syslog", "body": "Oct 20 17:48:35 203.0.113.8 ns0250-3750X: Oct 20 17:48:34.411 KST: %ADJ-3-RESOLVE_REQ: x"}]
    assert _run_alert_on_sqlite(sql, old + [other]) == []   # 두 장비 모두 수신 중 → 발화 없음
    assert {row["device_id"] for row in _run_alert_on_sqlite(sql, old[:1] + [other])} == {"ns0250"}   # 한 장비만 조용하면 그 장비만 발화


SWITCH_MARKERS = {   # alert -> a fragment only its search carries
    "infra-switch-config-change": "'SYS-5-CONFIG_I'", "infra-switch-login-failures": "'SEC_LOGIN-4-LOGIN_FAILED'",
    "infra-switch-severity-critical": "log_syslog_severity_code <=", UPLINK_ALERT: "changed state to down",
    "infra-switch-mac-flap": "'SW_MATM-4-MACFLAP_NOTIF'", "infra-switch-syslog-silent": "AS device_id, count(*) AS n",
}


def test_switch_alert_sql_fires_on_the_fixture_cases_and_only_those_when_it_runs_on_the_synthetic_records(o2):
    """The searches the verification step sends (rewritten SQL) are executed on the injected records — not just compared by name."""
    res = _apply(o2, extra={"o2c_switch_uplinks": UPLINKS})
    assert res.returncode == 0, res.stdout + res.stderr
    records = [r for p, _, rs in o2.ingests if "/system_logs_alert_verify/" in p for r in rs]
    searches = [sql for stream, sql in o2.searches if stream == "system_logs_alert_verify"]
    for name, marker in SWITCH_MARKERS.items():
        (sql,) = [s for s in searches if marker in s]
        spec = FIXTURES[name]
        fired = {m.group(1) for row in _run_alert_on_sqlite(sql, records) if (m := re.fullmatch(r"(.+)-\d+", str(row[spec["row_key"]])))}
        assert fired == {c["host"] for c in spec["cases"] if c["fires"]}, name


def test_switch_fixtures_cover_every_alert_with_firing_and_quiet_cases_and_off_roster_and_other_services():
    for name in list(SWITCH_ALERTS) + [UPLINK_ALERT]:
        cases = FIXTURES[name]["cases"]
        assert {c["fires"] for c in cases} == {True, False}, name
        assert FIXTURES[name]["host_field"] == "device_id", name
    assert any(c.get("off_roster") for c in FIXTURES["infra-switch-syslog-silent"]["cases"])
    assert any(r.get("service_name") != "switch-syslog" for n in SWITCH_ALERTS for c in FIXTURES[n]["cases"] for r in c["records"])
    assert any(c.get("watch_port") for c in FIXTURES[UPLINK_ALERT]["cases"])


# --- 방화벽(포티게이트) 로그 알림 (Spec #282 / Ticket-3) -----------------------------------------------------------------
# 입력 로그는 FortiOS Log Message Reference로 만든 합성 줄이다. 실장비 샘플(비공개 경로)로 키 이름·값 모양을 다시 검증해야 한다.
from openobserve_config import (o2c_fortigate_match, o2c_fortigate_vrl, o2c_missing_sql, o2c_valid_fortigate_aliases,  # noqa: E402
                                o2c_valid_fortigate_roster, o2c_valid_fortigate_values)

FORTIGATE_ALERTS = {   # name -> (severity, period minutes, silence minutes)
    "infra-fortigate-admin-login-failures": ("P2 경고", 5, 30),
    "infra-fortigate-change-unapproved": ("P1 긴급", 5, 5),
    "infra-fortigate-change-approved": ("P3 주의", 1440, 1440),
    "infra-fortigate-ha-failover": ("P2 경고", 5, 30),
    "infra-fortigate-critical-detection": ("P1 긴급", 5, 60),
    "infra-fortigate-syslog-silent": ("P2 경고", 120, 1440),
}
FORTIGATE_MARKERS = {   # alert -> a fragment only its search carries
    "infra-fortigate-admin-login-failures": "HAVING count(*) >=", "infra-fortigate-change-unapproved": "NOT (CASE WHEN",
    "infra-fortigate-change-approved": "AND (CASE WHEN", "infra-fortigate-ha-failover": 'subtype="ha"',
    "infra-fortigate-critical-detection": 'severity="critical"', "infra-fortigate-syslog-silent": "AS device_id, count(*) AS n",
}


def test_firewall_match_condition_accepts_quoted_and_bare_values_and_rejects_unsafe_input():
    cond = o2c_fortigate_match("subtype", ["ha"])
    assert """body LIKE '% subtype="ha"%'""" in cond and "body LIKE '% subtype=ha %'" in cond
    assert o2c_fortigate_match("cfgpath", ["system.admin", "user.local"]).count(" OR ") == 3
    for key, values in (("sub type", ["ha"]), ("subtype", ["ha' OR '1'='1"]), ("subtype", [])):
        with pytest.raises(ValueError):
            o2c_fortigate_match(key, values)
    assert o2c_valid_fortigate_values(["firewall.policy", "critical"]) and not o2c_valid_fortigate_values(["a'b"])


def test_firewall_roster_accepts_a_member_pair_written_with_plus_and_counts_any_member_as_receiving():
    assert o2c_valid_fortigate_roster(["ns0399", "ns0380+ns0381"]) and not o2c_valid_fortigate_roster(["ns0380+", "ns0399' OR '1", "fw 1", "a%b", ""])
    sql = o2c_missing_sql(["ns0380+ns0381"], "security_logs", "device_id", "service_name = 'fortigate-syslog'", "devname")
    assert sql.startswith("SELECT 'ns0380+ns0381' AS device_id") and "HAVING count(*) < 1" in sql
    assert "device_id = 'ns0380'" in sql and "device_id = 'ns0381'" in sql and """LIKE '%devname="ns0381%'""" in sql
    standby_only = [{"service_name": "fortigate-syslog", "device_id": "ns0381", "body": 'devname="ns0381" x'}]
    quiet = [{"service_name": "fortigate-syslog", "device_id": "ns0399", "body": 'devname="ns0399" x'}]
    table_sql = sql.replace('"security_logs"', '"t"')
    assert _run_alert_on_sqlite(table_sql, standby_only, "t") == []   # 한 멤버라도 보내면 쌍은 수신 중
    assert [r["device_id"] for r in _run_alert_on_sqlite(table_sql, quiet, "t")] == ["ns0380+ns0381"]


def test_firewall_alerts_are_created_on_security_logs_with_the_specified_grades_windows_and_silences(o2):
    assert _apply(o2).returncode == 0
    for name, (sev, period, silence) in FORTIGATE_ALERTS.items():
        a = o2.store["alert"][name]
        assert a["stream_name"] == "security_logs" and a["stream_type"] == "logs", name
        assert a["context_attributes"]["severity"] == sev, name
        assert (a["trigger_condition"]["period"], a["trigger_condition"]["silence"]) == (period, silence), name
        assert a["destinations"] == ["infra-automation-webhook"] and a["enabled"], name
        assert "fortigate-syslog" in a["query_condition"]["sql"], name
        for key in ("what", "why", "action", "runbook"):
            assert a["context_attributes"][key].strip(), (name, key)
        assert a["context_attributes"]["runbook"].endswith("#" + name.removeprefix("infra-")), name


def test_firewall_alert_sql_needs_no_firewall_column_so_it_is_valid_before_the_first_firewall_line_arrives(o2):
    """security_logs has no firewall column until a firewall line is ingested; a missing column would fail every evaluation (O2C-036)."""
    assert _apply(o2).returncode == 0
    for name in FORTIGATE_ALERTS:
        sql = _sql(o2, name).replace("AS device_id", "")
        for column in ("device_id", "device_name", "fortigate_log_type", "fortigate_log_subtype", "fortigate_policy_id"):
            assert not re.search(rf"(?<![A-Za-z_'\"]){column}(?![A-Za-z_'\"])", sql), (name, column)


def test_approved_hours_split_changes_into_unapproved_p1_and_approved_p3_and_every_value_is_a_role_variable(o2):
    assert _apply(o2).returncode == 0
    out, inside = _sql(o2, "infra-fortigate-change-unapproved"), _sql(o2, "infra-fortigate-change-approved")
    assert "NOT (" in out and ">= 9" in out and "< 18" in out and "NOT (" not in inside and ">= 9" in inside
    extra = {"o2c_fortigate_approved_start_hour": 8, "o2c_fortigate_approved_end_hour": 20, "o2c_fortigate_login_fail_threshold": 9,
             "o2c_fortigate_silent_minutes": 45, "o2c_fortigate_detection_severities": ["critical", "high"],
             "o2c_fortigate_policy_cfgpaths": ["firewall.policy"], "o2c_fortigate_account_cfgpaths": ["system.admin"],
             "o2c_fortigate_syslog_roster": ["ns0399", "ns0380+ns0381"]}
    assert _apply(o2, extra=extra).returncode == 0
    assert ">= 8" in _sql(o2, "infra-fortigate-change-unapproved") and "< 20" in _sql(o2, "infra-fortigate-change-approved")
    assert "HAVING count(*) >= 9" in _sql(o2, "infra-fortigate-admin-login-failures")
    assert 'severity="high"' in _sql(o2, "infra-fortigate-critical-detection")
    assert 'cfgpath="firewall.policy6"' not in _sql(o2, "infra-fortigate-change-approved")
    silent = o2.store["alert"]["infra-fortigate-syslog-silent"]
    assert silent["trigger_condition"]["period"] == 45
    assert set(re.findall(r"SELECT '([^']+)' AS device_id", silent["query_condition"]["sql"])) == {"ns0399", "ns0380+ns0381"}


def test_silent_alert_watches_only_the_explicit_list_and_the_default_list_is_empty_and_the_window_is_shorter_than_the_switch_one(o2):
    """The default list is empty: no firewall sends logs yet, so any default member would raise a false alert (opt in as each starts sending)."""
    assert _apply(o2).returncode == 0
    silent = o2.store["alert"]["infra-fortigate-syslog-silent"]
    assert set(re.findall(r"SELECT '([^']+)' AS device_id", silent["query_condition"]["sql"])) == {"none"}   # 절대 행을 돌려주지 않는 가지 하나
    assert "HAVING count(*) < 0" in silent["query_condition"]["sql"]
    assert silent["trigger_condition"]["period"] < o2.store["alert"]["infra-switch-syslog-silent"]["trigger_condition"]["period"]
    assert _apply(o2, extra={"o2c_fortigate_syslog_roster": ["ns0399"]}).returncode == 0
    sql = _sql(o2, "infra-fortigate-syslog-silent")
    assert "'ns0399'" in sql and "ns0380" not in sql and "ns0381" not in sql   # 목록에 없는 장비는 허위 알림을 만들지 않는다


@pytest.mark.parametrize("extra", [
    {"o2c_fortigate_syslog_roster": ["ns0399' OR '1'='1"]},
    {"o2c_fortigate_syslog_roster": ["Example Branch FW"]},
    {"o2c_fortigate_device_aliases": {"example_branch_fw": "server01"}},
    {"o2c_fortigate_device_aliases": {"example_branch_fw": "ns0000' OR '1'='1"}},
    {"o2c_fortigate_device_aliases": {"example\"fw": "ns0000"}},
    {"o2c_fortigate_device_aliases": {"fw.corp": "ns0000"}},
    {"o2c_fortigate_device_aliases": ["ns0000"]},
    {"o2c_fortigate_policy_cfgpaths": ["firewall.policy' OR '1'='1"]},
    {"o2c_fortigate_detection_severities": ["critical%"]},
    {"o2c_fortigate_approved_start_hour": 18, "o2c_fortigate_approved_end_hour": 9},
    {"o2c_fortigate_approved_start_hour": "9; DROP"},
    {"o2c_fortigate_ha_ignored_logids": ["0108037903' OR '1'='1"]},
    {"o2c_fortigate_ha_ignored_logids": ["abc"]},
    {"o2c_fortigate_ha_ignored_logids": [108037903]},
])
def test_invalid_firewall_variables_fail_before_any_request(o2, extra):
    res = _apply(o2, extra=extra)
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []
    assert "1' OR" not in res.stdout + res.stderr


def test_firewall_alerts_do_not_break_the_existing_ones(o2):
    assert _apply(o2).returncode == 0
    assert (EXPECTED_ALERTS - set(FORTIGATE_ALERTS)) <= set(o2.store["alert"])
    for name, (sev, period, silence) in SWITCH_ALERTS.items():
        trigger = o2.store["alert"][name]["trigger_condition"]
        assert (trigger["period"], trigger["silence"]) == (period, silence)
    assert FORTIGATE_FN in o2.store["function"]


def test_firewall_alert_sql_fires_on_the_fixture_cases_and_only_those_when_it_runs_on_the_synthetic_records(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    records = [r for p, _, rs in o2.ingests if "/security_logs_alert_verify/" in p for r in rs]
    searches = [sql for stream, sql in o2.searches if stream == "security_logs_alert_verify" and "fortigate-syslog" in sql]
    for name, marker in FORTIGATE_MARKERS.items():
        (sql,) = [s for s in searches if marker in s]
        spec = FIXTURES[name]
        own = {c["host"] for c in spec["cases"]}   # the alerts share one stream: like the verification step, judge only this alert's own cases
        fired = {m.group(1) for row in _run_alert_on_sqlite(sql, records, "security_logs_alert_verify")
                 if (m := re.fullmatch(r"(.+)-[0-9a-f]+", str(row[spec["row_key"]]))) and m.group(1) in own}
        assert fired == {c["host"] for c in spec["cases"] if c["fires"]}, name


def test_firewall_fixtures_cover_every_alert_with_firing_and_quiet_cases_and_boundaries():
    for name in FORTIGATE_ALERTS:
        cases = FIXTURES[name]["cases"]
        assert {c["fires"] for c in cases} == {True, False}, name
        assert all(r.get("service_name") for c in cases for r in c["records"]), name
    assert any(c.get("off_roster") for c in FIXTURES["infra-fortigate-syslog-silent"]["cases"])
    assert any(r.get("service_name") != "fortigate-syslog" for n in FORTIGATE_ALERTS for c in FIXTURES[n]["cases"] for r in c["records"])
    names = " ".join(c["name"] for c in FIXTURES["infra-fortigate-change-unapproved"]["cases"] + FIXTURES["infra-fortigate-change-approved"]["cases"])
    assert "승인 시간 안" in names and "승인 시간 밖" in names and "시각이 없는" in names


def test_every_firewall_alert_has_a_runbook_entry_that_states_the_synthetic_input_caveat_and_the_list_procedure():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for name in FORTIGATE_ALERTS:
        anchor = name.removeprefix("infra-")
        assert f'<a id="{anchor}"></a>' in runbook and f"(`{name}`)" in runbook, name
    for token in ("o2c_fortigate_syslog_roster", "o2c_fortigate_approved_start_hour", "o2c_fortigate_account_cfgpaths", "합성", "실장비"):
        assert token in runbook, token


def test_firewall_silent_sql_does_not_read_the_device_id_column_even_with_a_roster(o2):
    """The WHERE clause must use only columns that always exist: device_id appears in security_logs only after the first processed firewall line."""
    assert _apply(o2, extra={"o2c_fortigate_syslog_roster": ["ns0399", "ns0380+ns0381"]}).returncode == 0
    sql = _sql(o2, "infra-fortigate-syslog-silent")
    assert "ns0380" in sql and "ns0381" in sql and "ns0399" in sql
    assert not re.search(r"(?<![A-Za-z_'\"])device_id\s*=", sql) and "WHERE device_id" not in sql
    assert 'LIKE \'%devname="ns0381%\'' in sql


def test_missing_sql_without_field_column_matches_only_on_body_and_still_counts_a_pair_member():
    sql = o2c_missing_sql(["ns0380+ns0381"], "security_logs", "device_id", "service_name = 'fortigate-syslog'", "devname", field_column=False)
    assert sql.startswith("SELECT 'ns0380+ns0381' AS device_id") and "device_id =" not in sql
    table = sql.replace('"security_logs"', '"t"').replace("AS device_id", "AS device")
    only_body = [{"service_name": "fortigate-syslog", "body": 'devname="ns0381" x'}]   # device_id 컬럼 자체가 없다
    assert _run_alert_on_sqlite(table, only_body, "t") == []
    assert len(_run_alert_on_sqlite(table, [{"service_name": "fortigate-syslog", "body": 'devname="ns0399" x'}], "t")) == 1


# 장비 이름 별칭(Spec #282): 관리번호로 hostname을 못 바꾼 장비는 원래 이름을 그대로 쓴다. 이름은 가짜(Example_Branch_FW)만 쓴다.
ALIASES = {"example_branch_fw": "ns0000"}


def test_alias_table_defaults_to_empty_and_the_function_body_carries_it_only_when_set(o2):
    assert _apply(o2).returncode == 0
    base = o2.store["function"][FORTIGATE_FN]["function"]
    assert "device_aliases = {}" in base and "example_branch_fw" not in base
    assert _apply(o2, extra={"o2c_fortigate_device_aliases": ALIASES}).returncode == 0
    changed = o2.store["function"][FORTIGATE_FN]["function"]
    assert '"example_branch_fw": "ns0000"' in changed and changed != base   # 변수가 바뀌면 함수가 갱신된다


def test_alias_validation_accepts_normalized_names_and_management_numbers_only():
    assert o2c_valid_fortigate_aliases({}) and o2c_valid_fortigate_aliases(ALIASES) and o2c_valid_fortigate_aliases(None)
    for bad in ({"Example_Branch_FW": "ns0000"}, {"fw.corp": "ns0000"}, {"fw": "server01"}, {"fw": "ns0000+ns0001"}, {"f w": "ns0000"}, ["x"]):
        assert not o2c_valid_fortigate_aliases(bad)


def test_alias_injection_leaves_the_source_unchanged_for_an_empty_table_and_rejects_a_source_without_the_marker():
    src = "a = 1\ndevice_aliases = {}  # marker\n.\n"
    assert o2c_fortigate_vrl(src, {}) == src
    assert o2c_fortigate_vrl(src, ALIASES) == 'a = 1\ndevice_aliases = {"example_branch_fw": "ns0000"}\n.\n'
    with pytest.raises(ValueError):
        o2c_fortigate_vrl("a = 1\n", ALIASES)


def test_silent_roster_accepts_the_original_device_name_case_insensitively():
    assert o2c_valid_fortigate_roster(["Example_Branch_FW", "ns0380+ns0381"])
    sql = o2c_missing_sql(["Example_Branch_FW"], "security_logs", "device_id", "service_name = 'fortigate-syslog'", "devname", False)
    table_sql = sql.replace('"security_logs"', '"t"')
    for devname in ("Example_Branch_FW", "EXAMPLE_BRANCH_FW", "example_branch_fw"):
        assert _run_alert_on_sqlite(table_sql, [{"service_name": "fortigate-syslog", "body": 'devname="%s" x' % devname}], "t") == []
        assert _run_alert_on_sqlite(table_sql, [{"service_name": "fortigate-syslog", "body": 'devname=%s x' % devname}], "t") == []
    assert _run_alert_on_sqlite(table_sql, [{"service_name": "fortigate-syslog", "body": 'devname="other_fw" x'}], "t") != []


# --- 실로그 샘플로 방화벽 알림 SQL 검증 (Spec #282) --------------------------------------------------------------------
# tests/fixtures/fortigate_real_lines.tsv: 실제 FortiOS 줄을 가짜 값으로 치환한 것이다. 알림 SQL은 body와 service_name만 읽으므로
# 레코드는 {service_name, body, source_address}다(source_address는 변환 함수가 srcip, 없으면 ui의 주소로 채운 값).
# 검증 범위: 관리자 로그인 실패/성공, 정책·로그 설정 변경, 트래픽, UTM(ips·virus·dlp·anomaly), HA 인터페이스 실패 줄.
# 검증되지 않은 것: HA 전환(상태 변경) 실제 줄, 실제 장비가 만든 웹필터·앱제어 줄, SSL VPN 로그인 실패 줄.
REAL_LINES = {}
for _raw in (ROOT_DIR / "tests" / "fixtures" / "fortigate_real_lines.tsv").read_text(encoding="utf-8").splitlines():
    if _raw and not _raw.startswith("#"):
        _name, _tag, _line = _raw.split("\t", 2)
        REAL_LINES[_name] = _line
REAL_SOURCE = {"login_failed": "192.0.2.11", "login_success": "192.0.2.11"}


def _real(name, times=1, at=None):
    """Records made of one real line; ``at`` replaces the device time (HH:MM:SS) of the line."""
    body = REAL_LINES[name] if at is None else re.sub(r" time=\d\d:\d\d:\d\d ", f" time={at} ", REAL_LINES[name], count=1)
    return [{"service_name": "fortigate-syslog", "body": body, "source_address": REAL_SOURCE.get(name)} for _ in range(times)]


def _real_rows(o2, alert, records, **extra):
    assert _apply(o2, extra=extra).returncode == 0
    return _run_alert_on_sqlite(_sql(o2, alert).replace('"security_logs"', '"t"'), records, "t")


def test_real_admin_login_failures_fire_only_from_five_failed_admin_logins_of_one_source(o2):
    rows = _real_rows(o2, "infra-fortigate-admin-login-failures", _real("login_failed", 5))
    assert [(r["device"], r["source_address"], r["failures"]) for r in rows] == [("example_branch_fw", "192.0.2.11", 5)]
    quiet = _real("login_failed", 4) + _real("login_success", 9) + _real("local_in_deny", 9) + _real("policy_edit_gui", 9)
    assert _real_rows(o2, "infra-fortigate-admin-login-failures", quiet) == []


@pytest.mark.parametrize("at, fires_unapproved", [("03:10:00", True), ("14:15:43", False), ("08:59:59", True), ("09:00:00", False), ("18:00:00", True)])
def test_real_policy_changes_split_by_the_device_time_into_unapproved_and_approved(o2, at, fires_unapproved):
    records = _real("policy_edit_gui", at=at) + _real("policy_edit_jsconsole", at=at)
    out = _real_rows(o2, "infra-fortigate-change-unapproved", records)
    inside = _real_rows(o2, "infra-fortigate-change-approved", records)
    assert bool(out) is fires_unapproved and bool(inside) is not fires_unapproved
    rows = out or inside
    assert {(r["device"], r["cfgpath"], r["admin"], r["changes"]) for r in rows} == {("example_branch_fw", "firewall.policy", "example-admin", 1),
                                                                                       ("ns0001", "firewall.policy", "example-admin", 1)}


def test_real_changes_of_other_config_paths_and_non_config_lines_do_not_fire_the_change_alerts(o2):
    records = [r for n in ("syslogd_filter_edit", "log_setting_edit", "login_success", "forward_accept", "ips_high") for r in _real(n, at="03:10:00")]
    assert _real_rows(o2, "infra-fortigate-change-unapproved", records) == []
    assert _real_rows(o2, "infra-fortigate-change-approved", _real("log_setting_edit")) == []


def test_real_logging_config_paths_can_be_added_to_the_watched_changes_by_a_role_variable(o2):
    extra = {"o2c_fortigate_policy_cfgpaths": ["firewall.policy", "log.syslogd.filter", "log.setting"]}
    rows = _real_rows(o2, "infra-fortigate-change-unapproved", _real("syslogd_filter_edit", at="03:10:00") + _real("log_setting_edit", at="03:10:00"), **extra)
    assert {r["cfgpath"] for r in rows} == {"log.syslogd.filter", "log.setting"}


def test_real_ha_alert_fires_on_the_ha_line_only(o2):
    rows = _real_rows(o2, "infra-fortigate-ha-failover", _real("ha_interface_failed"))
    assert [(r["device"], r["event"], r["events"]) for r in rows] == [("ns0001", "HA device interface failed", 1)]
    others = [r for n in REAL_LINES if n != "ha_interface_failed" for r in _real(n)]
    assert _real_rows(o2, "infra-fortigate-ha-failover", others) == []


HA_SYNC_INFO = ('date=2026-10-21 time=13:44:11 devname="ns0002" logid="0108037903" type="event" subtype="ha" level="information" '
                'logdesc="Synchronization status with primary" msg="The sync status with the primary"')
HA_SYNTHETIC_CHANGE = ('date=2026-10-21 time=13:45:00 devname="ns0002" logid="0108037999" type="event" subtype="ha" level="critical" '
                       'logdesc="Synthetic member state changed" msg="synthetic state change"')   # 합성: 상태 변경 성격의 가짜 logid


def _ha(body):
    return [{"service_name": "fortigate-syslog", "body": body}]


def test_ha_alert_skips_the_informational_sync_log_by_default_but_still_fires_on_other_ha_logids(o2):
    assert _real_rows(o2, "infra-fortigate-ha-failover", _ha(HA_SYNC_INFO)) == []
    rows = _real_rows(o2, "infra-fortigate-ha-failover", _ha(HA_SYNC_INFO) + _ha(HA_SYNTHETIC_CHANGE))
    assert [(r["device"], r["events"]) for r in rows] == [("ns0002", 1)]
    assert 'NOT LIKE \'%logid="0108037903"%\'' in _sql(o2, "infra-fortigate-ha-failover")


def test_ha_ignored_logids_is_a_role_variable_and_an_empty_list_counts_every_ha_line(o2):
    rows = _real_rows(o2, "infra-fortigate-ha-failover", _ha(HA_SYNC_INFO), o2c_fortigate_ha_ignored_logids=[])
    assert [r["events"] for r in rows] == [1] and "NOT LIKE" not in _sql(o2, "infra-fortigate-ha-failover")
    extra = {"o2c_fortigate_ha_ignored_logids": ["0108037903", "0108037999"]}
    assert _real_rows(o2, "infra-fortigate-ha-failover", _ha(HA_SYNC_INFO) + _ha(HA_SYNTHETIC_CHANGE), **extra) == []


def test_real_critical_detection_fires_on_a_critical_severity_and_on_an_infected_file_but_not_on_lower_severities(o2):
    rows = _real_rows(o2, "infra-fortigate-critical-detection", _real("anomaly_critical"))
    assert [(r["device"], r["attack"], r["detections"]) for r in rows] == [("ns0001", "tcp_syn_flood", 1)]
    rows = _real_rows(o2, "infra-fortigate-critical-detection", _real("virus_infected"))   # 실제 바이러스 로그에는 severity 키가 없다
    assert [(r["device"], r["attack"], r["detections"]) for r in rows] == [("ns0001", "virus_test3", 1)]
    quiet = [r for n in ("ips_high", "dlp_info", "forward_deny_policy0", "login_failed", "ha_interface_failed", "fsso_logon") for r in _real(n)]
    assert _real_rows(o2, "infra-fortigate-critical-detection", quiet) == []


def test_real_lines_keep_the_silent_alert_quiet_for_a_device_that_sent_and_fire_for_one_that_did_not(o2):
    records = _real("login_failed") + _real("forward_deny_policy0")   # 사무실(관리번호 없는 이름), idc 장비
    rows = _real_rows(o2, "infra-fortigate-syslog-silent", records, o2c_fortigate_syslog_roster=["Example_Branch_FW", "ns0001", "ns0399"])
    assert {r["device_id"] for r in rows} == {"ns0399"}


# --- 알림 메시지 형식: 라벨·조치 줄 나눔 (Spec #282 후속) -----------------------------------------------------------------
def _filters():
    import importlib.util
    spec = importlib.util.spec_from_file_location("o2c_filter_fmt", ROOT_DIR / "filter_plugins" / "openobserve_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("count", [2, 3, 4])
def test_action_filter_splits_circled_numbers_into_numbered_lines(count):
    marks = "①②③④"[:count]
    text = " ".join(f"{m} 항목{i}" for i, m in enumerate(marks, 1))
    expected = "".join(f"\n{i}. 항목{i}" for i in range(1, count + 1))
    assert _filters().o2c_action_lines(text) == expected


def test_action_filter_turns_a_single_sentence_into_one_numbered_line():
    assert _filters().o2c_action_lines("로그를 확인한다") == "\n1. 로그를 확인한다"


def test_action_filter_keeps_an_empty_action_empty():
    assert _filters().o2c_action_lines("") == "" and _filters().o2c_action_lines("   ") == ""



def test_template_uses_the_new_labels_and_not_the_old_ones(o2):
    assert _apply(o2).returncode == 0
    text = json.loads(o2.store["template"]["infra-automation-webhook"]["body"])["content"]["text"]
    for label in ("■ 현상: {what}", "■ 영향: {why}", "■ 대상 {alert_count}건:\n{rows:10}", "■ 조치:{action}", "▶ 런북: ", "▶ {link_label}: {alert_url}", "⏱ 평가: ", "📋 규칙: {alert_name}"):
        assert label in text, label
    assert "무슨 일" not in text and "왜 중요" not in text


def test_rendered_body_with_a_multiline_action_is_valid_json(o2):
    """OpenObserve는 context_attributes를 JSON 이스케이프해서 본문에 넣는다 — 개행이 있어도 본문 JSON이 깨지지 않는다."""
    assert _apply(o2).returncode == 0
    tpl = o2.store["template"]["infra-automation-webhook"]["body"]
    action = _filters().o2c_action_lines("① 하나 ② 둘 ③ 셋")
    rendered = tpl.replace("{action}", json.dumps(action, ensure_ascii=False)[1:-1])
    text = json.loads(rendered)["content"]["text"]
    assert "■ 조치:\n1. 하나\n2. 둘\n3. 셋\n\n▶ 런북" in text


def test_every_alert_action_is_one_numbered_line_per_item_after_rendering(o2):
    assert _apply(o2).returncode == 0
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    source = {a["name"]: a["action"] for a in defaults["o2c_alerts"]}
    assert len(o2.store["alert"]) >= 36 + len(PROMQL_ALERTS)
    for name, alert in o2.store["alert"].items():
        action = alert["context_attributes"]["action"]
        lines = action.split("\n")
        assert lines[0] == "" and len(lines) >= 2, name
        assert [ln.split(". ", 1)[0] for ln in lines[1:]] == [str(i) for i in range(1, len(lines))], name
        assert not re.search("[①-⑳]", action) and all(ln.split(". ", 1)[1].strip() for ln in lines[1:]), name
        if name in source:
            assert len(lines) - 1 == max(1, len(re.findall("[①-⑳]", source[name]))), name


def test_second_run_after_the_action_conversion_changes_nothing(o2):
    """계획의 비교는 변환된 값 기준이다 — 반영 직후 두 번째 실행은 변경 0건이다."""
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    assert _apply(o2).returncode == 0 and o2.writes == []


# --- o2c_plan 단위: 삭제는 폐기 목록만, 관리 밖 infra- 알림은 건드리지 않고 알려 준다 ---------------------------------------------------
import importlib.util as _ilu   # noqa: E402

_spec = _ilu.spec_from_file_location("o2c_filters", ROOT_DIR / "filter_plugins" / "openobserve_config.py")
o2c = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(o2c)


def _alert_want(name):
    body = {"name": name, "enabled": True}
    return {"kind": "alert", "name": name, "body": body, "match": body, "secret": False}


def _server(*names):
    return {"alert": [{"alert_id": "id-" + n, "name": n, "enabled": True} for n in names]}


def test_plan_deletes_a_retired_alert_that_exists_on_the_server():
    plan = o2c.o2c_plan([], _server("infra-gone"), "default", retired=["infra-gone"])
    assert [(a["op"], a["name"], a["path"]) for a in plan] == [("delete", "infra-gone", "/api/v2/default/alerts/id-infra-gone")]


def test_plan_ignores_a_retired_alert_that_is_not_on_the_server():
    assert o2c.o2c_plan([], _server("infra-other"), "default", retired=["infra-gone"]) == []


def test_plan_never_deletes_an_infra_alert_that_is_not_retired_and_lists_it_as_unmanaged():
    existing = _server("infra-kept-by-hand", "infra-defined", "infra-gone", "team-x")
    desired = [_alert_want("infra-defined")]
    plan = o2c.o2c_plan(desired, existing, "default", retired=["infra-gone"])
    assert [a["name"] for a in plan if a["op"] == "delete"] == ["infra-gone"]
    assert o2c.o2c_unmanaged_alerts(desired, existing, ["infra-gone"]) == ["infra-kept-by-hand"]


def test_plan_without_a_retired_list_deletes_nothing():
    assert o2c.o2c_plan([], _server("infra-a", "infra-b"), "default") == []


@pytest.mark.parametrize("names,ok", [([], True), (["infra-a", "infra-b-1"], True), (["Infra-a"], False), (["infra-"], False),
                                      (["team-a"], False), (["infra-a", "infra-a"], False), (["infra a"], False), ([1], False),
                                      ("infra-a", False)])
def test_retired_names_need_the_infra_format_and_no_duplicates(names, ok):
    assert o2c.o2c_valid_retired_alerts(names) is ok


def test_a_current_alert_definition_on_the_retired_list_is_a_conflict():
    assert o2c.o2c_retired_conflicts(["infra-a", "infra-b"], ["infra-b", "infra-c"]) == ["infra-b"]
    assert o2c.o2c_retired_conflicts(["infra-a"], ["infra-c"]) == []


# --- PromQL 알림 (#282): 정의 복원, 수렴, 검증 제외, 템플릿(행 수 제한·링크 라벨), P1 전용 destination ----------------------------------
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
PROMQL_DEFS = [a for a in DEFAULTS["o2c_alerts"] if a.get("promql")]
P1_DEST = "ops-p1-webhook"
SUBQUERY_OVER_SUM = re.compile(r"sum by\([^)]*\)\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\[\d+[smhd]:\d+[smhd]\]")


def _balanced(text):
    stack, pairs, in_quote = [], {")": "(", "]": "[", "}": "{"}, False
    for ch in text:
        if ch == "'":
            in_quote = not in_quote
        elif in_quote:
            continue
        elif ch in "([{":
            stack.append(ch)
        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):
            return False
    return not stack and not in_quote


def test_promql_definitions_are_the_seventeen_alerts_with_unique_infra_names():
    names = [a["name"] for a in DEFAULTS["o2c_alerts"]]
    assert len(names) == len(set(names))
    assert {a["name"] for a in PROMQL_DEFS} == set(PROMQL_ALERTS) and len(PROMQL_DEFS) == 17
    assert all(re.fullmatch(r"infra-[a-z0-9-]+", n) for n in PROMQL_ALERTS)


@pytest.mark.parametrize("alert", PROMQL_DEFS, ids=lambda a: a["name"])
def test_promql_definition_is_well_formed_and_matches_the_definition_table(alert):
    sev, period, freq, silence, op, value, stream, pending = PROMQL_ALERTS[alert["name"]]
    q = alert["promql"]
    assert isinstance(q, str) and q.strip() and _balanced(q), alert["name"]
    assert not SUBQUERY_OVER_SUM.search(q), "sum by() 결과를 서브쿼리로 감싸면 OpenObserve에서 빈 결과가 나온다"
    assert not re.search(r"\[\d+[smhd]:\d+[smhd]\]", q), "서브쿼리는 OpenObserve에서 지속 조건을 만들지 못한다(#318)"
    assert alert["severity"] == sev and alert["severity_icon"] == {"P1": "🔴", "P2": "🟠", "P3": "🟡"}[sev[:2]]
    assert (alert["period"], alert["frequency"], alert["silence"]) == (period, freq, silence)
    assert int(alert.get("pending_minutes", 0)) == pending
    if pending:   # 지속 조건 알림은 period를 frequency와 같게 둔다(한 평가 = period 안의 한 점, 연속성은 pending이 만든다)
        assert period == freq, alert["name"]
        assert "내내" not in alert["what"] + alert["description"], "PromQL 평가는 구간 안의 한 점이라 '내내'가 성립하지 않는다"
    assert (alert["promql_operator"], alert["promql_value"], alert["stream"], alert["stream_type"]) == (op, value, stream, "metrics")
    assert "sql" not in alert and alert["row_template"].startswith("• ")
    assert '"' not in alert["row_template"] and "\\" not in alert["row_template"]   # 행 값을 JSON 본문에 그대로 넣으므로 템플릿이 따옴표·역슬래시를 만들지 않는다
    fields = set(re.findall(r"\{(\w+)\}", alert["row_template"]))
    assert "value" in fields and fields <= PROMQL_ROW_FIELDS
    for key in ("title", "what", "why"):
        assert alert[key].strip() and '"' not in alert[key] and "\n" not in alert[key], key
    assert len(re.findall("[①-⑳]", alert["action"])) >= 2 and alert["runbook"].endswith("#" + alert["name"].removeprefix("infra-"))
    assert re.search(r"\d+분", alert["description"]) and "재통지" in alert["description"]


def test_subquery_over_sum_by_check_catches_the_known_bad_shape():
    assert SUBQUERY_OVER_SUM.search("sum by(host_name)(rate(x[5m]))[6h:5m]")
    assert not SUBQUERY_OVER_SUM.search("min_over_time((1 - avg by(host_name)(x{a='b'}))[10m:1m])")


def test_caddy_4xx_needs_100_requests_in_10_minutes_and_5xx_keeps_10():
    by = {a["name"]: a["promql"] for a in PROMQL_DEFS}
    assert by["infra-caddy-4xx-error-rate"].endswith("[10m])) >= 100)")
    assert by["infra-caddy-5xx-error-rate"].endswith("[10m])) >= 10)")
    assert "code!~'401|499'" in by["infra-caddy-4xx-error-rate"]


AVAILABLE_UNDER_10 = "((sum by(host_name)(system_linux_memory_available) / sum by(host_name)(system_memory_limit)) < 0.10)"


def test_swap_usage_is_p3_and_needs_low_available_memory_too():
    a = {d["name"]: d for d in PROMQL_DEFS}["infra-swap-usage"]
    assert a["severity"] == "P3 주의" and a["severity_icon"] == "🟡"
    assert a["promql"].count(" and on(host_name) ") == 1 and a["promql"].endswith(AVAILABLE_UNDER_10)
    assert a["promql"].startswith("(system_paging_utilization{state='used'} * 100) and on(host_name)")
    assert a["promql_value"] == 80 and "10%" in a["what"] and "10%" in a["title"] and "사용 가능 메모리" in a["description"]


def test_memory_pressure_keeps_1000_major_faults_and_needs_low_available_memory_too():
    a = {d["name"]: d for d in PROMQL_DEFS}["infra-memory-pressure"]
    assert a["promql"] == "sum by(host_name)(rate(system_paging_faults{type='major'}[5m])) and on(host_name) " + AVAILABLE_UNDER_10
    assert a["promql_value"] == 1000 and a["severity"] == "P2 경고" and "10%" in a["what"]


DISK_DEVICES = "device=~'^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|dm-[0-9]+|md[0-9]+)$'"


@pytest.mark.parametrize("direction", ["read", "write"])
def test_disk_latency_is_a_30_minute_average_on_whole_devices_with_minimum_iops_and_30_minute_pending(direction):
    a = {d["name"]: d for d in PROMQL_DEFS}[f"infra-disk-{direction}-latency"]
    q = a["promql"]
    assert DEFAULTS["o2c_disk_latency_min_iops"] == 5
    assert q.endswith(f" and on(host_name,device) (sum by(host_name,device)(rate(system_disk_operations{{direction='{direction}',{DISK_DEVICES}}}[30m])) >= {{{{ o2c_disk_latency_min_iops }}}})")
    assert q.count("[30m]") == 3 and "[5m]" not in q and q.count(DISK_DEVICES) == 3   # 지연 분자·분모·IOPS 하한 모두 30분 평균, 파티션 제외
    assert q.count("{{ o2c_disk_latency_min_iops }}") == 1 and "{{ o2c_disk_latency_min_iops }}" in a["what"]
    assert (a["promql_value"], a["period"], a["frequency"], a["pending_minutes"]) == (100, 5, 5, 30)
    assert "30분" in a["what"] and "내내" not in a["what"]


def test_openobserve_regex_matchers_are_anchored_where_whole_names_matter():
    """OpenObserve 레이블 정규식은 앞뒤가 고정되지 않는다(실측: 'sd[a-z]+'가 sda1에 맞음). 장치·CPU 상태 필터는 ^(...)$로 감싼다."""
    by = {d["name"]: d["promql"] for d in PROMQL_DEFS}
    assert by["infra-disk-io-saturation"].count(DISK_DEVICES) == 1
    for name in ("infra-cpu-usage-p1", "infra-cpu-usage-p2"):
        assert "state=~'^(idle|wait|steal)$'" in by[name] and "min_over_time" not in by[name]


def test_small_thresholds_are_compared_inside_the_query_before_rounding():
    """Config가 round()로 감싸 비교하므로 1%·코어당 2 같은 작은 임계는 PromQL 안에서 비교하고 바깥은 >= 0이다."""
    by = {d["name"]: d for d in PROMQL_DEFS}
    for name, inner in (("infra-network-errors", " * 100) > 1)"), ("infra-cpu-load-saturation", "system_cpu_logical_count) > 2")):
        assert inner in by[name]["promql"] and (by[name]["promql_operator"], by[name]["promql_value"]) == (">=", 0), name
    assert "system_network_packets" in by["infra-network-errors"]["promql"] and "increase(system_network_errors" in by["infra-network-errors"]["promql"]


def test_disk_fill_4h_is_p1_and_the_24h_alert_leaves_its_filesystems_to_it():
    by = {d["name"]: d for d in PROMQL_DEFS}
    four, day = by["infra-disk-fill-4h"]["promql"], by["infra-disk-fill-24h"]["promql"]
    assert "/ 3600) < 4)" in four and ">= 80)" in four and "[6h]" in four
    assert " unless on(host_name,mountpoint,device) (" in day and day.split(" unless ")[1].count("< 4)") == 1   # 같은 파일시스템에 P1·P2가 함께 오지 않는다
    inode = by["infra-inode-fill-24h"]["promql"]
    assert "[1h]" not in inode and inode.count("[6h]") == 2 and "< 40)" in inode


def test_cpu_alerts_are_downgraded_without_renaming():
    by = {d["name"]: d for d in DEFAULTS["o2c_alerts"]}
    assert by["infra-cpu-usage-p1"]["severity"] == "P2 경고" and by["infra-cpu-usage-p2"]["severity"] == "P3 주의"
    assert by["infra-cpu-iowait"]["severity"] == by["infra-cpu-steal"]["severity"] == "P3 주의"
    assert not set(DEFAULTS["o2c_retired_alerts"]) & set(by)


def test_every_promql_alert_has_a_runbook_section_and_a_spec_row():
    runbook, spec = RUNBOOK.read_text(encoding="utf-8"), (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for a in PROMQL_DEFS:
        anchor = a["runbook"].split("#", 1)[1]
        assert f'<a id="{anchor}"></a>' in runbook and f"`{a['name']}`" in runbook, a["name"]
        assert f"`{a['name']}`" in spec, a["name"]


def test_promql_alerts_are_created_as_promql_metrics_alerts_to_the_current_destination(o2):
    assert _apply(o2).returncode == 0
    for name, (sev, period, freq, silence, op, value, stream, pending) in PROMQL_ALERTS.items():
        a = o2.store["alert"][name]
        assert a["pending_period_sec"] == pending * 60, name
        assert a["stream_type"] == "metrics" and a["stream_name"] == stream and a["is_real_time"] is False, name
        qc = a["query_condition"]
        assert qc["type"] == "promql" and qc["promql"].strip() and "sql" not in qc, name
        assert qc["promql_condition"] == {"column": "value", "operator": op, "value": value}, name
        assert a["trigger_condition"] == {"period": period, "operator": ">=", "threshold": 1, "frequency": freq,
                                          "frequency_type": "minutes", "silence": silence, "align_time": True}, name
        assert a["destinations"] == ["infra-automation-webhook"] and a["row_template_type"] == "String" and a["enabled"] is True, name
        assert a["context_attributes"]["severity"] == sev and a["context_attributes"]["link_label"] == "상세 보기", name
        assert a["context_attributes"]["action"].startswith("\n1. "), name


def test_log_alerts_keep_the_sql_condition_and_the_link_label(o2):
    assert _apply(o2).returncode == 0
    for name in EXPECTED_ALERTS:
        a = o2.store["alert"][name]
        assert a["query_condition"]["type"] == "sql" and "align_time" not in a["trigger_condition"], name
        # 원문 링크가 있으면 {alert_url}은 "상세 보기"로 두고 원문은 raw_log_line에 싣는다. 없으면 "로그 보기" 그대로
        has_raw = bool(a["context_attributes"]["raw_log_line"])
        assert a["context_attributes"]["link_label"] == ("상세 보기" if has_raw else "로그 보기"), name


def test_promql_alert_conditions_are_rendered_with_the_iops_variable_and_converge(o2):
    assert _apply(o2).returncode == 0
    for d in ("read", "write"):
        q = o2.store["alert"][f"infra-disk-{d}-latency"]["query_condition"]["promql"]
        assert ">= 5)" in q and "{{" not in q and _balanced(q)
    assert o2.store["alert"]["infra-swap-usage"]["query_condition"]["promql"].endswith("< 0.10))")
    o2.writes.clear()
    assert _apply(o2).returncode == 0 and o2.writes == []
    assert _apply(o2, extra={"o2c_disk_latency_min_iops": 20}).returncode == 0
    puts = sorted(p for m, p, _ in o2.writes if m == "PUT")
    assert len(puts) == 2 and ">= 20)" in o2.store["alert"]["infra-disk-write-latency"]["query_condition"]["promql"]


def test_promql_alerts_converge_and_a_drift_is_one_update(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    assert _apply(o2).returncode == 0 and o2.writes == []
    alert = o2.store["alert"]["infra-swap-usage"]
    alert["query_condition"]["promql_condition"]["value"] = 50
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    assert [(m, p) for m, p, _ in o2.writes] == [("PUT", f"/api/v2/default/alerts/{alert['alert_id']}")]
    assert o2.store["alert"]["infra-swap-usage"]["query_condition"]["promql_condition"]["value"] == 80


def test_promql_alerts_are_not_verified_with_synthetic_records_but_their_evaluation_errors_still_fail(o2):
    assert _apply(o2).returncode == 0
    assert len(o2.searches) == len(EXPECTED_ALERTS)
    assert not any(s in PROMQL_ALERTS for s in FIXTURES)   # 픽스처도 없다(같은 스트림을 쓰는 기존 알림의 합성 레코드만 들어간다)
    o2.history = [{"alert_name": "infra-swap-usage", "status": "error", "timestamp": 1}]
    res = _apply(o2)
    assert res.returncode != 0 and "infra-swap-usage" in res.stdout


def _desired_spec(alerts, p1=""):
    return {"org": "default", "stream": "security_logs", "destination_name": "dest-a", "template_name": "tpl", "template_body": "{}",
            "webhook_url": "https://hooks.example.internal/x", "function_name": "f", "pipeline_name": "p", "vrl": "x",
            "alerts": alerts, "p1_destination": p1}


def _alert_bodies(spec):
    return {d["name"]: d["body"] for d in o2c.o2c_desired(spec) if d["kind"] == "alert"}


def test_a_promql_alert_must_be_on_a_metrics_stream():
    alert = dict(PROMQL_DEFS[0], stream_type="logs", action="① a ② b")
    with pytest.raises(ValueError, match="metrics"):
        o2c.o2c_desired(_desired_spec([alert]))


def test_promql_body_is_built_and_compared_as_a_subset_of_what_the_server_returns():
    want = next(d for d in o2c.o2c_desired(_desired_spec([dict(PROMQL_DEFS[0], action="① a ② b")])) if d["kind"] == "alert")
    stored = dict(want["body"], alert_id="a1", owner="x", updated_at=1, query_condition=dict(want["body"]["query_condition"], sql=""))
    existing = {"alert": [stored], "destination": [{"name": "dest-a"}]}
    assert o2c.o2c_plan([want], existing, "default") == []
    stored["query_condition"]["promql_condition"] = dict(stored["query_condition"]["promql_condition"], value=1)
    assert [a["op"] for a in o2c.o2c_plan([want], existing, "default")] == ["update"]


def test_verify_plan_skips_promql_alerts_even_without_fixtures():
    plan = o2c.o2c_verify_plan([PROMQL_DEFS[0]], {}, "default", "_v", "1", 0)
    assert plan == {"ingest": [], "searches": []}


@pytest.mark.parametrize("dest, sev, expected", [("", "P1 긴급", "dest-a"), ("ops-p1", "P1 긴급", "ops-p1"),
                                                  ("ops-p1", "P2 경고", "dest-a"), ("ops-p1", "P3 주의", "dest-a")])
def test_p1_destination_applies_to_p1_alerts_only_and_defaults_to_the_current_destination(dest, sev, expected):
    alert = dict(PROMQL_DEFS[0], severity=sev, action="① a ② b")
    assert _alert_bodies(_desired_spec([alert], dest))[alert["name"]]["destinations"] == [expected]


def test_default_p1_destination_is_empty():
    assert DEFAULTS["o2c_p1_destination"] == ""


def test_p1_destination_routes_every_p1_alert_log_or_metric_and_nothing_else(o2):
    o2.store["destination"][P1_DEST] = {"name": P1_DEST}
    assert _apply(o2, extra={"o2c_p1_destination": P1_DEST}).returncode == 0
    for name, a in o2.store["alert"].items():
        p1 = a["context_attributes"]["severity"].startswith("P1")
        assert a["destinations"] == [P1_DEST if p1 else "infra-automation-webhook"], name
    assert o2.store["alert"]["infra-root-login-success"]["destinations"] == [P1_DEST]
    assert o2.store["alert"]["infra-disk-fill-4h"]["destinations"] == [P1_DEST]
    assert o2.store["alert"]["infra-cpu-usage-p1"]["destinations"] == ["infra-automation-webhook"]   # #318에서 P2로 내렸다
    assert o2.store["alert"][SELFTEST]["destinations"] == ["infra-automation-webhook"]
    o2.writes.clear()
    assert _apply(o2, extra={"o2c_p1_destination": P1_DEST}).returncode == 0 and o2.writes == []


def test_p1_destination_that_does_not_exist_fails_before_any_write(o2):
    res = _apply(o2, extra={"o2c_p1_destination": P1_DEST})
    assert res.returncode != 0 and o2.writes == []


def test_clearing_the_p1_destination_moves_p1_alerts_back_with_updates_only_for_them(o2):
    o2.store["destination"][P1_DEST] = {"name": P1_DEST}
    assert _apply(o2, extra={"o2c_p1_destination": P1_DEST}).returncode == 0
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    p1 = {n for n, a in o2.store["alert"].items() if a["context_attributes"]["severity"].startswith("P1")}
    assert {p.rsplit("/", 1)[1] for _, p, _ in o2.writes} == {o2.store["alert"][n]["alert_id"] for n in p1}
    assert all(m == "PUT" for m, _, _ in o2.writes)


@pytest.mark.parametrize("bad", ["ops p1", "ops/p1", "ops;p1", "한글"])
def test_invalid_p1_destination_name_fails_before_any_request(o2, bad):
    res = _apply(o2, extra={"o2c_p1_destination": bad})
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []


def test_missing_destinations_lists_names_known_neither_to_the_repository_nor_the_server():
    desired = [{"kind": "destination", "name": "a"}, {"kind": "alert", "name": "x", "body": {"destinations": ["a", "b"]}}]
    assert o2c.o2c_missing_destinations(desired, {}) == ["b"]
    assert o2c.o2c_missing_destinations(desired, {"destination": {"list": [{"name": "b"}]}}) == []


def test_row_values_with_quotes_and_backslashes_must_be_escaped_to_keep_the_body_json(o2):
    """OpenObserve가 {rows:10} 값을 이스케이프하는지는 실서버에서만 알 수 있다(배포 후 시험).
    여기서는 (1) 이스케이프된 값은 본문이 유효 JSON이고 (2) 이스케이프 없는 따옴표는 본문을 깨뜨림을 확인하며, 그래서 PromQL 행 템플릿은 숫자 value와 레이블만 쓴다."""
    assert _apply(o2).returncode == 0
    tpl = o2.store["template"]["infra-automation-webhook"]["body"]
    row = '• host"a \\ b: CPU 91%'
    escaped = json.dumps(row, ensure_ascii=False)[1:-1]
    text = json.loads(tpl.replace("{rows:10}", escaped))["content"]["text"]
    assert row in text and "■ 대상 {alert_count}건:" in text
    with pytest.raises(json.JSONDecodeError):
        json.loads(tpl.replace("{rows:10}", row))
    for a in PROMQL_DEFS:
        assert not re.search(r'["\\]', a["row_template"]), a["name"]


# --- 스트림이 바뀐 알림: update가 아니라 삭제 후 재생성 -------------------------------------------------------------------------------
def _alert_stream_want(name, stream="s_new", stream_type="logs"):
    body = {"name": name, "stream_name": stream, "stream_type": stream_type, "enabled": True}
    return {"kind": "alert", "name": name, "body": body, "match": body, "secret": False}


def _server_stream(name, stream, stream_type="logs"):
    return {"alert": [{"alert_id": "id-" + name, "name": name, "stream_name": stream, "stream_type": stream_type, "enabled": True}]}


def test_plan_recreates_an_alert_whose_stream_name_differs():
    plan = o2c.o2c_plan([_alert_stream_want("infra-a")], _server_stream("infra-a", "s_old"), "default")
    assert [(a["op"], a["method"], a["name"]) for a in plan] == [("recreate", "DELETE", "infra-a"), ("create", "POST", "infra-a")]
    assert plan[0]["path"] == "/api/v2/default/alerts/id-infra-a" and plan[1]["body"]["stream_name"] == "s_new"
    assert o2c.o2c_plan_summary(plan) == ["recreate alert infra-a (stream changed)"]


def test_plan_recreates_an_alert_whose_stream_type_differs():
    plan = o2c.o2c_plan([_alert_stream_want("infra-a", stream_type="metrics")], _server_stream("infra-a", "s_new", "logs"), "default")
    assert [a["op"] for a in plan] == ["recreate", "create"]


def test_plan_does_nothing_when_the_stream_matches():
    assert o2c.o2c_plan([_alert_stream_want("infra-a")], _server_stream("infra-a", "s_new"), "default") == []


def test_plan_updates_instead_when_only_other_fields_differ_and_when_the_server_reports_no_stream():
    want = _alert_stream_want("infra-a")
    plan = o2c.o2c_plan([want], {"alert": [dict(_server_stream("infra-a", "s_new")["alert"][0], enabled=False)]}, "default")
    assert [a["op"] for a in plan] == ["update"]
    plan = o2c.o2c_plan([want], {"alert": [{"alert_id": "id-infra-a", "name": "infra-a", "enabled": False}]}, "default")
    assert [a["op"] for a in plan] == ["update"]


def test_plan_recreate_leaves_alerts_not_in_the_definition_alone():
    existing = {"alert": _server_stream("infra-a", "s_old")["alert"] + _server_stream("infra-other", "s_x")["alert"]}
    plan = o2c.o2c_plan([_alert_stream_want("infra-a")], existing, "default")
    assert [(a["op"], a["name"]) for a in plan] == [("recreate", "infra-a"), ("create", "infra-a")]


def test_plan_recreate_name_is_not_deleted_twice_even_if_it_is_retired():
    plan = o2c.o2c_plan([_alert_stream_want("infra-a")], _server_stream("infra-a", "s_old"), "default", retired=["infra-a"])
    assert [a["op"] for a in plan] == ["recreate", "create"]


def test_recreate_on_the_server_deletes_then_creates_with_the_definition_and_then_converges(o2):
    assert _apply(o2).returncode == 0
    name = "infra-memory-usage-p1"
    o2.store["alert"][name] = dict(o2.store["alert"][name], stream_name="system_memory_usage")   # 서버에는 예전 스트림으로 남은 알림
    old_id = o2.store["alert"][name]["alert_id"]
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"recreate alert {name} (stream changed)" in res.stdout
    assert [(m, p) for m, p, _ in o2.writes] == [("DELETE", f"/api/v2/default/alerts/{old_id}"), ("POST", "/api/v2/default/alerts")]
    assert o2.store["alert"][name]["stream_name"] == "system_linux_memory_available" and o2.store["alert"][name]["alert_id"] != old_id
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and "(stream changed)" not in res.stdout


# --- 원문 로그 링크 (#282): 알림 SQL에서 원문 조회 SQL을 파생해 `/web/logs?...period=1d&query=<base64>`로 연다 -------------
def _filters():
    import importlib.util
    spec = importlib.util.spec_from_file_location("o2c_filters", ROOT_DIR / "filter_plugins" / "openobserve_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _decode_raw_url(url):
    from urllib.parse import parse_qs, urlsplit
    parts = urlsplit(url)
    qs = parse_qs(parts.query)
    return parts.path, {k: v[0] for k, v in qs.items()}, base64.b64decode(qs["query"][0]).decode("utf-8")


def _raw_line(alert):
    return alert["context_attributes"]["raw_log_line"]


def _raw_url(alert):
    """통지 본문에 실린 원문 로그 링크(단축 URL)."""
    line = _raw_line(alert)
    assert line.startswith("\n▶ 로그 보기: "), line
    return line.split(": ", 1)[1]


def _raw_original(o2, alert):
    """단축 URL이 가리키는 원본(`/web/logs?...`). Config가 서버에 등록했어야 찾을 수 있다."""
    m = re.fullmatch(r"(.+)/web/short/([0-9a-f]{16})\?org_identifier=default", _raw_url(alert))
    assert m and m.group(2) in o2.shorts, _raw_url(alert)
    original = o2.shorts[m.group(2)]
    assert hashlib.md5(original.encode()).hexdigest()[8:24] == m.group(2)
    return original


def test_raw_log_sql_keeps_where_verbatim_and_drops_select_list_group_by_and_having():
    f = _filters()
    sql = ("SELECT host_name, count(*) AS failures FROM \"security_logs\" "
           "WHERE event_action = 'ssh_login' AND (user_name = 'root' OR note = 'from where') "
           "GROUP BY host_name HAVING count(*) >= 10")
    assert f.o2c_raw_log_sql(sql, "security_logs") == (
        'SELECT * FROM "security_logs" WHERE event_action = \'ssh_login\' AND (user_name = \'root\' OR note = \'from where\') '
        "ORDER BY _timestamp DESC LIMIT 200")


def test_raw_log_sql_without_where_or_with_union_subquery_join_is_skipped():
    f = _filters()
    assert f.o2c_raw_log_sql('SELECT h, count(*) FROM "s" GROUP BY h HAVING count(*) > 1', "s") == ""   # HAVING만: 원문이 대상을 대변 못 함
    assert f.o2c_raw_log_sql("SELECT 'a' AS h FROM \"s\" WHERE x = 1 UNION ALL SELECT 'b' FROM \"s\" WHERE y = 2", "s") == ""
    assert f.o2c_raw_log_sql('SELECT h FROM "s" WHERE x IN (SELECT x FROM "t")', "s") == ""
    assert f.o2c_raw_log_sql('SELECT h FROM "s" JOIN "t" ON s.a = t.a WHERE x = 1', "s") == ""
    assert f.o2c_raw_log_sql('SELECT h FROM "other" WHERE x = 1', "s") == ""   # 알림 스트림과 다른 FROM
    assert f.o2c_raw_log_sql("", "s") == ""


def test_raw_log_url_round_trips_the_sql_with_quotes_and_non_ascii_and_uses_a_relative_period():
    f = _filters()
    sql = "SELECT * FROM \"system_logs\" WHERE body LIKE '%it''s \"quoted\" 한글 + / =%' ORDER BY _timestamp DESC LIMIT 200"
    url = f.o2c_raw_log_url("https://o2.example.test/", "default", "system_logs", sql)
    path, qs, decoded = _decode_raw_url(url)
    assert url.startswith("https://o2.example.test/web/logs?") and path == "/web/logs"
    assert decoded == sql
    assert qs["period"] == "1d" and "from" not in qs and "to" not in qs   # 정적 from/to를 박지 않는다
    assert (qs["stream"], qs["stream_type"], qs["sql_mode"], qs["org_identifier"]) == ("system_logs", "logs", "true", "default")
    assert "+" not in url.split("query=")[1].split("&")[0] and "/" not in url.split("query=")[1].split("&")[0]   # base64의 + / 는 퍼센트 인코딩


def test_log_alerts_with_a_derivable_where_carry_the_raw_log_link_and_the_others_do_not(o2):
    assert _apply(o2).returncode == 0
    alerts = o2.store["alert"]
    for name in ("infra-ssh-login-failures-per-source", "infra-root-login-success", "infra-oom-kill", "infra-disk-fs-errors",
                 "infra-switch-config-change", "infra-backup-failure"):
        ctx = alerts[name]["context_attributes"]
        path, qs, decoded = _decode_raw_url(_raw_original(o2, alerts[name]))
        assert path == "/web/logs" and qs["stream"] == alerts[name]["stream_name"], name
        assert decoded.startswith('SELECT * FROM "%s" WHERE ' % alerts[name]["stream_name"]), name
        assert decoded.endswith("ORDER BY _timestamp DESC LIMIT 200"), name
        assert not re.search(r"group by|having|count\(", decoded, re.I), name
        assert ctx["link_label"] == "상세 보기", name   # {alert_url}(알림 화면)은 상세, 원문은 별도 줄
    where = _decode_raw_url(_raw_original(o2, alerts["infra-ssh-login-failures-per-host"]))[2]
    assert "event_action = 'ssh_login' AND event_outcome = 'failure'" in where
    # raw_sql 직접 지정: HAVING만으로 거르는 집계
    for name, stream in (("infra-log-parse-errors-security-logs", "security_logs"), ("infra-log-parse-errors-system-logs", "system_logs")):
        assert _decode_raw_url(_raw_original(o2, alerts[name]))[2] == (
            'SELECT * FROM "%s" WHERE log_parse_error = true ORDER BY _timestamp DESC LIMIT 200' % stream)
    # 파생 불가·메트릭·PromQL·자가 시험은 기존 링크와 라벨을 그대로 둔다
    for name, alert in alerts.items():
        ctx = alert["context_attributes"]
        if name in ("infra-backup-missing", "infra-maintenance-missing", "infra-switch-syslog-silent", "infra-silent-host-p1", "infra-app-telemetry-silent", "infra-disk-usage-p1", SELFTEST) \
                or name in PROMQL_ALERTS:
            assert _raw_line(alert) == "", name
        assert ctx["link_label"] in ("로그 보기", "상세 보기"), name
        if _raw_line(alert) == "" and alert["stream_type"] == "logs" and name != SELFTEST:
            assert ctx["link_label"] == "로그 보기", name


def test_template_places_the_raw_log_line_right_after_the_alert_url(o2):
    assert _apply(o2).returncode == 0
    text = json.loads(o2.store["template"]["infra-automation-webhook"]["body"])["content"]["text"]
    assert "▶ {link_label}: {alert_url}{raw_log_line}\n" in text


def test_without_a_web_url_no_alert_gets_a_raw_log_link_and_the_second_run_changes_nothing(o2):
    assert _apply(o2, extra={"o2c_web_url": ""}).returncode == 0
    assert all(_raw_line(a) == "" for a in o2.store["alert"].values())
    o2.writes.clear()
    res = _apply(o2, extra={"o2c_web_url": ""})
    assert res.returncode == 0 and _changed(res) == 0 and o2.writes == []


def test_raw_log_link_run_converges_and_a_changed_web_url_updates_only_the_log_alerts(o2):
    assert _apply(o2).returncode == 0
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [], res.stdout
    assert _changed(res) == 0
    assert _raw_url(o2.store["alert"]["infra-oom-kill"]).startswith(o2.url + "/web/short/")   # 기본 베이스는 연결 엔드포인트
    assert _raw_original(o2, o2.store["alert"]["infra-oom-kill"]).startswith(o2.url + "/web/logs?")
    res = _apply(o2, extra={"o2c_web_url": "https://o2.public.example.test"})
    assert res.returncode == 0
    assert all(m == "PUT" for m, _, _ in o2.writes) and o2.writes
    assert _raw_url(o2.store["alert"]["infra-oom-kill"]).startswith("https://o2.public.example.test/web/short/")
    assert _raw_original(o2, o2.store["alert"]["infra-oom-kill"]).startswith("https://o2.public.example.test/web/logs?")
    assert _raw_line(o2.store["alert"]["infra-backup-missing"]) == ""


# --- 단축 URL: 통지 본문의 원문 로그 링크는 서버에 묻지 않고 계산한 단축 URL이고, 반영 때 등록한다 ----------------------------
def test_short_url_is_the_middle_of_the_md5_like_the_server():
    f = _filters()
    original = ("https://openobserve.ns0331.nanoit.kr/web/logs?stream_type=logs&stream=system_logs&period=15m&sql_mode=true"
                "&query=U0VMRUNUICogRlJPTSAic3lzdGVtX2xvZ3MiIExJTUlUIDEw&org_identifier=default&type=alerts&show_histogram=false")
    # 실서버(v1.0.4)가 이 원본에 돌려준 값(2026-10-22 실측)
    assert f.o2c_short_url("https://openobserve.ns0331.nanoit.kr/", "default", original) == \
        "https://openobserve.ns0331.nanoit.kr/web/short/d39e007b3b7a5af5?org_identifier=default"


def test_short_url_mismatch_compares_only_the_id_and_flags_failures():
    f = _filters()
    exp = "https://a.example.test/web/short/0123456789abcdef?org_identifier=default"
    ok = {"status": 200, "json": {"short_url": "https://other-host.example.test/web/short/0123456789abcdef?org_identifier=default"}, "item": {"expected": exp}}
    clash = {"status": 200, "json": {"short_url": "https://a.example.test/web/short/fedcba9876543210?org_identifier=default"}, "item": {"expected": exp}}
    down = {"status": 500, "json": {}, "item": {"expected": exp}}
    assert f.o2c_short_url_mismatches([ok]) == []
    assert f.o2c_short_url_mismatches([ok, clash, down]) == [exp, exp]


def test_every_raw_log_link_is_registered_once_and_the_notification_never_carries_the_long_url(o2):
    assert _apply(o2).returncode == 0
    lines = [a["context_attributes"]["raw_log_line"] for a in o2.store["alert"].values() if a["context_attributes"]["raw_log_line"]]
    assert lines and all("/web/logs?" not in line and "/web/short/" in line for line in lines)
    assert len(o2.shorts) == len({line for line in lines})
    for alert in o2.store["alert"].values():
        if alert["context_attributes"]["raw_log_line"]:
            _raw_original(o2, alert)


def test_a_short_url_hash_collision_stops_before_any_alert_write(o2):
    o2.short_collide = True
    res = _apply(o2)
    assert res.returncode != 0 and "O2C-019" in res.stdout
    assert not any("/alerts" in p for m, p, _ in o2.writes if m in ("POST", "PUT"))


def test_promql_alerts_round_the_value_so_notifications_carry_no_decimals(o2):
    assert _apply(o2).returncode == 0
    defs = {a["name"]: a["promql"] for a in PROMQL_DEFS}
    for name, q in defs.items():
        assert o2.store["alert"][name]["query_condition"]["promql"] == "round(%s)" % q.replace("{{ o2c_disk_latency_min_iops }}", "5"), name


# --- 지속 조건 pending_period_sec (#318): 알림 최상위 필드, 0도 항상 보내고 계획 비교에 들어간다 --------------------------------
def _one_alert_want(**extra):
    alert = dict(PROMQL_DEFS[0], action="① a ② b", **extra)
    return next(d for d in o2c.o2c_desired(_desired_spec([alert])) if d["kind"] == "alert")


def test_pending_minutes_become_top_level_pending_period_sec_and_zero_is_always_sent():
    want = _one_alert_want()
    assert want["body"]["pending_period_sec"] == 15 * 60 and "pending_period_sec" not in want["body"]["trigger_condition"]
    assert _one_alert_want(pending_minutes="30")["body"]["pending_period_sec"] == 1800   # 템플릿 렌더링 값(문자열)도 정수로
    no_pending = dict(PROMQL_DEFS[0], action="① a ② b")
    no_pending.pop("pending_minutes", None)
    body = next(d for d in o2c.o2c_desired(_desired_spec([no_pending])) if d["kind"] == "alert")["body"]
    assert body["pending_period_sec"] == 0   # 빼면 60 → 0으로 줄인 정의가 부분집합 비교에서 같게 보여 서버에 옛 값이 남는다


@pytest.mark.parametrize("server, minutes, ops", [(900, 15, []), (0, 15, ["update"]), (900, 0, ["update"]), (1800, 15, ["update"])])
def test_plan_compares_pending_period_sec_and_converges(server, minutes, ops):
    want = _one_alert_want(pending_minutes=minutes)
    stored = dict(want["body"], alert_id="a1", pending_period_sec=server)
    existing = {"alert": [stored], "destination": [{"name": "dest-a"}]}
    plan = o2c.o2c_plan([want], existing, "default")
    assert [a["op"] for a in plan] == ops
    if plan:   # 반영한 서버 상태(GET 응답에 pending_period_sec가 남는 것은 실서버 v1.0.4에서 확인)로 다시 계획하면 변경이 없다
        existing["alert"] = [dict(stored, **plan[0]["body"])]
        assert o2c.o2c_plan([want], existing, "default") == []


def test_pending_drift_on_the_server_is_one_update_and_the_rerun_writes_nothing(o2):
    assert _apply(o2).returncode == 0
    assert o2.store["alert"]["infra-disk-write-latency"]["pending_period_sec"] == 1800
    assert o2.store["alert"]["infra-oom-kill"]["pending_period_sec"] == 0 and o2.store["alert"]["infra-auditd-stopped"]["pending_period_sec"] == 120
    alert = o2.store["alert"]["infra-disk-write-latency"]
    alert["pending_period_sec"] = 0   # 서버에서 누군가 대기를 지운 상태
    o2.writes.clear()
    assert _apply(o2).returncode == 0
    assert [(m, p) for m, p, _ in o2.writes] == [("PUT", f"/api/v2/default/alerts/{alert['alert_id']}")]
    assert o2.store["alert"]["infra-disk-write-latency"]["pending_period_sec"] == 1800
    o2.writes.clear()
    res = _apply(o2)
    assert res.returncode == 0 and o2.writes == [] and _changed(res) == 0


# --- 보안 로그 알림 (#318) ------------------------------------------------------------------------------------------------
SECURITY_ALERTS = {   # name -> (severity, period, silence, pending minutes, marker only its search carries)
    "infra-ssh-bruteforce-success": ("P1 긴급", 15, 15, 0, "event_outcome IN ('failure', 'success')"),
    "infra-account-change": ("P2 경고", 5, 5, 0, "type=ADD_USER"),
    "infra-sudo-risky-command": ("P1 긴급", 5, 5, 0, "process_command_line"),
    "infra-auditd-stopped": ("P1 긴급", 10, 10, 2, "type=DAEMON_START"),
    "infra-account-lockout": ("P2 경고", 5, 5, 0, "account temporarily locked"),
}


def test_security_alerts_are_created_with_their_grades_windows_and_raw_log_links(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    for name, (sev, period, silence, pending, _marker) in SECURITY_ALERTS.items():
        a = o2.store["alert"][name]
        assert a["stream_name"] == "security_logs" and a["query_condition"]["type"] == "sql", name
        assert a["context_attributes"]["severity"] == sev, name
        trigger = a["trigger_condition"]
        assert (trigger["period"], trigger["frequency"], trigger["silence"], a["pending_period_sec"]) == (period, 1, silence, pending * 60), name
        decoded = _decode_raw_url(_raw_original(o2, a))[2]   # 모두 WHERE에서 원문 조회를 파생한다
        assert decoded.startswith('SELECT * FROM "security_logs" WHERE ') and "count(" not in decoded, name


def test_security_alert_sql_fires_on_the_fixture_cases_and_only_those_when_it_runs_on_the_synthetic_records(o2):
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    records = [r for p, _, rs in o2.ingests if "/security_logs_alert_verify/" in p for r in rs]
    searches = [sql for stream, sql in o2.searches if stream == "security_logs_alert_verify"]
    for name, (*_, marker) in SECURITY_ALERTS.items():
        (sql,) = [s for s in searches if marker in s]
        spec = FIXTURES[name]
        own = {c["host"] for c in spec["cases"]}
        rows = _run_alert_on_sqlite(sql, records, "security_logs_alert_verify")
        fired = {m.group(1) for row in rows if (m := re.fullmatch(r"(.+)-[0-9a-f]+", str(row["host_name"]))) and m.group(1) in own}
        assert fired == {c["host"] for c in spec["cases"] if c["fires"]}, name
        if name == "infra-account-change":   # 특권 그룹은 따로 표시하고 실행 계정은 auditd AUID에서 읽는다
            kinds = {(re.fullmatch(r"(.+)-[0-9a-f]+", r["host_name"]).group(1), r["change_kind"], r["actor"]) for r in rows
                     if re.fullmatch(r"(.+)-[0-9a-f]+", r["host_name"]).group(1) in own}
            assert ("verify-acct-wheel", "특권 그룹 변경", "opsverify") in kinds and ("verify-acct-add", "계정·그룹 추가", "opsverify") in kinds
        if name == "infra-sudo-risky-command":   # 통지 행에는 명령 원문 대신 종류 라벨만 싣는다
            labels = {r["command_kind"] for r in rows}
            assert labels <= {"SELinux 해제", "방화벽 규칙 초기화", "보안·로그 서비스 중지"} and "process_command_line" not in FIXTURES and \
                "{command_kind}" in o2.store["alert"][name]["row_template"] and "{process_command_line}" not in o2.store["alert"][name]["row_template"]


def test_security_fixtures_cover_every_new_alert_with_firing_and_quiet_cases():
    for name in SECURITY_ALERTS:
        assert {c["fires"] for c in FIXTURES[name]["cases"]} == {True, False}, name
    assert any("usermod --help" in r.get("body", "") or "--help" in r.get("body", "") for c in FIXTURES["infra-account-change"]["cases"] for r in c["records"])
    assert any("grantors=pam_faillock" in r.get("body", "") for c in FIXTURES["infra-account-lockout"]["cases"] for r in c["records"])


def test_sudo_risky_command_list_builds_safe_like_conditions_and_rejects_unsafe_input():
    groups = o2c.o2c_sudo_risky_groups([{"label": "SELinux 해제", "patterns": ["setenforce 0"]}], ["auditd"], "서비스 중지")
    assert groups[-1] == {"label": "서비스 중지", "patterns": [v % "auditd" for v in o2c.SERVICE_STOP_VERBS]}
    assert o2c.o2c_like_any(groups[:1], "process_command_line") == "(lower(process_command_line) LIKE '%setenforce 0%')"
    assert o2c.o2c_like_label(groups[:1], "process_command_line").startswith("CASE WHEN (lower(process_command_line) LIKE '%setenforce 0%') THEN 'SELinux 해제'")
    for bad in ([{"label": "x", "patterns": ["it's"]}], [{"label": "x", "patterns": ["a%b"]}], [{"label": "x", "patterns": ["UPPER"]}],
                [{"label": "a'b", "patterns": ["x"]}], [{"label": "x", "patterns": []}]):
        assert not o2c.o2c_valid_like_groups(bad), bad
        with pytest.raises(ValueError):
            o2c.o2c_like_any(bad, "process_command_line")
    with pytest.raises(ValueError):
        o2c.o2c_sudo_risky_groups([], ["auditd; drop"], "x")
    assert o2c.o2c_valid_group_names(["wheel", "systemd-journald"]) and not o2c.o2c_valid_group_names(["Wheel"])


@pytest.mark.parametrize("extra", [{"o2c_privileged_groups": []}, {"o2c_privileged_groups": ["wh'eel"]},
                                   {"o2c_sudo_risky_commands": [{"label": "x", "patterns": ["a'b"]}]},
                                   {"o2c_sudo_protected_services": ["Auditd"]}, {"o2c_ssh_bruteforce_min_failures": 0}])
def test_invalid_security_alert_variables_fail_before_any_request(o2, extra):
    res = _apply(o2, extra=extra)
    assert res.returncode != 0 and o2.reads == [] and o2.writes == []


def test_every_new_alert_has_a_runbook_section_and_a_spec_mention():
    runbook, spec = RUNBOOK.read_text(encoding="utf-8"), (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for name in list(SECURITY_ALERTS) + ["infra-disk-fill-4h"]:
        anchor = name.removeprefix("infra-")
        assert f'<a id="{anchor}"></a>' in runbook and f"`{name}`" in runbook and f"`{name}`" in spec, name
    assert "pending_period_sec" in spec and "pending_minutes" in spec


# --- RAID 상태 알림 (Spec #322 / Ticket-13, #335) ---------------------------------------------------------------------------
RAID_ALERTS = {   # alert -> a fragment only its search carries
    "infra-raid-write-cache-disabled": "kind = 'controller'\nAND (cache_status",
    "infra-raid-controller-fault": "kind = 'controller' AND hw_state <> 'ok'",
    "infra-raid-logical-drive-degraded": "kind = 'logical_drive'",
    "infra-raid-physical-drive-fault": "kind = 'physical_drive'",
    "infra-raid-cache-battery-fault": "kind = 'cache_battery'",
    "infra-raid-collection-error": "status IN ('timeout', 'error')",
    "infra-host-status-silent": "UNION ALL",
}


def test_raid_alert_sql_fires_on_the_fixture_cases_and_only_those_when_it_runs_on_the_synthetic_records(o2):
    """The searches the verification step sends are executed on the injected records (sqlite), not just compared by name."""
    res = _apply(o2)
    assert res.returncode == 0, res.stdout + res.stderr
    records = [r for p, _, rs in o2.ingests if "/host_status_logs_alert_verify/" in p for r in rs]
    searches = [sql for stream, sql in o2.searches if stream == "host_status_logs_alert_verify"]
    assert len(searches) == len(RAID_ALERTS)
    for name, marker in RAID_ALERTS.items():
        found = [s for s in searches if marker.replace("\n", " ") in s.replace("\n", " ")]
        assert len(found) == 1, (name, found)
        spec = FIXTURES[name]
        own = {c["host"] for c in spec["cases"]}   # the alerts share one stream: judge only this alert's own cases
        fired = {m.group(1) for row in _run_alert_on_sqlite(found[0], records, "host_status_logs_alert_verify")
                 if (m := re.fullmatch(r"(.+)-[0-9a-f]+", str(row["host_name"]))) and m.group(1) in own}
        assert fired == {c["host"] for c in spec["cases"] if c["fires"]}, name


def test_raid_alerts_are_p2_with_a_two_reading_window_and_a_runbook_entry(o2):
    assert _apply(o2).returncode == 0
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for name in RAID_ALERTS:
        alert = o2.store["alert"][name]
        assert alert["context_attributes"]["severity"] == "P2 경고", name
        assert alert["stream_name"] == "host_status_logs", name
        assert f"(`{name}`)" in runbook, name
    for name in set(RAID_ALERTS) - {"infra-raid-collection-error", "infra-host-status-silent"}:
        trigger = o2.store["alert"][name]["trigger_condition"]
        assert (trigger["period"], trigger["frequency"]) == (15, 5), name
        assert "HAVING count(*) >= 2" in o2.store["alert"][name]["query_condition"]["sql"], name


def test_raid_alert_sql_reads_only_fields_every_record_of_its_kind_carries():
    """OpenObserve rejects SQL on columns that do not exist yet: the alerts read only fields the collector always emits."""
    script = (ROOT_DIR / "roles" / "monitoring" / "files" / "host-agents-raid-status.sh").read_text(encoding="utf-8")
    for field in ("kind", "hw_state", "hw_name", "raw_state", "cache_status", "cache_reason", "backup_power_operation",
                  "status", "message"):
        assert f'\\"{field}\\":' in script or f'"{field}":' in script, field


def test_ssh_per_host_alert_fires_only_on_distributed_attacks_when_it_runs_on_the_fixtures(o2):
    """A single-source brute force is the per-source alert's job; the per-host alert must not repeat it."""
    assert _apply(o2).returncode == 0
    records = [r for p, _, rs in o2.ingests if "/security_logs_alert_verify/" in p for r in rs]
    (sql,) = [s for stream, s in o2.searches if stream == "security_logs_alert_verify" and "count(DISTINCT source_address)" in s]
    spec = FIXTURES["infra-ssh-login-failures-per-host"]
    own = {c["host"] for c in spec["cases"]}
    fired = {m.group(1) for row in _run_alert_on_sqlite(sql, records, "security_logs_alert_verify")
             if (m := re.fullmatch(r"(.+)-[0-9a-f]+", str(row["host_name"]))) and m.group(1) in own}
    assert fired == {c["host"] for c in spec["cases"] if c["fires"]} == {"verify-ssh-host-burst"}


# ---- 알림 대상 행의 발생 시각(KST) — Spec #339 / Ticket-1 (#341) ----

def _kst_us(text):
    """'2026-10-23 08:55:02' (KST) -> µs since the epoch."""
    return int(datetime.fromisoformat(text).replace(tzinfo=timezone(timedelta(hours=9))).timestamp()) * 1_000_000


def test_sqlite_date_format_helper_follows_the_openobserve_contract():
    us = 1_792_767_302_000_000   # 2026-10-23 14:55:02 UTC
    assert _date_format(us, "%m-%d %H:%M:%S", "+09:00") == "10-23 23:55:02"
    assert _date_format(us // 1_000_000, "%m-%d %H:%M:%S", "+09:00") == "10-23 23:55:02"   # seconds input
    assert _date_format(_kst_us("2026-10-23 08:59:14"), "%m-%d %H:%M:%S", "+09:00") == "10-23 08:59:14"
    assert _date_format(us, "%H:%M", "-05:30") == "09:25"
    assert _date_format(None, "%H", "+09:00") is None


def _row_lines(o2, name, records, stream):
    """What an operator reads: the alert's row template filled with every row its SQL returns on the records."""
    alert = o2.store["alert"][name]
    rows = _run_alert_on_sqlite(alert["query_condition"]["sql"], records, stream)
    return [re.sub(r"\{(\w+)\}", lambda m: str(row[m.group(1)]), alert["row_template"]) for row in rows]


def _fail(ts, source="203.0.113.10", host="ns0272"):
    return {"event_action": "ssh_login", "event_outcome": "failure", "user_name": "admin", "source_address": source,
            "host_name": host, "_timestamp": _kst_us(ts)}


def test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range(o2):
    assert _apply(o2).returncode == 0
    name = "infra-ssh-login-failures-per-source"
    one = [_fail("2026-10-23 08:59:14")] * 10
    assert _row_lines(o2, name, one, "security_logs") == ["• 203.0.113.10 → ns0272: 실패 10회 · 10-23 08:59:14"]
    two = [_fail("2026-10-23 08:55:02")] * 5 + [_fail("2026-10-23 08:59:14")] * 5
    assert _row_lines(o2, name, two, "security_logs") == ["• 203.0.113.10 → ns0272: 실패 10회 · 10-23 08:55:02~08:59:14"]


def test_event_time_range_across_midnight_keeps_both_dates(o2):
    assert _apply(o2).returncode == 0
    recs = [_fail("2026-10-23 23:58:00")] * 5 + [_fail("2026-10-24 00:02:30")] * 5
    assert _row_lines(o2, "infra-ssh-login-failures-per-source", recs, "security_logs") == [
        "• 203.0.113.10 → ns0272: 실패 10회 · 10-23 23:58:00~10-24 00:02:30"]


def test_event_time_does_not_change_which_sources_fire(o2):
    assert _apply(o2).returncode == 0
    recs = [_fail("2026-10-23 08:59:14", "203.0.113.11")] * 9 + [_fail("2026-10-23 08:59:14", "203.0.113.12")] * 10
    assert [r.split(" ")[1] for r in _row_lines(o2, "infra-ssh-login-failures-per-source", recs, "security_logs")] == ["203.0.113.12"]
    sql = _sql(o2, "infra-ssh-login-failures-per-source")
    assert "WHERE event_action = 'ssh_login' AND event_outcome = 'failure'" in sql
    assert "GROUP BY source_address, host_name HAVING count(*) >= 10" in sql


def test_per_source_rows_come_out_with_the_most_failures_first_so_the_10_row_cap_keeps_the_worst(o2):
    assert _apply(o2).returncode == 0
    recs = [_fail("2026-10-23 08:59:14", "203.0.113.11")] * 11 + [_fail("2026-10-23 08:59:14", "203.0.113.12")] * 30
    rows = _row_lines(o2, "infra-ssh-login-failures-per-source", recs, "security_logs")
    assert [r.split(" ")[1] for r in rows] == ["203.0.113.12", "203.0.113.11"]


def test_raw_log_link_survives_the_event_time_column(o2):
    assert _apply(o2).returncode == 0
    alert = o2.store["alert"]["infra-ssh-login-failures-per-source"]
    assert alert["context_attributes"]["raw_log_line"].startswith("\n▶ 로그 보기: http")
    from openobserve_config import o2c_raw_log_sql
    assert o2c_raw_log_sql(alert["query_condition"]["sql"], "security_logs") == (
        "SELECT * FROM \"security_logs\" WHERE event_action = 'ssh_login' AND event_outcome = 'failure' ORDER BY _timestamp DESC LIMIT 200")


def _rendered_message(o2, name, row_values):
    """The notification text with 10 rows filled the way OpenObserve does (every variable replaced)."""
    alert = o2.store["alert"][name]
    ctx = alert["context_attributes"]
    text = json.loads(o2.store["template"]["infra-automation-webhook"]["body"])["content"]["text"]
    rows = "\n".join(re.sub(r"\{(\w+)\}", lambda m: row_values[m.group(1)], alert["row_template"]) for _ in range(10))
    values = dict(ctx, rows=rows, alert_count="10", alert_url="https://o2.example.test/web/short/0123456789abcdef?org_identifier=default",
                  alert_trigger_time_str="2026-10-23T09:00:56", alert_name=name)
    text = text.replace("{rows:10}", "{rows}")
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), text)


# 가장 긴 현실적 값: IPv4 출발지, 5분 구간 실패 4자리(9999), 자정을 넘는 시각 범위
LONGEST_ROW_VALUES = {"source_address": "198.51.100.255", "host_name": "ns0272",
                      "failures": "9999", "event_time": "10-23 23:58:00~10-24 00:02:30", "sources": "999"}
COUNT_FIELDS = ("logins", "successes", "changes", "runs", "stops", "locks", "total", "parse_errors", "kills", "matches", "errors",
                "readings", "events", "detections", "downs", "flaps", "severity_code")
LONGEST_TEXT = {"user_name": "u" * 32, "actor": "u" * 32, "command_kind": "가" * 14, "change_kind": "가" * 9,   # 계정 이름 32자(리눅스 한계), 알림이 정한 짧은 라벨
                "container_name": "c" * 32, "cache_status": "permanently_disabled", "cache_reason": "r" * 30, "raw_state": "Predictive Failure",
                "status": "timeout", "tcpcheck_endpoint": "198.51.100.255:65535", "killed_process": "p" * 15, "hw_name": "h" * 24, "device": "ns0380+ns0381", "port": "GigabitEthernet1/0/48"}
TEXT_VALUE = "x" * 40   # 그 밖의 자유 문장 필드(명령·경로·이벤트 이름 등)의 현실적으로 긴 값


def test_every_alert_with_an_event_time_column_fits_the_2000_character_limit_with_10_longest_rows(o2):
    assert _apply(o2).returncode == 0
    with_time = [n for n, a in o2.store["alert"].items() if a["query_condition"]["type"] == "sql" and "event_time" in a["row_template"]]
    assert "infra-ssh-login-failures-per-source" in with_time
    for name in with_time:
        fields = set(re.findall(r"\{(\w+)\}", o2.store["alert"][name]["row_template"]))
        values = {f: LONGEST_ROW_VALUES.get(f, "999" if f in COUNT_FIELDS else LONGEST_TEXT.get(f, TEXT_VALUE)) for f in fields}
        assert len(_rendered_message(o2, name, values)) <= 2000, name


UNCHANGED_ROW_TEMPLATES = {   # PromQL, missing-type, usage and self-test alerts keep their row templates byte for byte (#339)
    "infra-cpu-usage-p1": "• {host_name}: CPU {value}%", "infra-cpu-usage-p2": "• {host_name}: CPU {value}%",
    "infra-caddy-5xx-error-rate": "• {host_name}: 5xx 비율 {value}%", "infra-caddy-4xx-error-rate": "• {host_name}: 4xx 비율 {value}%",
    "infra-disk-fill-24h": "• {host_name} {mountpoint}: 약 {value}시간 뒤 가득 참",
    "infra-disk-fill-4h": "• {host_name} {mountpoint}: 약 {value}시간 뒤 가득 참",
    "infra-network-errors": "• {host_name} {device}({direction}): 오류 비율 {value}%",
    "infra-cpu-load-saturation": "• {host_name}: 코어당 load {value}", "infra-cpu-iowait": "• {host_name}: iowait {value}%",
    "infra-cpu-steal": "• {host_name}: steal {value}%", "infra-disk-io-saturation": "• {host_name} {device}: 큐 깊이 {value}",
    "infra-disk-read-latency": "• {host_name} {device}: 읽기 지연 {value}ms",
    "infra-disk-write-latency": "• {host_name} {device}: 쓰기 지연 {value}ms",
    "infra-inode-fill-24h": "• {host_name} {mountpoint}: 약 {value}시간 뒤 inode 고갈",
    "infra-conntrack-limit": "• {host_name}: conntrack 사용률 {value}%", "infra-swap-usage": "• {host_name} {device}: 스왑 사용률 {value}%",
    "infra-memory-pressure": "• {host_name}: 주요 페이지 폴트 초당 {value}건",
    "infra-disk-usage-p2": "• {host_name} {mountpoint}: 사용률 {usage_pct}%", "infra-disk-usage-p1": "• {host_name} {mountpoint}: 사용률 {usage_pct}%",
    "infra-inode-usage-p2": "• {host_name} {mountpoint}: 사용률 {usage_pct}%", "infra-inode-usage-p1": "• {host_name} {mountpoint}: 사용률 {usage_pct}%",
    "infra-memory-usage-p2": "• {host_name}: 사용률 {usage_pct}%", "infra-memory-usage-p1": "• {host_name}: 사용률 {usage_pct}%",
    "infra-silent-host-p2": "• {host_name}", "infra-silent-host-p1": "• {host_name}", "infra-backup-missing": "• {host}",
    "infra-maintenance-missing": "• {host}", "infra-host-status-silent": "• {host_name}", "infra-app-telemetry-silent": "• {host_name}",
    "infra-switch-syslog-silent": "• {device_id}", "infra-fortigate-syslog-silent": "• {device_id}",
    SELFTEST: "• {host_name}: 시험 레코드 {records}건 · 이스케이프 시험 값 {probe}",
}


def test_promql_missing_usage_and_selftest_row_templates_are_unchanged(o2):
    assert _apply(o2, extra={"o2c_switch_uplinks": UPLINKS}).returncode == 0
    for name, template in UNCHANGED_ROW_TEMPLATES.items():
        assert o2.store["alert"][name]["row_template"] == template, name


# ---- 알림 대상 행의 발생 시각 — Ticket-2 (#342): 나머지 security_logs 서버 알림 ----

def _ev(ts, **fields):
    return dict({"host_name": "ns0272", "_timestamp": _kst_us(ts)}, **fields)


SECURITY_TIME_CASES = {   # alert -> (record fields, expected row without the time)
    "infra-ssh-login-failures-per-host": (
        [dict(event_action="ssh_login", event_outcome="failure", source_address=f"203.0.113.{n}") for n in (1, 2, 3)] * 17,
        "• ns0272: 실패 51회 (출발지 3곳)"),
    "infra-root-login-success": (
        [dict(event_action="ssh_login", event_outcome="success", user_name="root", source_address="198.51.100.7")],
        "• ns0272 ← 198.51.100.7 (1회)"),
    "infra-sudo-escalation-failure": (
        [dict(event_action="sudo", event_outcome="failure", user_name="alice")], "• ns0272 / 사용자 alice: 실패 1회"),
    "infra-account-lockout": (
        [dict(body="pam_faillock(sshd:auth): Account temporarily locked")], "• ns0272: 잠금 기록 1건"),
}


@pytest.mark.parametrize("name", sorted(SECURITY_TIME_CASES))
def test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range(o2, name):
    assert _apply(o2).returncode == 0
    fields, expected = SECURITY_TIME_CASES[name]
    n = len(fields)
    one = [_ev("2026-10-23 08:59:14", **f) for f in fields]
    assert _row_lines(o2, name, one, "security_logs") == [f"{expected} · 10-23 08:59:14"]
    two = [_ev("2026-10-23 08:55:02", **f) for f in fields[: max(n // 2, 1)]] + [_ev("2026-10-23 08:59:14", **f) for f in fields[max(n // 2, 1):] or fields[:1]]
    assert _row_lines(o2, name, two, "security_logs")[0].endswith(" · 10-23 08:55:02~08:59:14")


def test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time(o2):
    assert _apply(o2).returncode == 0
    for name, stream in (("infra-log-parse-errors-security-logs", "security_logs"), ("infra-log-parse-errors-system-logs", "system_logs")):
        alert = o2.store["alert"][name]
        assert alert["row_template"].endswith(" · {event_time}")
        recs = [_ev("2026-10-23 08:55:02", log_parse_error=True)] * 60 + [_ev("2026-10-23 08:59:14", log_parse_error=False)] * 40
        rows = _row_lines(o2, name, recs, stream)
        assert rows and rows[0].endswith(" · 10-23 08:55:02~08:59:14"), name
        assert alert["context_attributes"]["raw_log_line"].startswith("\n▶ 로그 보기: http")


# ---- 알림 대상 행의 발생 시각 — Ticket-3 (#343): system·app·backup·host_status·tcpcheck ----

SYSTEM_TIME_CASES = {   # alert -> (stream, record fields, expected row without the time; "{n}" is the record count)
    "infra-oom-kill": ("system_logs", [dict(body="Out of memory: Killed process 123 (java) total-vm:1kB")],
                       "• ns0272: 종료된 프로세스 java ({n}건)"),
    "infra-disk-fs-errors": ("system_logs", [dict(body="blk_update_request: I/O error, dev sda")], "• ns0272: 오류 패턴 {n}건"),
    "infra-app-log-errors": ("app_logs", [dict(severity="error", container_name="api")], "• ns0272 / api: ERROR 이상 {n}건"),
    "infra-backup-failure": ("backup_logs", [dict(job="backup", success=False, host="ns0272")], "• ns0272: 실패 {n}건"),
    "infra-raid-collection-error": ("host_status_logs", [dict(kind="tool_status", status="error", message="m")] * 3,
                                    "• ns0272: error {n}회 (m)"),
    "infra-unreachable-host": ("tcpcheck_status", [dict(tcpcheck_endpoint="198.51.100.5:22", value=0)],
                               "• 198.51.100.5:22 (검사: ns0272)"),
}


@pytest.mark.parametrize("name", sorted(SYSTEM_TIME_CASES))
def test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last(o2, name):
    assert _apply(o2).returncode == 0
    stream, base, expected = SYSTEM_TIME_CASES[name]
    k = len(base)
    one = [_ev("2026-10-23 08:59:14", **f) for f in base]
    assert _row_lines(o2, name, one, stream) == [expected.format(n=k) + " · 10-23 08:59:14"]
    two = [_ev("2026-10-23 08:55:02", **f) for f in base] + [_ev("2026-10-23 08:59:14", **f) for f in base]
    rows = _row_lines(o2, name, two, stream)
    assert rows == [expected.format(n=2 * k) + " · 10-23 08:55:02~08:59:14"]


def test_backup_and_raid_missing_and_usage_alerts_keep_their_rows(o2):
    assert _apply(o2).returncode == 0
    for name in ("infra-backup-missing", "infra-maintenance-missing", "infra-host-status-silent", "infra-disk-usage-p1"):
        assert "event_time" not in o2.store["alert"][name]["row_template"], name
