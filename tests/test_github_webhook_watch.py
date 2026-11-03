"""github_webhook_watch 역할 테스트 (Spec #399 / Ticket-5, #404).

seam 1(빠름): 점검 모듈 `gww_check.check()`를 외부 API(GitHub)를 모사한 로컬 HTTP 서버에 직접 붙여 비교·재전송 선택 로직을 증명한다(ADR-0013 필터 직접 테스트).
seam 2(slow, 소수): 역할을 실제 `ansible-playbook`으로 실행해 하트비트 레코드, 실패 표면화, check 모드, no_log를 증명한다.
실제 호스트·주소·조직명·시크릿은 쓰지 않는다. 모든 값은 가짜다.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE_DIR = ROOT_DIR / "roles" / "github_webhook_watch"
DOC = ROOT_DIR / "docs" / "github_webhook_watch.md"
TOKEN = "fake-github-token-0123456789"
O2_PASSWORD = "fake-o2-password-abcdef"
HOOK_URL = "https://hooks.example.invalid/fake-secret-path"
ORG = "example-org"
EVENTS = ["meta", "organization", "member"]


def _load_module():
    spec = importlib.util.spec_from_file_location("gww_check", ROLE_DIR / "library" / "gww_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _iso(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _delivery(did, guid, hours_ago, status_code=200, redelivery=False):
    return {"id": did, "guid": guid, "delivered_at": _iso(hours_ago), "redelivery": redelivery,
            "status": "OK" if 200 <= status_code < 400 else "Fail", "status_code": status_code, "event": "meta"}


class _Fake:
    """GitHub 조직 웹훅 API + OpenObserve 수집 API를 한 서버로 모사한다."""

    def __init__(self):
        self.hooks = [{"id": 11, "active": True, "events": list(EVENTS), "config": {"url": HOOK_URL}}]
        self.deliveries = []
        self.page_size = 100
        self.mode = "ok"            # ok | api_500 | hooks_403
        self.redeliver_status = 202
        self.o2_status = 200
        self.raw_hooks = None       # 예상 밖 응답 형태 모사
        self.redirect_to = None     # 설정하면 hooks 요청을 다른 서버로 리다이렉트
        self.auth_seen = []         # 수신한 Authorization 헤더
        self.next_host = None       # Link next URL의 호스트를 바꿔 다른 출처 모사
        self.requests = []          # (method, path)
        self.redelivered = []       # delivery ids
        self.heartbeats = []        # 수신한 레코드
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body="", headers=None):
                data = body if isinstance(body, str) else json.dumps(body)
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data.encode())))
                self.end_headers()
                self.wfile.write(data.encode())

            def _authed(self):
                return self.headers.get("Authorization") == f"Bearer {TOKEN}"

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                outer.auth_seen.append(self.headers.get("Authorization"))
                u = urlparse(self.path)
                if outer.redirect_to:
                    return self._send(302, "", {"Location": outer.redirect_to + self.path})
                if not self._authed():
                    return self._send(401, {"message": "Bad credentials"})
                if outer.mode == "api_500":
                    return self._send(500, {"message": "boom"})
                if outer.mode == "hooks_403":
                    return self._send(403, {"message": "forbidden"})
                if u.path == f"/orgs/{ORG}/hooks":
                    return self._send(200, outer.hooks if outer.raw_hooks is None else outer.raw_hooks)
                m = re.match(rf"^/orgs/{ORG}/hooks/(\d+)/deliveries$", u.path)
                if m:
                    q = parse_qs(u.query)
                    start = int(q.get("cursor", ["0"])[0])
                    chunk = outer.deliveries[start:start + outer.page_size]
                    headers = {}
                    if start + outer.page_size < len(outer.deliveries):
                        nxt = f"http://{outer.next_host or self.headers['Host']}{u.path}?per_page=100&cursor={start + outer.page_size}"
                        headers["Link"] = f'<{nxt}>; rel="next"'
                    return self._send(200, chunk, headers)
                self._send(404, {"message": "Not Found"})

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n).decode()
                m = re.match(rf"^/orgs/{ORG}/hooks/\d+/deliveries/(\d+)/attempts$", self.path)
                if m:
                    if not self._authed():
                        return self._send(401, {"message": "Bad credentials"})
                    if outer.redeliver_status == 202:
                        outer.redelivered.append(int(m.group(1)))
                    return self._send(outer.redeliver_status, {})
                m = re.match(r"^/api/([^/]+)/([^/]+)/_json$", self.path)
                if m:
                    if outer.o2_status == 200:
                        outer.heartbeats.extend(json.loads(raw))
                    return self._send(outer.o2_status, {})
                self._send(404, {})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake():
    f = _Fake()
    yield f
    f.close()


@pytest.fixture(scope="module")
def gww():
    return _load_module()


def _params(fake, **over):
    p = {"api_url": fake.url, "org": ORG, "token": TOKEN, "hook_url": HOOK_URL, "expected_events": list(EVENTS),
         "window_hours": 72, "interval_hours": 6, "check_mode": False, "validate_certs": True, "timeout": 5, "max_pages": 10}
    p.update(over)
    return p


# --------------------------------------------------------------------------
# 훅 상태 비교 (AC1)
# --------------------------------------------------------------------------
def test_healthy_hook_reports_ok(gww, fake):
    r = gww.check(_params(fake))
    assert r["error"] == "" and r["hook_status"] == "ok" and r["hook_problems"] == []


def test_missing_hook_is_reported_as_status(gww, fake):
    fake.hooks = [{"id": 5, "active": True, "events": EVENTS, "config": {"url": "https://other.example.invalid/x"}}]
    r = gww.check(_params(fake))
    assert r["error"] == "" and r["hook_status"] == "missing"
    assert not any(m == "GET" and "/deliveries" in p for m, p in fake.requests)


def test_inactive_hook_is_reported_as_status(gww, fake):
    fake.hooks[0]["active"] = False
    r = gww.check(_params(fake))
    assert r["hook_status"] == "inactive" and "inactive" in r["hook_problems"]


def test_event_mismatch_is_reported_as_status(gww, fake):
    fake.hooks[0]["events"] = ["meta"]
    r = gww.check(_params(fake))
    assert r["hook_status"] == "events_mismatch"
    fake.hooks[0]["events"] = EVENTS + ["push"]
    assert gww.check(_params(fake))["hook_status"] == "events_mismatch"


def test_event_order_does_not_matter(gww, fake):
    fake.hooks[0]["events"] = list(reversed(EVENTS))
    assert gww.check(_params(fake))["hook_status"] == "ok"


# --------------------------------------------------------------------------
# 재전송 (AC2, AC6)
# --------------------------------------------------------------------------
def test_redelivers_only_failed_deliveries_inside_window(gww, fake):
    fake.deliveries = [
        _delivery(1, "g1", 2, 500),     # 재전송 대상
        _delivery(2, "g2", 3, 200),     # 성공
        _delivery(3, "g3", 71, 502),    # 기간 안 경계, 재전송 대상
        _delivery(4, "g4", 73, 500),    # 기간 밖(점검 주기 안) -> 재전송 불가, 만료로 센다
        _delivery(5, "g5", 5, 0),       # 시간 초과(status_code 0)도 실패
    ]
    r = gww.check(_params(fake))
    assert sorted(fake.redelivered) == [1, 3, 5]
    assert r["redelivered_count"] == 3 and r["failed_count"] == 0 and r["expired_count"] == 1


def test_already_redelivered_delivery_is_not_sent_again(gww, fake):
    fake.deliveries = [
        _delivery(10, "g1", 1, 200, redelivery=True),   # g1 재전송이 성공
        _delivery(9, "g1", 2, 500),
        _delivery(8, "g2", 1, 500, redelivery=True),    # g2 재전송이 다시 실패: 다시 보내지 않고 실패로 센다
        _delivery(7, "g2", 3, 500),
    ]
    r = gww.check(_params(fake))
    assert fake.redelivered == []
    assert r["redelivered_count"] == 0 and r["failed_count"] == 1


def test_second_run_does_not_redeliver_again(gww, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    assert gww.check(_params(fake))["redelivered_count"] == 1
    fake.deliveries.insert(0, _delivery(2, "g1", 0, 200, redelivery=True))
    assert gww.check(_params(fake))["redelivered_count"] == 0
    assert fake.redelivered == [1]


def test_redelivery_http_failure_counts_as_failed(gww, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500), _delivery(2, "g2", 2, 500)]
    fake.redeliver_status = 422
    r = gww.check(_params(fake))
    assert r["redelivered_count"] == 0 and r["failed_count"] == 2


@pytest.mark.parametrize("status", [404, 422, 500, 502])
def test_redelivery_api_error_sets_error_code(gww, fake, status):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    fake.redeliver_status = status
    assert gww.check(_params(fake))["error"] == f"api_http_{status}"


def test_redirect_is_not_followed_and_token_not_forwarded(gww, fake):
    other = _Fake()
    try:
        fake.redirect_to = other.url
        r = gww.check(_params(fake))
        assert r["error"] == "api_http_302"
        assert other.requests == [] and other.auth_seen == []
    finally:
        other.close()


def test_check_mode_never_redelivers(gww, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    r = gww.check(_params(fake, check_mode=True))
    assert fake.redelivered == [] and not any(m == "POST" for m, _ in fake.requests)
    assert r["redelivered_count"] == 0 and r["would_redeliver_count"] == 1


def test_follows_delivery_pages(gww, fake):
    fake.page_size = 2
    fake.deliveries = [_delivery(i, f"g{i}", 1 + i, 500) for i in range(1, 6)]
    r = gww.check(_params(fake))
    assert r["redelivered_count"] == 5


def test_truncated_delivery_listing_is_signalled(gww, fake):
    fake.page_size = 2
    fake.deliveries = [_delivery(i, f"g{i}", 1 + i, 500) for i in range(1, 8)]
    r = gww.check(_params(fake, max_pages=2))
    assert r["deliveries_truncated"] is True and r["redelivered_count"] == 4


def test_complete_delivery_listing_is_not_truncated(gww, fake):
    fake.page_size = 2
    fake.deliveries = [_delivery(i, f"g{i}", 1 + i, 500) for i in range(1, 6)]
    assert gww.check(_params(fake))["deliveries_truncated"] is False


def test_does_not_follow_next_link_to_another_origin(gww, fake):
    fake.page_size = 2
    fake.next_host = "127.0.0.1:1"  # 다른 출처(포트)면 토큰을 보내지 않는다
    fake.deliveries = [_delivery(i, f"g{i}", 1 + i, 500) for i in range(1, 6)]
    r = gww.check(_params(fake))
    assert r["redelivered_count"] == 2 and r["deliveries_truncated"] is True and r["error"] == ""


# --------------------------------------------------------------------------
# 예상 밖 응답 형태
# --------------------------------------------------------------------------
@pytest.mark.parametrize("raw", [{"message": "oops"}, [{"id": "x"}], ["str"], "text"])
def test_unexpected_response_shape_is_reported_as_error(gww, fake, raw):
    fake.raw_hooks = raw if raw != [{"id": "x"}] else [{"id": "x", "active": True, "events": EVENTS, "config": {"url": HOOK_URL}}]
    r = gww.check(_params(fake))
    assert r["error"] == "api_unexpected_response"


def test_unexpected_delivery_shape_is_reported_as_error(gww, fake):
    fake.deliveries = [{"guid": "g1", "delivered_at": _iso(1), "status_code": 500}]  # id 없음
    assert gww.check(_params(fake))["error"] == "api_unexpected_response"


# --------------------------------------------------------------------------
# API 실패·자격 없음 (AC4)
# --------------------------------------------------------------------------
@pytest.mark.parametrize("mode,code", [("api_500", "api_http_500"), ("hooks_403", "api_http_403")])
def test_api_failure_is_reported_as_error(gww, fake, mode, code):
    fake.mode = mode
    r = gww.check(_params(fake))
    assert r["error"] == code and r["hook_status"] == "unknown"


def test_wrong_credential_is_reported_as_error(gww, fake):
    assert gww.check(_params(fake, token="wrong"))["error"] == "api_http_401"


def test_missing_credential_errors_without_calling_api(gww, fake):
    r = gww.check(_params(fake, token=""))
    assert r["error"] == "credential_missing" and fake.requests == []


def test_unreachable_api_is_reported_as_error(gww, fake):
    url = fake.url
    fake.close()
    r = gww.check(_params(fake, api_url=url, timeout=1))
    assert r["error"] == "api_unreachable"


def test_error_text_never_contains_credential_or_url(gww, fake):
    fake.mode = "api_500"
    blob = json.dumps(gww.check(_params(fake)))
    assert TOKEN not in blob and HOOK_URL not in blob and fake.url not in blob


# --------------------------------------------------------------------------
# 정적 구조·추적성·안전 (AC5, AC7, AC9)
# --------------------------------------------------------------------------
def _tasks_by_id():
    found = {}

    def walk(items):
        for t in items:
            m = re.match(r"\[(GWW-\d{3})\]", t.get("name", ""))
            if m:
                found[m.group(1)] = t
            for key in ("block", "rescue", "always"):
                walk(t.get(key) or [])

    walk(yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")))
    return found


def test_interval_is_shorter_than_redelivery_window():
    d = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert d["gww_redelivery_window_hours"] == 72
    assert 0 < d["gww_check_interval_hours"] <= 6
    assert d["gww_check_interval_hours"] < d["gww_redelivery_window_hours"]


def test_role_asserts_interval_shorter_than_window():
    text = json.dumps(_tasks_by_id()["GWW-001"])
    assert "gww_check_interval_hours" in text and "gww_redelivery_window_hours" in text


def test_defaults_hold_no_credentials_or_real_urls():
    text = (ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8")
    d = yaml.safe_load(text)
    for key in ("gww_github_token", "gww_o2_password", "gww_hook_url", "gww_o2_endpoint"):
        assert "default('', true)" in d[key], key
    assert set(re.findall(r"https?://[A-Za-z0-9.-]+", text)) <= {"https://api.github.com", "http://openbao"}


def test_credential_and_url_tasks_are_no_log():
    for tid, t in _tasks_by_id().items():
        blob = json.dumps(t)
        if tid == "GWW-005":
            continue  # 값을 출력하지 않는 assert(조건식 문자열만 나온다): 안내 메시지가 보여야 해서 no_log를 쓰지 않는다
        if any(s in blob for s in ("gww_github_token", "gww_o2_password", "gww_kv", "vault_token", "role_id", "secret_id", "gww_hook_url")):
            assert t.get("no_log") is True, tid


def test_input_assert_is_not_no_log_so_guidance_is_visible():
    t = _tasks_by_id()["GWW-005"]
    assert not t.get("no_log")
    assert "[GWW-INPUT]" in t["ansible.builtin.assert"]["fail_msg"]
    assert "gww_github_org" in json.dumps(t) and "gww_hook_url" in json.dumps(t)


def test_spec_ids_match_docs_one_to_one():
    tasks = (ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")
    in_tasks = set(re.findall(r"\[(GWW-\d{3})\]", tasks))
    in_doc = set(re.findall(r"\|\s*`(GWW-\d{3})`", DOC.read_text(encoding="utf-8")))
    assert in_tasks and in_tasks == in_doc


def test_playbook_is_controller_only():
    play = yaml.safe_load((ROOT_DIR / "playbooks" / "github_webhook_watch.yml").read_text(encoding="utf-8"))[0]
    assert play["hosts"] == "localhost" and play["connection"] == "local" and play["gather_facts"] is False
    assert "github_webhook_watch" in [r if isinstance(r, str) else r.get("role") for r in play["roles"]]


def test_docs_index_lists_role():
    assert "github_webhook_watch.md" in (ROOT_DIR / "docs" / "INDEX.md").read_text(encoding="utf-8")


def test_doc_explains_semaphore_template_registration_and_contracts():
    doc = DOC.read_text(encoding="utf-8")
    for needle in ["Semaphore", "playbooks/github_webhook_watch.yml", "0 */6 * * *", "Ticket-8", "3일", "OpenBao",
                   "hook_status", "redelivered_count", "failed_count", "checked_at", "check 모드", "Webhooks"]:
        assert needle in doc, needle


def test_role_files_hold_no_real_values():
    files = [p for p in ROLE_DIR.rglob("*") if p.is_file() and p.suffix in (".yml", ".py")] + [DOC, ROOT_DIR / "playbooks" / "github_webhook_watch.yml"]
    assert files
    for p in files:
        text = p.read_text(encoding="utf-8")
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text), p
        assert not re.search(r"gh[pous]_[A-Za-z0-9]{20,}|github_pat_", text), p


# --------------------------------------------------------------------------
# 통합(slow): 실제 ansible-playbook 실행
# --------------------------------------------------------------------------
@pytest.fixture
def ansible_env(tmp_path):
    if shutil.which("ansible-playbook") is None:
        pytest.skip("ansible-playbook not installed")
    (tmp_path / "ansible.cfg").write_text(f"[defaults]\nroles_path = {ROOT_DIR / 'roles'}\nretry_files_enabled = False\n", encoding="utf-8")
    (tmp_path / "play.yml").write_text("- hosts: localhost\n  gather_facts: false\n  connection: local\n  roles:\n    - github_webhook_watch\n", encoding="utf-8")
    return tmp_path


def _run(env_dir, fake, extra=None, check=False):
    ev = {"gww_github_api_url": fake.url, "gww_github_token": TOKEN, "gww_github_org": ORG, "gww_hook_url": HOOK_URL,
          "gww_expected_events": EVENTS, "gww_o2_endpoint": fake.url, "gww_o2_org": "default",
          "gww_o2_user": "fake-o2-user", "gww_o2_password": O2_PASSWORD}
    ev.update(extra or {})
    (env_dir / "ev.yml").write_text(yaml.safe_dump(ev), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "OPENBAO_"))}
    env["ANSIBLE_CONFIG"] = str(env_dir / "ansible.cfg")
    cmd = ["ansible-playbook", "-i", "localhost,", str(env_dir / "play.yml"), "-e", f"@{env_dir / 'ev.yml'}"]
    if check:
        cmd.append("--check")
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=env_dir)


def test_run_leaves_heartbeat_with_time_status_and_counts(ansible_env, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    res = _run(ansible_env, fake)
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(fake.heartbeats) == 1
    hb = fake.heartbeats[0]
    assert hb["service_name"] == "github-webhook-watch" and hb["result"] == "ok"
    assert hb["hook_status"] == "ok" and hb["redelivered_count"] == 1 and hb["failed_count"] == 0
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", hb["checked_at"])
    assert fake.redelivered == [1]


def test_missing_hook_run_succeeds_and_heartbeat_carries_status(ansible_env, fake):
    fake.hooks = []
    res = _run(ansible_env, fake)
    assert res.returncode == 0, res.stdout + res.stderr
    assert fake.heartbeats[0]["hook_status"] == "missing"


def test_api_failure_fails_run_and_heartbeat_records_error(ansible_env, fake):
    fake.mode = "api_500"
    res = _run(ansible_env, fake)
    assert res.returncode != 0
    assert len(fake.heartbeats) == 1
    assert fake.heartbeats[0]["result"] == "error" and fake.heartbeats[0]["error"] == "api_http_500"


def test_missing_credential_fails_run_and_heartbeat_records_error(ansible_env, fake):
    res = _run(ansible_env, fake, extra={"gww_github_token": ""})
    assert res.returncode != 0
    assert fake.heartbeats[0]["error"] == "credential_missing"
    assert fake.requests == [("POST", "/api/default/security_logs/_json")]


def test_input_assert_message_is_visible_when_input_missing(ansible_env, fake):
    res = _run(ansible_env, fake, extra={"gww_o2_user": ""})
    out = res.stdout + res.stderr
    assert res.returncode != 0 and "[GWW-INPUT]" in out and fake.requests == []
    for secret in (TOKEN, O2_PASSWORD, HOOK_URL, "fake-secret-path"):
        assert secret not in out


@pytest.mark.parametrize("key", ["gww_github_org", "gww_hook_url"])
def test_empty_org_or_hook_url_fails_input_validation(ansible_env, fake, key):
    res = _run(ansible_env, fake, extra={key: ""})
    assert res.returncode != 0 and "[GWW-INPUT]" in res.stdout + res.stderr
    assert fake.requests == [] and fake.heartbeats == []


def test_truncated_listing_is_in_heartbeat(ansible_env, fake):
    fake.page_size = 1
    fake.deliveries = [_delivery(i, f"g{i}", 1, 200) for i in range(1, 4)]
    res = _run(ansible_env, fake, extra={"gww_max_pages": 1})
    assert res.returncode == 0, res.stdout + res.stderr
    assert fake.heartbeats[0]["deliveries_truncated"] is True


def test_redelivery_5xx_fails_run_and_heartbeat_records_error(ansible_env, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    fake.redeliver_status = 500
    res = _run(ansible_env, fake)
    assert res.returncode != 0
    assert fake.heartbeats[0]["result"] == "error" and fake.heartbeats[0]["error"] == "api_http_500"


def test_unexpected_response_fails_run_and_heartbeat_records_error(ansible_env, fake):
    fake.raw_hooks = {"message": "oops"}
    res = _run(ansible_env, fake)
    assert res.returncode != 0
    assert fake.heartbeats[0]["result"] == "error" and fake.heartbeats[0]["error"] == "api_unexpected_response"


def test_heartbeat_ingest_failure_fails_run(ansible_env, fake):
    fake.o2_status = 500
    assert _run(ansible_env, fake).returncode != 0


def test_check_mode_does_not_redeliver_or_write_heartbeat(ansible_env, fake):
    fake.deliveries = [_delivery(1, "g1", 2, 500)]
    res = _run(ansible_env, fake, check=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert fake.redelivered == [] and fake.heartbeats == []
    assert not any(m == "POST" for m, _ in fake.requests)


def test_interval_not_shorter_than_window_is_rejected(ansible_env, fake):
    res = _run(ansible_env, fake, extra={"gww_check_interval_hours": 72})
    assert res.returncode != 0 and fake.requests == []


def test_credentials_and_urls_never_printed(ansible_env, fake):
    for mode in ("ok", "api_500"):
        fake.mode = mode
        out = _run(ansible_env, fake)
        blob = out.stdout + out.stderr
        for secret in (TOKEN, O2_PASSWORD, HOOK_URL, "fake-secret-path"):
            assert secret not in blob
        assert fake.url not in blob
