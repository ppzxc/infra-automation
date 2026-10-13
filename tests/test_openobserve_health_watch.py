"""OpenObserve 생존 타이머 (Spec #184 / Ticket-7 #191).

1. 확인 스크립트(`roles/monitoring/files/openobserve-health-check.sh`)를 실제 bash로, 가짜 OpenObserve 헬스
   엔드포인트와 가짜 webhook 서버를 상대로 실행한다: 관찰하는 것은 webhook으로 간 요청과 종료코드뿐이다.
2. 배포 태스크(`o2_health_watch.yml`)를 localhost에서 실제 ansible-playbook으로 실행한다:
   검사하는 쪽 호스트에만 배포되고, 시크릿 env 파일 권한이 0600이다.
"""

import getpass
import grp
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "monitoring"
SCRIPT = ROLE / "files" / "openobserve-health-check.sh"
TASKS = ROLE / "tasks" / "o2_health_watch.yml"
WEBHOOK_URL_PATH = "/hook/SECRET-WEBHOOK-PATH"


class Server:
    """status가 바뀌는 HTTP 서버. 받은 요청을 기록한다."""

    def __init__(self, status=200):
        self.status = status
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                outer.requests.append({"method": self.command, "path": self.path, "body": body,
                                       "headers": dict(self.headers)})
                self.send_response(outer.status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = _handle

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def world(tmp_path):
    o2, hook = Server(200), Server(200)
    state = tmp_path / "state"
    state.mkdir()
    env_file = tmp_path / "env"
    env_file.write_text(
        f"O2_HEALTH_URL='{o2.url}/healthz'\n"
        f"O2_WEBHOOK_URL='{hook.url}{WEBHOOK_URL_PATH}'\n"
        "O2_WEBHOOK_AUTH_HEADER='X-NANOIT-ACCESS'\nO2_WEBHOOK_TOKEN='tok-123'\n"
        f"O2_HEALTH_STATE_DIR='{state}'\nO2_HEALTH_RENOTIFY_MINUTES='60'\n")
    yield type("World", (), {"o2": o2, "hook": hook, "state": state, "env_file": env_file})
    o2.close()
    hook.close()


def run_check(world, **extra_env):
    env = {**os.environ, "O2_HEALTH_ENV_FILE": str(world.env_file), **extra_env}
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=60)


def posts(world):
    return [r for r in world.hook.requests if r["method"] == "POST"]


def test_healthy_openobserve_sends_nothing(world):
    res = run_check(world)
    assert res.returncode == 0 and posts(world) == []
    assert [r["path"] for r in world.o2.requests] == ["/healthz"]


def test_failing_health_sends_one_p1_notification_to_the_webhook(world):
    world.o2.status = 503
    res = run_check(world)
    assert res.returncode == 0, res.stderr
    (req,) = posts(world)
    assert req["path"] == WEBHOOK_URL_PATH
    assert req["headers"]["X-NANOIT-ACCESS"] == "tok-123"
    text = json.loads(req["body"])["content"]["text"]
    assert "[P1 긴급]" in text and "OpenObserve" in text


def test_unreachable_openobserve_is_also_a_failure(world):
    run_check(world, O2_HEALTH_URL_OVERRIDE="http://127.0.0.1:1/healthz")
    assert len(posts(world)) == 1


def test_same_outage_is_renotified_only_after_60_minutes(world):
    world.o2.status = 503
    run_check(world)
    run_check(world)
    assert len(posts(world)) == 1
    marker = next(world.state.iterdir())
    old = time.time() - 61 * 60
    os.utime(marker, (old, old))
    run_check(world)
    assert len(posts(world)) == 2
    run_check(world)
    assert len(posts(world)) == 2


def test_recovery_sends_nothing_and_a_new_outage_notifies_immediately(world):
    world.o2.status = 503
    run_check(world)
    world.o2.status = 200
    run_check(world)
    assert len(posts(world)) == 1 and list(world.state.iterdir()) == []
    world.o2.status = 503
    run_check(world)
    assert len(posts(world)) == 2


def test_failed_webhook_delivery_fails_the_run_and_is_retried_next_time(world):
    world.o2.status = 503
    world.hook.status = 500
    assert run_check(world).returncode != 0
    world.hook.status = 200
    assert run_check(world).returncode == 0
    assert len(posts(world)) == 2


def test_manual_verification_override_points_the_check_at_a_wrong_url(world):
    """런북의 수동 검증: 대상 URL을 틀린 값으로 한 번 실행하면 통지가 도착한다."""
    run_check(world, O2_HEALTH_URL_OVERRIDE="http://127.0.0.1:1/healthz")
    assert len(posts(world)) == 1
    assert world.o2.requests == []


def test_webhook_secret_is_not_printed(world):
    world.o2.status = 503
    res = run_check(world)
    out = res.stdout + res.stderr
    assert "SECRET-WEBHOOK-PATH" not in out and "tok-123" not in out


@pytest.mark.parametrize("missing", ["O2_HEALTH_URL", "O2_WEBHOOK_URL"])
def test_missing_config_fails_the_unit_and_names_the_missing_setting(world, missing):
    lines = [l for l in world.env_file.read_text().splitlines() if not l.startswith(missing + "=")]
    world.env_file.write_text("\n".join(lines) + "\n")
    res = run_check(world)
    other = ({"O2_HEALTH_URL", "O2_WEBHOOK_URL"} - {missing}).pop()
    assert res.returncode != 0 and missing in res.stderr and other not in res.stderr
    assert posts(world) == []


# --- 배포 태스크 -------------------------------------------------------------------------------

def _deploy(tmp_path, is_checker, os_path="modern", expect_ok=True):
    t = tmp_path
    vars_ = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    vars_.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text()))
    vars_.update({
        "role_path": str(ROLE), "host_agents_os_path": os_path, "ansible_service_mgr": "sysv",
        "host_agents_o2_health_checker": "localhost" if is_checker else "ns0266",
        "o2_endpoint": "https://o2.example:5080", "o2_ca_file": "",
        "host_agents_shared_secrets": {"openobserve": {
            "alert_webhook_url": "https://hook.example/SECRET", "alert_webhook_token": "tok",
            "alert_webhook_auth_header": "X-NANOIT-ACCESS"}},
        "o2_health_script_path": str(t / "sbin" / "check.sh"), "o2_health_config_dir": str(t / "etc"),
        "o2_health_state_dir": str(t / "var"), "otelcol_systemd_unit_dir": str(t / "units"),
        "host_agents_owner": getpass.getuser(), "host_agents_group": grp.getgrgid(os.getgid()).gr_name,
    })
    (t / "sbin").mkdir()
    (t / "units").mkdir()
    (t / "vars.yml").write_text(yaml.safe_dump(vars_))
    pb = t / "deploy.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(t / "vars.yml")],
        "tasks": [{"ansible.builtin.import_tasks": str(TASKS)}]}]))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT, timeout=120)
    if expect_ok:
        assert res.returncode == 0, res.stdout + res.stderr
    return res


def mode(p):
    return oct(p.stat().st_mode & 0o7777)


def test_checker_host_gets_script_secret_env_and_five_minute_timer(tmp_path):
    res = _deploy(tmp_path, True)
    assert mode(tmp_path / "sbin" / "check.sh") == "0o755"
    env = tmp_path / "etc" / "env"
    assert mode(env) == "0o600" and "https://hook.example/SECRET" in env.read_text()
    assert "https://o2.example:5080/healthz" in env.read_text()
    assert mode(tmp_path / "etc") == "0o700"
    timer = (tmp_path / "units" / "openobserve-health.timer").read_text()
    assert "OnUnitActiveSec=5min" in timer and "WantedBy=timers.target" in timer
    service = (tmp_path / "units" / "openobserve-health.service").read_text()
    assert "Type=oneshot" in service and str(tmp_path / "sbin" / "check.sh") in service
    assert "SECRET" not in res.stdout + res.stderr


def test_other_hosts_get_nothing(tmp_path):
    _deploy(tmp_path, False)
    assert list((tmp_path / "sbin").iterdir()) == [] and list((tmp_path / "units").iterdir()) == []
    assert not (tmp_path / "etc").exists()


def test_checker_host_on_a_non_modern_path_fails_loudly_instead_of_silently_skipping(tmp_path):
    res = _deploy(tmp_path, True, os_path="legacy_el7", expect_ok=False)
    assert res.returncode != 0 and "OpenObserve 생존 타이머" in res.stdout + res.stderr
    assert list((tmp_path / "units").iterdir()) == []


def test_non_checker_host_on_a_non_modern_path_is_not_an_error(tmp_path):
    _deploy(tmp_path, False, os_path="legacy_el7")


def test_checker_host_is_declared_in_role_defaults_and_defaults_to_ns0266():
    d = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert d["host_agents_o2_health_checker"] == "ns0266"
