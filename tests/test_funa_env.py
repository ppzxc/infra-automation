"""funa_env 역할(#222): 가짜 OpenBao HTTP 서버 + ansible-playbook으로 파일 렌더링을 실제 실행한다.

root가 아니므로 소유자는 현재 사용자로 바꿔 돌리고(`funa_env_owner*`), 기본값이 root:dockermgmt·0644/0640인지는
기본값 파일로 따로 검증한다.
"""
import getpass
import grp
import json
import os
import re
import shutil
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "funa_env"
USER_GROUP = grp.getgrgid(os.getgid()).gr_name

NODE = {"FUNA_NODE_EXTERNAL_HOSTNAME": "n1.funa.test", "FUNA_NODE_EXTERNAL_WILDCARD_HOSTNAME": "*.n1.funa.test",
        "FUNA_NOTIFICATION_HEADER": "[FUNA n1] alert",
        "CLOUDFLARE_API_TOKEN": "cf-token-SECRET", "ansible_password": "ssh-pass-SECRET"}
CLUSTER = {"FUNA_FLOATING_HOSTNAME": "vip.funa.test", "FUNA_HEALTH_CHECK_URI": "/health", "FUNA_SERVICE_NAME": "funa",
           "TZ": "Asia/Seoul",
           "FUNA_NOTIFICATION_SMTP_FROM": "a@funa.test", "FUNA_NOTIFICATION_SMTP_HOST": "smtp.funa.test",
           "FUNA_NOTIFICATION_SMTP_PORT": 25, "FUNA_NOTIFICATION_SMTP_TO": "b@funa.test",
           "FUNA_NOTIFICATION_SMTP_USERNAME": "user", "FUNA_NOTIFICATION_NAVER_WORKS_BOT_URL": "https://bot.funa.test/x"}
PROXY = {"FUNA_ADMIN_TOKEN": "admin-token-SECRET", "DB_PASSWORD": "db-pass-SECRET"}
VRRP = {"FUNA_NOTIFICATION_SMTP_PASSWORD": "smtp-pass-SECRET", "FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN": "bot-token-SECRET"}
SECRETS = [v for d in (PROXY, VRRP) for v in d.values()] + ["ssh-pass-SECRET", "cf-token-SECRET"]


class _FakeOpenBao(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):  # noqa: N802
        status, body = self.routes.get(self.path, (404, {"errors": []}))
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _kv(data):
    return 200, {"data": {"data": data, "metadata": {"version": 1}}}


def _routes(**over):
    base = {
        "/v1/secret/data/hosts/n1": _kv(NODE),
        "/v1/secret/data/clusters/funa": _kv(CLUSTER),
        "/v1/secret/data/clusters/funa/proxy": _kv(PROXY),
        "/v1/secret/data/clusters/funa/vrrp": _kv(VRRP),
    }
    base.update(over)
    return base


@pytest.fixture
def openbao():
    server = HTTPServer(("127.0.0.1", 0), _FakeOpenBao)
    _FakeOpenBao.routes = _routes()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def run(tmp_path, addr, hosts=("n1",), groups=("funa_cluster",), check=False, extra=None, diff=True):
    dest = tmp_path / "etc"
    prof = tmp_path / "profile.d"
    prof.mkdir(exist_ok=True)
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "become": False, "roles": ["funa_env"]}]))
    inv = {"all": {
        "hosts": {h: {"_vault_token": "tok"} for h in hosts},
        "vars": {"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3", "vault_addr": addr,
                 "funa_env_dir": str(dest / "funa-cluster"), "funa_env_profile_dir": str(prof),
                 "funa_env_owner": getpass.getuser(),
                 "funa_env_owner_group": USER_GROUP, "funa_env_group": USER_GROUP},
        "children": {g: {"hosts": {h: {} for h in hosts if h == "n1"}} for g in groups},
    }}
    for k, v in (extra or {}).items():
        inv["all"]["vars"][k] = v
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml"), "-e", "vault_namespace=''"]
    if diff:
        cmd.append("--diff")
    if check:
        cmd.append("--check")
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR,
                         env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_ROLES_PATH": str(ROOT_DIR / "roles"),
                              "ANSIBLE_FILTER_PLUGINS": str(ROOT_DIR / "filter_plugins"),
                              "ANSIBLE_LOCALHOST_WARNING": "False", "ANSIBLE_DEPRECATION_WARNINGS": "False"})
    return res, dest / "funa-cluster", prof


pytestmark = pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed")


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def _kv_of(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def test_renders_files_with_modes_and_consumer_separation(tmp_path, openbao):
    res, d, prof = run(tmp_path, openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    cluster, proxy, vrrp = (d / "cluster.env", d / "proxy.secrets.env", d / "vrrp.secrets.env")
    assert _mode(cluster) == 0o644 and _mode(proxy) == 0o640 and _mode(vrrp) == 0o640
    assert grp.getgrgid(proxy.stat().st_gid).gr_name == USER_GROUP
    kv = _kv_of(cluster)
    assert kv["FUNA_NODE_EXTERNAL_HOSTNAME"] == "n1.funa.test" and kv["TZ"] == "Asia/Seoul"
    assert kv["FUNA_NODE_EXTERNAL_WILDCARD_HOSTNAME"] == "'*.n1.funa.test'"
    # 알림 헤더는 노드의 호스트명이 들어가므로 노드 KV에서 온다(클러스터 공통 KV에는 없다).
    assert kv["FUNA_NOTIFICATION_HEADER"] == "'[FUNA n1] alert'"
    assert "ansible_password" not in cluster.read_text()
    # 소비자별 분리: proxy 파일에는 keepalived 시크릿이 없고 그 반대도 같다
    assert set(_kv_of(proxy)) == set(PROXY) | {"CLOUDFLARE_API_TOKEN"} and set(_kv_of(vrrp)) == set(VRRP)
    assert not any(v in proxy.read_text() for v in VRRP.values())
    assert not any(v in vrrp.read_text() for v in PROXY.values())
    assert not any(s in cluster.read_text() for s in SECRETS)
    loader = prof / "funa-cluster.sh"
    assert _mode(loader) == 0o644 and "set -a" in loader.read_text() and not re.search(r"^\s*alias\b", loader.read_text(), re.M)


def test_no_secret_in_output_or_diff(tmp_path, openbao):
    res, _, _ = run(tmp_path, openbao)
    out = res.stdout + res.stderr
    assert res.returncode == 0
    assert not any(s in out for s in SECRETS), "시크릿 값이 출력에 나왔다"


def test_second_run_changes_nothing(tmp_path, openbao):
    assert run(tmp_path, openbao)[0].returncode == 0
    res, _, _ = run(tmp_path, openbao)
    assert res.returncode == 0, res.stdout
    assert re.search(r"n1\s*:.*changed=0", res.stdout), res.stdout


def test_login_shell_loader_loads_readable_files_only(tmp_path, openbao):
    _, d, prof = run(tmp_path, openbao)
    (d / "vrrp.secrets.env").chmod(0o000)
    script = f'. {prof}/funa-cluster.sh; echo "$TZ|$DB_PASSWORD|$FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN"'
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    (d / "vrrp.secrets.env").chmod(0o640)
    tz, db, bot = out.stdout.strip().split("|")
    assert (tz, db, bot) == ("Asia/Seoul", "db-pass-SECRET", "")


def test_host_outside_the_group_gets_nothing(tmp_path, openbao):
    res, d, prof = run(tmp_path, openbao, groups=("other",))
    assert res.returncode == 0, res.stdout
    assert not d.exists() and list(prof.iterdir()) == []


@pytest.mark.parametrize("routes, expect", [
    ({"/v1/secret/data/clusters/funa/proxy": _kv({k: v for k, v in PROXY.items() if k != "DB_PASSWORD"})},
     "required key DB_PASSWORD is missing"),
    ({"/v1/secret/data/hosts/n1": _kv({k: v for k, v in NODE.items() if k != "CLOUDFLARE_API_TOKEN"})},
     "clusters/funa/proxy: required key CLOUDFLARE_API_TOKEN is missing"),
    ({"/v1/secret/data/clusters/funa": _kv({k: v for k, v in CLUSTER.items() if k != "TZ"})},
     "required key TZ is missing"),
    ({"/v1/secret/data/hosts/n1": _kv({"ansible_password": "ssh-pass-SECRET"})},
     "required key FUNA_NODE_EXTERNAL_HOSTNAME is missing"),
    ({"/v1/secret/data/clusters/funa/vrrp": (404, {"errors": []})}, "clusters/funa/vrrp: OpenBao path does not exist"),
])
def test_missing_values_fail_naming_what_is_missing(tmp_path, openbao, routes, expect):
    _FakeOpenBao.routes = _routes(**routes)
    res, d, _ = run(tmp_path, openbao)
    out = res.stdout + res.stderr
    assert res.returncode != 0
    assert expect in out
    assert not any(s in out for s in SECRETS)
    assert not (d / "cluster.env").exists()


def test_openbao_error_stops_without_changes(tmp_path, openbao):
    _FakeOpenBao.routes = _routes(**{"/v1/secret/data/clusters/funa": (403, {"errors": ["permission denied"]})})
    res, d, _ = run(tmp_path, openbao)
    assert res.returncode != 0 and "OpenBao 조회 실패" in res.stdout
    assert not d.exists()


def test_missing_dockermgmt_group_fails_naming_it(tmp_path, openbao):
    res, d, _ = run(tmp_path, openbao, extra={"funa_env_group": "no-such-group-xyz"})
    assert res.returncode != 0
    assert "no-such-group-xyz" in res.stdout and "docker_engine" in res.stdout
    assert not d.exists()


def test_defaults_match_the_standard():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["funa_env_dir"] == "/etc/funa-cluster"
    assert defaults["funa_env_owner"] == "root" and defaults["funa_env_owner_group"] == "root"
    assert "dockermgmt" in defaults["funa_env_group"]
    tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "mode: '0640'" in tasks and "mode: '0644'" in tasks


def test_secret_tasks_use_no_log_and_no_diff():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))[0]["block"]
    by_id = {re.match(r"\[(FUNA-\d+)", t["name"]).group(1): t for t in tasks if t["name"].startswith("[FUNA-0")
             and "-FACT" not in t["name"]}
    for tid in ("FUNA-003", "FUNA-005", "FUNA-009"):
        assert by_id[tid].get("no_log") is True, tid
    assert by_id["FUNA-009"].get("diff") is False


def test_site_runs_funa_env_after_docker_engine():
    play = yaml.safe_load((ROOT_DIR / "playbooks" / "site.yml").read_text(encoding="utf-8"))[1]
    roles = [r["role"] for r in play["roles"]]
    assert roles.index("funa_env") == roles.index("docker_engine") + 1
