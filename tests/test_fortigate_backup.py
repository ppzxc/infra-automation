"""fortigate_backup 역할 테스트.

seam: cisco_backup 테스트와 같은 높이의 정적 구조 검사 + 장비 응답을 모사한 역할 실행.
장비는 로컬 HTTP 서버로 모사하며 실제 장비에는 닿지 않는다.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from openbao_fake import FakeOpenBao

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE_DIR = ROOT_DIR / "roles" / "fortigate_backup"
SECRET_TOKEN = "unit-test-token-0123456789"
CONFIG_BODY = "#config-version=FGT-TEST:opmode=0\nconfig system global\n    set hostname test\nend\n"
FILE_RE = re.compile(r"^(?P<device>[A-Za-z0-9-]+)_(?P<member>[A-Za-z0-9-]+)_(?P<ts>\d{8}T\d{6})\.conf$")


# --------------------------------------------------------------------------
# 정적 구조
# --------------------------------------------------------------------------
def test_role_and_playbook_structure():
    assert (ROLE_DIR / "tasks" / "main.yml").exists()
    assert (ROLE_DIR / "defaults" / "main.yml").exists()
    data = yaml.safe_load((ROOT_DIR / "playbooks" / "backup_fortigate.yml").read_text(encoding="utf-8"))
    play = data[0]
    assert play["hosts"] == "fortigate_firewalls"
    assert play["gather_facts"] is False
    assert play["connection"] == "local"
    assert "fortigate_backup" in [r if isinstance(r, str) else r.get("role") for r in play["roles"]]


def test_inventory_example_documents_group_without_secrets():
    text = (ROOT_DIR / "inventory" / "hosts.yml.example").read_text(encoding="utf-8")
    inv = yaml.safe_load(text)
    hosts = inv["all"]["children"]["fortigate_firewalls"]["hosts"]
    assert {"ns0380", "ns0399"} <= set(hosts)
    for vars_ in hosts.values():
        assert not vars_   # 주소·포트·토큰은 OpenBao Endpoint·Credential이 정한다


def test_defaults_have_ninety_day_retention_and_no_token():
    d = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert d["fortigate_backup_retention_days"] == 90
    assert d["fortigate_backup_validate_certs"] is True
    assert d["fortigate_backup_endpoint_preference"] == ["https"]
    for old in ("fortigate_api_token", "fortigate_backup_openbao_prefix", "fortigate_backup_openbao_mount",
                "fortigate_backup_openbao_namespace", "fortigate_backup_vault_addr", "fortigate_backup_api_port",
                "fortigate_backup_alert_webhook_url", "fortigate_backup_alert_webhook_token"):
        assert old not in d, old


def test_spec_ids_match_docs_one_to_one():
    tasks = (ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")
    doc = (ROOT_DIR / "docs" / "fortigate_backup.md").read_text(encoding="utf-8")
    in_tasks = set(re.findall(r"\[(FGBK-\d{3})\]", tasks))
    in_doc = set(re.findall(r"\|\s*`(FGBK-\d{3})`", doc))
    assert in_tasks and in_tasks == in_doc


def test_docs_index_lists_role():
    assert "fortigate_backup.md" in (ROOT_DIR / "docs" / "INDEX.md").read_text(encoding="utf-8")


def test_doc_records_naming_layout_and_decisions():
    doc = (ROOT_DIR / "docs" / "fortigate_backup.md").read_text(encoding="utf-8")
    for needle in ["<장비>_<멤버>_YYYYMMDDTHHMMSS", "RustFS", "암호화", "0600", "0700"]:
        assert needle in doc, needle


def _tasks_by_id():
    """Tasks keyed by Spec ID, including those inside block/always sections."""
    found = {}

    def walk(items):
        for t in items:
            m = re.match(r"\[(FGBK-\d{3})\]", t.get("name", ""))
            if m:
                found[m.group(1)] = t
            for key in ("block", "rescue", "always"):
                walk(t.get(key) or [])

    walk(yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")))
    return found


def test_no_plaintext_token_or_unprotected_secret_tasks():
    by_id = _tasks_by_id()
    for tid in ("FGBK-003", "FGBK-006", "FGBK-009", "FGBK-011", "FGBK-022"):
        assert by_id[tid].get("no_log") is True, tid
    # 검사 태스크의 fail_msg에는 값이 없다: no_log를 달면 [FORTIGATE-VIA] 사유가 가려진다.
    assert not by_id["FGBK-004"].get("no_log")
    assert "{{" not in by_id["FGBK-004"]["ansible.builtin.assert"]["fail_msg"].replace("{{ inventory_hostname }}", "")
    assert by_id["FGBK-011"]["ansible.builtin.copy"]["mode"] == "0600"
    assert by_id["FGBK-005"]["ansible.builtin.file"]["mode"] == "0700"
    assert "token" not in (ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 장비 응답 모사 + 역할 실행
# --------------------------------------------------------------------------
class _Device:
    def __init__(self):
        self.mode = "ok"
        self.config = CONFIG_BODY
        self.hostname = "fw-primary"
        self.serial = "FGTSERIAL000001"
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {SECRET_TOKEN}":
                    code, body = 401, "unauthorized"
                elif self.path.startswith("/api/v2/monitor/system/status"):
                    if outer.mode == "status_error":
                        code, body = 500, "boom"
                    else:
                        code = 200
                        body = json.dumps({"http_status": 200, "serial": outer.serial,
                                           "results": {"hostname": outer.hostname}, "version": "vA"})
                elif outer.mode == "empty":
                    code, body = 200, ""
                elif outer.mode == "html":
                    code, body = 200, "<html>login</html>"
                elif outer.mode == "error":
                    code, body = 500, "boom"
                else:
                    code, body = 200, outer.config
                self.send_response(code)
                if self.path.startswith("/api/v2/monitor/system/status") and code == 200:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body.encode())))
                self.end_headers()
                self.wfile.write(body.encode())

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def device():
    d = _Device()
    yield d
    d.close()


@pytest.fixture
def ansible_env(tmp_path):
    if shutil.which("ansible-playbook") is None:
        pytest.skip("ansible-playbook not installed")
    (tmp_path / "ansible.cfg").write_text(f"[defaults]\nroles_path = {ROOT_DIR / 'roles'}\nretry_files_enabled = False\n", encoding="utf-8")
    (tmp_path / "play.yml").write_text(
        "- hosts: all\n  gather_facts: false\n  connection: local\n  roles:\n    - fortigate_backup\n", encoding="utf-8"
    )
    return tmp_path


_BAOS = []


@pytest.fixture(autouse=True)
def _close_baos():
    yield
    while _BAOS:
        _BAOS.pop().close()


def _bao(device, targets=("ns0380",), token=SECRET_TOKEN, hook=None, address="127.0.0.1", via=None):
    """가짜 OpenBao: Asset마다 Endpoint https와 Credential api(+ alert/notify url). 스키마 검증을 켠다(가짜 값만)."""
    store = {}
    for ns in targets:
        store[f"inventory/assets/{ns}"] = {"description": "Fake firewall", "type": "firewall"}
        ep = {"protocol": "https", "address": address, "port": device.port, "credential": "api"}
        if via and ns == targets[0]:
            ep["via"] = via
        store[f"inventory/assets/{ns}/endpoints"] = {"https": ep}
        if token is not None:
            store[f"secrets/assets/{ns}/credentials/api"] = {"type": "api_token", "token": token}
    if hook is not None:
        store["secrets/services/alert/notify"] = {"url": hook.url}
    b = FakeOpenBao.with_schemas(store, namespace="infra", token="bao-test-token", approle=True)
    _BAOS.append(b)
    return b


def _run(env_dir, device, backup_dir, targets=("ns0380",), token=SECRET_TOKEN, extra=None, hook=None, bao=None):
    bao = bao or _bao(device, targets, token, hook)
    (env_dir / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": {inv: {} for inv in targets}}}), encoding="utf-8")
    ev = {
        "fortigate_backup_dir": str(backup_dir),
        "fortigate_backup_scheme": "http",
        "fortigate_backup_timeout": 5,
    }
    ev.update(extra or {})
    (env_dir / "ev.yml").write_text(yaml.safe_dump(ev), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "OPENBAO_"))}
    env["ANSIBLE_CONFIG"] = str(env_dir / "ansible.cfg")
    env["ANSIBLE_LOOKUP_PLUGINS"] = str(ROOT_DIR / "lookup_plugins")
    env["ANSIBLE_FILTER_PLUGINS"] = str(ROOT_DIR / "filter_plugins")
    env.update(bao.approle_env())
    res = subprocess.run(
        ["ansible-playbook", "-i", str(env_dir / "inv.yml"), str(env_dir / "play.yml"), "-e", f"@{env_dir / 'ev.yml'}"],
        capture_output=True, text=True, env=env, cwd=env_dir,
    )
    res.bao = bao
    return res


def _files(d):
    return sorted(p for p in Path(d).glob("*") if p.is_file())


def test_saved_per_target_with_responding_member_and_0600(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    res = _run(ansible_env, device, out, targets=("ns0380", "ns0399"))
    assert res.returncode == 0, res.stdout + res.stderr
    files = _files(out)
    assert len(files) == 2
    assert {FILE_RE.match(f.name)["device"] for f in files} == {"ns0380", "ns0399"}
    for f in files:
        m = FILE_RE.match(f.name)
        assert m["member"] == "fw-primary"
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert f.read_text(encoding="utf-8") == CONFIG_BODY
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    paths = [p for p, _ in device.requests]
    assert any(p.startswith("/api/v2/monitor/system/config/backup") for p in paths)
    assert any(p.startswith("/api/v2/monitor/system/status") for p in paths)
    assert all(a == f"Bearer {SECRET_TOKEN}" for _, a in device.requests)


def test_failover_changes_member_in_file_name_but_not_target(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    assert _run(ansible_env, device, out).returncode == 0
    device.hostname = "fw-secondary"
    time.sleep(1.1)
    assert _run(ansible_env, device, out).returncode == 0
    parsed = [FILE_RE.match(f.name) for f in _files(out)]
    assert [m["device"] for m in parsed] == ["ns0380", "ns0380"]
    assert {m["member"] for m in parsed} == {"fw-primary", "fw-secondary"}


def test_serial_can_be_member_and_name_is_sanitized(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    device.hostname = "weird_name.local"
    assert _run(ansible_env, device, out).returncode == 0
    assert FILE_RE.match(_files(out)[0].name)["member"] == "weird-name-local"
    for f in _files(out):
        f.unlink()
    assert _run(ansible_env, device, out, extra={"fortigate_backup_member_source": "serial"}).returncode == 0
    assert FILE_RE.match(_files(out)[0].name)["member"] == "FGTSERIAL000001"


@pytest.mark.parametrize("mode", ["empty", "html", "error"])
def test_bad_response_saves_nothing_and_fails(ansible_env, device, tmp_path, mode):
    device.mode = mode
    out = tmp_path / "bk"
    res = _run(ansible_env, device, out)
    assert res.returncode != 0
    assert _files(out) == []
    assert "FORTIGATE-RESPONSE" in res.stdout + res.stderr


def test_status_failure_saves_nothing_and_fails(ansible_env, device, tmp_path):
    device.mode = "status_error"
    res = _run(ansible_env, device, tmp_path / "bk")
    assert res.returncode != 0
    assert _files(tmp_path / "bk") == []
    assert "FORTIGATE-STATUS" in res.stdout + res.stderr


def test_bad_response_does_not_overwrite_previous_backup(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    assert _run(ansible_env, device, out).returncode == 0
    before = {f.name: f.read_text(encoding="utf-8") for f in _files(out)}
    device.mode = "empty"
    time.sleep(1.1)
    assert _run(ansible_env, device, out).returncode != 0
    assert {f.name: f.read_text(encoding="utf-8") for f in _files(out)} == before


def test_wrong_token_fails(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk", token="wrong")
    assert res.returncode != 0
    assert _files(tmp_path / "bk") == []


def test_missing_token_fails_before_calling_device(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk", token=None)
    assert res.returncode != 0
    assert "secrets/assets/ns0380/credentials/api" in res.stdout + res.stderr   # 없는 문서는 경로만 밝히고 실패한다
    assert device.requests == []


def test_token_never_printed(ansible_env, device, tmp_path):
    for mode in ("ok", "error", "status_error"):
        device.mode = mode
        res = _run(ansible_env, device, tmp_path / "bk")
        assert SECRET_TOKEN not in res.stdout + res.stderr
        assert "config system global" not in res.stdout + res.stderr


def test_retention_is_per_target_across_members(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    old = time.time() - 100 * 86400
    expired_other_member = out / "ns0380_fw-secondary_20200101T000000.conf"
    other_target = out / "ns0399_fw-x_20200101T000000.conf"
    recent = out / "ns0380_fw-secondary_20990101T000000.conf"
    for f in (expired_other_member, other_target, recent):
        f.write_text("x", encoding="utf-8")
    os.utime(expired_other_member, (old, old))
    os.utime(other_target, (old, old))
    res = _run(ansible_env, device, out)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not expired_other_member.exists()
    assert other_target.exists() and recent.exists()
    assert len(_files(out)) == 3


def test_retention_days_is_adjustable(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    f = out / "ns0380_fw-primary_20200101T000000.conf"
    f.write_text("x", encoding="utf-8")
    old = time.time() - 10 * 86400
    os.utime(f, (old, old))
    assert _run(ansible_env, device, out).returncode == 0
    assert f.exists()  # 기본 90일
    assert _run(ansible_env, device, out, extra={"fortigate_backup_retention_days": 5}).returncode == 0
    assert not f.exists()


def test_failed_backup_does_not_purge(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    f = out / "ns0380_fw-primary_20200101T000000.conf"
    f.write_text("x", encoding="utf-8")
    old = time.time() - 100 * 86400
    os.utime(f, (old, old))
    device.mode = "empty"
    assert _run(ansible_env, device, out).returncode != 0
    assert f.exists()


def test_underscore_in_device_rejected(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk", extra={"fortigate_device": "bad_name"})
    assert res.returncode != 0
    assert device.requests == []


# --------------------------------------------------------------------------
# 설정 변경 감지 (#286): 알림 수신기는 로컬 HTTP 서버로 모사한다.
# --------------------------------------------------------------------------
HASH = "SH2xYz9SECRETADMINHASHvalue"
PSK = "ENC SECRETPSKvalue123456"


def _cfg(version="FGT-vA-build1:opmode=0:vdom=0:user=admin", hostname="fw-primary", extra=""):
    return (
        f"#config-version={version}\n#conf_file_ver=123\n#buildno=1\n"
        f"config system global\n    set hostname \"{hostname}\"\n    set admintimeout 5\nend\n"
        f"config system admin\n    edit \"admin\"\n        set password ENC {HASH}\n    next\nend\n"
        f"config vpn ipsec phase1-interface\n    edit \"site-a\"\n        set psksecret {PSK}\n    next\nend\n"
        + extra
    )


class _Hook:
    def __init__(self):
        self.posts = []
        self.content_types = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.content_types.append(self.headers.get("Content-Type"))
                outer.posts.append((self.path, self.headers.get("X-NANOIT-ACCESS"), self.rfile.read(n).decode()))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def texts(self):
        return [b for _, _, b in self.posts]

    def close(self):
        self.server.shutdown()


@pytest.fixture
def hook():
    h = _Hook()
    yield h
    h.close()


def _drift_run(env_dir, device, out, hook, **extra):
    return _run(env_dir, device, out, extra=extra, hook=hook)


def _two_runs(env_dir, device, out, hook, first, second):
    device.config = first
    r1 = _drift_run(env_dir, device, out, hook)
    assert r1.returncode == 0, r1.stdout + r1.stderr
    device.config = second
    time.sleep(1.1)
    r2 = _drift_run(env_dir, device, out, hook)
    return r1, r2


def test_first_backup_has_no_alert_and_no_error(ansible_env, device, hook, tmp_path):
    device.config = _cfg()
    res = _drift_run(ansible_env, device, tmp_path / "bk", hook)
    assert res.returncode == 0, res.stdout + res.stderr
    assert hook.posts == []


def test_unchanged_or_header_only_change_does_not_alert(ansible_env, device, hook, tmp_path):
    _, r2 = _two_runs(ansible_env, device, tmp_path / "bk", hook, _cfg(), _cfg(version="FGT-vB-build9:opmode=0:vdom=0:user=other"))
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert hook.posts == []


def test_change_alerts_once_with_target_member_and_runbook_without_secrets(ansible_env, device, hook, tmp_path):
    out = tmp_path / "bk"
    changed = _cfg(extra='config firewall policy\n    edit 7\n        set name "allow-all"\n    next\nend\n').replace("admintimeout 5", "admintimeout 480")
    r1, r2 = _two_runs(ansible_env, device, out, hook, _cfg(), changed)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert len(hook.posts) == 1
    text = hook.texts()[0]
    for needle in ("P2", "■ 무슨 일", "■ 왜 중요", "■ 대상", "■ 조치", "▶ 런북", "#fortigate-config-change", "ns0380", "fw-primary",
                   "config firewall policy", "config system global"):
        assert needle in text, needle
    assert hook.posts[0][1] is None   # URL 자체가 권한이라 인증 헤더가 없다
    # 같은 변경으로 다시 실행해도 반복 알림 없음
    time.sleep(1.1)
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    assert len(hook.posts) == 1
    # 비밀 값은 알림·로그 어디에도 없다
    everything = text + r1.stdout + r1.stderr + r2.stdout + r2.stderr
    for secret in (HASH, "SECRETPSKvalue123456", hook.url, "allow-all", "480"):
        assert secret not in everything, secret


def test_alert_is_sent_as_plain_text_not_a_json_wrapper(ansible_env, device, hook, tmp_path):
    changed = _cfg().replace("admintimeout 5", "admintimeout 9")
    _, r2 = _two_runs(ansible_env, device, tmp_path / "bk", hook, _cfg(), changed)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert hook.content_types == ["text/plain; charset=utf-8"]
    body = hook.texts()[0]
    assert body.startswith("🟠 [P2 경고]") and "\n■ 조치" in body and '"content"' not in body


def test_a_body_over_the_old_2000_char_json_limit_is_delivered_whole(ansible_env, device, hook, tmp_path):
    """JSON 경로는 본문 2000자 초과를 거부했다. 변경 항목이 길어도 text/plain으로 잘림 없이 간다."""
    extra = "".join(f"config firewall section-{i:03d}-" + "x" * 60 + "\n    set a 1\nend\n" for i in range(60))
    out = tmp_path / "bk"
    device.config = _cfg()
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    device.config = _cfg(extra=extra)
    time.sleep(1.1)
    res = _drift_run(ansible_env, device, out, hook, fortigate_backup_alert_max_items=200)
    assert res.returncode == 0, res.stdout + res.stderr
    (body,) = hook.texts()
    assert len(body) > 2000
    assert "section-000-" in body and "section-059-" in body and "외 " not in body
    assert body.rstrip().endswith("fortigate-config-change")


def test_secret_only_change_alerts_but_never_prints_values(ansible_env, device, hook, tmp_path):
    changed = _cfg().replace(PSK, "ENC ROTATEDPSKvalue999")
    _, r2 = _two_runs(ansible_env, device, tmp_path / "bk", hook, _cfg(), changed)
    assert len(hook.posts) == 1
    assert "vpn ipsec phase1-interface" in hook.texts()[0]
    assert "ROTATEDPSKvalue999" not in hook.texts()[0] + r2.stdout + r2.stderr
    assert "SECRETPSKvalue123456" not in hook.texts()[0] + r2.stdout + r2.stderr


def test_member_failover_does_not_flag_member_specific_lines_but_marks_member_change(ansible_env, device, hook, tmp_path):
    out = tmp_path / "bk"
    device.config = _cfg()
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    device.hostname = "fw-secondary"
    device.config = _cfg(hostname="fw-secondary")
    time.sleep(1.1)
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    assert hook.posts == []  # 멤버 고유 줄(hostname)만 다르면 변경이 아니다
    device.config = _cfg(hostname="fw-secondary").replace("admintimeout 5", "admintimeout 9")
    time.sleep(1.1)
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    assert len(hook.posts) == 1  # 직전과 같은 멤버의 실제 변경: 알림
    assert "멤버 고유" not in hook.texts()[0]
    device.hostname = "fw-primary"
    device.config = _cfg(hostname="fw-primary").replace("admintimeout 5", "admintimeout 11")
    time.sleep(1.1)
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    assert len(hook.posts) == 2
    assert "fw-secondary" in hook.texts()[1] and "fw-primary" in hook.texts()[1]
    assert "멤버 고유" in hook.texts()[1]


def test_alert_failure_or_missing_webhook_fails_host_loudly(ansible_env, device, tmp_path):
    out = tmp_path / "bk"
    device.config = _cfg()
    assert _run(ansible_env, device, out).returncode == 0
    device.config = _cfg().replace("admintimeout 5", "admintimeout 9")
    time.sleep(1.1)
    res = _run(ansible_env, device, out)
    assert res.returncode != 0
    assert "FORTIGATE-ALERT" in res.stdout + res.stderr
    assert "config system global" in res.stdout + res.stderr  # 요지는 로그에 남는다(값 없음)
    assert "admintimeout 9" not in res.stdout + res.stderr


def _filters():
    import importlib.util
    spec = importlib.util.spec_from_file_location("fgdrift", ROLE_DIR / "filter_plugins" / "fortigate_config_drift.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FilterModule().filters()


def test_previous_backup_is_by_trailing_timestamp_not_member_name():
    f = _filters()["fortigate_backup_previous"]
    names = ["ns0380_zz-member_20260101T000000.conf", "ns0380_aa-member_20260102T000000.conf",
             "ns0380_mm-member_20260103T000000.conf", "ns0399_fw_20260102T120000.conf"]
    assert f(names, "ns0380_mm-member_20260103T000000.conf", "ns0380_") == "ns0380_aa-member_20260102T000000.conf"
    assert f(["ns0380_a_20260101T000000.conf"], "ns0380_a_20260101T000000.conf", "ns0380_") == ""


def test_changes_report_names_only_and_ignore_comment_lines():
    f = _filters()["fortigate_config_changes"]
    a = _cfg()
    assert f(a, _cfg(version="other"), False) == []
    got = f(_cfg().replace(HASH, "NEWHASH"), a, False)
    assert got == ['config system admin > edit "admin" (변경: password)']


def test_volatile_encrypted_keys_changing_between_exports_is_not_a_change():
    f = _filters()["fortigate_config_changes"]
    acme = 'config system acme\n    set store-passphrase ENC {}\nend\nconfig system ha\n    set password ENC {}\n    set priority 100\nend\n'
    a, b = _cfg() + acme.format("AAAA", "BBBB"), _cfg() + acme.format("CCCC", "DDDD")
    assert f(b, a, False) == []
    # 같은 섹션의 다른 키 변경과 키의 추가·삭제는 여전히 변경이다
    assert f(b.replace("priority 100", "priority 50"), a, False) == ["config system ha (변경: priority)"]
    no_pw = _cfg() + acme.format("AAAA", "BBBB").replace("    set password ENC BBBB\n", "")
    assert f(no_pw, a, False) == ["config system ha (변경: password)"]


def test_previous_that_is_not_a_fortios_config_is_no_baseline():
    f = _filters()["fortigate_config_changes"]
    assert f(_cfg(), "x", False) == []
    assert f(_cfg(), "", False) == []


def test_multiline_values_do_not_break_parsing():
    f = _filters()["fortigate_config_changes"]
    cert = 'config vpn certificate local\n    edit "c"\n        set certificate "-----BEGIN CERTIFICATE-----\nAAAA\nend\n-----END CERTIFICATE-----\n"\n    next\nend\n'
    assert f(_cfg() + cert, _cfg() + cert, False) == []
    assert len(f(_cfg() + cert.replace("AAAA", "BBBB"), _cfg() + cert, False)) == 1


def test_retention_runs_even_when_the_alert_cannot_be_delivered_but_the_host_still_fails(ansible_env, device, tmp_path):
    """FGBK-012/013 must not be skipped by the FGBK-021 failure, or a webhook outage lets backups pile up without limit."""
    out = tmp_path / "bk"
    out.mkdir()
    device.config = _cfg()
    assert _run(ansible_env, device, out).returncode == 0
    expired = out / "ns0380_fw-old_20200101T000000.conf"
    expired.write_text("x", encoding="utf-8")
    old = time.time() - 100 * 86400
    os.utime(expired, (old, old))
    device.config = _cfg().replace("admintimeout 5", "admintimeout 9")
    time.sleep(1.1)
    res = _run(ansible_env, device, out)   # webhook 없음: 변경 알림이 나가지 못한다
    assert res.returncode != 0 and "FORTIGATE-ALERT" in res.stdout + res.stderr
    assert not expired.exists()


def test_tasks_compute_token_and_member_once():
    tasks = (ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert tasks.count("lookup('openbao_connection'") == 1   # 해석은 한 번(FGBK-003)이다
    assert tasks.count("regex_replace('[^A-Za-z0-9-]'") == 1
    assert tasks.count("fortigate_backup_member(fortigate_backup_file_prefix)") == 1


def test_doc_records_why_there_is_no_molecule_verify():
    doc = (ROOT_DIR / "docs" / "fortigate_backup.md").read_text(encoding="utf-8")
    assert "molecule" in doc and "cisco_backup" in doc and "pytest" in doc
    assert not (ROLE_DIR / "molecule").exists()


# --------------------------------------------------------------------------
# OpenBao 새 구조 (Spec #511 / Ticket-18): Endpoint https + Credential api, alert/notify text/plain
# --------------------------------------------------------------------------
import sys  # noqa: E402

sys.path.insert(0, str(ROOT_DIR / "scripts"))
import openbao_validation as ov  # noqa: E402


def _required():
    return yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text(encoding="utf-8"))["fortigate_backup_openbao_required"]


def test_connection_comes_from_the_https_endpoint_and_api_credential_only(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk")
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(_files(tmp_path / "bk")) == 1 and device.requests
    assert {f"{r.mount}/{r.doc}" for r in res.bao.reads()} == {"inventory/assets/ns0380/endpoints", "secrets/assets/ns0380/credentials/api"}
    assert "127.0.0.1" not in res.stdout + res.stderr and str(device.port) not in res.stdout + res.stderr   # 주소·포트는 로그에 없다


def test_every_read_document_is_inside_the_declared_patterns_and_the_index(ansible_env, device, hook, tmp_path):
    device.config = _cfg()
    out = tmp_path / "bk"
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    device.config = _cfg().replace("admintimeout 5", "admintimeout 9")
    time.sleep(1.1)
    res = _drift_run(ansible_env, device, out, hook)
    assert res.returncode == 0, res.stdout + res.stderr
    docs = {f"{r.mount}/{r.doc}" for r in res.bao.reads()}
    assert "secrets/services/alert/notify" in docs
    patterns = list(_required())
    assert all(any(ov._matches(p, d) for p in patterns) for d in docs), docs
    assert res.bao.violations == []


def test_declared_required_keys_match_the_schemas():
    import json
    schema_dir = ROOT_DIR / "schemas" / "openbao"
    declared = _required()
    for pattern, keys in declared.items():
        sample = pattern.replace("+", "x")
        rel = ov.resolve_schema(sample)
        assert rel is not None, pattern
        schema = json.loads((schema_dir / rel).read_text(encoding="utf-8"))
        if "oneOf" in schema:   # credential: api_token 분기
            schema = next(b for b in schema["oneOf"] if b["properties"]["type"]["const"] == "api_token")
        assert set(keys) <= set(schema.get("required", [])), pattern


def test_the_required_declaration_is_what_the_assert_uses():
    tasks = (ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "fortigate_backup_openbao_required" in tasks


def test_a_via_endpoint_is_refused_because_the_api_is_called_from_the_controller(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk", targets=("ns0380",), bao=_bao(device, ("ns0380", "ns0399"), via="ns0399/https"))
    assert res.returncode != 0 and "FORTIGATE-VIA" in res.stdout + res.stderr
    assert SECRET_TOKEN not in res.stdout + res.stderr      # no_log가 없는 검사 태스크의 실패 출력에도 토큰은 없다
    assert device.requests == []


def test_a_missing_document_fails_with_its_path_and_status_even_though_the_task_is_no_log(ansible_env, device, tmp_path):
    res = _run(ansible_env, device, tmp_path / "bk", token=None)
    assert res.returncode != 0
    assert "secrets/assets/ns0380/credentials/api" in res.stdout + res.stderr


def test_alert_webhook_is_read_only_when_a_change_is_detected(ansible_env, device, hook, tmp_path):
    res = _drift_run(ansible_env, device, tmp_path / "bk", hook)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "secrets/services/alert/notify" not in {f"{r.mount}/{r.doc}" for r in res.bao.reads()}
