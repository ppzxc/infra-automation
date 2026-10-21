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
        assert "ansible_host" in vars_
        assert "token" not in " ".join(vars_)


def test_defaults_have_ninety_day_retention_and_no_token():
    d = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert d["fortigate_backup_retention_days"] == 90
    assert d["fortigate_api_token"] == ""
    assert d["fortigate_backup_validate_certs"] is True


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
    for tid in ("FGBK-002", "FGBK-003", "FGBK-004", "FGBK-006", "FGBK-009", "FGBK-011"):
        assert by_id[tid].get("no_log") is True, tid
    assert by_id["FGBK-011"]["ansible.builtin.copy"]["mode"] == "0600"
    assert by_id["FGBK-005"]["ansible.builtin.file"]["mode"] == "0700"
    assert "token" not in (ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8").replace("api_token", "").replace("webhook_token", "").replace("vault_token", "").replace("X-Vault-Token", "")


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


def _run(env_dir, device, backup_dir, targets=("ns0380",), token=SECRET_TOKEN, extra=None, host_vars=None, env_extra=None, drop_port=False):
    hosts = {inv: ({"ansible_host": "127.0.0.1"} if host_vars is None else dict(host_vars)) for inv in targets}
    (env_dir / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": hosts}}), encoding="utf-8")
    ev = {
        "fortigate_backup_dir": str(backup_dir),
        "fortigate_backup_scheme": "http",
        "fortigate_backup_api_port": device.port,
        "fortigate_api_token": token,
        "fortigate_backup_timeout": 5,
    }
    if drop_port:
        del ev["fortigate_backup_api_port"]
    ev.update(extra or {})
    (env_dir / "ev.yml").write_text(yaml.safe_dump(ev), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "OPENBAO_"))}
    env["ANSIBLE_CONFIG"] = str(env_dir / "ansible.cfg")
    env.update(env_extra or {})
    return subprocess.run(
        ["ansible-playbook", "-i", str(env_dir / "inv.yml"), str(env_dir / "play.yml"), "-e", f"@{env_dir / 'ev.yml'}"],
        capture_output=True, text=True, env=env, cwd=env_dir,
    )


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
    res = _run(ansible_env, device, tmp_path / "bk", token="")
    assert res.returncode != 0
    assert "FORTIGATE-TOKEN" in res.stdout + res.stderr
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
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.posts.append((self.path, self.headers.get("X-NANOIT-ACCESS"), self.rfile.read(n).decode()))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def texts(self):
        return [json.loads(b)["content"]["text"] for _, _, b in self.posts]

    def close(self):
        self.server.shutdown()


@pytest.fixture
def hook():
    h = _Hook()
    yield h
    h.close()


def _drift_run(env_dir, device, out, hook, **extra):
    ev = {"fortigate_backup_alert_webhook_url": hook.url, "fortigate_backup_alert_webhook_token": "hook-token-xyz"}
    ev.update(extra)
    return _run(env_dir, device, out, extra=ev)


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
    assert hook.posts[0][1] == "hook-token-xyz"
    # 같은 변경으로 다시 실행해도 반복 알림 없음
    time.sleep(1.1)
    assert _drift_run(ansible_env, device, out, hook).returncode == 0
    assert len(hook.posts) == 1
    # 비밀 값은 알림·로그 어디에도 없다
    everything = text + r1.stdout + r1.stderr + r2.stdout + r2.stderr
    for secret in (HASH, "SECRETPSKvalue123456", "hook-token-xyz", hook.url, "allow-all", "480"):
        assert secret not in everything, secret


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
    assert tasks.count("fortigate_backup_kv_response.json.data.data.api_token }}") == 1
    assert tasks.count("regex_replace('[^A-Za-z0-9-]'") == 1
    assert tasks.count("fortigate_backup_member(fortigate_backup_file_prefix)") == 1


def test_doc_records_why_there_is_no_molecule_verify():
    doc = (ROOT_DIR / "docs" / "fortigate_backup.md").read_text(encoding="utf-8")
    assert "molecule" in doc and "cisco_backup" in doc and "pytest" in doc
    assert not (ROLE_DIR / "molecule").exists()


# --------------------------------------------------------------------------
# OpenBao KV 접속 정보 (ansible_host / ansible_port / fqdn, 스위치 시크릿과 같은 키 이름)
# --------------------------------------------------------------------------
class _Bao:
    """Minimal OpenBao KV v2 stand-in: serves one secret per path and records the requests."""

    def __init__(self, data, status=200):
        outer = self
        self.requests = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("X-Vault-Token"), self.headers.get("X-Vault-Namespace")))
                body = json.dumps({"data": {"data": data}}) if status == 200 else "{}"
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body.encode())))
                self.end_headers()
                self.wfile.write(body.encode())

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def env(self):
        return {"VAULT_ADDR": self.url, "VAULT_TOKEN": "bao-test-token", "VAULT_NAMESPACE": "infra/prod/host"}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def bao_factory():
    made = []

    def make(data, status=200):
        b = _Bao(data, status)
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


def test_connection_info_comes_from_kv_when_inventory_has_only_the_host_name(ansible_env, device, bao_factory, tmp_path):
    """Semaphore inventories list host names only: address and port come from the KV, and the file is saved as usual."""
    bao = bao_factory({"api_token": SECRET_TOKEN, "ansible_host": "127.0.0.1", "ansible_port": str(device.port)})
    res = _run(ansible_env, device, tmp_path / "bk", token="", host_vars={}, drop_port=True, env_extra=bao.env())
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(_files(tmp_path / "bk")) == 1 and device.requests
    assert bao.requests[0][0] == "/v1/secret/data/fortigate/ns0380" and bao.requests[0][2] == "infra/prod/host"
    assert "127.0.0.1" not in res.stdout + res.stderr and str(device.port) not in res.stdout + res.stderr   # 주소·포트는 로그에 없다


def test_fqdn_in_kv_is_the_connection_target_and_the_inventory_address_still_wins_for_the_address(ansible_env, device, bao_factory, tmp_path):
    """fqdn (certificate name) is preferred as the target; here it is localhost, which only resolves when it is really used."""
    bao = bao_factory({"api_token": SECRET_TOKEN, "fqdn": "localhost", "ansible_host": "203.0.113.77"})
    res = _run(ansible_env, device, tmp_path / "bk", token="", env_extra=bao.env())   # 인벤토리 ansible_host=127.0.0.1이 KV 주소보다 우선
    assert res.returncode == 0, res.stdout + res.stderr
    assert device.requests and not any("203.0.113.77" in r[0] for r in device.requests)


def test_kv_address_is_used_when_inventory_has_none_and_kv_port_beats_the_variable(ansible_env, device, bao_factory, tmp_path):
    bao = bao_factory({"api_token": SECRET_TOKEN, "ansible_host": "127.0.0.1", "ansible_port": str(device.port)})
    res = _run(ansible_env, device, tmp_path / "bk", token="", host_vars={}, extra={"fortigate_backup_api_port": 1}, env_extra=bao.env())
    assert res.returncode == 0, res.stdout + res.stderr


def test_kv_without_connection_keys_keeps_the_old_behaviour_and_missing_address_fails_without_values(ansible_env, device, bao_factory, tmp_path):
    bao = bao_factory({"api_token": SECRET_TOKEN})
    assert _run(ansible_env, device, tmp_path / "bk", token="", env_extra=bao.env()).returncode == 0   # 인벤토리 ansible_host 사용
    res = _run(ansible_env, device, tmp_path / "bk2", token="", host_vars={}, env_extra=bao.env())     # 주소가 어디에도 없다
    assert res.returncode != 0 and "FORTIGATE-TOKEN" in res.stdout + res.stderr
    assert SECRET_TOKEN not in res.stdout + res.stderr


def test_inventory_address_and_injected_token_work_even_when_the_kv_path_does_not_exist(ansible_env, device, bao_factory, tmp_path):
    bao = bao_factory({}, status=404)
    res = _run(ansible_env, device, tmp_path / "bk", env_extra=bao.env())
    assert res.returncode == 0, res.stdout + res.stderr


def test_doc_names_the_kv_connection_keys_without_values():
    doc = (ROOT_DIR / "docs" / "fortigate_backup.md").read_text(encoding="utf-8")
    for key in ("ansible_host", "ansible_port", "fqdn"):
        assert f"`{key}`" in doc, key
