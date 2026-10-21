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


def test_no_plaintext_token_or_unprotected_secret_tasks():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8"))
    by_id = {re.match(r"\[(FGBK-\d{3})\]", t["name"]).group(1): t for t in tasks}
    for tid in ("FGBK-002", "FGBK-003", "FGBK-006", "FGBK-009", "FGBK-011"):
        assert by_id[tid].get("no_log") is True, tid
    assert by_id["FGBK-011"]["ansible.builtin.copy"]["mode"] == "0600"
    assert by_id["FGBK-005"]["ansible.builtin.file"]["mode"] == "0700"
    assert "token" not in (ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8").replace("api_token", "").replace("vault_token", "").replace("X-Vault-Token", "")


# --------------------------------------------------------------------------
# 장비 응답 모사 + 역할 실행
# --------------------------------------------------------------------------
class _Device:
    def __init__(self):
        self.mode = "ok"
        self.hostname = "fw-primary"
        self.serial = "FGT70GTEST000001"
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
                                           "results": {"hostname": outer.hostname}, "version": "v7.2.13"})
                elif outer.mode == "empty":
                    code, body = 200, ""
                elif outer.mode == "html":
                    code, body = 200, "<html>login</html>"
                elif outer.mode == "error":
                    code, body = 500, "boom"
                else:
                    code, body = 200, CONFIG_BODY
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


def _run(env_dir, device, backup_dir, targets=("ns0380",), token=SECRET_TOKEN, extra=None):
    hosts = {inv: {"ansible_host": "127.0.0.1"} for inv in targets}
    (env_dir / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": hosts}}), encoding="utf-8")
    ev = {
        "fortigate_backup_dir": str(backup_dir),
        "fortigate_backup_scheme": "http",
        "fortigate_backup_api_port": device.port,
        "fortigate_api_token": token,
        "fortigate_backup_timeout": 5,
    }
    ev.update(extra or {})
    (env_dir / "ev.yml").write_text(yaml.safe_dump(ev), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "OPENBAO_"))}
    env["ANSIBLE_CONFIG"] = str(env_dir / "ansible.cfg")
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
    assert FILE_RE.match(_files(out)[0].name)["member"] == "FGT70GTEST000001"


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
