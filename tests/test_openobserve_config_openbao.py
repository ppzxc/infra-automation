"""OpenObserve Config의 OpenBao 읽기 계약(Spec #511 / Ticket-16).

역할은 공용 읽기 지점(`lookup('openbao_doc')`)으로만 읽고, 읽는 문서는 `openobserve_config_openbao_required`가 선언한다.
같은 선언을 스키마 `required` 대조와 요청 기록 단언이 쓴다. 가짜 서버(`fake_openbao`)와 fixture 값만 쓴다.
"""
import json
import os
import re
import subprocess
import sys

import pytest
import yaml

from o2c_render import PLAYBOOK, ROOT_DIR

sys.path.insert(0, str(ROOT_DIR / "scripts"))
import openbao_validation as ov  # noqa: E402

ROLE = ROOT_DIR / "roles" / "openobserve_config"
REQUIRED = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))["openobserve_config_openbao_required"]
INDEX = yaml.safe_load((ROOT_DIR / "schemas" / "openbao" / "index.yml").read_text(encoding="utf-8"))


def _regex(pattern):
    return re.compile("^" + "[^/]+".join(re.escape(p) for p in pattern.split("+")) + "$")


def test_every_declared_pattern_is_in_the_index_and_its_required_keys_are_required_by_the_schema():
    for pattern, keys in REQUIRED.items():
        assert pattern in INDEX, pattern
        schema = json.loads((ROOT_DIR / "schemas" / "openbao" / INDEX[pattern]).read_text(encoding="utf-8"))
        assert set(keys) <= set(schema.get("required", [])), pattern
        for key in keys:
            assert key in schema["properties"], (pattern, key)


def test_the_role_declares_no_documents_of_the_secrets_assets_agents_kind():
    assert not [p for p in REQUIRED if p.startswith("secrets/assets/")]


def _render(fake, tmp_path, monkeypatch):
    for var in ("VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_ADDR", "VAULT_NAMESPACE", "VAULT_MOUNT"):
        monkeypatch.delenv(var, raising=False)
    groups = {"servers": {"hosts": {h: {} for h in ("ns0001", "ns0002")}}}
    inventory = tmp_path / "hosts.yml"
    inventory.write_text(yaml.safe_dump({"all": {"children": groups}}), encoding="utf-8")
    env = dict(os.environ, ANSIBLE_NOCOLOR="1", VAULT_ADDR=fake.url, VAULT_ROLE_ID="role-fixture", VAULT_SECRET_ID="secret-fixture")
    cmd = ["ansible-playbook", "-i", str(inventory), str(PLAYBOOK), "-e", json.dumps({"o2c_render_dump": str(tmp_path / "d.json")})]
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)


def test_the_run_reads_only_declared_documents_through_one_approle_login(fake_openbao, tmp_path, monkeypatch):
    res = _render(fake_openbao, tmp_path, monkeypatch)
    assert res.returncode == 0, res.stdout + res.stderr
    docs = {f"{r.mount}/{r.doc}" for r in fake_openbao.reads()}
    patterns = [_regex(p) for p in REQUIRED]
    assert docs and all(any(p.match(d) for p in patterns) for d in docs), docs
    # 선언한 문서 중 이 실행이 반드시 읽어야 하는 것(작업 설정·Asset·Endpoints 포함)
    for pattern in REQUIRED:
        assert any(_regex(pattern).match(d) for d in docs), pattern
    assert len(fake_openbao.logins()) == 1   # 호스트·문서마다 로그인하지 않는다
    assert all(r.namespace == "infra" for r in fake_openbao.reads())


def test_a_denied_document_stops_the_run_with_the_path_and_status_only(fake_openbao, tmp_path, monkeypatch):
    fake_openbao.deny("secrets", "services/openobserve/admin")
    res = _render(fake_openbao, tmp_path, monkeypatch)
    assert res.returncode != 0
    assert "secrets/services/openobserve/admin" in res.stdout and "403" in res.stdout


def test_the_role_has_no_own_openbao_reading_code_token_fallback_or_test_bypass_variables():
    text = "".join(p.read_text(encoding="utf-8") for p in [PLAYBOOK, *ROLE.rglob("*")] if p.is_file() and p.suffix in (".yml", ".j2"))
    for banned in ("VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_NAMESPACE", "OPENBAO_", "o2c_vault", "_kv_fixture", "agents/openobserve", "/v1/"):
        assert banned not in text, banned


# --- 호스트별 알림 설정과 사설 CA는 OpenBao 문서에서 읽는다(최종 리뷰 5·6번) ---------------------------------------------------

def _render_with(directory, *, config=None):
    from o2c_render import fixture_args
    directory.mkdir()
    cmd = ["ansible-playbook", "-i", "localhost,", str(PLAYBOOK),
           *fixture_args("http://127.0.0.1:9", config=config, extra={"o2c_render_dump": str(directory / "d.json")})]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300,
                         env=dict(os.environ, ANSIBLE_NOCOLOR="1"))
    assert res.returncode == 0, res.stdout + res.stderr
    return (directory / "d.json").read_text(encoding="utf-8")


def test_host_exclusions_thresholds_and_provisioning_accounts_come_from_the_job_config_document(tmp_path):
    base = _render_with(tmp_path / "base")
    for marker in ("ns0297", "ns0300", "deployer"):
        assert marker not in base
    cfg = {"resource_exclusions": [{"host": "ns0297", "mount": "/data"}],
           "resource_thresholds": [{"host": "ns0300", "p2": 97, "p1": 99}],
           "audit_provisioning_accounts": ["deployer"]}
    out = _render_with(tmp_path / "cfg", config=cfg)
    for marker in ("ns0297", "ns0300", "deployer"):
        assert marker in out, marker


def test_the_new_job_config_keys_are_schema_checked():
    ok = {"resource_exclusions": [{"host": "ns0297", "mount": "/data", "metric": "disk"}],
          "resource_thresholds": [{"host": "ns0300", "p2": 97, "p1": 99}], "audit_provisioning_accounts": ["deployer"]}
    assert ov.validate_document("inventory/config/openobserve_config", ok) == []
    for bad in ({"resource_exclusions": [{"mount": "/data"}]}, {"resource_exclusions": [{"host": "ns1", "metric": "cpu"}]},
                {"resource_thresholds": [{"host": "ns1", "p2": "97"}]}, {"audit_provisioning_accounts": [""]}):
        assert ov.validate_document("inventory/config/openobserve_config", bad), bad


def test_the_private_ca_file_comes_from_the_openobserve_service_document(tmp_path):
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars_files": [str(ROLE / "defaults" / "main.yml")],
             "tasks": [{"ansible.builtin.assert": {"that": ["o2c_ca_file == '/etc/pki/fake-o2-ca.pem'"], "quiet": True}}]}]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump(play))
    docs = {"o2c_docs": {"inventory/services/openobserve": {"url": "https://o2.example.test", "ca_file": "/etc/pki/fake-o2-ca.pem"}}}
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb), "-e", json.dumps(docs)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr


def test_the_o2_ca_file_extra_variable_still_wins_over_the_document(tmp_path):
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars_files": [str(ROLE / "defaults" / "main.yml")],
             "tasks": [{"ansible.builtin.assert": {"that": ["o2c_ca_file == '/runner/ca.pem'"], "quiet": True}}]}]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump(play))
    extra = {"o2_ca_file": "/runner/ca.pem",
             "o2c_docs": {"inventory/services/openobserve": {"url": "https://o2.example.test", "ca_file": "/etc/pki/fake-o2-ca.pem"}}}
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb), "-e", json.dumps(extra)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
