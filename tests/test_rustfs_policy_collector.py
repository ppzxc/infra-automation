"""scripts/collect-rustfs-policy.py (#368): RustFS 서비스 계정·정책 읽기 전용 수집.

네트워크 없이 검증한다 -- 가짜 fetch로 정규화 출력만 본다.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from openbao_fake import FakeOpenBao  # noqa: E402

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "collect-rustfs-policy.py"
spec = importlib.util.spec_from_file_location("collect_rustfs_policy", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SECRET = "AKIA-SUPER-SECRET-KEY-0001"

POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
                   "Resource": ["arn:aws:s3:::b2/*", "arn:aws:s3:::b1/*"]}],
})


def fake_fetch(path, query=None):
    query = query or {}
    if path.endswith("/list-users"):
        return {"ppzxc": {"policyName": "readwrite,consoleAdmin", "status": "enabled"},
                "openobserve": {"policyName": "readwrite", "status": "enabled"}}
    if path.endswith("/groups"):
        return ["hosts"]
    if path.endswith("/group"):
        return {"name": "hosts", "status": "enabled", "policy": "readwrite", "members": [],
                "updatedAt": "2026-01-01T00:00:00Z"}
    if path.endswith("/list-canned-policies"):
        return {"readwrite": {}, "readonly": {}}
    if path.endswith("/info-canned-policy"):
        return {"policy_name": query["name"], "policy": json.loads(POLICY)}
    if path.endswith("/list-service-accounts"):
        if query.get("user") == "ppzxc":
            return {"accounts": [{"parentUser": "ppzxc", "accountStatus": "on", "impliedPolicy": True,
                                  "accessKey": SECRET, "name": "svc-a", "expiration": "1970-01-01T00:00:00Z"}]}
        return {"accounts": []}
    if path.endswith("/info-service-account"):
        return {"parentUser": "ppzxc", "accountStatus": "on", "impliedPolicy": False,
                "policy": POLICY, "name": "svc-a"}
    raise AssertionError(path)


def test_report_never_contains_access_key_and_hashes_it():
    out = mod.build_report(fake_fetch)
    assert SECRET not in out
    assert mod.key_id(SECRET) in out
    assert re.fullmatch(r"[0-9a-f]{12}", mod.key_id(SECRET))


def test_report_is_deterministic_and_sorted():
    a = mod.build_report(fake_fetch)
    assert a == mod.build_report(fake_fetch)
    assert "updatedAt" not in a
    # 정책 안 Resource·Action은 정렬돼 출력된다.
    assert a.index("b1/*") < a.index("b2/*")
    assert a.index("s3:GetObject") < a.index("s3:PutObject")


def test_report_shows_users_groups_and_service_account_effective_policy():
    out = mod.build_report(fake_fetch)
    assert "readwrite,consoleAdmin" in out          # 사용자 정책
    assert "## groups" in out and "hosts" in out
    assert "implied=True" in out or "implied=False" in out
    assert "s3:PutObject" in out                    # 서비스 계정 인라인 정책 요약


def test_only_get_requests_are_defined():
    text = SCRIPT.read_text()
    assert '"GET"' in text
    for verb in ("PUT", "POST", "DELETE", "PATCH"):
        assert f'"{verb}"' not in text


# --- 새 OpenBao 구조(Spec #511 / Ticket-15) -------------------------------------------------------

def test_credentials_come_from_the_new_structure_with_the_operator_token():
    """`inventory/services/rustfs`(주소·리전)와 `secrets/services/rustfs/maintenance`(키)를 `infra` 네임스페이스에서 읽는다."""
    with FakeOpenBao.with_schemas(namespace="infra", token="operator-token") as bao:
        got = mod.read_rustfs_service({"VAULT_ADDR": bao.url, "VAULT_TOKEN": "operator-token"})
    assert got == {"endpoint": "https://s3.example.test", "region": "fake-region-1",
                   "access_key": "fake-access-0015", "secret_key": "fake-secret-0016"}
    assert sorted(f"{r.mount}/{r.doc}" for r in bao.reads()) == ["inventory/services/rustfs", "secrets/services/rustfs/maintenance"]
    assert bao.violations == []


def test_env_file_values_fill_in_the_connection(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# 주석\nVAULT_TOKEN=operator-token\n")
    with FakeOpenBao.with_schemas(namespace="infra", token="operator-token") as bao:
        env = {**mod._parse_env_file(env_file), "VAULT_ADDR": bao.url}
        assert mod.read_rustfs_service(env)["access_key"] == "fake-access-0015"


def test_missing_document_or_token_stops_with_the_document_path_only():
    with FakeOpenBao.with_schemas({}, namespace="infra", token="operator-token") as bao:
        with pytest.raises(SystemExit) as exc:
            mod.read_rustfs_service({"VAULT_ADDR": bao.url, "VAULT_TOKEN": "operator-token"})
    assert "inventory/services/rustfs" in str(exc.value) and "404" in str(exc.value)
    with pytest.raises(SystemExit) as exc:
        mod.read_rustfs_service({"VAULT_ADDR": "http://127.0.0.1:1"})
    assert "VAULT_TOKEN" in str(exc.value)


def test_script_has_no_old_structure_or_fallback():
    text = SCRIPT.read_text()
    for old in ("agents/rustfs", "infra/prod/host", "secret/data", "OPENBAO_URL", "OPENBAO_TOKEN", "maintenance_access_key", "rustfs_endpoint"):
        assert old not in text, old
