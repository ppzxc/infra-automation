"""scripts/collect-rustfs-policy.py (#368): RustFS 서비스 계정·정책 읽기 전용 수집.

네트워크 없이 검증한다 -- 가짜 fetch로 정규화 출력만 본다.
"""
import importlib.util
import json
import re
from pathlib import Path

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
