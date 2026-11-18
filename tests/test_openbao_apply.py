"""OpenBao 적용 도구(`scripts/openbao_apply.py`)와 선언 코드(`openbao/`)의 검사 (#505 변경: OpenTofu 대신 Python 스크립트).

정적 검사는 코드 파일만 읽는다. 통합 검사는 공용 가짜 OpenBao(tests/openbao_fake.py)에 스크립트를 직접 돌린다. 값은 모두 가짜다.
"""
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from openbao_fake import APPROLE_TOKEN, FakeOpenBao

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import openbao_apply as oa  # noqa: E402

CODE = ROOT / "openbao"
SCRIPT = ROOT / "scripts" / "openbao_apply.py"
ROLES_YML = CODE / "roles.yml"
POLICIES = CODE / "policies"

TOKEN = "fake-bootstrap-token-0001"
RUNNER = "198.51.100.0/24"
AGENT = "203.0.113.7/32"
HASH = "$2b$10$" + "a" * 53          # 형식만 맞춘 가짜 bcrypt 해시
HASH2 = "$2b$10$" + "b" * 53


def _roles():
    return yaml.safe_load(ROLES_YML.read_text(encoding="utf-8"))


def _strip_comments(text):
    return re.sub(r"(?m)^\s*#.*$", "", text)


def _policy_paths(name):
    return re.findall(r'path\s+"([^"]+)"', _strip_comments((POLICIES / name).read_text(encoding="utf-8")))


# ---- 정적: 선언 코드 --------------------------------------------------------------------------------------------------

def test_kv_v2_mounts_and_auth_mounts_declared():
    data = _roles()
    assert set(data["mounts"]) == {"inventory", "secrets"}
    for spec in data["mounts"].values():
        assert spec["type"] == "kv" and spec["version"] == 2
    assert {n: s["type"] for n, s in data["auth_mounts"].items()} == {"userpass": "userpass", "approle": "approle"}
    assert data["namespace"] == "infra"


def test_applier_policy_covers_only_control_plane_paths_never_kv_data():
    paths = _policy_paths("applier.hcl")
    assert paths
    allowed = ("sys/policies/acl", "auth/approle/role", "sys/mounts", "sys/auth", "auth/userpass/users")
    for p in paths:
        assert p.startswith(allowed), p
    for core in ("sys/policies/acl/*", "auth/approle/role/*", "sys/mounts/*", "sys/auth/*"):
        assert core in paths
    # auth/token(자식 토큰 발급)이 없다: 스크립트는 AppRole 로그인 토큰을 그대로 쓴다.
    assert not any(p.startswith(("inventory", "secrets", "auth/token", "sys/*", "*")) for p in paths)


def test_applier_cannot_mint_secret_ids_for_other_roles():
    text = _strip_comments((POLICIES / "applier.hcl").read_text(encoding="utf-8"))
    for p in ("auth/approle/role/+/secret-id", "auth/approle/role/+/secret-id-accessor/*"):
        assert re.search(rf'path "{re.escape(p)}" \{{\s*capabilities = \["deny"\]', text), p
    assert 'path "+' not in text and 'path "*' not in text


def test_applier_approle_short_lived_one_use_and_bound_to_runner_cidrs():
    applier = _roles()["applier"]
    assert 0 < applier["secret_id_ttl"] <= 86400
    assert applier["secret_id_num_uses"] == 1
    assert applier["token_ttl"] == 1800 and applier["token_max_ttl"] == 3600
    assert applier["cidrs"] == "runner"
    assert applier["policies"] == ["applier"]


@pytest.mark.parametrize("path", [ROLES_YML, SCRIPT, *sorted(POLICIES.glob("*.hcl"))], ids=lambda p: p.name)
def test_no_ip_or_cidr_literals_in_repo_code(path):
    for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", path.read_text(encoding="utf-8")):
        pytest.fail(f"{path.name}: IP/CIDR 리터럴 {token} (OPENBAO_*_CIDRS 환경변수로 받는다)")


def test_script_never_deletes_or_tunes_or_mints_secret_ids():
    code = _strip_comments(SCRIPT.read_text(encoding="utf-8"))
    code = re.sub(r'""".*?"""', "", code, flags=re.S)
    for forbidden in ('"DELETE"', "tune", "secret-id", "auth/token", "custom-secret-id"):
        assert forbidden not in code, forbidden


# ---- 통합: 가짜 OpenBao ------------------------------------------------------------------------------------------------

def make_env(fake, **extra):
    env = {**fake.env(TOKEN), "OPENBAO_RUNNER_CIDRS": RUNNER, "OPENBAO_AGENT_SESSION_CIDRS": AGENT,
           "OPENBAO_OPERATOR_PASSWORD_HASHES": json.dumps({"alice": HASH})}
    env.update(extra)
    return env


def run(fake, capsys, *argv, **extra):
    capsys.readouterr()
    code = oa.main(list(argv), make_env(fake, **extra))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.fixture
def fake():
    with FakeOpenBao(namespace="infra", token=TOKEN) as f:
        yield f


def writes(fake):
    return [r for r in fake.requests if r.method == "POST"]


def test_plan_on_empty_server_reports_everything_and_exits_2_without_writing(fake, capsys):
    code, out, _ = run(fake, capsys, "plan")
    assert code == 2
    assert "mount\tinventory\tcreate" in out and "auth\tapprole\tcreate" in out
    assert "policy\tapplier\tcreate" in out and "approle\tagent_session\tcreate" in out
    assert "operator\talice\tcreate" in out
    assert writes(fake) == []


def test_apply_writes_everything_then_second_apply_and_plan_have_no_changes(fake, capsys):
    code, out, _ = run(fake, capsys, "apply")
    assert code == 0
    data = _roles()
    assert set(fake.mounts) == set(data["mounts"]) and fake.mounts["inventory"]["options"] == {"version": "2"}
    assert set(fake.auth_mounts) == set(data["auth_mounts"])
    assert set(fake.policies) == {p.stem for p in POLICIES.glob("*.hcl")}
    assert set(fake.roles) == {"applier", *data["families"]}
    assert fake.users["alice"]["token_policies"] == ["operator"]
    before = len(writes(fake))
    code, out, _ = run(fake, capsys, "apply")
    assert code == 0 and out == "" and len(writes(fake)) == before   # 멱등: 두 번째 apply는 변경 0
    code, out, _ = run(fake, capsys, "plan")
    assert code == 0 and out == ""


def test_role_settings_follow_the_declaration_and_environment_cidrs(fake, capsys):
    run(fake, capsys, "apply")
    applier, agent, other = fake.roles["applier"], fake.roles["agent_session"], fake.roles["provision"]
    assert applier["secret_id_ttl"] == 86400 and applier["secret_id_num_uses"] == 1
    assert applier["secret_id_bound_cidrs"] == [RUNNER] == applier["token_bound_cidrs"]
    assert agent["secret_id_ttl"] == 86400
    assert agent["secret_id_bound_cidrs"] == [AGENT] == agent["token_bound_cidrs"]
    assert other["secret_id_ttl"] == 15552000 and other["token_ttl"] == 1800 and other["token_max_ttl"] == 7200
    assert other["token_policies"] == ["inventory-base", "connect", "funa-secrets"]


def test_drift_is_reported_by_key_name_and_fixed_by_apply(fake, capsys):
    run(fake, capsys, "apply")
    fake.policies["connect"] = "path \"x\" {}\n"
    fake.roles["provision"]["token_max_ttl"] = 1
    fake.roles["host_audit"]["secret_id_bound_cidrs"] = ["192.0.2.1/32"]
    code, out, _ = run(fake, capsys, "plan")
    assert code == 2
    assert "policy\tconnect\tupdate" in out
    assert "approle\tprovision\tupdate token_max_ttl" in out
    assert "approle\thost_audit\tupdate secret_id_bound_cidrs" in out
    assert "192.0.2.1" not in out
    run(fake, capsys, "apply")
    assert run(fake, capsys, "plan")[0] == 0


def test_operator_password_changed_on_server_is_not_drift_but_policy_change_is(fake, capsys):
    run(fake, capsys, "apply")
    fake.users["alice"]["password_hash"] = HASH2       # 서버에서 바꾼 비밀번호
    assert run(fake, capsys, "plan")[0] == 0
    fake.users["alice"]["token_policies"] = ["default"]
    code, out, _ = run(fake, capsys, "plan")
    assert code == 2 and "operator\talice\tupdate token_policies" in out


def test_rotate_operators_rewrites_hashes_only_when_asked(fake, capsys):
    run(fake, capsys, "apply")
    fake.users["alice"]["password_hash"] = HASH2
    run(fake, capsys, "apply")
    assert fake.users["alice"]["password_hash"] == HASH2          # 해시는 비교·덮어쓰기 대상이 아니다
    code, out, _ = run(fake, capsys, "apply", "--rotate-operators")
    assert code == 0 and "operator\talice\trotate" in out
    assert fake.users["alice"]["password_hash"] == HASH


def test_apply_never_deletes_and_never_mints_secret_ids_or_tunes_mounts(fake, capsys):
    run(fake, capsys, "apply")
    fake.policies["hand-made"] = "x"
    fake.roles["hand-made"] = {}
    fake.mounts["hand-made"] = {"type": "kv"}
    fake.mounts["inventory"]["description"] = "changed by hand"
    code, out, _ = run(fake, capsys, "apply")
    assert code == 0
    assert "policy\thand-made\t코드에 없음" in out and "approle\thand-made\t코드에 없음" in out
    assert "hand-made" in fake.policies and "hand-made" in fake.roles and "hand-made" in fake.mounts
    assert fake.mounts["inventory"]["description"] == "changed by hand"       # tune하지 않는다
    assert fake.deletes() == []
    assert not [r for r in fake.requests if "secret-id" in r.path or "auth/token" in r.path or "tune" in r.path]


def test_existing_mount_is_not_rewritten(fake, capsys):
    fake.mounts["inventory"] = {"type": "kv", "options": {"version": "2"}}
    run(fake, capsys, "apply")
    assert not [r for r in writes(fake) if r.path == "/v1/sys/mounts/inventory"]


def test_secrets_never_appear_in_output(fake, capsys):
    for argv in (("plan",), ("apply",), ("apply", "--rotate-operators")):
        _, out, err = run(fake, capsys, *argv)
        for secret in (RUNNER, AGENT, HASH, TOKEN, "198.51.100", "203.0.113"):
            assert secret not in out + err, (argv, secret)


@pytest.mark.parametrize("name, value", [
    ("OPENBAO_RUNNER_CIDRS", ""), ("OPENBAO_RUNNER_CIDRS", " , "), ("OPENBAO_AGENT_SESSION_CIDRS", ""),
    ("OPENBAO_OPERATOR_PASSWORD_HASHES", "not-json"),
    ("OPENBAO_OPERATOR_PASSWORD_HASHES", json.dumps({"alice": "plain-text-password-1"})),
    ("OPENBAO_OPERATOR_PASSWORD_HASHES", json.dumps(["alice"])),
])
def test_bad_input_is_rejected_before_any_write_without_echoing_values(fake, capsys, name, value):
    code, out, err = run(fake, capsys, "apply", **{name: value})
    assert code == 2 and writes(fake) == []
    assert "plain-text-password-1" not in out + err and "not-json" not in out + err


def test_missing_connection_or_credentials_is_input_error(fake, capsys):
    env = make_env(fake)
    for drop in ("VAULT_ADDR", "VAULT_TOKEN"):
        bad = {k: v for k, v in env.items() if k != drop}
        capsys.readouterr()
        assert oa.main(["plan"], bad) == 2


def test_server_failure_reports_status_only(fake, capsys):
    code, out, err = run(fake, capsys, "plan", VAULT_TOKEN="wrong-token-value")
    assert code == 1 and "403" in err and "wrong-token-value" not in out + err


def test_approle_login_token_is_used_as_is_without_child_token():
    with FakeOpenBao(namespace="infra", approle=True) as fake:
        env = {**fake.approle_env(), "OPENBAO_RUNNER_CIDRS": RUNNER, "OPENBAO_AGENT_SESSION_CIDRS": AGENT}
        assert oa.main(["apply"], env) == 0
        assert len(fake.logins()) == 1
        assert all(r.token == APPROLE_TOKEN for r in fake.requests if r.path != "/v1/auth/approle/login")
        assert not [r for r in fake.requests if "auth/token" in r.path]
        assert not fake.users            # 운영자 해시가 없으면 사용자는 다루지 않는다


def test_unreadable_code_dir_is_usage_error_not_empty_plan(fake, capsys, tmp_path):
    code, _, err = run(fake, capsys, "--code-dir", str(tmp_path), "plan")
    assert code == 2 and "읽을 수 없다" in err and writes(fake) == []


def test_single_host_cidr_is_the_same_whether_the_server_adds_a_prefix_or_not():
    """실서버는 token_bound_cidrs의 단일 IP를 접두사 없이 돌려준다(secret_id_bound_cidrs는 /32를 붙여 돌려준다)."""
    want = {"token_bound_cidrs": ["192.0.2.7/32", "198.51.100.0/24"], "secret_id_bound_cidrs": ["192.0.2.7/32"]}
    have = {"token_bound_cidrs": ["198.51.100.0/24", "192.0.2.7"], "secret_id_bound_cidrs": ["192.0.2.7/32"]}
    assert oa.role_drift(want, have) == []
    assert oa.role_drift(want, {**have, "token_bound_cidrs": ["192.0.2.8"]}) == ["token_bound_cidrs"]
