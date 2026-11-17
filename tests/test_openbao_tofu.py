"""OpenBao OpenTofu 골격의 정적 검사(Spec #511 / Ticket-6, #517).

tofu 바이너리 없이 코드 파일만 읽는다. fmt/validate는 CI(`tofu` 잡)가 돌린다.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOFU = ROOT / "tofu" / "openbao"
DOC = ROOT / "docs" / "openbao_opentofu.md"
RISK = ROOT / "docs" / "runbooks" / "openbao-opentofu-risk-check.md"
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"

TF_FILES = sorted(TOFU.glob("*.tf"))


def _tf(name):
    return (TOFU / name).read_text(encoding="utf-8")


def _all_tf():
    return "\n".join(p.read_text(encoding="utf-8") for p in TF_FILES)


def _strip_comments(text):
    return re.sub(r"(?m)^\s*#.*$", "", text)


def test_vault_provider_version_is_pinned_exactly():
    # `= x.y.z` 정확 고정. `~>`나 범위는 허용하지 않는다.
    m = re.search(r'source\s*=\s*"hashicorp/vault"\s*version\s*=\s*"([^"]+)"', _tf("versions.tf"))
    assert m, "hashicorp/vault provider 버전이 없다"
    assert re.fullmatch(r"=\s*\d+\.\d+\.\d+", m.group(1)), m.group(1)


def test_lock_file_is_committed():
    assert (TOFU / ".terraform.lock.hcl").is_file()
    assert 'provider "registry.opentofu.org/hashicorp/vault"' in (TOFU / ".terraform.lock.hcl").read_text()


def test_state_backend_is_s3_with_no_endpoint_or_credentials_in_code():
    code = _strip_comments(_tf("versions.tf"))
    assert 'backend "s3"' in code
    for forbidden in ("endpoint", "access_key", "secret_key", "token"):
        assert forbidden not in code, forbidden


def test_state_and_plan_encrypted_with_pbkdf2_enforced():
    code = _strip_comments(_tf("versions.tf"))
    assert "key_provider.pbkdf2.main" in code
    assert re.search(r"state\s*\{[^}]*enforced\s*=\s*true", code, re.S)
    assert re.search(r"plan\s*\{[^}]*enforced\s*=\s*true", code, re.S)


def test_no_openbao_key_provider_and_no_passphrase_in_code():
    code = _strip_comments(_all_tf())
    assert 'key_provider "openbao"' not in code
    assert "passphrase" not in code, "passphrase는 TF_ENCRYPTION 환경변수로만 받는다"


def test_kv_v2_mounts_and_auth_mounts_declared():
    mounts = _tf("mounts.tf")
    for path in ("inventory", "secrets"):
        block = re.search(rf'resource "vault_mount" "{path}" \{{(.*?)\n\}}', mounts, re.S)
        assert block, path
        assert f'path        = "{path}"' in block.group(1)
        assert 'type        = "kv"' in block.group(1)
        assert 'version = "2"' in block.group(1)
    auth = _tf("auth.tf")
    assert 'type        = "userpass"' in auth
    assert 'type        = "approle"' in auth


def test_operator_users_use_hash_only_and_are_sensitive():
    auth = _tf("auth.tf")
    assert "operator_password_hashes" in auth
    assert "password_hash" in auth
    assert not re.search(r'"password"\s*=', auth)
    var = re.search(r'variable "operator_password_hashes" \{(.*?)\n\}', _tf("variables.tf"), re.S).group(1)
    assert "sensitive   = true" in var


def test_provider_scoped_to_namespace_without_child_token():
    code = _tf("provider.tf")
    assert "namespace = var.namespace" in code
    assert "skip_child_token = true" in code  # applier에 auth/token/create 권한이 없다(런북 확인 결과)
    assert re.search(r'variable "namespace" \{.*?default\s*=\s*"infra"', _tf("variables.tf"), re.S)


def _policy_paths(text):
    return re.findall(r'path\s+"([^"]+)"', _strip_comments(text))


def test_applier_policy_covers_only_control_plane_paths_never_kv_data():
    paths = _policy_paths((TOFU / "policies" / "applier.hcl").read_text(encoding="utf-8"))
    assert paths
    allowed = ("sys/policies/acl", "auth/approle/role", "sys/mounts", "sys/auth", "auth/userpass/users")
    for p in paths:
        assert p.startswith(allowed), p
    for core in ("sys/policies/acl/*", "auth/approle/role/*", "sys/mounts/*", "sys/auth/*"):
        assert core in paths
    assert not any(p.startswith(("inventory", "secrets", "auth/token", "sys/*", "*")) for p in paths)


def test_applier_cannot_mint_secret_ids_for_other_roles():
    text = _strip_comments((TOFU / "policies" / "applier.hcl").read_text(encoding="utf-8"))
    for p in ("auth/approle/role/+/secret-id", "auth/approle/role/+/secret-id-accessor/*"):
        assert re.search(rf'path "{re.escape(p)}" \{{\s*capabilities = \["deny"\]', text), p


def test_applier_policy_has_no_wildcard_root_or_kv_capabilities():
    text = _strip_comments((TOFU / "policies" / "applier.hcl").read_text(encoding="utf-8"))
    assert 'path "+' not in text and 'path "*' not in text


def test_applier_approle_short_lived_and_bound_to_runner_cidrs():
    code = _tf("applier.tf")
    ttl = int(re.search(r"secret_id_ttl\s*=\s*(\d+)", code).group(1))
    assert 0 < ttl <= 86400
    assert re.search(r"secret_id_num_uses\s*=\s*1\b", code)
    assert "secret_id_bound_cidrs = var.runner_cidrs" in code
    assert "token_bound_cidrs     = var.runner_cidrs" in code
    assert "vault_approle_auth_backend_role_secret_id" not in _all_tf(), "secret_id는 state에 남기지 않는다"


@pytest.mark.parametrize("path", [*TF_FILES, TOFU / "policies" / "applier.hcl"], ids=lambda p: p.name)
def test_no_ip_or_cidr_literals_in_repo_code(path):
    for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", path.read_text(encoding="utf-8")):
        pytest.fail(f"{path.name}: IP/CIDR 리터럴 {token} (TF_VAR_*로 받는다)")


def test_runner_cidrs_has_no_default():
    var = re.search(r'variable "runner_cidrs" \{(.*?)\n\}', _tf("variables.tf"), re.S).group(1)
    assert "default" not in var


def test_ci_runs_tofu_fmt_and_validate():
    wf = WORKFLOW.read_text(encoding="utf-8")
    assert "opentofu/setup-opentofu" in wf
    assert "tofu fmt -check -recursive" in wf
    assert "tofu init -backend=false" in wf
    assert "tofu validate" in wf


def test_config_doc_documents_template_and_secrets_handling():
    doc = DOC.read_text(encoding="utf-8")
    assert "Auto Approve" in doc and "끔" in doc
    for needle in ("TF_ENCRYPTION", "pbkdf2", "TF_VAR_runner_cidrs", "TF_VAR_operator_password_hashes", "tofu/openbao"):
        assert needle in doc, needle


def test_risk_check_runbook_records_three_open_risks_honestly():
    text = RISK.read_text(encoding="utf-8")
    for needle in ("자식 토큰", "버전 문자열", "네임스페이스"):
        assert needle in text, needle
    assert "확인 결과" in text
    assert "openbao-operations" in text  # T1 머지 후 합칠 것
