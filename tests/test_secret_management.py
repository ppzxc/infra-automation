import pytest
import yaml
from jinja2 import Environment
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_requirements_includes_hashi_vault():
    """Verify requirements.yml includes community.hashi_vault collection"""
    req_file = ROOT_DIR / "requirements.yml"
    assert req_file.exists(), f"requirements.yml missing in {ROOT_DIR}"
    
    with open(req_file, 'r', encoding='utf-8') as f:
        req_data = yaml.safe_load(f)
    
    collections = req_data.get("collections", [])
    col_names = [c["name"] if isinstance(c, dict) else c for c in collections]
    assert "community.hashi_vault" in col_names, "community.hashi_vault must be listed in requirements.yml"

def test_all_group_vars_hybrid_secret_structure():
    """Verify group_vars/all.yml and all.yml.example have hybrid secret resolution patterns"""
    for fname in ["all.yml", "all.yml.example"]:
        fpath = ROOT_DIR / "inventory" / "group_vars" / fname
        if not fpath.exists():
            continue
        content = fpath.read_text(encoding='utf-8')
        assert "community.hashi_vault.hashi_vault" in content or "openbao" in content.lower()
        assert "ansible_user" in content
        assert "ansible_password" in content
        assert "ansible_become_password" in content
        # Check standard VAULT_ADDR and no OPENBAO_ADDR scope creep
        assert "VAULT_ADDR" in content
        assert "OPENBAO_ADDR" not in content, f"OPENBAO_ADDR should not be present in {fname}"
        # Check correct secret paths (no duplicated prefix)
        assert "secret=nodes/" in content
        assert "secret=global/services" in content
        assert "engine_mount_point=secret" in content
        # Ensure shadow feature flags are not defined in all.yml
        assert "enable_openbao_ssh_ca:" not in content
        assert "enable_boundary:" not in content

def test_hybrid_secret_resolution_logic():
    """Verify Jinja2 template fallback mechanism for credentials"""
    env = Environment()

    template_str = """
    {%- set _vault_secret = vault_mock | default({}, true) -%}
    {%- set user = local_user | default(_vault_secret.get('ansible_user'), true) | default('ppzxc', true) -%}
    {%- set password = local_password | default(_vault_secret.get('ansible_password'), true) | default('default_pass', true) -%}
    {{ {'user': user, 'password': password} | tojson }}
    """
    tmpl = env.from_string(template_str)

    # Case 1: Local variable defined (Local priority)
    res_local = yaml.safe_load(tmpl.render(local_user="admin_local", local_password="pass_local", vault_mock={"ansible_user": "vault_user", "ansible_password": "vault_pass"}))
    assert res_local["user"] == "admin_local"
    assert res_local["password"] == "pass_local"

    # Case 2: Local not defined, Vault secret present
    res_vault = yaml.safe_load(tmpl.render(local_user="", local_password="", vault_mock={"ansible_user": "vault_user", "ansible_password": "vault_pass"}))
    assert res_vault["user"] == "vault_user"
    assert res_vault["password"] == "vault_pass"

    # Case 3: Neither defined (Default fallback)
    res_default = yaml.safe_load(tmpl.render(local_user="", local_password="", vault_mock={}))
    assert res_default["user"] == "ppzxc"
    assert res_default["password"] == "default_pass"
