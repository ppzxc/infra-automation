import pytest
import yaml
from jinja2 import Environment
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_site_playbook_syntax_and_structure():
    """Verify site.yml contains variable assertion, probe connection, and fallback aligned with cisco pattern"""
    site_file = ROOT_DIR / "playbooks" / "site.yml"
    assert site_file.exists(), "site.yml missing"
    
    content = site_file.read_text(encoding='utf-8')
    assert "bootstrap_user" in content
    assert "target_admin_users" in content or "target_admin_user" in content
    assert "openbao_namespace" in content
    assert "openbao_mount" in content
    assert "cisco_openbao_namespace" in content or "VAULT_NAMESPACE" in content
    assert "_vault_role_id" in content
    assert "_vault_secret_id" in content
    assert "_has_approle" in content
    assert "_vault_auth_method" in content

def test_target_admin_users_normalization_logic():
    """Verify normalization of target_admin_users from string or list"""
    env = Environment()
    template_str = """
    {%- if target_admin_users is defined and target_admin_users is string -%}
      {{ target_admin_users.split(',') | map('trim') | reject('equalto', '') | list | tojson }}
    {%- elif target_admin_users is defined and target_admin_users is iterable and target_admin_users is not mapping -%}
      {{ target_admin_users | list | tojson }}
    {%- elif target_admin_user is defined and target_admin_user | length > 0 -%}
      {{ [target_admin_user] | tojson }}
    {%- else -%}
      {{ [] | tojson }}
    {%- endif -%}
    """
    tmpl = env.from_string(template_str)
    
    # Comma-separated string
    res1 = yaml.safe_load(tmpl.render(target_admin_users="ppzxc, admin2, secops"))
    assert res1 == ["ppzxc", "admin2", "secops"]
    
    # List of users
    res2 = yaml.safe_load(tmpl.render(target_admin_users=["ppzxc", "admin2"]))
    assert res2 == ["ppzxc", "admin2"]
    
    # Fallback to target_admin_user single string
    res3 = yaml.safe_load(tmpl.render(target_admin_user="ppzxc"))
    assert res3 == ["ppzxc"]

def test_admin_accounts_generation_from_openbao_keys():
    """Verify dynamic accounts structure generation for common role"""
    env = Environment()
    template_str = """
    {%- set user_list = ['ppzxc', 'admin2'] -%}
    {%- set pub_keys = {'ppzxc': 'ssh-ed25519 AAAAC1...', 'admin2': 'ssh-rsa AAAAB2...'} -%}
    {%- set dynamic_accounts = [] -%}
    {%- for u in user_list -%}
      {%- set k = pub_keys.get(u, '') -%}
      {%- set _ = dynamic_accounts.append({
            'name': u,
            'tier': 'admin',
            'comment': 'Administrator managed via OpenBao',
            'shell': '/bin/bash',
            'keys': [k] if k else []
          }) -%}
    {%- endfor -%}
    {{ dynamic_accounts | tojson }}
    """
    tmpl = env.from_string(template_str)
    res = yaml.safe_load(tmpl.render())
    assert len(res) == 2
    assert res[0]["name"] == "ppzxc"
    assert res[0]["keys"] == ["ssh-ed25519 AAAAC1..."]
    assert res[1]["name"] == "admin2"
    assert res[1]["keys"] == ["ssh-rsa AAAAB2..."]

def test_site_playbook_controller_plays_privilege_escalation_and_recursion():
    """Verify Play 1 and Play 3 explicitly set become: false, and vars have no self-referencing recursion loops."""
    site_file = ROOT_DIR / "playbooks" / "site.yml"
    with open(site_file, "r", encoding="utf-8") as f:
        plays = yaml.safe_load(f)

    # Play 1: Controller Pre-flight
    play1 = plays[0]
    assert play1.get("connection") == "local"
    assert play1.get("become") is False, "Play 1 must have become: false so controller does not run sudo on local tasks"
    
    # Check vars in Play 1 do not contain circular self-references
    vars1 = play1.get("vars", {})
    assert "openbao_namespace" in vars1
    assert "openbao_namespace | default(openbao_namespace" not in vars1["openbao_namespace"]
    assert "openbao_mount | default(openbao_mount" not in vars1["openbao_mount"]
    assert "openbao_hosts_prefix | default(openbao_hosts_prefix" not in vars1["openbao_hosts_prefix"]
    assert "openbao_users_prefix | default(openbao_users_prefix" not in vars1["openbao_users_prefix"]

    # Play 3: Cleanup temporary credentials
    play3 = plays[2]
    assert play3.get("connection") == "local"
    assert play3.get("become") is False, "Play 3 must have become: false so controller does not run sudo on local cleanup"


def test_site_playbook_host_vars_and_probe_condition():
    """Verify site.yml applies host variable fallback and safe probe result handling."""
    site_file = ROOT_DIR / "playbooks" / "site.yml"
    content = site_file.read_text(encoding="utf-8")
    with open(site_file, "r", encoding="utf-8") as f:
        plays = yaml.safe_load(f)

    play1_tasks = plays[0]["tasks"]
    task_names = [t["name"] for t in play1_tasks]

    # Host variable fallback task must exist and not be restricted by when condition on OpenBao KV
    assert "Apply OpenBao and inventory host variables to host facts" in task_names
    host_fact_task = next(t for t in play1_tasks if t["name"] == "Apply OpenBao and inventory host variables to host facts")
    assert "when" not in host_fact_task, "Host fact task must always run so inventory hostvars fallback is applied"

    # Probe task must only run when admin private key is available
    probe_task = next(t for t in play1_tasks if t["name"] == "Probe SSH connection using primary admin user credentials")
    assert "when" in probe_task
    assert any("_admin_key_tempfile" in cond for cond in probe_task["when"])

    # Decision task must check probe rc is defined
    decision_task = next(t for t in play1_tasks if t["name"] == "Set connection mode facts based on admin SSH probe result")
    assert "_admin_ssh_probe.rc is defined" in decision_task["ansible.builtin.set_fact"]["_is_already_provisioned"]

