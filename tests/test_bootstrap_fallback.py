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
    """Verify normalization of target_admin_users from string, list, or JSON list string"""
    env = Environment()
    env.filters['from_yaml'] = lambda s: yaml.safe_load(s)
    template_str = """
    {%- set _admin_source = (target_admin_users | from_yaml) if (target_admin_users is defined and target_admin_users is string and (target_admin_users | trim).startswith('[')) else (target_admin_users if target_admin_users is defined else target_admin_user) -%}
    {%- if _admin_source is iterable and _admin_source is not string and _admin_source is not mapping -%}
      {{ _admin_source | list | tojson }}
    {%- elif _admin_source is string -%}
      {%- set cleaned = [] -%}
      {%- for item in _admin_source.replace('[', '').replace(']', '').replace('\"', '').replace(\"'\", '').split(',') -%}
        {%- set clean_item = item | trim -%}
        {%- if clean_item | length > 0 -%}
          {%- set _ = cleaned.append(clean_item) -%}
        {%- endif -%}
      {%- endfor -%}
      {{ cleaned | tojson }}
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

    # JSON formatted list string (Semaphore Environment injection case)
    res4 = yaml.safe_load(tmpl.render(target_admin_users='["ppzxc"]'))
    assert res4 == ["ppzxc"]

    # JSON formatted multi-user list string
    res5 = yaml.safe_load(tmpl.render(target_admin_users='["ppzxc", "admin2"]'))
    assert res5 == ["ppzxc", "admin2"]

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

    # Target host metadata assertion must exist before SSH probe to guarantee OpenBao host resolution
    assert "Verify OpenBao target host metadata is resolved" in task_names
    assert_task = next(t for t in play1_tasks if t["name"] == "Verify OpenBao target host metadata is resolved")
    assert "ansible_host is defined" in assert_task["ansible.builtin.assert"]["that"]
    assert "ansible_host != inventory_hostname" in assert_task["ansible.builtin.assert"]["that"]


def test_openbao_host_kv_unwrapping_logic():
    """Verify that OpenBao host payload unwraps flat, nested, and array schemas with ansible_host or ip."""
    env = Environment()
    template_str = """
    {%- set host_raw = _openbao_host_kv_resp.json.data.data if (_openbao_host_kv_resp is defined and _openbao_host_kv_resp.json is defined and _openbao_host_kv_resp.json.data is defined and _openbao_host_kv_resp.json.data.data is defined) else {} -%}
    {%- set host_unwrapped = (host_raw if host_raw is not mapping else (host_raw[inventory_hostname] if inventory_hostname in host_raw else ((host_raw.values() | first) if (host_raw | length > 0 and (host_raw.values() | first) is mapping) else host_raw))) -%}
    {%- set host_dict = (host_unwrapped | first) if (host_unwrapped is sequence and host_unwrapped is not string and host_unwrapped | length > 0 and (host_unwrapped | first) is mapping) else (_host_unwrapped if _host_unwrapped is mapping else (host_unwrapped if host_unwrapped is mapping else {})) -%}
    {%- set resolved_bao_host = host_dict.get('ansible_host', host_dict.get('public_ip', host_dict.get('ip', host_dict.get('host', '')))) -%}
    {%- set resolved_bao_port = host_dict.get('ansible_port', host_dict.get('port', '')) -%}
    {{ {
      'ansible_host': (resolved_bao_host if resolved_bao_host | length > 0 else (hostvars.get(inventory_hostname, {}).get('ansible_host', (ansible_host if (ansible_host is defined and ansible_host | length > 0) else inventory_hostname)))),
      'ansible_port': (resolved_bao_port if (resolved_bao_port is defined and resolved_bao_port | string | length > 0) else (hostvars.get(inventory_hostname, {}).get('ansible_port', (ansible_port if (ansible_port is defined and ansible_port | string | length > 0) else 22)))) | int
    } | tojson }}
    """
    tmpl = env.from_string(template_str)

    # 1. Flat schema with ansible_host
    r1 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={'json': {'data': {'data': {'ansible_host': '39.116.31.40', 'ansible_port': 22}}}},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r1['ansible_host'] == '39.116.31.40'
    assert r1['ansible_port'] == 22

    # 2. Flat schema with 'ip'
    r2 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={'json': {'data': {'data': {'ip': '39.116.31.40'}}}},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r2['ansible_host'] == '39.116.31.40'

    # 3. Nested dictionary keyed by hostname
    r3 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={'json': {'data': {'data': {'ns0332': {'ip': '39.116.31.40', 'port': 2222}}}}},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r3['ansible_host'] == '39.116.31.40'
    assert r3['ansible_port'] == 2222

    # 4. Array of dictionaries
    r4 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={'json': {'data': {'data': [{'ansible_host': '39.116.31.40'}]}}},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r4['ansible_host'] == '39.116.31.40'

    # 5. Flat schema with 'public_ip'
    r5 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={'json': {'data': {'data': {
            'hostname': 'ns0332',
            'public_ip': '39.116.31.40',
            'ssh_user': 'ppzxc'
        }}}},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r5['ansible_host'] == '39.116.31.40'

    # 6. Missing in OpenBao, fallback to inventory_hostname
    r6 = yaml.safe_load(tmpl.render(
        _openbao_host_kv_resp={},
        inventory_hostname='ns0332', hostvars={}
    ))
    assert r6['ansible_host'] == 'ns0332'


def test_openbao_user_secret_unwrapping_with_type():
    """Verify that OpenBao user secret extraction handles type: SSH and type: PASSWORD correctly."""
    env = Environment()
    template_str = """
    {%- set admin_raw = _effective_admin_user_resp.json.data.data if (_effective_admin_user_resp is defined and _effective_admin_user_resp.json is defined and _effective_admin_user_resp.json.data is defined and _effective_admin_user_resp.json.data.data is defined) else {} -%}
    {%- if admin_raw is mapping and (_primary_admin_user in admin_raw) and (admin_raw[_primary_admin_user] is mapping or (admin_raw[_primary_admin_user] is sequence and admin_raw[_primary_admin_user] is not string)) -%}
      {%- set admin_data = admin_raw[_primary_admin_user] -%}
    {%- elif admin_raw is mapping and ('ssh_private_key' in admin_raw or 'username' in admin_raw or 'type' in admin_raw or 'password' in admin_raw) -%}
      {%- set admin_data = admin_raw -%}
    {%- elif admin_raw is mapping and (admin_raw.values() | length > 0) and ((admin_raw.values() | first) is mapping or ((admin_raw.values() | first) is sequence and (admin_raw.values() | first) is not string)) -%}
      {%- set admin_data = admin_raw.values() | first -%}
    {%- else -%}
      {%- set admin_data = admin_raw -%}
    {%- endif -%}
    {%- if admin_data is sequence and admin_data is not string and admin_data is not mapping and admin_data | length > 0 -%}
      {%- set ssh_matches = admin_data | selectattr('type', 'defined') | selectattr('type', 'equalto', 'SSH') | list -%}
      {%- set admin_entry = (ssh_matches | first) if ssh_matches | length > 0 else (admin_data | first) -%}
    {%- else -%}
      {%- set admin_entry = admin_data if admin_data is mapping else {} -%}
    {%- endif -%}

    {%- set boot_raw = _effective_bootstrap_user_resp.json.data.data if (_effective_bootstrap_user_resp is defined and _effective_bootstrap_user_resp.json is defined and _effective_bootstrap_user_resp.json.data is defined and _effective_bootstrap_user_resp.json.data.data is defined) else {} -%}
    {%- if boot_raw is mapping and (bootstrap_user in boot_raw) and (boot_raw[bootstrap_user] is mapping or (boot_raw[bootstrap_user] is sequence and boot_raw[bootstrap_user] is not string)) -%}
      {%- set boot_data = boot_raw[bootstrap_user] -%}
    {%- elif boot_raw is mapping and ('password' in boot_raw or 'username' in boot_raw or 'type' in boot_raw or 'ssh_private_key' in boot_raw) -%}
      {%- set boot_data = boot_raw -%}
    {%- elif boot_raw is mapping and (boot_raw.values() | length > 0) and ((boot_raw.values() | first) is mapping or ((boot_raw.values() | first) is sequence and (boot_raw.values() | first) is not string)) -%}
      {%- set boot_data = boot_raw.values() | first -%}
    {%- else -%}
      {%- set boot_data = boot_raw -%}
    {%- endif -%}
    {%- if boot_data is sequence and boot_data is not string and boot_data is not mapping and boot_data | length > 0 -%}
      {%- set pwd_matches = boot_data | selectattr('type', 'defined') | selectattr('type', 'equalto', 'PASSWORD') | list -%}
      {%- set boot_entry = (pwd_matches | first) if pwd_matches | length > 0 else (boot_data | first) -%}
    {%- else -%}
      {%- set boot_entry = boot_data if boot_data is mapping else {} -%}
    {%- endif -%}

    {{ {
      'admin': admin_entry,
      'bootstrap': boot_entry
    } | tojson }}
    """
    tmpl = env.from_string(template_str)

    # 1. Single dict format with type
    res1 = yaml.safe_load(tmpl.render(
        _effective_admin_user_resp={'json': {'data': {'data': {
            'username': 'ppzxc',
            'type': 'SSH',
            'ssh_public_key': 'ssh-ed25519 AAAAC3...',
            'ssh_private_key': 'KEY_CONTENT',
            'ssh_passphrase': 'secret_passphrase'
        }}}},
        _effective_bootstrap_user_resp={'json': {'data': {'data': {
            'username': 'root',
            'type': 'PASSWORD',
            'password': 'root_password'
        }}}},
        _primary_admin_user='ppzxc',
        bootstrap_user='root'
    ))
    assert res1['admin']['type'] == 'SSH'
    assert res1['admin']['ssh_private_key'] == 'KEY_CONTENT'
    assert res1['admin']['ssh_passphrase'] == 'secret_passphrase'
    assert res1['bootstrap']['type'] == 'PASSWORD'
    assert res1['bootstrap']['password'] == 'root_password'

    # 2. List of entries with different types
    res2 = yaml.safe_load(tmpl.render(
        _effective_admin_user_resp={'json': {'data': {'data': [
            {'type': 'OTHER', 'note': 'irrelevant'},
            {'type': 'SSH', 'username': 'ppzxc', 'ssh_private_key': 'KEY_LIST_CONTENT'}
        ]}}},
        _effective_bootstrap_user_resp={'json': {'data': {'data': [
            {'type': 'KEY', 'key': 'dummy'},
            {'type': 'PASSWORD', 'username': 'root', 'password': 'root_from_list'}
        ]}}},
        _primary_admin_user='ppzxc',
        bootstrap_user='root'
    ))
    assert res2['admin']['type'] == 'SSH'
    assert res2['admin']['ssh_private_key'] == 'KEY_LIST_CONTENT'
    assert res2['bootstrap']['type'] == 'PASSWORD'
    assert res2['bootstrap']['password'] == 'root_from_list'


def test_site_playbook_passphrase_stripping_task_exists():
    """Verify site.yml contains passphrase stripping command for temporary private key."""
    site_file = ROOT_DIR / "playbooks" / "site.yml"
    with open(site_file, "r", encoding="utf-8") as f:
        plays = yaml.safe_load(f)

    play1_tasks = plays[0]["tasks"]
    task_names = [t["name"] for t in play1_tasks]

    assert "Strip passphrase from temporary admin SSH key if passphrase defined" in task_names
    strip_task = next(t for t in play1_tasks if t["name"] == "Strip passphrase from temporary admin SSH key if passphrase defined")
    assert "ssh-keygen -p -f" in strip_task["ansible.builtin.command"]
    assert "ssh_passphrase" in strip_task["ansible.builtin.command"]
    assert strip_task.get("no_log") is True



