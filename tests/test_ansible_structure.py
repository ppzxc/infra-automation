import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_ansible_inventory_and_vars():
    """Ansible inventory and group_vars verification (Target Nodes / Loadbalancers)"""
    inv_file = ROOT_DIR / "inventory" / "hosts.yml"
    if not inv_file.exists():
        inv_file = ROOT_DIR / "inventory" / "hosts.yml.example"
    assert inv_file.exists(), f"Inventory file missing in {ROOT_DIR}"
    
    with open(inv_file, 'r', encoding='utf-8') as f:
        inv_data = yaml.safe_load(f)
    assert "all" in inv_data, "Inventory missing root 'all' key"
    children = inv_data["all"].get("children", {})
    assert "servers" in children, "Missing 'servers' group in inventory"
    
    # group_vars verification
    all_vars_file = ROOT_DIR / "inventory" / "group_vars" / "all.yml"
    assert all_vars_file.exists(), "group_vars/all.yml is missing"
    with open(all_vars_file, 'r', encoding='utf-8') as f:
        all_vars = yaml.safe_load(f)
    assert "admin_user" in all_vars, "admin_user is not defined in all.yml"
    assert "timezone" in all_vars, "timezone is not defined in all.yml"
    assert "otel_target_endpoint" in all_vars, "otel_target_endpoint is not defined in all.yml"

    # servers group_vars verification
    servers_vars_file = ROOT_DIR / "inventory" / "group_vars" / "servers.yml"
    assert servers_vars_file.exists(), "group_vars/servers.yml is missing"

def test_ansible_playbooks_structure():
    """Ansible playbooks structure verification for Target Node Provisioner"""
    playbooks_dir = ROOT_DIR / "playbooks"
    assert (playbooks_dir / "provision_servers.yml").exists(), "provision_servers.yml is missing"
    assert (playbooks_dir / "provision.yml").exists(), "provision.yml is missing"
    assert (playbooks_dir / "maintenance.yml").exists(), "maintenance.yml is missing"
    assert (playbooks_dir / "site.yml").exists(), "site.yml is missing"

def test_ansible_roles_structure():
    """Ansible roles structure verification (Deep access_security module)"""
    roles_dir = ROOT_DIR / "roles"
    expected_roles = [
        "docker_engine",
        "common",
        "security",
        "access_security",
        "monitoring"
    ]
    for role in expected_roles:
        assert (roles_dir / role).exists(), f"Role {role} is missing"
        assert (roles_dir / role / "tasks" / "main.yml").exists(), f"Role {role} main task file is missing"

def test_access_security_role_integration():
    """Verify access_security deep module tasks and defaults"""
    role_dir = ROOT_DIR / "roles" / "access_security"
    defaults_file = role_dir / "defaults" / "main.yml"
    tasks_file = role_dir / "tasks" / "main.yml"
    
    assert defaults_file.exists(), "access_security defaults/main.yml missing"
    assert tasks_file.exists(), "access_security tasks/main.yml missing"
    
    with open(defaults_file, 'r', encoding='utf-8') as f:
        defaults = yaml.safe_load(f)
    assert defaults.get("enable_access_security") is True
    assert "openbao_ssh_ca_public_key" in defaults
    assert "boundary_worker_tags" in defaults

    tasks_content = tasks_file.read_text(encoding='utf-8')
    assert "[ACC-001]" in tasks_content
    assert "[ACC-004]" in tasks_content
    assert "[ACC-009]" in tasks_content

def test_monitoring_otel_system_logs():
    """OTel system log collection paths (ISMS/ISMS-P compliance)"""
    defaults_file = ROOT_DIR / "roles" / "monitoring" / "defaults" / "main.yml"
    assert defaults_file.exists(), "monitoring defaults/main.yml is missing"
    with open(defaults_file, 'r', encoding='utf-8') as f:
        defaults = yaml.safe_load(f)

    assert "otel_system_logs" in defaults, "otel_system_logs should be defined in defaults"
    logs = defaults["otel_system_logs"]

    expected_logs = [
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/secure",
        "/var/log/auth.log",
        "/var/log/sudo.log",
        "/var/log/audit/audit.log",
        "/var/log/cron*",
        "/var/log/fail2ban.log",
        "/var/log/dnf.log",
        "/var/log/yum.log",
        "/var/log/dpkg.log",
        "/var/log/firewalld",
    ]
    for expected in expected_logs:
        assert expected in logs, f"Expected log path {expected} missing from otel_system_logs"

def test_monitoring_node_exporter_removed_and_hostmetrics_enabled():
    """Node Exporter cleanup and OTel hostmetrics receiver verification"""
    defaults_file = ROOT_DIR / "roles" / "monitoring" / "defaults" / "main.yml"
    with open(defaults_file, 'r', encoding='utf-8') as f:
        defaults = yaml.safe_load(f)

    assert "node_exporter_version" not in defaults, "node_exporter_version should be completely removed"
    assert "node_exporter_port" not in defaults, "node_exporter_port should be completely removed"
    assert "otel_hostmetrics_interval" in defaults, "otel_hostmetrics_interval should be defined"
    assert "otel_hostmetrics_scrapers" in defaults, "otel_hostmetrics_scrapers should be defined"
    assert "cleanup_legacy_node_exporter" in defaults, "cleanup_legacy_node_exporter should be present"

    # Template verification
    template_file = ROOT_DIR / "roles" / "monitoring" / "templates" / "otelcol-contrib.yaml.j2"
    assert template_file.exists(), "otelcol-contrib template file is missing"
    template_content = template_file.read_text(encoding='utf-8')
    assert "node_exporter" not in template_content, "Template should not contain node_exporter references"
    assert "hostmetrics:" in template_content, "Template must configure hostmetrics receiver"
    assert "traces:" in template_content, "Template must configure traces pipeline"

def test_security_enhanced_firewall_ingress_and_docker_rules():
    """Verify security role enhanced firewall ingress and docker IPSet rules integration"""
    defaults_file = ROOT_DIR / "roles" / "security" / "defaults" / "main.yml"
    tasks_file = ROOT_DIR / "roles" / "security" / "tasks" / "main.yml"
    all_vars_file = ROOT_DIR / "inventory" / "group_vars" / "all.yml"

    with open(defaults_file, 'r', encoding='utf-8') as f:
        defaults = yaml.safe_load(f)
    assert "firewall_ingress_rules" in defaults, "firewall_ingress_rules missing from security defaults"
    assert "docker_firewall_whitelists" in defaults, "docker_firewall_whitelists missing from security defaults"

    with open(all_vars_file, 'r', encoding='utf-8') as f:
        all_vars = yaml.safe_load(f)
    assert "firewall_ingress_rules" in all_vars, "firewall_ingress_rules missing from all.yml"
    assert "docker_firewall_whitelists" in all_vars, "docker_firewall_whitelists missing from all.yml"

    tasks_content = tasks_file.read_text(encoding='utf-8')
    assert "[SEC-019]" in tasks_content, "Task [SEC-019] missing in security tasks"
    assert "[SEC-020]" in tasks_content, "Task [SEC-020] missing in security tasks"
    assert "[SEC-021]" in tasks_content, "Task [SEC-021] missing in security tasks"
    assert "[SEC-022]" in tasks_content, "Task [SEC-022] missing in security tasks"
    assert "[SEC-023]" in tasks_content, "Task [SEC-023] missing in security tasks"

