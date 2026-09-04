import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_requirements_includes_cisco_ios():
    """Verify requirements.yml defines cisco.ios collection"""
    req_file = ROOT_DIR / "requirements.yml"
    assert req_file.exists(), "requirements.yml is missing"
    with open(req_file, "r", encoding="utf-8") as f:
        req_data = yaml.safe_load(f)
    collections = [col.get("name") for col in req_data.get("collections", []) if isinstance(col, dict)]
    assert "cisco.ios" in collections, "cisco.ios collection missing in requirements.yml"

def test_cisco_backup_role_structure():
    """Verify roles/cisco_backup structure and required files"""
    role_dir = ROOT_DIR / "roles" / "cisco_backup"
    assert role_dir.exists(), "roles/cisco_backup directory missing"
    assert (role_dir / "tasks" / "main.yml").exists(), "roles/cisco_backup/tasks/main.yml missing"
    assert (role_dir / "defaults" / "main.yml").exists(), "roles/cisco_backup/defaults/main.yml missing"

def test_cisco_backup_playbook_structure():
    """Verify playbooks/backup_cisco.yml exists and defines correct hosts and role"""
    playbook_file = ROOT_DIR / "playbooks" / "backup_cisco.yml"
    assert playbook_file.exists(), "playbooks/backup_cisco.yml is missing"
    with open(playbook_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, list) and len(data) > 0
    play = data[0]
    assert play.get("hosts") == "cisco_switches"
    assert play.get("gather_facts") is False
    roles = [r if isinstance(r, str) else r.get("role") for r in play.get("roles", [])]
    assert "cisco_backup" in roles

def test_inventory_cisco_switches_example():
    """Verify cisco_switches group is documented in inventory hosts and group_vars"""
    inv_example = ROOT_DIR / "inventory" / "hosts.yml.example"
    with open(inv_example, "r", encoding="utf-8") as f:
        inv_data = yaml.safe_load(f)
    children = inv_data["all"].get("children", {})
    assert "cisco_switches" in children, "cisco_switches group missing from hosts.yml.example"

    cisco_vars_file = ROOT_DIR / "inventory" / "group_vars" / "cisco_switches.yml"
    assert cisco_vars_file.exists(), "group_vars/cisco_switches.yml is missing"
    with open(cisco_vars_file, "r", encoding="utf-8") as f:
        cisco_vars = yaml.safe_load(f)
    assert cisco_vars.get("ansible_network_os") in ["cisco.ios", "cisco.ios.ios"]
    assert cisco_vars.get("ansible_connection") == "network_cli"

def test_cisco_backup_spec_ids_in_tasks_and_docs():
    """Verify CISCO spec IDs exist in tasks and docs"""
    tasks_file = ROOT_DIR / "roles" / "cisco_backup" / "tasks" / "main.yml"
    doc_file = ROOT_DIR / "docs" / "cisco_backup.md"
    assert tasks_file.exists()
    assert doc_file.exists()

    tasks_content = tasks_file.read_text(encoding="utf-8")
    doc_content = doc_file.read_text(encoding="utf-8")

    expected_specs = ["CISCO-001", "CISCO-002", "CISCO-003", "CISCO-004", "CISCO-005", "CISCO-006", "CISCO-007"]
    for spec in expected_specs:
        assert f"[{spec}]" in tasks_content, f"Spec [{spec}] missing in tasks"
        assert f"`{spec}`" in doc_content, f"Spec `{spec}` missing in docs"
