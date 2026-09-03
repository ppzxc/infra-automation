import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_requirements_includes_lockdown_role():
    """Verify requirements.yml defines the pilot ansible-lockdown.rhel9_cis role"""
    req_file = ROOT_DIR / "requirements.yml"
    assert req_file.exists(), "requirements.yml missing"
    with open(req_file, "r", encoding="utf-8") as f:
        req_data = yaml.safe_load(f)

    roles = req_data.get("roles", [])
    role_names = [r["name"] if isinstance(r, dict) else r for r in roles]
    assert "ansible-lockdown.rhel9_cis" in role_names, "ansible-lockdown.rhel9_cis role should be listed in requirements.yml for audit pilot"

def test_audit_rhel9_cis_playbook_structure():
    """Verify playbooks/audit_rhel9_cis.yml exists, is safe (audit_only: true), and isolates Rocky 9"""
    playbook_file = ROOT_DIR / "playbooks" / "audit_rhel9_cis.yml"
    assert playbook_file.exists(), "playbooks/audit_rhel9_cis.yml must exist"

    with open(playbook_file, "r", encoding="utf-8") as f:
        pb_data = yaml.safe_load(f)

    assert isinstance(pb_data, list), "Playbook must be a list of plays"
    assert len(pb_data) > 0, "Playbook must contain at least one play"

    play = pb_data[0]
    vars_dict = play.get("vars", {})

    # Safety constraint: MUST be audit_only
    assert vars_dict.get("rhel9_cis_audit_only") is True, "Pilot playbook MUST enforce rhel9_cis_audit_only: true to prevent system alterations"

    # Tasks check: must include ansible-lockdown.rhel9_cis with OS guard
    tasks = play.get("tasks", [])
    assert len(tasks) > 0, "Playbook must have tasks"

    role_included = False
    for task in tasks:
        include_role = task.get("ansible.builtin.include_role") or task.get("include_role")
        if include_role and include_role.get("name") == "ansible-lockdown.rhel9_cis":
            role_included = True
            when_cond = task.get("when", [])
            when_str = str(when_cond)
            assert "ansible_distribution_major_version" in when_str or "ansible_os_family" in when_str, "Must guard CIS role with OS version checks"

    assert role_included, "Playbook must include ansible-lockdown.rhel9_cis role"

def test_adr_evaluation_doc_exists():
    """Verify ADR documentation exists for hardening framework evaluation"""
    adr_file = ROOT_DIR / "docs" / "adr" / "0004-hardening-framework-evaluation.md"
    assert adr_file.exists(), "docs/adr/0004-hardening-framework-evaluation.md must exist"
    content = adr_file.read_text(encoding="utf-8")
    assert "dev-sec" in content
    assert "ansible-lockdown" in content
    assert "audit_only" in content.lower()

def test_sysctl_and_security_enhanced_params():
    """Verify safe sysctl and kernel parameters from hardening standards are incorporated in common defaults, docs, and tests"""
    common_defaults_file = ROOT_DIR / "roles" / "common" / "defaults" / "main.yml"
    with open(common_defaults_file, "r", encoding="utf-8") as f:
        common_defaults = yaml.safe_load(f)

    sysctl_settings = common_defaults.get("sysctl_settings", {})
    # Core hardened sysctl settings in defaults
    assert sysctl_settings.get("fs.protected_hardlinks") == 1
    assert sysctl_settings.get("fs.protected_symlinks") == 1
    assert sysctl_settings.get("kernel.randomize_va_space") == 2

    # 3-Way Spec Traceability verification in docs and molecule tests
    common_doc = (ROOT_DIR / "docs" / "common.md").read_text(encoding="utf-8")
    assert "fs.protected_hardlinks" in common_doc
    assert "kernel.randomize_va_space" in common_doc

    verify_file = (ROOT_DIR / "molecule" / "default" / "verify.yml").read_text(encoding="utf-8")
    assert "fs.protected_hardlinks" in verify_file
    assert "kernel.randomize_va_space" in verify_file
