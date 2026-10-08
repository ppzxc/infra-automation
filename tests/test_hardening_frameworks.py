import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_cis_audit_pilot_removed():
    """The CIS audit pilot (ADR-0004) is superseded by Host Audit (ADR-0009) and must not return"""
    assert not (ROOT_DIR / "playbooks" / "audit_rhel9_cis.yml").exists()
    req_data = yaml.safe_load((ROOT_DIR / "requirements.yml").read_text(encoding="utf-8"))
    roles = req_data.get("roles") or []
    role_names = [r["name"] if isinstance(r, dict) else r for r in roles]
    assert "ansible-lockdown.rhel9_cis" not in role_names


def test_adr_evaluation_doc_exists():
    """Verify ADR documentation exists for hardening framework evaluation"""
    adr_file = ROOT_DIR / "docs" / "adr" / "0004-hardening-framework-evaluation.md"
    assert adr_file.exists(), "docs/adr/0004-hardening-framework-evaluation.md must exist"
    content = adr_file.read_text(encoding="utf-8")
    assert "dev-sec" in content
    assert "ansible-lockdown" in content
    assert "audit_only" in content.lower()
    assert "ADR-0009" in content, "ADR-0004 must point to ADR-0009, which supersedes its CIS audit pilot"

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

    verify_file = "\n".join(
        f.read_text(encoding="utf-8") for f in sorted((ROOT_DIR / "molecule").glob("*/verify.yml"))
    )
    assert "fs.protected_hardlinks" in verify_file
    assert "kernel.randomize_va_space" in verify_file
