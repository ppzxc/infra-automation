"""Spec #282 / Ticket-1: the firewall log runbook exists, covers the required sections and stays free of infra details (public repo)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT / "docs" / "runbooks" / "fortigate-syslog.md"


def test_runbook_covers_filter_ha_checks_and_onboarding_and_is_indexed():
    text = RUNBOOK.read_text()
    for needle in ("fortigate-syslog", "security_logs", "정책별 로그 설정", "HA 관리 인터페이스", "점검 절차", "신규 방화벽 편입 절차",
                   "허용(accept) 트래픽 전체", "비공개", "수용 위험", "ns0380", "ns0381", "ns0399"):
        assert needle in text, needle
    assert "runbooks/fortigate-syslog.md" in (ROOT / "docs" / "INDEX.md").read_text()


def test_runbook_has_no_ip_address_or_device_command():
    text = RUNBOOK.read_text()
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    assert not re.search(r"^\s*(config|set|end|edit|diagnose|execute)\s", text, re.M)


PUBLIC_FILES = ["docs/runbooks/fortigate-syslog.md", "docs/fortigate_backup.md", "docs/runbooks/alerts.md", "docs/openobserve_config.md",
                "roles/fortigate_backup/defaults/main.yml", "roles/fortigate_backup/tasks/main.yml", "roles/openobserve_config/defaults/main.yml",
                "roles/openobserve_config/files/vrl/fortigate_semantics.vrl", "inventory/hosts.yml.example", "filter_plugins/openobserve_config.py"]
FORBIDDEN = re.compile(r"\b(70G|60F)\b|FortiGate\s*\d|FortiOS\s*\d|\b7\.[24](\.\d+)?\b|Active-Passive"
                       r"|아직 (하지|설정하지|전혀)|설정하지 않았|syslog 설정은 아직|전송을 아직")


def test_public_docs_and_code_have_no_model_version_or_current_device_state():
    """The repository is public: device model, FortiOS version, HA details and 'not configured yet' states stay in the private checklist."""
    for rel in PUBLIC_FILES:
        for n, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
            assert not FORBIDDEN.search(line), (rel, n, line[:80])


def test_firewall_tests_use_only_reserved_documentation_addresses():
    """Synthetic addresses in firewall tests must come from RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24), loopback or private ranges."""
    ok = re.compile(r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")
    for rel in ("tests/test_openobserve_vrl.py", "tests/test_fortigate_backup.py", "tests/test_fortigate_runbook.py", "tests/test_openobserve_config.py",
                "tests/fixtures/fortigate_real_lines.tsv"):
        for ip in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", (ROOT / rel).read_text()):
            assert ok.match(ip), (rel, ip)
