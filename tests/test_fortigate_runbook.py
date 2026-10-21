"""Spec #282 / Ticket-1: the firewall log runbook exists, covers the required sections and stays free of infra details (public repo)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT / "docs" / "runbooks" / "fortigate-syslog.md"


def test_runbook_covers_filter_ha_checks_and_onboarding_and_is_indexed():
    text = RUNBOOK.read_text()
    for needle in ("fortigate-syslog", "security_logs", "정책별 로그 설정", "HA 관리 인터페이스", "점검 절차", "신규 방화벽 편입 절차",
                   "허용(accept) 트래픽 전체", "비공개", "수용 위험", "ns0380", "ns0381", "ns0399", "7.2", "7.4"):
        assert needle in text, needle
    assert "runbooks/fortigate-syslog.md" in (ROOT / "docs" / "INDEX.md").read_text()


def test_runbook_has_no_ip_address_or_device_command():
    text = RUNBOOK.read_text()
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    assert not re.search(r"^\s*(config|set|end|edit|diagnose|execute)\s", text, re.M)
