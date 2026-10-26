"""월간 로그 점검 런북 (Spec #322 / Ticket-11, #333).

런북은 문서라 동작은 없지만 인수 기준은 기계로 확인할 수 있다: 월간 점검 절차·기록 양식·관찰 목록이 있고,
실제 기록은 비공개 노트에 둔다고 밝히며, 공개 저장소라 IP·계정·포트 같은 인프라 상세가 없다.
"""
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "monthly-log-review.md"
INDEX = ROOT_DIR / "docs" / "INDEX.md"


def _text():
    return RUNBOOK.read_text(encoding="utf-8")


def _section(title):
    text = _text()
    match = re.search(rf"^## {re.escape(title)}.*?(?=^## |\Z)", text, re.S | re.M)
    assert match, f"'## {title}' 절이 없다"
    return match.group(0)


def test_the_runbook_has_the_procedure_the_record_template_and_the_watch_list():
    for title in ("월간 점검 절차", "점검 기록 양식", "관찰 목록"):
        assert _section(title).strip()


def test_the_procedure_names_the_streams_and_the_queries_to_run_and_what_to_record():
    procedure = _section("월간 점검 절차")
    for stream in ("security_logs", "system_logs", "backup_logs", "host_status_logs"):
        assert stream in procedure, stream
    assert "SELECT" in procedure                                   # 어떤 쿼리를 보는지
    assert "기록" in procedure                                      # 무엇을 기록하는지
    steps = re.findall(r"^\d+\. ", procedure, re.M)
    assert len(steps) >= 6


def test_the_record_template_is_a_fill_in_form_and_says_real_records_stay_private():
    template = _section("점검 기록 양식")
    assert "비공개 노트" in _text() and "비공개 노트" in template
    for field in ("점검 기간", "점검자", "결과", "조치"):
        assert field in template, field


def test_the_watch_list_holds_the_four_unseen_log_kinds_and_the_volume_remeasurement():
    watch = _section("관찰 목록")
    for item in ("HA 상태 변경", "SSL VPN", "웹 필터", "앱 제어", "IPv6", "로그량"):
        assert item in watch, item


def test_the_runbook_carries_no_infrastructure_details():
    text = _text()
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), "IP 주소"
    assert not re.search(r"\bns0\d{3}\b", text), "관리번호(장비 식별)"
    assert not re.search(r"(?i)\bport\s*[:=]?\s*\d{2,5}\b|포트\s*\d{2,5}|\b[A-Za-z][A-Za-z0-9.-]*:\d{2,5}\b", text), "포트 번호(host:port)"
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text), "시크릿 값"
    assert not re.search(r"\b[a-z][a-z0-9_.-]*@[a-z0-9.-]+\.[a-z]{2,}\b", text, re.I), "계정·이메일"


def test_the_runbook_is_linked_from_the_docs_index():
    assert "runbooks/monthly-log-review.md" in INDEX.read_text(encoding="utf-8")
