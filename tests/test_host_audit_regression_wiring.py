"""Host Audit Security Regression: 문서·런북·태스크 배선·템플릿 (Spec #364 / Ticket-10, #377).

정의만 읽는 검사(ADR-0013): 3-Way 문서 표, 런북 필수 절과 인프라 상세 부재, 읽기 전용 태스크 선언, 프로브의 변경 명령 부재,
보고서 템플릿 렌더. 판정 로직은 test_host_audit_regression.py, 프로브 동작은 test_host_audit_regression_probe.py.
"""
import re
import sys
from pathlib import Path

import jinja2
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_regression import ITEMS  # noqa: E402

ROLE = ROOT_DIR / "roles" / "host_audit"
DOC = (ROOT_DIR / "docs" / "host_audit.md").read_text(encoding="utf-8")
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "host-audit-regression.md"
PROBE = ROLE / "files" / "regression_probe.sh"


def test_every_item_is_in_the_doc_table_and_every_runbook_expectation_has_an_item():
    for code in ITEMS:
        assert "| `%s` |" % code in DOC, code
    mgmt = (ROOT_DIR / "docs" / "runbooks" / "mgmt-web-loopback-bind.md").read_text(encoding="utf-8")
    ids = re.findall(r"\| (EXP-[A-Z]+-\d) \|", mgmt)
    assert ids == ["EXP-MGMT-1", "EXP-MGMT-2", "EXP-MGMT-3"]
    assert set(ids) <= set(ITEMS)
    assert {m["area"] for m in ITEMS.values()} == {"관리 웹 접점", "수신 접점", "원격 접속", "탐지·로그 보존", "백업 정책", "시크릿 파일"}


def test_docs_name_the_task_ids_and_the_runbook_is_indexed():
    for task in ("AUD-700", "AUD-701", "AUD-710"):
        assert task in DOC
    assert "runbooks/host-audit-regression.md" in (ROOT_DIR / "docs" / "INDEX.md").read_text(encoding="utf-8")


def test_the_runbook_has_snapshot_diff_rollback_and_approval_and_no_infra_details():
    text = RUNBOOK.read_text(encoding="utf-8")
    for needle in ("롤백", "기준선 스냅샷", "diff", "운영자 승인", "통과 여부만", "host_audit_regression_enabled=false"):
        assert needle in text, needle
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert not re.search(r"\bns0\d{3}\b", text)
    assert not re.search(r"\b[A-Za-z][A-Za-z0-9.-]*:\d{2,5}\b", text)
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text)


def test_the_probe_task_is_read_only_and_only_runs_when_declared():
    probe, record = yaml.safe_load((ROLE / "tasks" / "regression.yml").read_text(encoding="utf-8"))
    assert "read-only" in probe["name"] and probe["check_mode"] is False and probe["changed_when"] is False
    assert probe["ignore_unreachable"] is True and probe["become"] is True
    assert any("host_audit_regression_expect | length > 0" in c for c in probe["when"])
    assert any("host_audit_regression_expect | length > 0" in c for c in record["when"])
    main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert main.index("regression.yml") < main.index("[AUD-012]")  # 호스트 JSON에 저장되기 전에 기록에 들어간다


def test_the_probe_script_uses_no_mutating_command():
    text = "\n".join(line for line in PROBE.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#"))
    forbidden = (r"\b(rm|mv|cp|chmod|chown|touch|mkdir|tee)\s|systemctl\s+(start|stop|restart|reload|enable|disable)"
                 r"|docker\s+(rm|stop|exec|run|kill|restart)|fail2ban-client\s+(set|start|stop|reload)|auditctl\s+-[DRea]|>>")
    assert not re.search(forbidden, text), re.search(forbidden, text).group(0)


def test_the_report_template_draws_ids_and_verdicts_without_infra_detail():
    records = [{"inventory_hostname": "h1", "status": "ok", "security_regression": {"status": "ok", "reason": "", "results": [
        {"code": "EXP-SSH-1", "verdict": "통과"}, {"code": "EXP-SSH-2", "verdict": "실패"}]}}]
    model = host_audit_report_model(records, {"targets": ["h1"], "regression_backup": [{"code": "EXP-BAK-1", "verdict": "통과"}]})
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")))
    html = env.get_template("sections/security_regression.html.j2").render(host_audit_model=model)
    assert "EXP-SSH-2" in html and "실패" in html and "EXP-BAK-1" in html and "h1" in html
    assert not re.search(r"\d+\.\d+\.\d+\.\d+", html)
