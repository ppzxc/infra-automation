"""GitHub 감사 웹훅 런북 (Spec #399 / Ticket-7, #406).

런북은 문서라 동작은 없지만 인수 기준은 기계로 확인할 수 있다: 수집/미수집 이벤트 표와 공백, 출발지 대역 갱신 절차,
단계별 승인·스냅샷 diff·롤백이 있는 서버 적용 절차, 월간 점검 연결, INDEX·모니터링 문서 갱신, 그리고 공개 저장소라
호스트 번호·주소·포트·수신 경로·조직명의 실제 값이 없는지.
"""
import re
from pathlib import Path
from runbook_helpers import runbook_section

ROOT = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT / "docs" / "runbooks" / "github-audit-webhook.md"
MONTHLY = ROOT / "docs" / "runbooks" / "monthly-log-review.md"
INDEX = ROOT / "docs" / "INDEX.md"
MONITORING = ROOT / "docs" / "monitoring.md"
WATCH = ROOT / "docs" / "github_webhook_watch.md"


def _section(title, numbered=True):
    return runbook_section(RUNBOOK, title, numbered=numbered)


def test_runbook_is_indexed_and_linked_from_monitoring_and_watch_docs():
    assert "runbooks/github-audit-webhook.md" in INDEX.read_text(encoding="utf-8")
    assert "runbooks/github-audit-webhook.md" in MONITORING.read_text(encoding="utf-8")
    assert "github-audit-webhook.md" in WATCH.read_text(encoding="utf-8")


def test_runbook_has_the_required_sections():
    for title in ("수집 범위", "수집 공백과 보완", "출발지 대역 갱신", "서버 적용 절차", "롤백", "서버 적용 뒤 검증"):
        assert _section(title).strip(), title


def test_scope_table_lists_collected_events_and_the_gaps_explicitly():
    scope = _section("수집 범위")
    for event in ("repository", "public", "team", "repository_ruleset", "personal_access_token_request", "meta",
                  "organization", "member", "membership", "org_block", "branch_protection_rule", "deploy_key", "custom_property"):
        assert f"`{event}`" in scope, event
    for item in ("수집되지 않는", "로그인", "2FA", "토큰 사용", "Actions 설정", "시크릿 변경"):
        assert item in scope, item
    assert "월간" in _section("수집 공백과 보완")


def test_monthly_review_has_the_audit_log_export_step_with_the_unverified_free_plan_status():
    text = MONTHLY.read_text(encoding="utf-8")
    step = re.search(r"^\d+\. \*\*GitHub 조직 감사 로그 내보내기.*?(?=^\d+\. \*\*|^## )", text, re.S | re.M)
    assert step, "감사 로그 내보내기 단계가 없다"
    body = step.group(0)
    assert "미확인" in body and "Ticket-1" in body and "Ticket-8" in body
    assert "180일" in body and "JSON" in body
    assert "GitHub 감사 로그" in text.split("## 점검 기록 양식")[1]      # 기록 양식에도 행이 있다


def test_source_range_refresh_procedure_follows_the_ingress_safe_change_rules():
    s = _section("출발지 대역 갱신")
    for needle in ("/meta", "hooks", "sed -i", "inode", ">>", "POST", "고정 경로", "거부", "별도 matcher", "롤백", "승인"):
        assert needle in s, needle


def test_apply_procedure_has_steps_approval_snapshot_diff_and_rollback():
    s = _section("서버 적용 절차")
    for needle in ("승인", "스냅샷", "diff", "바인딩", "OpenBao", "조직 웹훅", "Semaphore", "Host Agents", "사용자 확정"):
        assert needle in s, needle
    assert len(re.findall(r"^\| [A-Z]-\d ", s, re.M)) >= 6
    rb = _section("롤백")
    for needle in ("웹훅", "입구", "Host Agents", "시크릿"):
        assert needle in rb, needle
    verify = _section("서버 적용 뒤 검증")
    for needle in ("MON-069", "MON-070", "MON-071", "docker.service.wants", "401", "재바인딩"):
        assert needle in verify, needle


def test_runbook_says_final_severity_and_event_subscription_are_the_users_decision():
    assert "사용자" in RUNBOOK.read_text(encoding="utf-8") and "확정" in RUNBOOK.read_text(encoding="utf-8")


def test_no_real_hosts_addresses_ports_paths_or_org_names_in_the_runbook_or_edits():
    for path in (RUNBOOK, MONTHLY):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text), path
        assert not re.search(r"\bns\d{4}\b", text), path
        assert not re.search(r"(?<![\w.])(port|포트)\s*[=:]?\s*\d{2,5}\b", text, re.I), path
        assert not re.search(r"https?://(?!docs\.github\.com|github\.com/ppzxc/infra-automation)", text), path
        assert not re.search(r"ppzxc(?!/infra-automation)", text), path
