"""OpenBao 재설계 문서 구조 검사 (Spec #511 / Ticket-1, #512).

ADR-0014, CONTEXT 용어, 운영 런북, 전환 런북은 문서라 동작은 없지만 인수 기준은 기계로 확인할 수 있다:
결정 항목·기각한 대안·범위 밖 한 줄, 용어 여섯 개와 Service 예시 여섯 개, 런북 절, INDEX 등록,
그리고 공개 저장소라 실제 주소·시각·카나리 이름이 없는지.
"""
import re
from pathlib import Path

from runbook_helpers import runbook_section

ROOT = Path(__file__).resolve().parent.parent
ADR = ROOT / "docs" / "adr" / "0014-openbao-storage-structure-and-access-policy.md"
OPERATIONS = ROOT / "docs" / "runbooks" / "openbao-operations.md"
CUTOVER = ROOT / "docs" / "runbooks" / "openbao-cutover.md"
CONTEXT = ROOT / "CONTEXT.md"
INDEX = ROOT / "docs" / "INDEX.md"

PUBLIC_FILES = (ADR, OPERATIONS, CUTOVER)


def _read(path):
    return path.read_text(encoding="utf-8")


def test_adr_records_the_structure_decisions():
    text = _read(ADR)
    assert text.startswith("---\nstatus: accepted\n")
    for item in ("`infra`", "`inventory/`", "`secrets/`", "소유 대상", "작업 계열", "JSON Schema", "`index.yml`",
                 "등록 도구", "OpenTofu", "AppRole", "`operator`", "`admin`"):
        assert item in text, item


def test_adr_lists_each_rejected_alternative_with_a_reason():
    section = runbook_section(ADR, "Considered Options")
    for option in ("현행 유지", "다단 네임스페이스", "작업별 저장", "이중 읽기", "문서 버전"):
        row = next((line for line in section.splitlines() if option in line), None)
        assert row, option
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[1] == "기각", option
        assert cells[2].startswith("기각 이유:") and len(cells[2]) > 40, f"{option}: 기각 이유가 없다"


def test_adr_states_the_out_of_scope_items_in_one_line():
    lines = [l for l in _read(ADR).splitlines() if "이 ADR에서 정하지 않음" in l]
    assert len(lines) == 1
    assert "동적 자격증명" in lines[0] and "감사 장치" in lines[0]


def test_context_has_the_six_terms_and_six_service_examples():
    text = _read(CONTEXT)
    for term in ("Asset", "Endpoint", "Credential", "Automation Identity", "Service", "Operator"):
        assert f"**{term}**:" in text, term
    service = re.search(r"^\*\*Service\*\*:\n(.+)$", text, re.M).group(1)
    for name in ("OpenObserve", "RustFS", "GitHub", "alert platform", "FUNA Cluster", "Semaphore"):
        assert name in service, name


def test_operations_runbook_covers_the_recurring_procedures():
    text = _read(OPERATIONS)
    for title in ("secret_id 발급과 교체", "만료 알림 대응", "OpenTofu 적용", "state passphrase 보관",
                  "operator 사용자 추가", "비상용 admin 사용"):
        assert runbook_section(OPERATIONS, title, numbered=True).strip(), title
    assert "response-wrapping" in text and "180일" in text
    assert "오프라인 사본" in runbook_section(OPERATIONS, "state passphrase 보관", numbered=True)
    assert "Semaphore" in runbook_section(OPERATIONS, "state passphrase 보관", numbered=True)
    admin = runbook_section(OPERATIONS, "비상용 admin 사용", numbered=True)
    assert "참조" in admin and "Credential" in admin and "삭제" in admin


def test_cutover_runbook_has_the_nine_steps_in_order():
    steps = runbook_section(CUTOVER, "전환 순서", numbered=True)
    numbered = re.findall(r"^(\d+)\. ", steps, re.M)
    assert numbered == [str(n) for n in range(1, 10)]
    by_number = dict(re.findall(r"^(\d+)\. (.+)$", steps, re.M))
    for number, keyword in (("2", "admin"), ("3", "OpenTofu"), ("6", "동결 창을 시작"), ("7", "전환 PR"),
                            ("8", "확인 목록"), ("9", "스케줄")):
        assert keyword in by_number[number], (number, keyword)


def test_cutover_runbook_covers_freeze_checks_rollback_and_cleanup():
    freeze = runbook_section(CUTOVER, "동결 창 규칙", numbered=True)
    assert "스케줄" in freeze and "옛 KV 쓰기" in freeze and "2시간" in freeze
    checks = runbook_section(CUTOVER, "계열별 확인 목록", numbered=True)
    for family in ("provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit",
                   "network_backup", "github_webhook_watch", "periodic_check"):
        assert f"`{family}`" in checks, family
    assert "403" in checks
    rollback = runbook_section(CUTOVER, "되돌리기", numbered=True)
    assert "revert" in rollback and "Environment" in rollback and "데이터" in rollback
    cleanup = runbook_section(CUTOVER, "옛 구조 삭제", numbered=True)
    assert "2주" in cleanup and "raft" in cleanup and "월간 Host Audit" in cleanup
    assert cutover_points_to_private_note()


def cutover_points_to_private_note():
    return "~/.local/share/infra-automation/openbao-restructure/" in _read(CUTOVER)


def test_runbooks_and_adr_are_indexed():
    index = _read(INDEX)
    for path in PUBLIC_FILES:
        assert path.relative_to(ROOT / "docs").as_posix() in index, path.name


def test_public_docs_have_no_real_addresses_or_clock_times():
    for path in PUBLIC_FILES:
        text = _read(path)
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text), f"{path.name}: IP 주소"
        assert not re.search(r"\b\d{1,2}:\d{2}\b", text), f"{path.name}: 시각"
        assert not re.search(r"\bns\d{4}\b", text), f"{path.name}: 관리번호"
