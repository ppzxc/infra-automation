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
                 "등록 도구", "openbao_apply.py", "AppRole", "`operator`", "`admin`"):
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


def test_context_has_the_six_terms_and_five_service_examples():
    text = _read(CONTEXT)
    for term in ("Asset", "Endpoint", "Credential", "Automation Identity", "Service", "Operator"):
        assert f"**{term}**:" in text, term
    service = re.search(r"^\*\*Service\*\*:\n(.+)$", text, re.M).group(1)
    for name in ("OpenObserve", "RustFS", "alert platform", "FUNA Cluster", "Semaphore"):
        assert name in service, name


def test_operations_runbook_covers_the_recurring_procedures():
    text = _read(OPERATIONS)
    for title in ("secret_id 발급과 교체", "만료 알림 대응", "정책 적용", "운영자 비밀번호 해시 만들기",
                  "operator 사용자 추가", "비상용 admin 사용"):
        assert runbook_section(OPERATIONS, title, numbered=True).strip(), title
    assert "response-wrapping" in text and "180일" in text
    apply_section = runbook_section(OPERATIONS, "정책 적용", numbered=True)
    assert "plan" in apply_section and "apply" in apply_section and "변경이 없다" in apply_section
    assert "bcrypt" in runbook_section(OPERATIONS, "운영자 비밀번호 해시 만들기", numbered=True)
    admin = runbook_section(OPERATIONS, "비상용 admin 사용", numbered=True)
    assert "참조" in admin and "Credential" in admin and "삭제" in admin


def test_cutover_runbook_has_the_nine_steps_in_order():
    steps = runbook_section(CUTOVER, "전환 순서", numbered=True)
    numbered = re.findall(r"^(\d+)\. ", steps, re.M)
    assert numbered == [str(n) for n in range(1, 10)]
    by_number = dict(re.findall(r"^(\d+)\. (.+)$", steps, re.M))
    for number, keyword in (("2", "admin"), ("3", "openbao_apply.py"), ("6", "동결 창을 시작"), ("7", "전환 PR"),
                            ("8", "확인 목록"), ("9", "스케줄")):
        assert keyword in by_number[number], (number, keyword)


def test_cutover_runbook_covers_freeze_checks_rollback_and_cleanup():
    freeze = runbook_section(CUTOVER, "동결 창 규칙", numbered=True)
    assert "스케줄" in freeze and "옛 KV 쓰기" in freeze and "2시간" in freeze
    checks = runbook_section(CUTOVER, "계열별 확인 목록", numbered=True)
    for family in ("provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit",
                   "network_backup", "periodic_check"):
        assert f"`{family}`" in checks, family
    assert "403" in checks
    rollback = runbook_section(CUTOVER, "되돌리기", numbered=True)
    assert "revert" in rollback and "Environment" in rollback and "데이터" in rollback
    cleanup = runbook_section(CUTOVER, "옛 구조 삭제", numbered=True)
    assert "2주" in cleanup and "raft" in cleanup and "월간 Host Audit" in cleanup
    assert "~/.local/share/infra-automation/openbao-restructure/" in _read(CUTOVER), "비공개 노트를 가리키지 않는다"


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
        assert not re.search(r"https?://|\b\d{1,2}\s?(KST|UTC)\b|/\d{1,2}\b(?=[\s`)])", text), f"{path.name}: URL·시각·CIDR"


# --- 전환 PR 문서(Spec #511 / Ticket-20, #531) -------------------------------------------------------------------------

INTEGRATION = ROOT / "docs" / "openbao_integration.md"
SEMAPHORE = ROOT / "docs" / "semaphore-setup.md"
AGENTS = ROOT / "AGENTS.md"


def test_integration_doc_follows_the_agreed_table_of_contents_and_copies_no_key_table():
    text = _read(INTEGRATION)
    heads = re.findall(r"^## (\d+)\. (.+)$", text, re.M)
    assert [h[1].split()[0] for h in heads] == ["개요", "골격", "저장", "접속", "인증과", "실패", "새", "관련"]
    assert "schemas/openbao/index.yml" in text and "openbao/policies" in text
    for stale in ("VAULT_MOUNT", "OPENBAO_", "infra/prod/host", "Hybrid Fallback", "secret/data", "hosts/<ns>"):
        assert stale not in text, stale
    assert "required_keys" not in text and "| 키 |" not in text


def test_semaphore_setup_has_one_environment_per_family_and_no_token_or_mount_trace():
    text = _read(SEMAPHORE)
    for family in ("provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit", "network_backup",
                   "periodic_check"):
        assert re.search(rf"^\| `{family}` \|", text, re.M), family
    for old in ("VAULT_TOKEN", "VAULT_MOUNT", "OPENBAO_HOSTS_PREFIX", "infra/prod/host"):
        assert old not in text, old


def test_the_old_adrs_carry_a_superseded_by_adr_0014_line():
    for name in ("0006-host-agents-otelcol-resticprofile", "0009-host-audit-read-only-inspection",
                 "0012-container-app-telemetry-via-host-otelcol"):
        text = _read(ROOT / "docs" / "adr" / f"{name}.md")
        assert re.search(r"\(개정[^)]*#531\)[^\n]*ADR-0014", text), name


def test_index_and_readme_describe_the_new_integration_doc():
    assert "동적 시크릿" not in _read(INDEX)
    assert "VAULT_TOKEN" not in _read(ROOT / "README.md")


def test_agents_rules_state_the_agent_session_and_do_not_call_the_reader_a_hashicorp_lookup_plugin():
    text = _read(AGENTS)
    section4 = text.split("## 4.", 1)[1].split("\n## ", 1)[0]
    assert "에이전트 세션" in section4 and "`inventory/`" in section4 and "계열 템플릿" in section4
    assert "openbao_integration.md" in section4
    assert "Vault lookup 플러그인" not in text


def test_no_current_doc_describes_the_old_openbao_layout():
    """옛 구조 설명이 남은 현재 동작 문서가 없다(ADR·research·prototypes와 전환 런북은 당시 기록이라 제외)."""
    old = re.compile(r"OpenBao `hosts/|OpenBao `agents/(?:openobserve|rustfs)|`OPENBAO_[A-Z_]*PREFIX`|`infra/prod/host`의 `secret`")
    for path in (ROOT / "docs").rglob("*.md"):
        rel = path.relative_to(ROOT / "docs").parts
        if rel[0] in ("adr", "research", "prototypes") or path.name in ("openbao-cutover.md",):
            continue
        assert not old.search(_read(path)), path
