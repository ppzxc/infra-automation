"""관리용 웹 접점 루프백 바인드 런북 (Spec #364 / Ticket-2, #369).

compose 원본이 저장소에 없어 변경은 서버에서 운영자 승인 후 한다. 저장소에는 런북만 남으므로 런북이 승인 항목별
체크리스트·롤백·부정 시험·#377 기대치를 갖추고, 금지 사항(overseer 재생성, 시크릿 값 출력)을 어기는 명령이 없는지,
공개 저장소라 인프라 상세가 없는지만 가볍게 검사한다.
"""
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "mgmt-web-loopback-bind.md"
INDEX = ROOT_DIR / "docs" / "INDEX.md"


def _text():
    return RUNBOOK.read_text(encoding="utf-8")


def _section(title):
    match = re.search(rf"^## {re.escape(title)}.*?(?=^## |\Z)", _text(), re.S | re.M)
    assert match, f"'## {title}' 절이 없다"
    return match.group(0)


def _commands():
    """코드 블록 안의 명령 줄만 모은다(주석 제외)."""
    lines = []
    for block in re.findall(r"```[a-z]*\n(.*?)```", _text(), re.S):
        lines += [l.strip() for l in block.splitlines() if l.strip() and not l.strip().startswith("#")]
    return lines


def test_the_runbook_is_linked_from_the_index():
    assert "runbooks/mgmt-web-loopback-bind.md" in INDEX.read_text(encoding="utf-8")


def test_the_runbook_has_the_required_sections_in_apply_order():
    text = _text()
    titles = ["금지 사항", "적용 전 기준선", "승인 항목별 체크리스트", "롤백", "적용 후 검증", "부정 시험", "Host Audit 기대치"]
    positions = [text.find(f"## {t}") for t in titles]
    assert all(p >= 0 for p in positions), dict(zip(titles, positions))
    # 롤백은 적용 전에 적는다: 체크리스트 앞이 아니라도 적용(체크리스트)보다 먼저 읽히는 기준선 뒤에 있어야 한다
    assert positions == sorted(positions), "절 순서가 적용 순서와 다르다"


def test_the_checklist_has_one_row_per_approval_item_with_rollback_and_approval_columns():
    checklist = _section("승인 항목별 체크리스트")
    rows = re.findall(r"^\| (?:M|R)-\d+ \|.*$", checklist, re.M)
    assert len(rows) >= 3
    header = re.search(r"^\| 항목 .*$", checklist, re.M)
    assert header and "롤백" in header.group(0) and "운영자 승인" in header.group(0)


def test_the_baseline_and_the_post_check_use_the_same_collector_command_and_a_diff():
    for title in ("적용 전 기준선", "적용 후 검증"):
        assert "scripts/collect-security-baseline.sh" in _section(title), title
    assert "diff" in _section("적용 후 검증")
    assert "비공개" in _section("적용 후 검증")


def test_the_negative_tests_cover_internet_direct_and_outside_allowed_source():
    neg = _section("부정 시험")
    assert "인터넷" in neg and "허용 밖" in neg and "허용 출발지" in neg
    assert "비공개 경로에 지정" in neg


def test_the_prohibitions_name_the_overseer_recreation_and_value_printing():
    ban = _section("금지 사항")
    assert "overseer" in ban and "재생성" in ban
    assert "값" in ban and "출력" in ban


def test_no_command_recreates_overseer_or_prints_secret_values():
    forbidden = [
        r"compose\b.*\b(up|down|rm|restart)\b",
        r"--force-recreate",
        r"docker\s+(rm|stop|restart|kill)\b",
        r"\b(cat|head|tail|less|printenv|env)\b.*(\.env|secrets?)",
        r"docker\s+(inspect|exec)\b",
        r"compose\b.*\bconfig\b",
        r"echo\s+\$",
    ]
    for line in _commands():
        for pattern in forbidden:
            assert not re.search(pattern, line), f"금지 명령: {line}"


def test_the_expectations_for_host_audit_are_listed_with_ids_and_a_pass_criterion():
    section = _section("Host Audit 기대치")
    rows = re.findall(r"^\| EXP-MGMT-\d+ \|(.*)$", section, re.M)
    assert len(rows) >= 3
    assert "읽기 전용" in section and "#377" in section
    assert "ADR-0012" in section  # 루프백 단정 금지: OTLP 수신기는 예외


def test_the_runbook_carries_no_infrastructure_details():
    text = _text()
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), "IP 주소"
    assert not re.search(r"\bns0\d{3}\b", text), "관리번호(장비 식별)"
    assert not re.search(r"(?i)\bport\s*[:=]?\s*\d{2,5}\b|포트\s*\d{2,5}|\b[A-Za-z0-9.\-\[\]]+:\d{2,5}\b", text), "포트 번호"
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text), "시크릿 값"
    assert not re.search(r"\b[a-z][a-z0-9_.-]*@[a-z0-9.-]+\.[a-z]{2,}\b", text, re.I), "계정·이메일"
