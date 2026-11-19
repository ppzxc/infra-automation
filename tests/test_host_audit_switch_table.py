"""스위치 Host Audit 적용 표(docs/host_audit_switch.md) 구조 검사 (Spec #568 / Ticket-1).

표는 Ticket-3·4가 판정 함수를 짜는 근거다. 38개 항목이 빠짐없이 있고, 값이 허용 범위 안이며,
해당없음·점검불가에 사유가 있고, 공개 저장소라 장비 식별 정보가 없는지만 본다(판정 내용의 옳고 그름은 사람이 검수한다).
"""
import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parent.parent / "docs" / "host_audit_switch.md"
COLUMNS = ["항목 코드", "항목명", "중요도", "분류", "L2", "L3", "판정 근거", "사유"]
EXTRA_COLUMN = "취약 판정 조건"
CODES = [f"N-{n:02d}" for n in range(1, 39)]
CATEGORIES = {"계정", "접근", "패치", "로그", "기능"}
LEVELS = {"상", "중", "하"}
STATES = {"적용", "해당없음", "점검불가"}
ALLOWED_SHOW = {"running-config", "version"}


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


@pytest.fixture(scope="module")
def text():
    assert DOC.exists(), "docs/host_audit_switch.md가 없다"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def rows(text):
    header = next((_cells(l) for l in text.splitlines() if l.startswith("| 항목 코드")), None)
    assert header is not None, "표 머리(항목 코드 ...)가 없다"
    assert header[:8] == COLUMNS and header[8:] == [EXTRA_COLUMN]
    data = [dict(zip(header, _cells(l))) for l in text.splitlines() if re.match(r"\|\s*N-\d+\s*\|", l)]
    return data


def test_all_38_items_exist_exactly_once_in_order(rows):
    assert [r["항목 코드"] for r in rows] == CODES


def test_category_follows_the_spec_ranges(rows):
    expected = {**{f"N-{n:02d}": "계정" for n in range(1, 6)}, **{f"N-{n:02d}": "접근" for n in range(6, 12)},
                "N-12": "패치", **{f"N-{n:02d}": "로그" for n in range(13, 17)},
                **{f"N-{n:02d}": "기능" for n in range(17, 39)}}
    for r in rows:
        assert r["분류"] in CATEGORIES
        assert r["분류"] == expected[r["항목 코드"]], r["항목 코드"]


def test_importance_and_l2_l3_values_are_valid(rows):
    for r in rows:
        assert r["중요도"] in LEVELS, r["항목 코드"]
        assert r["L2"] in STATES, r["항목 코드"]
        assert r["L3"] in STATES, r["항목 코드"]


def test_every_row_has_name_basis_and_vulnerable_condition(rows):
    for r in rows:
        for col in ("항목명", "판정 근거", EXTRA_COLUMN):
            assert r[col] and r[col] != "-", (r["항목 코드"], col)


def test_not_applicable_and_unverifiable_rows_have_a_reason(rows):
    for r in rows:
        if {r["L2"], r["L3"]} & {"해당없음", "점검불가"}:
            assert r["사유"] and r["사유"] != "-", r["항목 코드"]


def test_applicable_everywhere_rows_do_not_need_a_reason(rows):
    # 사유 열은 해당없음·점검불가 전용이다. 둘 다 적용이면 비워 둔다(사유가 있으면 읽는 사람이 혼동한다).
    for r in rows:
        if r["L2"] == "적용" and r["L3"] == "적용":
            assert r["사유"] in ("", "-"), r["항목 코드"]


def test_n12_is_version_collection_only_and_fixed_unverifiable(rows, text):
    n12 = next(r for r in rows if r["항목 코드"] == "N-12")
    assert n12["L2"] == "점검불가" and n12["L3"] == "점검불가"
    assert "show version" in n12["판정 근거"]
    assert "점검불가(수동 확인)" in text


def test_telnet_session_itself_is_vulnerable_under_n08(rows):
    n08 = next(r for r in rows if r["항목 코드"] == "N-08")
    assert "Telnet" in n08[EXTRA_COLUMN]


def test_doc_states_the_l2_l3_rule_and_read_only_commands(text):
    assert "ip routing" in text and "SVI" in text
    assert "L3" in text and "L2" in text
    assert "인벤토리 변수" in text


def test_only_show_running_config_and_show_version_are_named(text):
    named = set(re.findall(r"\bshow\s+([a-z][a-z-]*)", text))
    assert named <= ALLOWED_SHOW, named - ALLOWED_SHOW
    assert named == ALLOWED_SHOW


def test_no_device_identifiers_in_the_public_doc(text):
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text), "IPv4 주소 패턴"
    assert not re.search(r"\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{0,4}\b", text), "IPv6 주소 패턴"
    assert not re.search(r"\bns\d{4}\b", text), "관리번호 패턴"
