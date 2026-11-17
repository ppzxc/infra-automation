"""공용 필수 키 충족 필터 `openbao_required_gaps`의 옵션별 의미(최종 리뷰 5차 7번).

각 옵션 조합은 이 필터로 모은 옛 구현과 같은 결과를 내야 한다(wrapper·역할 태스크의 기존 테스트가 통과한다)."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "filter_plugins"))
from openbao_required import openbao_required_gaps as gaps  # noqa: E402

REQ = {"inventory/services/rustfs": ["url"], "secrets/assets/+/agents": ["restic_password", "x"]}


def test_scope_required_reports_unread_documents_key_by_key_and_none_empty_counts_none_and_empty():
    docs = {"secrets/assets/+/agents": {"restic_password": "", "x": None}}
    assert gaps(docs, REQ) == ["inventory/services/rustfs.url", "secrets/assets/+/agents.restic_password", "secrets/assets/+/agents.x"]


def test_host_substitution_and_plus_skipping():
    assert gaps({}, REQ, host="ns0001", skip_plus=False)[1] == "secrets/assets/ns0001/agents.restic_password"
    assert gaps({}, REQ, skip_plus=True) == ["inventory/services/rustfs.url"]


def test_scope_docs_with_missing_doc_line_and_blank_strings():
    docs = {"inventory/services/rustfs": None, "secrets/assets/+/agents": {"restic_password": "  ", "x": 0}, "other": {"k": ""}}
    assert gaps(docs, REQ, scope="docs", missing_doc="doc", blank="blank") == [
        "inventory/services/rustfs(문서 없음)", "secrets/assets/+/agents.restic_password"]   # 0은 비지 않았고, 선언에 없는 문서는 키를 보지 않는다


def test_skip_ignores_documents_that_were_not_read_and_falsy_counts_zero_and_false():
    docs = {"secrets/assets/+/agents": {"restic_password": 0, "x": "ok"}}
    assert gaps(docs, REQ, missing_doc="skip", blank="falsy") == ["secrets/assets/+/agents.restic_password"]


def test_absent_only_looks_at_key_presence_and_formats():
    docs = {"inventory/services/rustfs": {}, "secrets/assets/+/agents": {"restic_password": "", "x": 1}}
    assert gaps(docs, REQ, blank="absent", fmt="colon") == ["inventory/services/rustfs:url"]
    assert gaps({}, {"a": ["k"]}, fmt="colon_space") == ["a: k"]


def test_a_bad_option_is_an_error_not_a_silent_pass():
    with pytest.raises(Exception):
        gaps({}, REQ, blank="nope")
    with pytest.raises(Exception):
        gaps({}, REQ, scope="x")


def test_no_role_keeps_its_own_missing_key_loop():
    import re
    for path in (ROOT / "roles").rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"for\s+\w+,\s*keys\s+in\s+\w+_openbao_required\.items\(\)", text), str(path)
