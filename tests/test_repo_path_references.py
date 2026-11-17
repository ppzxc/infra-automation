"""README·Makefile·docs가 가리키는 playbooks/·inventory/group_vars/ 파일이 실제로 있는지 본다(최종 리뷰 8번).

지워진 파일을 설명하는 줄("제거", "옛", "삭제", "없다" 같은 말이 함께 있는 줄)과 연구 노트(docs/research, docs/adr)는 제외한다.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATH_RE = re.compile(r"\b((?:playbooks|inventory/group_vars)/[A-Za-z0-9_./-]+\.ya?ml)\b")
HISTORY_WORDS = ("제거", "옛", "삭제", "없다", "없는", "폐지", "removed")


def _files():
    yield ROOT / "README.md"
    yield ROOT / "Makefile"
    yield from sorted((ROOT / "docs").glob("*.md"))
    yield from sorted((ROOT / "docs" / "runbooks").glob("*.md"))


def test_documents_do_not_point_at_missing_playbooks_or_group_vars():
    missing = []
    for path in _files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(w in line for w in HISTORY_WORDS):
                continue
            for ref in PATH_RE.findall(line):
                if "<" in ref or "*" in ref or "example" in ref:
                    continue
                if not (ROOT / ref).exists():
                    missing.append(f"{path.relative_to(ROOT)}:{n} {ref}")
    assert missing == []
