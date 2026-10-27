"""런북 테스트가 같이 쓰는 helper: 마크다운 절 추출(Spec #364 리뷰 정리).

`tests/conftest.py`는 건드리지 않는 파일이라 별도 모듈로 둔다.
"""
import re
from pathlib import Path


def runbook_section(path, title, numbered=False):
    """`## <title>`(numbered면 `## <번호>. <title>`)로 시작하는 절 본문을 돌려준다. 없으면 AssertionError."""
    prefix = r"[0-9]+\. " if numbered else ""
    text = Path(path).read_text(encoding="utf-8")
    match = re.search(rf"^## {prefix}{re.escape(title)}.*?(?=^## |\Z)", text, re.S | re.M)
    assert match, f"'## {title}' 절이 없다"
    return match.group(0)
