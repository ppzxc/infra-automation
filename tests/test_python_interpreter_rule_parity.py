"""`access.python_interpreter`의 스키마 규칙과 런타임 필터 규칙이 같다(최종 리뷰 5차 5번).

put·Periodic Check(스키마)가 통과시킨 값이 실행(필터)에서 실패하거나 그 반대가 되면 안 된다.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "filter_plugins"))
sys.path.insert(0, str(ROOT / "scripts"))
import openbao_validation as ov  # noqa: E402
from openbao_ssh import python_interpreter_problem  # noqa: E402

CASES = ["/usr/bin/python3", "/usr/local/bin/python3.11", "/opt/py/bin/python", "/opt/python+x/bin/python",
         "python3", "/srv/semaphore/venv/bin/python", "/opt/Semaphore/bin/python", "/home/x/.venv/bin/python",
         "/home/x/.VENV/bin/python", "/tmp/py/python", "/TMP/py/python", "/var/tmp/py/python", "auto_silent",
         "/usr/bin/../bin/python", "/usr/bin/..", "/../python", "/usr/bin/python3; rm", "/usr/bin/pyth on", "/usr/bin/python3\n", ""]


@pytest.mark.parametrize("value", CASES)
def test_schema_and_filter_agree_on_every_case(value):
    asset = {"description": "d", "access": {"python_interpreter": value}}
    schema_ok = ov.validate_document("inventory/assets/ns0001", asset) == []
    filter_ok = value != "" and python_interpreter_problem(value) is None
    assert schema_ok == filter_ok, (value, schema_ok, filter_ok)
