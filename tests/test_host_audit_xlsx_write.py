"""Host Audit xlsx writer module (Spec #488 / Ticket-6, #494).

The file the module wrote is reopened with openpyxl (test-only dependency): cell values, bold header, column
widths, wrapping, frozen pane. Same input -> same bytes.
"""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

openpyxl = pytest.importorskip("openpyxl")

ROOT_DIR = Path(__file__).resolve().parent.parent
MODULE = ROOT_DIR / "roles" / "host_audit" / "library" / "host_audit_xlsx_write.py"

HEADERS = ["그룹", "자산명", "위험도", "비고"]
ROWS = [["계정 관리", "h1", 3, "첫째 줄\n둘째 줄"], ["파일 관리", "h1", 1, "<b>&amp; \x07 text</b>"]]
FOOTER = ["출처 문장", "실행 ID: ha-1"]
WIDTHS = [14, 10, 8, 60]


def _args(dest):
    return {"dest": str(dest), "sheet": "이행계획서", "headers": HEADERS, "rows": ROWS, "footer": FOOTER,
            "widths": WIDTHS}


def _run(args):
    """Run the module as Ansible does: a python file with a JSON args file."""
    path = args.pop("_args_file")
    Path(path).write_text(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    res = subprocess.run([sys.executable, str(MODULE), str(path)], capture_output=True, text=True, env=env)
    return json.loads(res.stdout)


def _write(tmp_path, name="a.xlsx", **override):
    dest = tmp_path / "xlsx" / name
    args = dict(_args(dest), _args_file=tmp_path / (name + ".json"), **override)
    out = _run(args)
    assert not out.get("failed"), out
    return dest, out


def test_values_header_style_widths_wrap_and_frozen_pane(tmp_path):
    dest, out = _write(tmp_path)
    assert out["changed"] is True
    ws = openpyxl.load_workbook(dest).active
    assert ws.title == "이행계획서"
    assert [c.value for c in ws[1]] == HEADERS
    assert [c.value for c in ws[2]] == ROWS[0]
    assert ws["C2"].value == 3 and isinstance(ws["C2"].value, int)
    assert ws["D2"].value == "첫째 줄\n둘째 줄"
    assert ws["D3"].value == "<b>&amp;  text</b>"  # markup stays text, XML-illegal control characters are dropped
    assert all(c.font.bold for c in ws[1]) and not ws["A2"].font.bold
    assert ws["D2"].alignment.wrap_text is True and ws["A1"].alignment.wrap_text is True
    assert ws["D2"].alignment.vertical == "top"
    assert ws.freeze_panes == "A2"
    assert [ws.column_dimensions[c].width for c in "ABCD"] == WIDTHS
    assert ws["A5"].value == "출처 문장" and ws["A6"].value == "실행 ID: ha-1"  # after one blank row


def test_same_input_gives_the_same_bytes_and_a_second_run_changes_nothing(tmp_path):
    first, _ = _write(tmp_path, "one.xlsx")
    second, out2 = _write(tmp_path, "two.xlsx")
    assert first.read_bytes() == second.read_bytes()
    again = _run(dict(_args(first), _args_file=tmp_path / "again.json"))
    assert again["changed"] is False
    with zipfile.ZipFile(first) as zf:
        assert {i.date_time for i in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_different_input_gives_different_bytes(tmp_path):
    first, _ = _write(tmp_path, "one.xlsx")
    other = tmp_path / "xlsx" / "other.xlsx"
    args = dict(_args(other), _args_file=tmp_path / "o.json", footer=["다른 문장"])
    _run(args)
    assert first.read_bytes() != other.read_bytes()


def test_file_mode_is_private_and_the_directory_is_created(tmp_path):
    dest, _ = _write(tmp_path)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert stat.S_IMODE(dest.parent.stat().st_mode) == 0o700


def test_rows_must_fit_the_header(tmp_path):
    dest = tmp_path / "bad.xlsx"
    out = _run(dict(_args(dest), rows=[["only one"]], _args_file=tmp_path / "b.json"))
    assert out.get("failed") is True and not dest.exists()


def test_unsupported_cell_types_are_refused(tmp_path):
    dest = tmp_path / "bad.xlsx"
    out = _run(dict(_args(dest), rows=[["a", "b", 1.5, "d"]], _args_file=tmp_path / "b.json"))
    assert out.get("failed") is True and not dest.exists()


def test_the_writer_uses_only_the_standard_library():
    spec = importlib.util.spec_from_file_location("host_audit_xlsx_write", MODULE)
    source = MODULE.read_text(encoding="utf-8")
    assert spec is not None
    assert "openpyxl" not in source and "xlsxwriter" not in source
