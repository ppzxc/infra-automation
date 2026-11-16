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

# CI installs requirements-test.txt, so a missing openpyxl there must fail instead of silently skipping the round trip.
if os.environ.get("CI"):
    import openpyxl
else:
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
    module_args = dict(args)
    Path(path).write_text(json.dumps({"ANSIBLE_MODULE_ARGS": module_args}))
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
    assert out["msg"] == "row 2 has 1 cells, the header has 4"  # readable: no value of the rows is masked


def test_other_cell_types_are_written_as_text_and_none_as_an_empty_cell(tmp_path):
    dest = tmp_path / "t.xlsx"
    out = _run(dict(_args(dest), rows=[["a", None, 1.5, "\ud800 lone"]], _args_file=tmp_path / "t.json"))
    assert not out.get("failed"), out
    ws = openpyxl.load_workbook(dest).active
    assert [c.value for c in ws[2]] == ["a", None, "1.5", " lone"]


def test_check_mode_reports_changed_only_when_the_bytes_differ(tmp_path):
    first, _ = _write(tmp_path, "c.xlsx")
    same = _run(dict(_args(first), _args_file=tmp_path / "c1.json", _ansible_check_mode=True))
    assert same["changed"] is False
    other = _run(dict(_args(first), footer=["x"], _args_file=tmp_path / "c2.json", _ansible_check_mode=True))
    assert other["changed"] is True


def test_a_failed_write_leaves_no_temp_file_in_the_directory(tmp_path):
    spec = importlib.util.spec_from_file_location("host_audit_xlsx_write", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    dest = tmp_path / "x" / "f.xlsx"
    dest.parent.mkdir()
    real = os.replace

    def boom(*_a):
        raise OSError("disk full")

    os.replace = boom
    try:
        with pytest.raises(OSError):
            mod._write(str(dest), b"data")
    finally:
        os.replace = real
    assert list(dest.parent.iterdir()) == []


def test_a_file_with_the_right_bytes_but_a_wrong_mode_is_fixed_and_reported_changed(tmp_path):
    dest, _ = _write(tmp_path, "m.xlsx")
    dest.chmod(0o644)
    out = _run(dict(_args(dest), _args_file=tmp_path / "m1.json"))
    assert out["changed"] is True and stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_invalid_sheet_names_and_empty_headers_are_refused(tmp_path):
    for bad in ({"sheet": "x" * 32}, {"sheet": "a/b"}, {"sheet": "'a"}, {"widths": [300, 1, 1, 1]},
                {"headers": [], "rows": []}):
        dest = tmp_path / "bad.xlsx"
        out = _run(dict(_args(dest), _args_file=tmp_path / "v.json", **bad))
        assert out.get("failed") is True and not dest.exists(), bad


def test_a_cell_over_the_xlsx_limit_is_cut_and_warned(tmp_path):
    dest = tmp_path / "long.xlsx"
    out = _run(dict(_args(dest), rows=[["a", "b", 1, "x" * 40000]], _args_file=tmp_path / "l.json"))
    assert not out.get("failed") and "were cut" in json.dumps(out["warnings"])
    cell = openpyxl.load_workbook(dest).active["D2"].value
    assert len(cell) == 32767 and cell.endswith("…")


def test_error_messages_and_paths_are_not_masked_by_short_cell_values(tmp_path):
    """rows is a no_log argument; masking is narrowed so a host-name-sized cell does not blank the message."""
    dest = tmp_path / "xlsx" / "host-audit-r-1.xlsx"
    rows = [["1", "1", 1, "2"], ["host-audit", "2", 3, "xlsx"], ["a"]]
    out = _run(dict(_args(dest), rows=rows, _args_file=tmp_path / "n.json"))
    assert out["failed"] is True and out["msg"] == "row 4 has 1 cells, the header has 4"
    ok = _run(dict(_args(dest), rows=rows[:2], _args_file=tmp_path / "n2.json"))
    assert ok["dest"] == str(dest) and ok["size"] > 0


def test_long_free_text_stays_masked_in_the_result(tmp_path):
    secret = "an evidence line that is long enough to stay masked"
    dest = tmp_path / "xlsx" / "w.xlsx"
    out = _run(dict(_args(dest), rows=[["a", "b", 1, secret], ["a"]], _args_file=tmp_path / "s.json"))
    assert out["failed"] is True and secret not in json.dumps(out)


def test_more_widths_than_headers_is_refused(tmp_path):
    dest = tmp_path / "w.xlsx"
    out = _run(dict(_args(dest), widths=[1, 2, 3, 4, 5], _args_file=tmp_path / "w.json"))
    assert out.get("failed") is True and not dest.exists()


def test_the_cut_warning_counts_after_normalization(tmp_path):
    dest = tmp_path / "n.xlsx"
    short = "x" * 32760 + "\r\n" * 4  # 32,768 raw, 32,764 after normalization: not cut
    out = _run(dict(_args(dest), rows=[["a", "b", 1, short]], _args_file=tmp_path / "n.json"))
    assert "warnings" not in out
    cell = openpyxl.load_workbook(dest).active["D2"].value
    assert len(cell) == 32764


def test_the_cell_limit_counts_utf16_units_like_excel(tmp_path):
    dest = tmp_path / "e.xlsx"
    text = "\U0001F600" * 20000  # 20,000 characters, 40,000 UTF-16 units
    out = _run(dict(_args(dest), rows=[["a", "b", 1, text]], _args_file=tmp_path / "e.json"))
    assert "were cut" in json.dumps(out["warnings"])
    cell = openpyxl.load_workbook(dest).active["D2"].value
    assert cell.endswith("…") and len(cell.encode("utf-16-le")) // 2 <= 32767


def test_a_missing_parent_directory_is_an_error_not_a_created_tree(tmp_path):
    dest = tmp_path / "gone" / "xlsx" / "a.xlsx"
    out = _run(dict(_args(dest), _args_file=tmp_path / "p.json"))
    assert out["failed"] is True and not (tmp_path / "gone").exists()


def test_a_write_error_names_the_destination(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    out = _run(dict(_args(blocker / "sub" / "a.xlsx"), _args_file=tmp_path / "o.json"))
    assert out["failed"] is True and "cannot write" in out["msg"] and "a.xlsx" in out["msg"]


def test_huge_integers_become_text_and_the_sheet_name_is_measured_in_utf16(tmp_path):
    dest = tmp_path / "i.xlsx"
    out = _run(dict(_args(dest), rows=[["a", "b", 2 ** 70, "d"]], _args_file=tmp_path / "i.json"))
    assert not out.get("failed")
    assert openpyxl.load_workbook(dest).active["C2"].value == str(2 ** 70)
    bad = _run(dict(_args(tmp_path / "s.xlsx"), sheet="\U0001F600" * 16, _args_file=tmp_path / "s.json"))
    assert bad["failed"] is True


def test_the_workbook_declares_a_book_view_for_the_sheet_view(tmp_path):
    dest, _ = _write(tmp_path, "b.xlsx")
    with zipfile.ZipFile(dest) as zf:
        assert b"<bookViews><workbookView/></bookViews>" in zf.read("xl/workbook.xml")


def test_text_of_only_illegal_characters_is_an_empty_cell(tmp_path):
    dest = tmp_path / "z.xlsx"
    out = _run(dict(_args(dest), rows=[["\x00\x07", "b", 1, "d"]], _args_file=tmp_path / "z.json"))
    assert not out.get("failed")
    with zipfile.ZipFile(dest) as zf:
        assert b'<c r="A2" s="2"/>' in zf.read("xl/worksheets/sheet1.xml")


def test_a_long_coerced_value_is_warned_about_too(tmp_path):
    dest = tmp_path / "co.xlsx"
    out = _run(dict(_args(dest), rows=[["a", "b", 1, ["x" * 40000]]], _args_file=tmp_path / "co.json"))
    assert "were cut" in json.dumps(out["warnings"])


def test_the_writer_uses_only_the_standard_library():
    spec = importlib.util.spec_from_file_location("host_audit_xlsx_write", MODULE)
    source = MODULE.read_text(encoding="utf-8")
    assert spec is not None
    assert "openpyxl" not in source and "xlsxwriter" not in source
