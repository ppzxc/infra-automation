"""Host Audit xlsx zip module (Spec #488 / Ticket-7, #495, AUD-026).

The zip the module wrote is reopened with zipfile: members, order, fixed times, mode, same input -> same bytes.
"""
import os
import stat
import zipfile
from pathlib import Path

from module_runner import run_module_file

ROOT_DIR = Path(__file__).resolve().parent.parent
MODULE = ROOT_DIR / "roles" / "host_audit" / "library" / "host_audit_zip_write.py"


def _run(tmp_path, args, check_mode=False):
    module_args = dict(args)
    if check_mode:
        module_args["_ansible_check_mode"] = True
    return run_module_file(MODULE, module_args, tmp_path / "args.json")


def _dir(tmp_path):
    d = tmp_path / "xlsx"
    d.mkdir()
    (d / "b.xlsx").write_bytes(b"B-bytes")
    (d / "a.xlsx").write_bytes(b"A-bytes")
    (d / ".hidden.tmp").write_bytes(b"partial")
    (d / "notes.txt").write_bytes(b"not an xlsx")
    return d


def test_zip_holds_the_xlsx_files_sorted_with_fixed_times_and_nothing_else(tmp_path):
    d = _dir(tmp_path)
    dest = d / "host-audit-ha-1-xlsx.zip"
    out = _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})
    assert not out.get("failed") and out["changed"] is True
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    with zipfile.ZipFile(dest) as z:
        assert z.namelist() == ["a.xlsx", "b.xlsx"]
        assert z.read("a.xlsx") == b"A-bytes" and z.read("b.xlsx") == b"B-bytes"
        assert {i.date_time for i in z.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        assert z.testzip() is None


def test_same_input_gives_the_same_bytes_and_a_second_run_changes_nothing(tmp_path):
    d = _dir(tmp_path)
    dest = d / "host-audit-ha-1-xlsx.zip"
    _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})
    first = dest.read_bytes()
    for f in d.glob("*.xlsx"):  # new mtimes must not leak into the archive
        os.utime(f, (1_900_000_000, 1_900_000_000))
    out = _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})
    assert out["changed"] is False and dest.read_bytes() == first
    (d / "a.xlsx").write_bytes(b"A-changed")
    assert _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})["changed"] is True
    assert dest.read_bytes() != first


def test_an_existing_zip_in_the_directory_is_never_packed_into_itself(tmp_path):
    d = _dir(tmp_path)
    dest = d / "host-audit-ha-1-xlsx.zip"
    _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})
    _run(tmp_path, {"src_dir": str(d), "dest": str(dest)})
    with zipfile.ZipFile(dest) as z:
        assert z.namelist() == ["a.xlsx", "b.xlsx"]


def test_named_files_are_packed_and_others_never(tmp_path):
    d = _dir(tmp_path)
    dest = d / "host-audit-ha-1-xlsx.zip"
    out = _run(tmp_path, {"src_dir": str(d), "dest": str(dest), "names": ["b.xlsx"]})
    assert not out.get("failed")
    with zipfile.ZipFile(dest) as z:
        assert z.namelist() == ["b.xlsx"]  # a.xlsx is on disk but was not named (a stale file of an earlier run)


def test_a_named_file_that_is_missing_or_not_a_plain_name_fails(tmp_path):
    d = _dir(tmp_path)
    for bad in ("nope.xlsx", "../a.xlsx"):
        out = _run(tmp_path, {"src_dir": str(d), "dest": str(d / "z.zip"), "names": [bad]})
        assert out["failed"] is True and bad in out["msg"]
    assert not (d / "z.zip").exists()


def test_check_mode_writes_nothing(tmp_path):
    d = _dir(tmp_path)
    dest = d / "host-audit-ha-1-xlsx.zip"
    out = _run(tmp_path, {"src_dir": str(d), "dest": str(dest)}, check_mode=True)
    assert out["changed"] is True and not dest.exists()


def test_a_missing_source_directory_fails_with_its_path(tmp_path):
    out = _run(tmp_path, {"src_dir": str(tmp_path / "none"), "dest": str(tmp_path / "x.zip")})
    assert out["failed"] is True and str(tmp_path / "none") in out["msg"]
