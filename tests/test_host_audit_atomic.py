"""Host Audit shared atomic file writer (Spec #488): used by the xlsx and zip modules (AUD-025, AUD-026)."""
import importlib.util
import stat
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "host_audit_atomic", ROOT_DIR / "roles" / "host_audit" / "module_utils" / "host_audit_atomic.py")
atomic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(atomic)


def test_write_reports_a_change_once_and_keeps_mode_0600(tmp_path):
    dest = tmp_path / "f.bin"
    assert atomic.write_atomic(str(dest), b"abc") is True
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600 and dest.read_bytes() == b"abc"
    assert atomic.write_atomic(str(dest), b"abc") is False
    dest.chmod(0o644)  # right bytes, wrong mode is a change
    assert atomic.write_atomic(str(dest), b"abc") is True and stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_a_missing_parent_is_an_error_unless_one_level_is_asked_for(tmp_path):
    with pytest.raises(OSError):
        atomic.write_atomic(str(tmp_path / "x" / "f.bin"), b"a")
    assert atomic.write_atomic(str(tmp_path / "x" / "f.bin"), b"a", create_parent=True) is True
    assert stat.S_IMODE((tmp_path / "x").stat().st_mode) == 0o700
    with pytest.raises(OSError):  # never a deeper tree
        atomic.write_atomic(str(tmp_path / "p" / "q" / "f.bin"), b"a", create_parent=True)
