"""CI 샤딩(`TEST_SHARD`)이 같은 `xdist_group`을 한 샤드에 묶는지 확인한다(#348, 샤드마다 렌더링을 되풀이하지 않게)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

CONFTEST = Path(__file__).with_name("conftest.py")

SAMPLE = '''
import pytest

pytestmark = pytest.mark.xdist_group("shared")

@pytest.mark.parametrize("n", range(12))
def test_grouped(n):
    pass
'''


def _collected(tmp_path, shard):
    env = {**os.environ, "TEST_SHARD": f"{shard}/3"}
    out = subprocess.run(
        [sys.executable, "-I", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "no:xdist",
         "-c", os.devnull, "--rootdir", str(tmp_path), str(tmp_path)],
        env=env, cwd=tmp_path, capture_output=True, text=True, check=False).stdout
    return [line for line in out.splitlines() if "::" in line]


def test_same_xdist_group_stays_in_one_shard(tmp_path):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_sample.py").write_text(SAMPLE, encoding="utf-8")
    sizes = [len(_collected(tmp_path, shard)) for shard in (1, 2, 3)]
    assert sorted(sizes) == [0, 0, 12], sizes


CLASSIFY_SAMPLE = '''
import pytest

def _run():
    return ["ansible-playbook", "x.yml"]

@pytest.fixture(scope="session")
def shared():
    return _run()

@pytest.fixture
def per_test():
    return _run()

def test_reads_session_fixture(shared):
    assert shared

def test_runs_directly():
    _run()

def test_uses_function_fixture(per_test):
    assert per_test

@pytest.fixture
def per_test_on_shared(shared):
    return shared

def test_function_fixture_over_session_fixture(per_test_on_shared):
    assert per_test_on_shared
'''


def _names(tmp_path, marker):
    out = subprocess.run(
        [sys.executable, "-I", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "no:xdist",
         "-c", os.devnull, "--rootdir", str(tmp_path), "-m", marker, str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, check=False).stdout
    return {line.split("::")[1] for line in out.splitlines() if "::" in line}


def test_auto_slow_ignores_session_fixture_but_not_direct_or_function_scope_runs(tmp_path):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_sample.py").write_text(CLASSIFY_SAMPLE, encoding="utf-8")
    assert _names(tmp_path, "slow") == {"test_runs_directly", "test_uses_function_fixture"}
    assert _names(tmp_path, "not slow") == {"test_reads_session_fixture", "test_function_fixture_over_session_fixture"}
