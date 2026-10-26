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
