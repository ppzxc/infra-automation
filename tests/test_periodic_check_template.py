"""Periodic Check 템플릿 정적 검사 (Spec #511 / Ticket-9, #520). 운영 서버에 접속하지 않는다."""
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "scripts" / "run-periodic-check.sh"
SETUP = (ROOT / "docs" / "semaphore-setup.md").read_text(encoding="utf-8")


def test_runner_image_installs_jsonschema():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^\s+jsonschema\b", dockerfile, re.M), "러너 이미지 pip 목록에 jsonschema가 없다"


def test_template_defined_in_setup_doc():
    assert "OpenBao — Periodic Check" in SETUP
    assert "scripts/run-periodic-check.sh" in SETUP
    assert "periodic_check" in SETUP


def test_environment_uses_approle_without_vault_token():
    # periodic_check Environment는 AppRole 자격만 주입한다(VAULT_TOKEN 대체 경로 폐지, Spec #511).
    section = SETUP.split("### Periodic Check Environment", 1)[1].split("\n## ", 1)[0]
    for name in ("VAULT_ADDR", "VAULT_NAMESPACE", "VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        assert name in section
    assert "VAULT_TOKEN" in section and "넣지 않는다" in section


def test_wrapper_is_executable_and_strict():
    assert WRAPPER.stat().st_mode & stat.S_IXUSR
    assert "set -euo pipefail" in WRAPPER.read_text(encoding="utf-8")


def _run(tmp_path, python_exit=None):
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path)}
    if python_exit is not None:
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        stub = bindir / "python3"
        stub.write_text("#!/bin/sh\nexit %d\n" % python_exit)
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        env["PATH"] = "%s:%s" % (bindir, env["PATH"])
    return subprocess.run(["bash", str(WRAPPER)], env=env, cwd=tmp_path, capture_output=True, text=True)


def test_wrapper_propagates_failure_exit_code(tmp_path):
    assert _run(tmp_path, python_exit=1).returncode == 1
    assert _run(tmp_path, python_exit=2).returncode == 2


def test_wrapper_passes_on_success(tmp_path):
    assert _run(tmp_path, python_exit=0).returncode == 0


def test_wrapper_fails_without_connection_settings(tmp_path):
    # 실제 check: VAULT_ADDR가 없으면 접속하지 않고 설정 오류(2)로 끝난다.
    assert _run(tmp_path).returncode == 2
