"""scripts/collect-security-baseline.sh (#368): 서버 보안 상태 읽기 전용 수집기.

서버에 닿지 않는 속성만 검증한다 -- 문법, 변경 명령 부재, 결과 저장 위치 안전장치,
시크릿 누출 차단, 같은 입력에서 같은 출력(결정성).
"""
import os
import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "collect-security-baseline.sh"

# 서버 상태를 바꾸거나 파일 내용을 읽는 명령. 수집기에 있으면 안 된다.
FORBIDDEN = [
    r"\brm\b", r"\bmv\b", r"\bcp\b", r"\btee\b", r"\bchmod\b", r"\bchown\b",
    r"\bsed\s+-i", r"systemctl\s+(start|stop|restart|reload|enable|disable|mask)",
    r"firewall-cmd[^\n]*--(add|remove|set|reload|permanent)",
    r"\bauditctl\s+(-[aAdDeRw]\b|-b\b)", r"docker\s+(run|rm|rmi|stop|start|restart|"
    r"pull|prune|compose\s+up)", r"\bdocker\s+exec\b", r"(?<![-\w])cat(?![-\w])", r"\bhead\b",
    r"\btail\b", r"\bless\b",
]


def _code():
    # 서버에서 실행되는 remote_main만 본다(운영자 PC의 결과 폐기용 rm은 대상 밖).
    # 주석과 빈 줄은 제외한다.
    text = SCRIPT.read_text()
    body = text[text.index("remote_main() {"):text.index("# --- 운영자 쪽")]
    return "\n".join(l for l in body.splitlines() if l.strip() and not l.lstrip().startswith("#"))


def test_syntax_ok():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_no_mutating_or_content_reading_commands():
    code = _code()
    for pat in FORBIDDEN:
        assert not re.search(pat, code), f"금지 패턴 발견: {pat}"


def test_script_is_executable():
    assert SCRIPT.stat().st_mode & stat.S_IXUSR


def _run(args, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env
    )


def _call(fn, arg):
    # 스크립트를 source해 함수만 호출한다.
    return subprocess.run(
        ["bash", "-c", f'source "{SCRIPT}"; {fn} "$1"', "_", arg], capture_output=True, text=True
    )


def test_refuses_output_dir_inside_git_repo(tmp_path):
    r = _call("check_out_dir", str(REPO / "baseline-out"))
    assert r.returncode != 0
    assert "저장소" in r.stderr


def test_accepts_output_dir_outside_git_repo(tmp_path):
    r = _call("check_out_dir", str(tmp_path / "out"))
    assert r.returncode == 0, r.stderr


def test_secret_guard_rejects_private_key_and_assignments(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("## x\n-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert _call("check_no_secrets", str(bad)).returncode != 0
    bad.write_text("## x\nS3_SECRET_KEY=abcdef123\n")
    assert _call("check_no_secrets", str(bad)).returncode != 0


def test_secret_guard_accepts_metadata_only(tmp_path):
    ok = tmp_path / "ok.txt"
    ok.write_text("## secret-files\n640 root:dockermgmt /opt/services/x/proxy.secrets.env\n")
    assert _call("check_no_secrets", str(ok)).returncode == 0


def test_remote_mode_is_deterministic_and_non_secret(tmp_path):
    """같은 상태에서 두 번 돌리면 출력이 같다. 가짜 PATH로 외부 명령을 고정한다."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("ss", "docker", "firewall-cmd", "nft", "iptables", "sshd",
                 "fail2ban-client", "auditctl", "systemctl", "systemd-analyze",
                 "hostname"):
        p = bindir / name
        p.write_text("#!/bin/sh\necho stub-$(basename $0)\n")
        p.chmod(0o755)
    sudo = bindir / "sudo"
    sudo.write_text('#!/bin/sh\nshift\nexec "$@"\n')  # sudo -n <cmd>
    sudo.chmod(0o755)
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "BASELINE_FIND_ROOTS": str(tmp_path)}
    (tmp_path / "proxy.secrets.env").write_text("TOKEN=should-not-appear\n")
    a = _run(["--remote"], env)
    b = _run(["--remote"], env)
    assert a.returncode == 0, a.stderr
    assert a.stdout == b.stdout
    assert "should-not-appear" not in a.stdout
    assert "proxy.secrets.env" in a.stdout


def test_remote_aborts_when_sudo_unavailable(tmp_path):
    if os.geteuid() == 0:
        return
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sudo = bindir / "sudo"
    sudo.write_text("#!/bin/sh\nexit 1\n")
    sudo.chmod(0o755)
    r = _run(["--remote"], {"PATH": f"{bindir}:{os.environ['PATH']}"})
    assert r.returncode != 0
    assert "sudo" in r.stderr


def test_secret_guard_is_case_insensitive(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("password=hunter2\n")
    assert _call("check_no_secrets", str(bad)).returncode != 0


def test_failure_label_names_real_command_not_sudo(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("sudo", 'shift\nexec "$@"'), ("firewall-cmd", "exit 7")):
        p = bindir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(0o755)
    r = _run(["--remote"], {"PATH": f"{bindir}:{os.environ['PATH']}", "BASELINE_FIND_ROOTS": str(tmp_path)})
    assert "(unavailable: firewall-cmd --get-active-zones exit=7)" in r.stdout
    assert "(unavailable: sudo" not in r.stdout


def test_sshd_match_blocks_section_present(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("sudo", 'shift\nexec "$@"'), ("sshd", "echo permitrootlogin no")):
        p = bindir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(0o755)
    r = _run(["--remote"], {"PATH": f"{bindir}:{os.environ['PATH']}", "BASELINE_FIND_ROOTS": str(tmp_path),
                            "BASELINE_SSHD_MATCH_ADDRS": "192.0.2.1"})
    assert "## sshd-match-blocks" in r.stdout
    assert "# addr=192.0.2.1" in r.stdout
