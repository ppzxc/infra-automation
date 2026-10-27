"""scripts/collect-receiver-sources.sh (#370): 수신기 실제 출발지·트랩 인증 문자열 읽기 전용 수집기.

서버에 닿지 않는 속성만 검증한다 -- 문법, 변경 명령 부재, 저장 위치 안전장치,
인증 문자열 값 마스킹, 결정성.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "collect-receiver-sources.sh"

FORBIDDEN = [
    r"\brm\b", r"\bmv\b", r"\bcp\b", r"\btee\b", r"\bchmod\b", r"\bchown\b",
    r"\bsed\s+-[a-zA-Z]*i", r"systemctl\s+(start|stop|restart|reload|enable|disable|mask)",
    r"firewall-cmd", r"\biptables\b", r"\bnft\b", r"\bconntrack\s+-[DIFU]\b",
    r"docker\s+(run|rm|rmi|stop|start|restart|pull|prune|compose|exec|kill)",
    r"syslog-ng-ctl\s+reload", r"\bkill(all)?\b", r"\bsnmptrap\b", r"\blogger\b",
    r"(?<![-\w])cat(?![-\w])", r"\bhead\b", r"\btail\b", r"\bless\b", r"\bmktemp\b",
]


def _code():
    text = SCRIPT.read_text()
    body = text[text.index("remote_main() {"):text.index("# --- 운영자 쪽")]
    return "\n".join(l for l in body.splitlines() if l.strip() and not l.lstrip().startswith("#"))


def _stubs(tmp_path, extra=None):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    bodies = {
        "sudo": 'shift\nexec "$@"',
        "hostname": "echo stub-host",
        "ss": "echo 'udp UNCONN 0 0 0.0.0.0:162 0.0.0.0:* users:((\"snmptrapd\",pid=1,fd=5))'",
        "conntrack": "echo 'udp 17 20 src=192.0.2.10 dst=192.0.2.1 sport=1 dport=162 src=192.0.2.1 dst=192.0.2.10 sport=162 dport=1'",
        "docker": "true",
    }
    bodies.update(extra or {})
    for name, body in bodies.items():
        p = bindir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(0o755)
    return bindir


def _run(args, env_extra=None):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True,
                          env=dict(os.environ, **(env_extra or {})))


def _call(fn, arg):
    return subprocess.run(["bash", "-c", f'source "{SCRIPT}"; {fn} "$1"', "_", arg],
                          capture_output=True, text=True)


def _remote(tmp_path, log_lines, conf_lines=""):
    bindir = _stubs(tmp_path)
    log = tmp_path / "trap.log"
    log.write_text(log_lines)
    conf = tmp_path / "snmptrapd.conf"
    conf.write_text(conf_lines)
    return _run(["--remote"], {
        "PATH": f"{bindir}:{os.environ['PATH']}", "RECEIVER_TRAP_LOG_FILES": str(log),
        "RECEIVER_TRAP_CONF_FILES": str(conf), "RECEIVER_SYSLOG_DIR": str(tmp_path / "remote"),
    })


LOG = (
    'UDP: [192.0.2.10]:41000->[192.0.2.1]:162 SNMPv2-MIB::snmpTrapCommunity.0 = STRING: "s3cretvalue"\n'
    'UDP: [192.0.2.11]:41001->[192.0.2.1]:162 SNMPv2-MIB::snmpTrapCommunity.0 = STRING: "public"\n'
)


def test_syntax_ok():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_script_is_executable():
    assert SCRIPT.stat().st_mode & stat.S_IXUSR


def test_no_mutating_commands():
    code = _code()
    for pat in FORBIDDEN:
        assert not re.search(pat, code), f"금지 패턴 발견: {pat}"


def test_refuses_output_dir_inside_git_repo():
    r = _call("check_out_dir", str(REPO / "out"))
    assert r.returncode != 0 and "저장소" in r.stderr


def test_accepts_output_dir_outside_git_repo(tmp_path):
    assert _call("check_out_dir", str(tmp_path / "out")).returncode == 0


def test_secret_guard_rejects_assignment(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("community_token=abc123\n")
    assert _call("check_no_secrets", str(bad)).returncode != 0


def test_sources_are_collected_and_auth_values_are_masked(tmp_path):
    r = _remote(tmp_path, LOG)
    assert r.returncode == 0, r.stderr
    srcs = r.stdout.split("## trap-sources-from-logs")[1].split("\n## ")[0]
    assert "192.0.2.10" in srcs and "192.0.2.11" in srcs
    assert "s3cretvalue" not in r.stdout and "s3cretvalue" not in r.stderr
    masked = r.stdout.split("## trap-auth-strings-masked")[1].split("\n## ")[0]
    assert re.search(r"len=11 sha256:[0-9a-f]{12}$", masked, re.M)
    assert "len=6" in masked and "default-string" in masked


def test_conntrack_sources_listed_without_counters(tmp_path):
    r = _remote(tmp_path, LOG)
    sect = r.stdout.split("## conntrack-sources")[1].split("\n## ")[0]
    assert "192.0.2.10" in sect
    assert "sport" not in sect


def test_config_directive_hides_string_and_passphrase(tmp_path):
    conf = ("authCommunity log,net confidentialstr 192.0.2.0/24\n"
            "createUser alice SHA mysecretpassphrase\n"
            "disableAuthorization no\n")
    r = _remote(tmp_path, "", conf)
    sect = r.stdout.split("## trap-auth-directives")[1]
    assert "confidentialstr" not in r.stdout
    assert "mysecretpassphrase" not in r.stdout
    assert "source=192.0.2.0/24" in sect
    assert "createUser name=alice" in sect
    assert "disableAuthorization no" in sect


def test_output_is_deterministic_and_passes_secret_guard(tmp_path):
    a = _remote(tmp_path, LOG, "authCommunity log,net xyzxyz\n")
    b = _remote(tmp_path, LOG, "authCommunity log,net xyzxyz\n")
    assert a.stdout == b.stdout
    out = tmp_path / "out.txt"
    out.write_text(a.stdout)
    assert _call("check_no_secrets", str(out)).returncode == 0


def test_remote_aborts_when_sudo_unavailable(tmp_path):
    if os.geteuid() == 0:
        return
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sudo = bindir / "sudo"
    sudo.write_text("#!/bin/sh\nexit 1\n")
    sudo.chmod(0o755)
    r = _run(["--remote"], {"PATH": f"{bindir}:{os.environ['PATH']}"})
    assert r.returncode != 0 and "sudo" in r.stderr


# --- 런북 문서 검사 ---------------------------------------------------------------
RUNBOOK = REPO / "docs" / "runbooks" / "receiver-source-restriction.md"
INDEX = REPO / "docs" / "INDEX.md"


def test_runbook_has_required_sections_and_firewall_invariant():
    text = RUNBOOK.read_text(encoding="utf-8")
    for title in ("실현성 확인 보고 양식", "적용 전 수집", "적용 절차", "롤백 절차", "적용 후 검증", "체크리스트", "Host Audit 연계"):
        assert re.search(rf"^## \d+\. {title}", text, re.M), title
    assert "수신기가 실제로 보는 출발지" in text
    assert "방화벽 체인 불변" in text
    assert "부정 시험" in text
    assert "collect-receiver-sources.sh" in text


def test_runbook_carries_no_infrastructure_details():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), "IP 주소"
    assert not re.search(r"\bns0\d{3}\b", text), "관리번호"
    assert not re.search(r"(?i)\bport\s*[:=]?\s*\d{2,5}\b|포트\s*\d{2,5}|\b[A-Za-z][A-Za-z0-9.-]*:\d{2,5}\b", text), "포트"
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text), "시크릿 값"


def test_runbook_is_linked_from_the_docs_index():
    assert "runbooks/receiver-source-restriction.md" in INDEX.read_text(encoding="utf-8")
