"""Host Audit Security Regression probe (Spec #364 / Ticket-10, #377).

프로브(roles/host_audit/files/regression_probe.sh)를 이 머신의 sh로 가짜 루트(HA_REGRESSION_ROOT)와
PATH 위의 가짜 조회 명령(ss, docker, sshd, fail2ban-client, auditctl, systemctl)으로 실행한다.
정상 상태에서 PASS, 의도적으로 퇴행시킨 상태에서 FAIL이 나오는 것과 출력에 값이 없는 것을 본다.
공개 저장소라 주소는 문서용(RFC 5737)·가짜 값만 쓴다.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
PROBE = ROOT_DIR / "roles" / "host_audit" / "files" / "regression_probe.sh"

SSHD_CONFIG = """PermitRootLogin no
# BEGIN ANSIBLE MANAGED sshd source restriction (#371)
Match Address *,!127.0.0.1,!::1,!192.0.2.0/24
    DenyUsers *
# END ANSIBLE MANAGED sshd source restriction (#371)
"""
SYSLOG_CONF = """filter f_known { netmask("192.0.2.0/24"); };
log { source(s_net); filter(f_known); destination(d_files); };
"""
TRAP_CONF = "authCommunity log,execute,net secret-1 192.0.2.7\n"
AUDIT_RULES = (
    "-w /etc/passwd -p wa -k identity\n-w /etc/pam.d/ -p wa -k auth_config\n"
    "-w /etc/sudoers -p wa -k sudo_config\n-w /etc/ssh/sshd_config -p wa -k sshd_config\n"
    "-w /etc/fake.key -p rwa -k secret_access\n"
)
# 기본 허용 목록 밖에서 청취하는 접점이 없는 상태: 관리 웹은 루프백, 프록시(443)와 SSH(22)만 모든 주소.
SS_OK = """State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 0.0.0.0:443 0.0.0.0:*
LISTEN 0 128 127.0.0.1:3000 0.0.0.0:*
"""


def _shim(bindir, name, body):
    path = bindir / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def _env_files(root, sshd_config=SSHD_CONFIG):
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text(sshd_config)
    (root / "etc/systemd/journald.conf.d").mkdir(parents=True)
    (root / "etc/systemd/journald.conf.d/persistent.conf").write_text("[Journal]\nStorage=persistent\n")
    (root / "var/log/journal").mkdir(parents=True)
    (root / "etc/syslog").mkdir(parents=True)
    (root / "etc/syslog/user.conf").write_text(SYSLOG_CONF)
    (root / "etc/snmp").mkdir(parents=True)
    (root / "etc/snmp/snmptrapd.conf").write_text(TRAP_CONF)
    (root / "opt/app").mkdir(parents=True)
    secret = root / "opt/app/root-only.key"
    secret.write_text("x")
    secret.chmod(0o600)
    envf = root / "opt/app/proxy.secrets.env"
    envf.write_text("x")
    envf.chmod(0o640)


def _shims(bindir, ss=SS_OK, f2b_actions="dummy", audit=AUDIT_RULES, sshd_deny=True, agent_active=True):
    bindir.mkdir(parents=True, exist_ok=True)
    _shim(bindir, "ss", "cat <<'E'\n%sE\n" % ss)
    _shim(bindir, "docker", "exit 0\n")
    _shim(bindir, "sshd", (
        'for a in "$@"; do case "$a" in user=*addr=*) addr=${a##*addr=};; esac; done\n'
        'echo "port 22"\n'
        'case "$addr" in 192.0.2.*|127.0.0.1) echo "denyusers none";; *) %s;; esac\n'
        % ('echo "denyusers *"' if sshd_deny else 'echo "denyusers none"')))
    _shim(bindir, "fail2ban-client", (
        'case "$1 $2" in "status sshd") exit 0;; "get sshd") echo "The jail sshd has the following actions:"; echo "%s";; esac\n' % f2b_actions))
    _shim(bindir, "auditctl", "cat <<'E'\n%sE\n" % audit)
    _shim(bindir, "systemctl", 'case "$*" in *otelcol*) exit %d;; *) exit 3;; esac\n' % (0 if agent_active else 3))


EXPECT = {
    "HA_MGMT_WEB_PORTS": "3000",
    "HA_MGMT_WILDCARD_ALLOWED": "22 443",
    "HA_MGMT_REMOVED_PORTS": "9000",
    "HA_MGMT_REMOVED_NAMES": "old-admin",
    "HA_RECV_SYSLOG_CONF": "/etc/syslog/user.conf",
    "HA_RECV_TRAP_CONF": "/etc/snmp/snmptrapd.conf",
    "HA_SSH": "1",
    "HA_SSH_ALLOWED_ADDRS": "192.0.2.10",
    "HA_DET_JOURNALD": "1",
    "HA_DET_F2B": "1",
    "HA_DET_F2B_NOFW": "1",
    "HA_DET_AUDIT": "1",
    "HA_DET_AUDIT_SECRET": "1",
    "HA_DET_AGENT": "otelcol",
    "HA_SEC_ROOTS": "/opt",
    "HA_SEC_FILES": "/opt/app/root-only.key",
    "HA_SEC_ENV_FILES": "/opt/app/proxy.secrets.env",
}


def _run(tmp_path, env_extra=None, **shim_kwargs):
    root = tmp_path / "root"
    bindir = tmp_path / "bin"
    if not root.exists():
        _env_files(root)
    _shims(bindir, **shim_kwargs)
    user = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    group = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
    env = {"PATH": "%s:%s" % (bindir, os.environ["PATH"]), "HA_REGRESSION_ROOT": str(root),
           "HA_FAKE_ROOT_OWNER": user, "HA_FAKE_DOCKERMGMT_GROUP": group}
    env.update(EXPECT)
    env.update(env_extra or {})
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    body = out.stdout.split("__HOST_AUDIT_REGRESSION_BEGIN__")[1].split("__HOST_AUDIT_REGRESSION_END__")[0]
    return dict(line.split("|") for line in body.split() if "|" in line)


ALL_IDS = ["EXP-MGMT-1", "EXP-MGMT-2", "EXP-MGMT-3", "EXP-RECV-1", "EXP-RECV-2", "EXP-RECV-3",
           "EXP-SSH-1", "EXP-SSH-2", "EXP-SSH-3", "EXP-SSH-4",
           "EXP-DET-1", "EXP-DET-2", "EXP-DET-3", "EXP-DET-4", "EXP-DET-5", "EXP-DET-6", "EXP-DET-7",
           "EXP-SEC-1", "EXP-SEC-2", "EXP-SEC-3"]


def test_a_healthy_host_passes_every_declared_item(tmp_path):
    result = _run(tmp_path)
    assert sorted(result) == sorted(ALL_IDS)
    assert set(result.values()) == {"PASS"}, result


def test_nothing_declared_prints_nothing(tmp_path):
    blank = {k: "" for k in EXPECT}
    assert _run(tmp_path, blank) == {}


def test_output_carries_only_ids_and_verdicts(tmp_path):
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, env={"PATH": os.environ["PATH"], **EXPECT, "HA_REGRESSION_ROOT": str(tmp_path)})
    for line in out.stdout.splitlines():
        assert line.startswith("__") or re.fullmatch(r"EXP-[A-Z]+-\d\|(PASS|FAIL|UNK)", line), line
    assert not re.search(r"\d+\.\d+\.\d+\.\d+|:\d{2,5}", out.stdout)


def test_probe_writes_nothing_on_the_host(tmp_path):
    _run(tmp_path)
    before = sorted(str(p) for p in (tmp_path / "root").rglob("*"))
    _run(tmp_path)
    assert before == sorted(str(p) for p in (tmp_path / "root").rglob("*"))


# 퇴행: (이름, 퇴행시키는 방법, 실패해야 하는 항목)
def _unbind_mgmt(tmp):  # 관리 웹이 모든 주소에 열림
    return {"ss": SS_OK + "LISTEN 0 128 0.0.0.0:3000 0.0.0.0:*\n"}


def _extra_wildcard(tmp):  # 허용 목록에 없는 포트가 모든 주소에 열림(프록시 외 경로)
    return {"ss": SS_OK + "LISTEN 0 128 [::]:8080 [::]:*\n"}


def _removed_back(tmp):  # 제거한 인터페이스 포트가 다시 올라옴
    return {"ss": SS_OK + "LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*\n"}


@pytest.mark.parametrize("shims,failing", [
    (_unbind_mgmt, {"EXP-MGMT-1", "EXP-MGMT-2"}),
    (_extra_wildcard, {"EXP-MGMT-2"}),
    (_removed_back, {"EXP-MGMT-3"}),
])
def test_listener_regressions_fail(tmp_path, shims, failing):
    result = _run(tmp_path, **shims(tmp_path))
    assert {k for k, v in result.items() if v == "FAIL"} == failing


def test_docker_published_all_addresses_fails_mgmt(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    _run(tmp_path)  # shims
    _shim(tmp_path / "bin", "docker", 'case "$1" in ps) case "$*" in *Names*) exit 0;; *) echo "0.0.0.0:3000->3000/tcp, :::3000->3000/tcp";; esac;; esac\n')
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, env={
        "PATH": "%s:%s" % (tmp_path / "bin", os.environ["PATH"]), "HA_REGRESSION_ROOT": str(root), **EXPECT})
    assert "EXP-MGMT-1|FAIL" in out.stdout


def test_receiver_regressions_fail(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "etc/syslog/user.conf").write_text("destination d { file(\"/x\"); };\n")  # 필터 없음
    (root / "etc/snmp/snmptrapd.conf").write_text("disableAuthorization yes\n")  # 인증 없음, 기본 허용
    result = _run(tmp_path)
    assert result["EXP-RECV-1"] == "FAIL" and result["EXP-RECV-2"] == "FAIL"


def test_trap_default_string_fails(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "etc/snmp/snmptrapd.conf").write_text("authCommunity log,execute,net public 192.0.2.7\n")
    result = _run(tmp_path)
    assert result["EXP-RECV-2"] == "PASS" and result["EXP-RECV-3"] == "FAIL"


def test_ssh_block_removed_fails_block_and_allow_list_items(tmp_path):
    root = tmp_path / "root"
    _env_files(root, sshd_config="PermitRootLogin no\n")
    result = _run(tmp_path, sshd_deny=False)
    assert {result[i] for i in ("EXP-SSH-1", "EXP-SSH-2", "EXP-SSH-4")} == {"FAIL"}


def test_ssh_empty_allow_list_fails(tmp_path):
    root = tmp_path / "root"
    _env_files(root, sshd_config=SSHD_CONFIG.replace(",!192.0.2.0/24", ""))
    assert _run(tmp_path)["EXP-SSH-4"] == "FAIL"


def test_ssh_blocking_an_allowed_source_fails(tmp_path):
    # 모든 주소를 막는 설정(허용 출발지도 거부)
    root = tmp_path / "root"
    _env_files(root)
    _shims(tmp_path / "bin")
    _shim(tmp_path / "bin", "sshd", 'echo "port 22"\necho "denyusers *"\n')
    env = {"PATH": "%s:%s" % (tmp_path / "bin", os.environ["PATH"]), "HA_REGRESSION_ROOT": str(root), "HA_SSH": "1", "HA_SSH_ALLOWED_ADDRS": "192.0.2.10"}
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, env=env).stdout
    assert "EXP-SSH-3|FAIL" in out


def test_ssh_unknown_when_sshd_cannot_evaluate(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    _shims(tmp_path / "bin")
    _shim(tmp_path / "bin", "sshd", "exit 255\n")
    env = {"PATH": "%s:%s" % (tmp_path / "bin", os.environ["PATH"]), "HA_REGRESSION_ROOT": str(root), "HA_SSH": "1"}
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, env=env).stdout
    assert "EXP-SSH-2|UNK" in out and "EXP-SSH-3|UNK" in out


def test_journald_volatile_fails(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "etc/systemd/journald.conf.d/persistent.conf").write_text("[Journal]\nStorage=volatile\n")
    assert _run(tmp_path)["EXP-DET-1"] == "FAIL"


def test_journald_without_directory_fails(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "var/log/journal").rmdir()
    assert _run(tmp_path)["EXP-DET-1"] == "FAIL"


def test_fail2ban_with_a_firewall_action_fails_only_the_action_item(tmp_path):
    result = _run(tmp_path, f2b_actions="iptables-multiport")
    assert result["EXP-DET-2"] == "PASS" and result["EXP-DET-3"] == "FAIL"


def test_missing_audit_keys_or_execve_tracing_fail(tmp_path):
    no_keys = _run(tmp_path, audit="-w /etc/passwd -p wa -k identity\n")
    assert no_keys["EXP-DET-4"] == "FAIL" and no_keys["EXP-DET-6"] == "FAIL"
    execve = _run(tmp_path, audit=AUDIT_RULES + "-a always,exit -S execve -k exec\n")
    assert execve["EXP-DET-5"] == "FAIL" and execve["EXP-DET-4"] == "PASS"


def test_no_loaded_audit_rules_fail(tmp_path):
    result = _run(tmp_path, audit="No rules\n")
    assert result["EXP-DET-4"] == "FAIL"


def test_stopped_log_agent_fails(tmp_path):
    assert _run(tmp_path, agent_active=False)["EXP-DET-7"] == "FAIL"


def test_secret_permission_regressions_fail(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "opt/app/root-only.key").chmod(0o644)
    (root / "opt/app/proxy.secrets.env").chmod(0o644)
    result = _run(tmp_path)
    assert {result[i] for i in ("EXP-SEC-1", "EXP-SEC-2", "EXP-SEC-3")} == {"FAIL"}


def test_env_file_wrong_group_or_missing_file_fails(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    result = _run(tmp_path, {"HA_FAKE_DOCKERMGMT_GROUP": "no-such-group", "HA_SEC_FILES": "/opt/app/gone.key"})
    assert result["EXP-SEC-3"] == "FAIL" and result["EXP-SEC-2"] == "FAIL"


def test_env_file_exception_mode_is_allowed_but_not_wider(tmp_path):
    root = tmp_path / "root"
    _env_files(root)
    (root / "opt/app/proxy.secrets.env").chmod(0o660)
    assert _run(tmp_path)["EXP-SEC-3"] == "FAIL"
