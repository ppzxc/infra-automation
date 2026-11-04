"""적재된 감사 규칙과 배포한 규칙의 차이를 보는 필터 (#424).

`audit_rules_drift(loaded, declared)`는 `auditctl -l` 출력과 규칙 파일 본문을 비교해 차이 목록을 돌려준다(빈 목록 = 같음).
`auditctl -l`은 watch를 `-w` 또는 `-F path=/dir=` 형식으로, 키를 `-k` 또는 `-F key=`로 찍을 수 있어 두 표기를 모두 같게 본다.
공개 저장소라 가짜 경로만 쓴다.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from audit_rules import FilterModule, audit_rules_drift, audit_rules_drift_summary, audit_rules_probe_drift  # noqa: E402

DECLARED = """# Overseer Auditd Security Rules
-D
-b 8192
-f 1

-w /etc/passwd -p wa -k identity
-w /etc/pam.d/ -p wa -k auth_config
-w /etc/sudoers.d/ -p wa -k sudo_config
-w /srv/example/app.secrets.env -p rwa -k secret_access
"""

# `auditctl -l`이 watch를 -w 형식으로 찍는 경우
LOADED_W = """-w /etc/passwd -p wa -k identity
-w /etc/pam.d -p wa -k auth_config
-w /etc/sudoers.d -p wa -k sudo_config
-w /srv/example/app.secrets.env -p rwa -k secret_access
"""

# 같은 규칙을 -F path=/dir= 형식으로 찍는 경우(감사 패키지 버전에 따라 다르다)
LOADED_F = """-a always,exit -F path=/etc/passwd -F perm=wa -F key=identity
-a always,exit -F dir=/etc/pam.d -F perm=wa -F key=auth_config
-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F key=sudo_config
-a always,exit -F path=/srv/example/app.secrets.env -F perm=rwa -F key=secret_access
"""


def test_same_rules_have_no_drift_in_either_print_format():
    assert audit_rules_drift(LOADED_W, DECLARED) == []
    assert audit_rules_drift(LOADED_F, DECLARED) == []


def test_control_lines_comments_and_order_do_not_matter():
    shuffled = "\n".join(reversed(LOADED_W.strip().splitlines())) + "\n"
    assert audit_rules_drift(shuffled, DECLARED) == []
    assert audit_rules_drift(LOADED_W, "-e 1\n--backlog_wait_time 60000\n" + DECLARED + "# -w /etc/gone -k gone\n") == []


def test_nothing_loaded_reports_every_declared_rule_as_missing():
    drift = audit_rules_drift("No rules\n", DECLARED)
    assert len(drift) == 4
    assert all(line.startswith("적재 안 됨") for line in drift)
    assert audit_rules_drift("", DECLARED) == drift


def test_leftover_execve_rule_is_reported_as_unexpected():
    loaded = LOADED_W + "-a always,exit -F arch=b64 -S execve -F key=exec_log\n-a always,exit -F arch=b32 -S execve -F key=exec_log\n"
    assert audit_rules_drift(loaded, DECLARED) == ["선언에 없는 규칙이 적재됨: 키 exec_log"]


def test_changed_permissions_or_missing_watch_are_reported():
    loaded = LOADED_W.replace("-p wa -k identity", "-p w -k identity").replace("-w /etc/sudoers.d -p wa -k sudo_config\n", "")
    drift = audit_rules_drift(loaded, DECLARED)
    assert "적재 안 됨: watch /etc/passwd 권한 wa 키 identity" in drift
    assert "적재 안 됨: watch /etc/sudoers.d 권한 wa 키 sudo_config" in drift
    assert "선언에 없는 규칙이 적재됨: watch /etc/passwd 권한 w 키 identity" in drift


def test_permission_letter_order_is_not_drift():
    assert audit_rules_drift("-w /x -p aw -k k\n", "-w /x -p wa -k k\n") == []


def test_syscall_rules_are_compared_by_key():
    declared = "-a always,exit -F arch=b64 -S mount -k mounts\n-a always,exit -F arch=b32 -S mount -k mounts\n"
    loaded = "-a always,exit -F arch=b64 -S mount -F key=mounts\n-a always,exit -F arch=b32 -S mount -F key=mounts\n"
    assert audit_rules_drift(loaded, declared) == []
    assert audit_rules_drift("No rules", declared) == ["적재 안 됨: 키 mounts"]


def test_registered_as_a_jinja_filter():
    assert FilterModule().filters()["audit_rules_drift"] is audit_rules_drift
    assert FilterModule().filters()["audit_rules_probe_drift"] is audit_rules_probe_drift
    assert FilterModule().filters()["audit_rules_drift_summary"] is audit_rules_drift_summary


# --- 다른 rules.d 파일 (augenrules는 rules.d/*.rules를 모두 합쳐 적재한다) -------------------------

OTHER = "-D\n-b 8192\n-w /etc/hosts -p wa -k hosts_change\n-a always,exit -F arch=b64 -S mount -k mounts\n"


def test_rules_from_other_rules_d_files_count_as_declared():
    probe = LOADED_W + "-w /etc/hosts -p wa -k hosts_change\n-a always,exit -F arch=b64 -S mount -F key=mounts\n" + "__OVERSEER_OTHER_RULES__\n" + OTHER
    assert audit_rules_probe_drift(probe, DECLARED) == []


def test_probe_output_still_reports_missing_and_stale_rules():
    probe = "-a always,exit -F arch=b64 -S execve -F key=exec_log\n__OVERSEER_OTHER_RULES__\n" + OTHER
    drift = audit_rules_probe_drift(probe, DECLARED)
    assert "적재 안 됨: watch /etc/hosts 권한 wa 키 hosts_change" in drift
    assert "선언에 없는 규칙이 적재됨: 키 exec_log" in drift
    assert len([d for d in drift if d.startswith("적재 안 됨")]) == 6


def test_probe_output_without_other_files_behaves_like_the_plain_comparison():
    assert audit_rules_probe_drift(LOADED_W + "__OVERSEER_OTHER_RULES__\n", DECLARED) == []
    assert audit_rules_probe_drift(LOADED_W, DECLARED) == []
    assert audit_rules_probe_drift("No rules\n__OVERSEER_OTHER_RULES__\n", DECLARED) == audit_rules_drift("", DECLARED)


# --- 권한 생략 watch (#424 리뷰) ----------------------------------------------------------------

def test_watch_without_p_equals_rwxa():
    # `-p` 없는 watch는 모든 권한(rwxa)이고 `auditctl -l`은 `-p rwxa`로 찍는다.
    assert audit_rules_drift("-w /x -p rwxa -k k", "-w /x -k k") == []
    assert audit_rules_drift("-w /x -k k", "-w /x -p rwxa -k k") == []
    assert audit_rules_drift("-a always,exit -F path=/x -F perm=rwxa -F key=k", "-w /x -k k") == []
    assert audit_rules_drift("-w /x -p wa -k k", "-w /x -k k") != []


# --- 로그에 남는 요약은 경로를 담지 않는다 ------------------------------------------------------

def test_summary_has_counts_and_key_names_but_no_paths():
    declared = DECLARED + "-w /srv/example/other.key -p rwa -k secret_access\n"
    probe = "-a always,exit -F arch=b64 -S execve -F key=exec_log\n__OVERSEER_OTHER_RULES__\n"
    summary = audit_rules_drift_summary(probe, declared)
    assert "적재 안 됨 5건" in summary and "선언에 없는 규칙 1건" in summary
    for key in ("identity", "auth_config", "sudo_config", "secret_access", "exec_log"):
        assert key in summary
    for secret in ("/srv/example", "/etc/passwd", "other.key", "app.secrets.env"):
        assert secret not in summary


def test_summary_is_empty_when_there_is_no_drift():
    assert audit_rules_drift_summary(LOADED_W + "__OVERSEER_OTHER_RULES__\n", DECLARED) == ""
