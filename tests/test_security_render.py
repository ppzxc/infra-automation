"""security 역할 탐지·복구 렌더링 테스트(Spec #364 / #372).

auditd 규칙·fail2ban jail·journald 영구 저장 드롭인을 세션당 한 번만 렌더링해(`security_rendered`) 기대치를 읽는다.
`ansible-playbook`을 테스트마다 돌리지 않으므로 `slow`가 아니다(AGENTS.md 5.1). 렌더링 helper는 `tests/security_render.py`(#371도 재사용).
"""
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

from security_render import ROOT_DIR, rule_lines, security_tasks, shared_render
from security_render import security_task as _task

pytestmark = pytest.mark.xdist_group("security-render")

ROLE = ROOT_DIR / "roles" / "security"


@pytest.fixture(scope="session")
def security_rendered():
    """`{케이스: {audit|fail2ban|journald|sshd_source: 렌더링 텍스트}}`."""
    return shared_render()


# --- auditd 규칙 -------------------------------------------------------------------------------

def test_audit_rules_do_not_trace_every_execve(security_rendered):
    for case, out in security_rendered.items():
        if "audit" not in out:  # 감시 키 계산만 보는 케이스(CASE_OUTPUTS)
            continue
        lines = rule_lines(out["audit"])  # 주석은 제외
        # execve는 자격 전환(-C uid!=euid, gid!=egid)이 있는 증적 규칙만 건다(아래 절). 필터 없는 execve 규칙은 전수 추적이다.
        assert all(_rule(ln)["compares"] for ln in lines if ln.startswith("-a ") and "execve" in ln), case
        # syscall 규칙은 알림 키 둘과 증적 전용 키 넷뿐이다(아래 절). 그 밖의 syscall을 전수로 추적하지 않는다.
        assert {_rule(ln)["key"] for ln in lines if ln.startswith("-a ")} <= set(ALERT_SYSCALL_KEYS) | EVIDENCE_SYSCALL_KEYS, case


def test_audit_rules_keep_meaningful_events(security_rendered):
    lines = rule_lines(security_rendered["default"]["audit"])
    for expected in ("-D", "-w /etc/shadow -p wa -k identity", "-w /etc/pam.d/ -p wa -k auth_config",
                     "-w /etc/sudoers.d/ -p wa -k sudo_config", "-w /etc/ssh/sshd_config -p wa -k sshd_config",
                     "-w /etc/docker/ -p wa -k container_config"):
        assert expected in lines
    assert lines[0] == "-D"


def test_audit_rules_are_small(security_rendered):
    assert len(rule_lines(security_rendered["default"]["audit"])) < 50


def test_audit_rules_have_no_secret_watch_without_configured_paths(security_rendered):
    assert "secret_access" not in security_rendered["default"]["audit"]


def test_audit_rules_watch_configured_secret_and_container_paths(security_rendered):
    lines = rule_lines(security_rendered["secret_paths"]["audit"])
    assert "-w /srv/example/app.secrets.env -p rwa -k secret_access" in lines
    assert "-w /srv/example/other.key -p rwa -k secret_access" in lines
    assert "-w /srv/example/compose/ -p wa -k container_config" in lines


def test_audit_rules_do_not_lock_the_rule_set(security_rendered):
    # -e 2(잠금)는 규칙 변경에 재부팅이 필요해 쓰지 않는다.
    assert not any(ln.startswith("-e ") for ln in rule_lines(security_rendered["default"]["audit"]))


# --- syscall 규칙: /var/log 삭제·자르기와 커널 모듈 (Spec #433 / Ticket-5, #431) -------------------------------------------

ALERT_SYSCALL_KEYS = ("var_log_delete", "kernel_module")   # 알림이 읽는 syscall 규칙 키. 증적 전용 규칙(#435)은 이 목록에 넣지 않는다
EVIDENCE_SYSCALL_KEYS = {"evidence_privileged_exec", "evidence_file_delete", "evidence_time_change", "evidence_mount"}   # Evidence-Only Watch Key(#435)
EVIDENCE_KEYS = EVIDENCE_SYSCALL_KEYS | {"evidence_login_records"}


def _rule(line):
    """`-a always,exit -F arch=b64 -S a,b -F x=y -k key` -> {arch, syscalls, fields, key}."""
    tokens = line.split()
    assert tokens[:2] == ["-a", "always,exit"], line
    out = {"arch": None, "syscalls": set(), "fields": [], "compares": [], "key": None}
    it = iter(tokens[2:])
    for flag in it:
        value = next(it)
        if flag == "-S":
            out["syscalls"] |= set(value.split(","))
        elif flag == "-F" and value.startswith("arch="):
            out["arch"] = value.removeprefix("arch=")
        elif flag == "-F":
            out["fields"].append(value)
        elif flag == "-C":   # 필드끼리 비교(uid!=euid)
            out["compares"].append(value)
        elif flag == "-k":
            out["key"] = value
        else:
            raise AssertionError(line)
    return out


def _syscall_rules(text, key):
    return [_rule(ln) for ln in rule_lines(text) if ln.startswith("-a ") and f" -k {key}" in ln]


AUID_UNSET_FORMS = ("auid!=unset", "auid!=4294967295")   # audit.rules(7): 둘은 같은 뜻이다(EL6·7 auditd는 숫자만 안전)


def _is_login_user_only(rule):
    return "auid>=1000" in rule["fields"] and any(f in rule["fields"] for f in AUID_UNSET_FORMS)


def _syscalls_by_arch(rules):
    out = {}
    for r in rules:
        out.setdefault(r["arch"], set()).update(r["syscalls"])
    return out


def test_kernel_module_rules_catch_load_and_unload_by_login_users_on_both_arches(security_rendered):
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "kernel_module")
        assert rules, case
        assert all(_is_login_user_only(r) for r in rules), case
        expected = {"init_module", "delete_module"} | (set() if case == "el6" else {"finit_module"})
        assert _syscalls_by_arch(rules) == {"b64": expected, "b32": expected}, case


def test_el6_rules_leave_out_finit_module_because_the_el6_kernel_has_no_such_syscall_and_auditctl_would_reject_the_whole_rule(security_rendered):
    for case, out in security_rendered.items():
        assert any("finit_module" in ln for ln in rule_lines(out["audit"])) == (case != "el6"), case


def test_var_log_rules_catch_delete_rename_truncate_and_o_trunc_opens_under_var_log_for_login_users_on_both_arches(security_rendered):
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "var_log_delete")
        assert rules and all(_is_login_user_only(r) for r in rules), case
        assert all("dir=/var/log" in r["fields"] for r in rules), case          # 경로 필터는 디렉터리 하위 전체
        by_arch = _syscalls_by_arch(rules)
        for arch in ("b64", "b32"):
            assert {"unlink", "unlinkat", "rename", "renameat", "truncate", "ftruncate", "creat", "open", "openat"} <= by_arch[arch], arch
        assert set(by_arch) == {"b64", "b32"}, case


def test_the_open_rules_match_the_truncate_flag_and_any_write_open_so_truncate_s0_and_ftruncate_leave_a_record(security_rendered):
    """`open`은 flags가 두 번째 인자(a1), `openat`은 세 번째(a2)다. `&`는 마스크 중 하나라도 켜져 있으면 참이다.
    O_TRUNC(0x200)는 `> file`을 잡고, 쓰기 열기(O_WRONLY 0x1 | O_RDWR 0x2 = 0x3)는 `truncate -s0`(O_TRUNC 없이 열고 ftruncate)과
    파일 기술자만 받는 ftruncate를 잡는다(#441). 읽기 열기(O_RDONLY)는 어느 쪽에도 걸리지 않는다."""
    rules = _syscall_rules(security_rendered["default"]["audit"], "var_log_delete")
    for arch in ("b64", "b32"):
        opens = [r for r in rules if r["arch"] == arch and r["syscalls"] & {"open", "openat"}]
        assert opens, arch
        for r in opens:
            assert not (r["syscalls"] & {"unlink", "unlinkat", "rename", "renameat", "truncate", "ftruncate", "creat"}), r
        got = {(tuple(sorted(r["syscalls"])), tuple(f for f in r["fields"] if f[:1] == "a" and f[2:3] == "&")) for r in opens}
        assert got == {
            (("open",), ("a1&0x200",)), (("openat",), ("a2&0x200",)),
            (("open",), ("a1&0x3",)), (("openat",), ("a2&0x3",)),
        }, arch


def test_the_syscall_rules_are_independent_of_host_variables_and_never_log_everything(security_rendered):
    default = {k: _syscall_rules(security_rendered["default"]["audit"], k) for k in ALERT_SYSCALL_KEYS}
    for case, out in security_rendered.items():
        syscall_lines = [ln for ln in rule_lines(out["audit"]) if ln.startswith("-a ")]
        assert _syscall_rules(out["audit"], "var_log_delete") == default["var_log_delete"], case
        if case != "el6":                             # EL6만 finit_module이 빠진다(위 테스트)
            assert _syscall_rules(out["audit"], "kernel_module") == default["kernel_module"], case
        for ln in syscall_lines:                      # 알림 키 규칙은 로그인 사용자 필터를 갖는다(사용자 구분 없는 전수 기록 금지). 증적 규칙의 필터는 그 티켓이 정한다
            if _rule(ln)["key"] in ALERT_SYSCALL_KEYS:
                assert _is_login_user_only(_rule(ln)), ln


def test_syscall_rule_keys_are_distinct_from_the_watch_keys_so_alerts_and_evidence_can_tell_them_apart(security_rendered):
    lines = rule_lines(security_rendered["default"]["audit"])
    watch_keys = {ln.split(" -k ")[1] for ln in lines if ln.startswith("-w ")}
    syscall_keys = {_rule(ln)["key"] for ln in lines if ln.startswith("-a ")}
    assert syscall_keys == set(ALERT_SYSCALL_KEYS) | EVIDENCE_SYSCALL_KEYS
    assert not set(ALERT_SYSCALL_KEYS) & watch_keys             # 알림이 읽는 키는 감시 키와 겹치지 않는다
    assert watch_keys & syscall_keys == {"evidence_time_change"}  # 같은 뜻(시간 변경)의 syscall 규칙과 /etc/localtime 감시만 한 증적 키를 나눈다


def test_var_log_syscall_rules_come_before_every_other_rule_that_matches_a_file_under_var_log(security_rendered):
    """커널은 첫 번째로 맞는 규칙의 키만 기록한다(audit.rules(7), first match wins). `-w /var/log/sudo.log` 감시가 var_log_delete보다 앞이면
    로그인 사용자가 sudo.log를 지우거나 자른 기록이 `sudo_logs` 키로만 남아 P1 알림이 울리지 않는다(`sudo_logs`는 알림 대상이 아니다).
    그래서 /var/log 경로를 다루는 다른 규칙은 모두 var_log_delete 규칙 뒤에 있어야 한다. 증적 전용 규칙(#435)도 마찬가지다."""
    for case, out in security_rendered.items():
        if case == "secret_path_under_var_log":      # 알려진 한계(아래 전용 테스트): 사용자 지정 시크릿 감시는 1~5절이라 앞에 온다
            continue
        lines = rule_lines(out["audit"])
        first = next(i for i, ln in enumerate(lines) if ln.endswith("-k var_log_delete"))
        others = [i for i, ln in enumerate(lines) if "/var/log" in ln and not ln.endswith("-k var_log_delete")]
        assert others and all(i > first for i in others), case          # sudo.log 감시는 남아 있되 뒤에 있다
        assert any(lines[i].endswith("-k sudo_logs") for i in others), case


def test_syscall_rules_come_after_the_reset_and_the_failure_mode_and_never_lock(security_rendered):
    lines = rule_lines(security_rendered["default"]["audit"])
    assert lines[0] == "-D"
    first_syscall = next(i for i, ln in enumerate(lines) if ln.startswith("-a "))
    assert all(ln.startswith(("-b ", "-f ")) for ln in lines[1:3]) and first_syscall > 2


# --- fail2ban banaction ------------------------------------------------------------------------

def test_fail2ban_jail_keeps_sshd_defaults(security_rendered):
    text = security_rendered["default"]["fail2ban"]
    assert text.startswith("[sshd]\nenabled = true\n")
    assert "maxretry = 5" in text and "findtime = 10m" in text and "bantime = 1h" in text


def test_fail2ban_banaction_dummy_is_an_explicit_opt_in(security_rendered):
    text = security_rendered["unmanaged_firewall"]["fail2ban"]
    assert "banaction = dummy" in text and "banaction_allports = dummy" in text
    for word in ("iptables", "firewalld", "nftables", "ufw"):
        assert word not in text


def test_fail2ban_banaction_is_left_to_the_distro_for_managed_hosts(security_rendered):
    assert "banaction" not in security_rendered["managed_firewall"]["fail2ban"]


def test_fail2ban_banaction_default_keeps_the_distro_behaviour_for_every_host():
    # 이미 방화벽 연동 방식으로 차단 중인 호스트의 방어를 낮추지 않도록, 방화벽 그룹과 무관하게 기본은 빈 값(배포판 기본)이다.
    # dummy는 운영자가 변수로 명시할 때만 쓴다(unmanaged_firewall 케이스).
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["fail2ban_banaction"] == ""


# --- journald 영구 저장 ------------------------------------------------------------------------

def test_journald_dropin_is_persistent_storage(security_rendered):
    assert security_rendered["default"]["journald"] == "[Journal]\nStorage=persistent\n"


def test_journald_dropin_does_not_duplicate_common_retention_keys(security_rendered):
    text = security_rendered["default"]["journald"]
    assert "SystemMaxUse" not in text and "MaxRetentionSec" not in text  # 보존 한도는 common(COMMON-017)이 정한다


def test_journald_tasks_are_systemd_only_and_notify_a_handler():
    for spec_id in ("SEC-053", "SEC-054"):
        whens = _task(spec_id)["when"]
        assert any("ansible_service_mgr" in w for w in whens) and any("_raw_path_effective" in w for w in whens), spec_id
    assert _task("SEC-054")["notify"][0] == "Restart systemd-journald"  # 뒤따르는 재시작·확인 핸들러는 test_security_journald_handlers.py(#391)
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    assert "Restart systemd-journald" in {h["name"] for h in handlers}


def test_journal_directory_and_dropin_modes_are_explicit():
    loop = {i["path"]: i["mode"] for i in _task("SEC-053")["loop"]}
    assert loop == {"/var/log/journal": "2755", "/etc/systemd/journald.conf.d": "0755"}
    assert _task("SEC-054")["ansible.builtin.template"]["mode"] == "0644"


# --- 방화벽 불변 -------------------------------------------------------------------------------

def test_detection_tasks_never_touch_the_firewall():
    for spec_id in ("SEC-053", "SEC-054", "SEC-055", "SEC-056"):
        text = yaml.safe_dump(_task(spec_id)).lower()
        for word in ("firewall", "iptables", "ufw", "nft"):
            assert word not in text, (spec_id, word)


def test_audit_watch_paths_are_filtered_by_existence():
    assert "audit_watch_paths" in yaml.safe_dump(_task("SEC-055"))
    assert "_audit_watch_paths_effective" in yaml.safe_dump(_task("SEC-056"))
    assert "stat.exists" in yaml.safe_dump(_task("SEC-056"))


def test_render_runs_once_per_session(security_rendered):
    assert set(security_rendered) >= {"default", "unmanaged_firewall", "managed_firewall", "secret_paths"}


def test_journald_tasks_and_handler_do_not_swallow_failures():
    for spec_id in ("SEC-053", "SEC-054"):
        assert "failed_when" not in _task(spec_id), spec_id
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    restart = next(h for h in handlers if h["name"] == "Restart systemd-journald")
    assert "failed_when" not in restart
    assert any("ansible_service_mgr" in w for w in restart["when"])


def test_auditd_tasks_only_tolerate_a_missing_audit_package():
    # failed_when: false는 모든 오류를 가린다. 패키지가 없는 경우만 건너뛰고 그 밖의 실패는 드러내야 한다.
    for spec_id, marker in (("SEC-012", "does not exist"), ("SEC-013", "Could not find the requested service")):
        failed_when = _task(spec_id)["failed_when"]
        assert failed_when is not False, spec_id
        assert marker in yaml.safe_dump(failed_when), spec_id


# --- journal 디렉터리 그룹 (A1) ----------------------------------------------------------------

def test_journal_directory_group_follows_the_system_default_when_the_group_exists():
    # 시스템 기본(부팅 tmpfiles)은 root:systemd-journal이다. 그룹이 없는 환경은 root로 둔다(없는 그룹을 지정하면 실패한다).
    probe = _task("SEC-080")
    assert "ansible.builtin.getent" in probe and probe["ansible.builtin.getent"]["key"] == "systemd-journal"
    assert probe["failed_when"] is False
    group = _task("SEC-053")["ansible.builtin.file"]["group"]
    expr = Environment().compile_expression(group.strip("{} "))
    assert expr(item={"path": "/var/log/journal"}, getent_group={"systemd-journal": ["x", "1", ""]}) == "systemd-journal"
    assert expr(item={"path": "/var/log/journal"}, getent_group={}) == "root"
    assert expr(item={"path": "/etc/systemd/journald.conf.d"}, getent_group={"systemd-journal": ["x", "1", ""]}) == "root"


def test_journal_group_probe_runs_before_the_directory_task():
    names = [t["name"] for t in security_tasks()]
    assert names.index(next(n for n in names if n.startswith("[SEC-080]"))) < names.index(next(n for n in names if n.startswith("[SEC-053]")))


# --- auditd 로그 로테이션 (A5) -----------------------------------------------------------------

def test_auditd_rotation_defaults_and_task():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["audit_max_log_file"] == 50 and defaults["audit_num_logs"] == 10
    task = _task("SEC-081")
    lineinfile = task["ansible.builtin.lineinfile"]
    assert lineinfile["path"] == "/etc/audit/auditd.conf" and lineinfile["mode"] == "0640"
    env = Environment()
    rendered = {}
    for i in task["loop"]:
        item = {"key": i["key"], "value": env.from_string(i["value"]).render(**defaults)}
        rendered[i["key"]] = env.from_string(lineinfile["line"]).render(item=item)
    assert rendered == {"max_log_file": "max_log_file = 50", "num_logs": "num_logs = 10"}
    assert task["notify"] == "Reload auditd"
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    reload_handler = next(h for h in handlers if h["name"] == "Reload auditd")
    assert reload_handler["ansible.builtin.service"]["state"] == "reloaded"


def test_auditd_rotation_is_redhat_non_raw_and_tolerates_only_a_missing_package():
    task = _task("SEC-081")
    assert any("_raw_path_effective" in w for w in task["when"]) and any("RedHat" in w for w in task["when"])
    assert any("does not exist" in w or "Destination" in w for w in task["failed_when"])


# --- Evidence-Only Watch Key: 알림 없이 증적으로만 남는 규칙 (Spec #433 / Ticket-8, #435) -------------------------------------------
# 규칙·키 설계는 docs/security.md의 "Evidence-Only Watch Key" 표. 키 이름은 `evidence_` 접두어라 이름만 보고 알림이 없는 키임을 안다(CONTEXT.md).

def _watch_lines(text, key):
    return [ln for ln in rule_lines(text) if ln.startswith("-w ") and ln.endswith(f" -k {key}")]


def test_evidence_keys_are_named_so_you_can_tell_they_have_no_alert_and_never_collide_with_alert_or_watch_keys(security_rendered):
    assert all(k.startswith("evidence_") for k in EVIDENCE_KEYS)
    for case, out in security_rendered.items():
        lines = rule_lines(out["audit"])
        keys = {ln.rsplit(" -k ", 1)[1] for ln in lines if " -k " in ln}
        if case not in ("evidence_paths_partly_missing", "evidence_paths_all_missing"):
            assert EVIDENCE_KEYS <= keys, case
        assert {k for k in keys if k.startswith("evidence_")} <= EVIDENCE_KEYS, case       # 접두어는 이 다섯 키에만 쓴다
        assert not set(ALERT_SYSCALL_KEYS) & EVIDENCE_KEYS, case


def test_privileged_command_rule_records_setuid_and_setgid_transitions_for_login_users_on_both_arches_without_a_file_list(security_rendered):
    """방식: setuid 파일 목록(`-F path=… -F perm=x`)이 아니라 execve의 자격 전환 필터다(근거는 docs/security.md). 전수 execve가 아니라 uid!=euid·gid!=egid만 남는다."""
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "evidence_privileged_exec")
        assert {(r["arch"], tuple(r["compares"])) for r in rules} == {(a, (c,)) for a in ("b64", "b32") for c in ("uid!=euid", "gid!=egid")}, case
        assert all(r["syscalls"] == {"execve"} and _is_login_user_only(r) for r in rules), case
        assert not any("path=" in f or "perm=" in f or "dir=" in f for r in rules for f in r["fields"]), case     # 호스트별 파일 목록이 없다


def test_login_user_file_delete_rule_is_the_cis_delete_set_on_both_arches(security_rendered):
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "evidence_file_delete")
        assert rules and all(_is_login_user_only(r) and not r["compares"] for r in rules), case
        assert _syscalls_by_arch(rules) == {a: {"unlink", "unlinkat", "rename", "renameat"} for a in ("b64", "b32")}, case
        assert not any("dir=" in f or "path=" in f for r in rules for f in r["fields"]), case       # 경로 필터 없음(/var/log는 var_log_delete가 먼저 잡는다)


def test_time_change_rules_cover_clock_changes_for_login_users_on_both_arches_and_watch_localtime(security_rendered):
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "evidence_time_change")
        assert all(_is_login_user_only(r) for r in rules), case
        assert _syscalls_by_arch(rules) == {a: {"adjtimex", "settimeofday", "clock_settime"} for a in ("b64", "b32")}, case
        clock = [r for r in rules if "clock_settime" in r["syscalls"]]
        assert len(clock) == 2 and all(r["syscalls"] == {"clock_settime"} and "a0=0x0" in r["fields"] for r in clock), case   # 시스템 시계(CLOCK_REALTIME)만
    assert _watch_lines(security_rendered["default"]["audit"], "evidence_time_change") == ["-w /etc/localtime -p wa -k evidence_time_change"]


def test_mount_rule_covers_mount_for_login_users_on_both_arches(security_rendered):
    for case, out in security_rendered.items():
        rules = _syscall_rules(out["audit"], "evidence_mount")
        assert rules and all(_is_login_user_only(r) for r in rules), case
        assert _syscalls_by_arch(rules) == {"b64": {"mount"}, "b32": {"mount"}}, case


def test_login_record_files_are_watched_for_writes_and_attribute_changes(security_rendered):
    default = _watch_lines(security_rendered["default"]["audit"], "evidence_login_records")
    assert sorted(default) == sorted(f"-w {p} -p wa -k evidence_login_records" for p in
                                     ("/var/log/wtmp", "/var/log/btmp", "/var/run/utmp", "/var/log/lastlog"))


def test_evidence_watch_paths_that_do_not_exist_are_left_out_so_the_rule_set_still_loads(security_rendered):
    """`-w`는 없는 경로에서 적재를 실패시킬 수 있다(이야기 26). 역할이 먼저 존재를 확인해(SEC-100·SEC-101) 있는 경로만 `_audit_evidence_watch_paths_effective`로 넘긴다."""
    lines = rule_lines(security_rendered["evidence_paths_partly_missing"]["audit"])
    assert "-w /var/log/wtmp -p wa -k evidence_login_records" in lines
    assert not any(p in ln for ln in lines for p in ("/var/log/btmp", "/var/run/utmp", "/var/log/lastlog", "/etc/localtime"))
    none = rule_lines(security_rendered["evidence_paths_all_missing"]["audit"])
    assert not any(ln.startswith("-w ") and "evidence_" in ln for ln in none)
    assert EVIDENCE_SYSCALL_KEYS == {_rule(ln)["key"] for ln in none if ln.startswith("-a ") and _rule(ln)["key"] in EVIDENCE_SYSCALL_KEYS}   # syscall 규칙은 경로가 없어도 남는다


def test_evidence_watch_path_defaults_are_the_same_in_the_template_and_the_role_defaults(security_rendered):
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    declared = sorted(f"-w {e['path']} -p wa -k {e['key']}" for e in defaults["audit_evidence_watch_paths"])
    rendered = sorted(ln for ln in rule_lines(security_rendered["default"]["audit"]) if ln.startswith("-w ") and " -k evidence_" in ln)
    assert declared == rendered


def test_evidence_rules_are_login_user_only_and_come_after_the_alert_syscall_rules(security_rendered):
    """첫 매치만 기록되므로(audit.rules(7)) 알림 키(var_log_delete)와 겹치는 증적 규칙(파일 삭제·로그인 기록)은 그 뒤에 있어야 /var/log 삭제가 알림 키로 남는다."""
    for case, out in security_rendered.items():
        lines = rule_lines(out["audit"])
        last_alert = max(i for i, ln in enumerate(lines) if ln.endswith("-k var_log_delete") or ln.endswith("-k kernel_module"))
        evidence = [i for i, ln in enumerate(lines) if " -k evidence_" in ln]
        assert evidence and min(evidence) > last_alert, case
        assert all(_is_login_user_only(_rule(ln)) for ln in lines if ln.startswith("-a ") and " -k evidence_" in ln), case


def test_evidence_syscall_rules_come_from_the_shared_macro_only():
    template = (ROLE / "templates" / "audit.rules.j2").read_text(encoding="utf-8")
    body = template.split("{% endmacro %}", 1)[1]
    for key in EVIDENCE_SYSCALL_KEYS:
        assert f"'{key}'" in body and "login_user_syscall_rule(" in body, key
    assert "-a always,exit" not in "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))       # 매크로 밖에서 syscall 규칙을 손으로 쓰지 않는다


def test_evidence_path_filter_tasks_read_only_and_only_in_the_provisioning_path():
    stat, fact = _task("SEC-100"), _task("SEC-101")
    assert "ansible.builtin.stat" in stat and "ansible.builtin.set_fact" in fact
    assert "audit_evidence_watch_paths" in yaml.safe_dump(stat)
    assert "_audit_evidence_watch_paths_effective" in yaml.safe_dump(fact) and "stat.exists" in yaml.safe_dump(fact)
    for task in (stat, fact):                      # Host Provisioning 경로(raw 아님)에서만 돌고 호스트를 바꾸지 않는다
        assert "_raw_path_effective" in yaml.safe_dump(task)


def test_evidence_only_keys_are_documented_with_no_alert_and_a_decision_basis_and_are_verified_by_molecule():
    sec = (ROOT_DIR / "docs" / "security.md").read_text(encoding="utf-8")
    verify = (ROOT_DIR / "molecule" / "fast" / "verify.yml").read_text(encoding="utf-8")
    for key in EVIDENCE_KEYS:
        rows = [ln for ln in sec.splitlines() if ln.startswith("> |") and f"`{key}`" in ln]
        assert rows and all("알림 없음, 증적 전용" in ln for ln in rows), key        # 명세 표에 드러난다
        assert key in verify, key                                                     # Molecule verify.yml이 같은 키를 본다
    for token in ("uid!=euid", "perm=x", "setuid 파일 목록", "미실시", "#436", "키별 증가량", "ausearch"):
        assert token in sec, token


def test_evidence_watches_come_before_the_evidence_syscall_rules_so_a_file_delete_does_not_take_over_their_keys(security_rendered):
    """첫 매치만 기록된다(audit.rules(7)). 경로 필터 없는 `evidence_file_delete`가 앞에 있으면 `/etc/localtime`·`/var/run/utmp`를 지우거나 바꾼 기록이
    시간 변경·로그인 기록 키를 잃는다. 감시가 앞이면 그 키로 남고, 오래된 auditctl이 syscall 줄을 거부해도 감시는 이미 올라가 있다."""
    for case, out in security_rendered.items():
        lines = rule_lines(out["audit"])
        watches = [i for i, ln in enumerate(lines) if ln.startswith("-w ") and " -k evidence_" in ln]
        syscalls = [i for i, ln in enumerate(lines) if ln.startswith("-a ") and " -k evidence_" in ln]
        assert syscalls and (not watches or max(watches) < min(syscalls)), case


def test_known_limit_a_custom_audit_watch_path_under_var_log_comes_before_var_log_delete_and_takes_its_key(security_rendered):
    """한계 고정(#435 리뷰): 사용자 지정 `audit_watch_paths`(1~5절)는 syscall 규칙(6절)보다 앞이라, `/var/log` 아래 경로를 넣으면 로그인 사용자가
    그 파일을 지울 때 첫 매치 키가 `secret_access`가 되어 `var_log_delete` P1이 울리지 않는다. 이 순서를 바꾸면 이 테스트와 docs/security.md의 한계 줄을 함께 고친다."""
    lines = rule_lines(security_rendered["secret_path_under_var_log"]["audit"])
    watch = next(i for i, ln in enumerate(lines) if ln == "-w /var/log/example/app.secret -p rwa -k secret_access")
    assert watch < next(i for i, ln in enumerate(lines) if ln.endswith("-k var_log_delete"))
    assert "첫 매치" in (ROOT_DIR / "docs" / "security.md").read_text(encoding="utf-8").split("audit_watch_paths`가 `/var/log` 아래", 1)[1][:400]


def test_audit_rules_are_deployed_only_by_the_security_role_and_the_host_agents_playbooks_do_not_include_it():
    """에이전트만 설치된 호스트는 Host Agents 플레이북으로만 다뤄지고(ADR-0006) 감사 규칙(audit.rules.j2)은 security 역할만 배포한다."""
    for name in ("host_agents.yml", "host_agents_maintenance.yml"):
        plays = yaml.safe_load((ROOT_DIR / "playbooks" / name).read_text(encoding="utf-8"))
        roles = {r["role"] if isinstance(r, dict) else r for play in plays for r in play.get("roles", [])}
        assert "security" not in roles and "access_security" not in roles, name
        assert "audit.rules" not in (ROOT_DIR / "playbooks" / name).read_text(encoding="utf-8"), name
    users = [p for sub in ("tasks", "handlers", "templates") for p in (ROOT_DIR / "roles").glob(f"*/{sub}/**/*")     # 배포 코드만(defaults의 주석 언급은 제외)
             if p.is_file() and "audit.rules.j2" in p.read_text(encoding="utf-8", errors="ignore")]
    assert users and all(p.is_relative_to(ROLE) for p in users), users
