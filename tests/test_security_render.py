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
        lines = rule_lines(out["audit"])  # 주석은 제외
        assert not any("execve" in ln for ln in lines), case
        # syscall 규칙은 로그인 사용자의 /var/log 삭제·커널 모듈만이다(아래 절). 그 밖의 syscall을 전수로 추적하지 않는다.
        assert {_rule(ln)["key"] for ln in lines if ln.startswith("-a ")} <= set(ALERT_SYSCALL_KEYS), case


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


def _rule(line):
    """`-a always,exit -F arch=b64 -S a,b -F x=y -k key` -> {arch, syscalls, fields, key}."""
    tokens = line.split()
    assert tokens[:2] == ["-a", "always,exit"], line
    out = {"arch": None, "syscalls": set(), "fields": [], "key": None}
    it = iter(tokens[2:])
    for flag in it:
        value = next(it)
        if flag == "-S":
            out["syscalls"] |= set(value.split(","))
        elif flag == "-F" and value.startswith("arch="):
            out["arch"] = value.removeprefix("arch=")
        elif flag == "-F":
            out["fields"].append(value)
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


def test_the_o_trunc_open_rules_only_match_opens_with_the_truncate_flag(security_rendered):
    """`open`은 flags가 두 번째 인자(a1), `openat`은 세 번째(a2)다. O_TRUNC = 0x200이고, 이 비트 없는 열기(읽기·덧붙이기)는 걸리지 않는다."""
    rules = _syscall_rules(security_rendered["default"]["audit"], "var_log_delete")
    for arch in ("b64", "b32"):
        opens = [r for r in rules if r["arch"] == arch and r["syscalls"] & {"open", "openat"}]
        assert opens, arch
        for r in opens:
            assert not (r["syscalls"] & {"unlink", "unlinkat", "rename", "renameat", "truncate", "ftruncate", "creat"}), r
        flag_field = {"open": "a1&0x200", "openat": "a2&0x200"}
        assert {tuple(sorted(r["syscalls"])): [f for f in r["fields"] if f[:1] == "a" and f[2:3] == "&"] for r in opens} == \
            {("open",): [flag_field["open"]], ("openat",): [flag_field["openat"]]}, arch


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
    assert syscall_keys == set(ALERT_SYSCALL_KEYS) and not syscall_keys & watch_keys


def test_var_log_syscall_rules_come_before_every_other_rule_that_matches_a_file_under_var_log(security_rendered):
    """커널은 첫 번째로 맞는 규칙의 키만 기록한다(audit.rules(7), first match wins). `-w /var/log/sudo.log` 감시가 var_log_delete보다 앞이면
    로그인 사용자가 sudo.log를 지우거나 자른 기록이 `sudo_logs` 키로만 남아 P1 알림이 울리지 않는다(`sudo_logs`는 알림 대상이 아니다).
    그래서 /var/log 경로를 다루는 다른 규칙은 모두 var_log_delete 규칙 뒤에 있어야 한다. 증적 전용 규칙(#435)도 마찬가지다."""
    for case, out in security_rendered.items():
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
