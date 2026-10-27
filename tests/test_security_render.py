"""security 역할 탐지·복구 렌더링 테스트(Spec #364 / #372).

auditd 규칙·fail2ban jail·journald 영구 저장 드롭인을 세션당 한 번만 렌더링해(`security_rendered`) 기대치를 읽는다.
`ansible-playbook`을 테스트마다 돌리지 않으므로 `slow`가 아니다(AGENTS.md 5.1). 렌더링 helper는 `tests/security_render.py`(#371도 재사용).
"""
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

from security_render import ROOT_DIR, render_security, rule_lines

pytestmark = pytest.mark.xdist_group("security-render")

ROLE = ROOT_DIR / "roles" / "security"


@pytest.fixture(scope="session")
def security_rendered(tmp_path_factory):
    """`{케이스: {audit|fail2ban|journald: 렌더링 텍스트}}`."""
    return render_security(tmp_path_factory.mktemp("security-render"))


def _tasks(tasks=None):
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")) if tasks is None else tasks
    for t in tasks:
        if "block" in t:
            yield from _tasks(t["block"])
        else:
            yield t


def _task(spec_id):
    found = [t for t in _tasks() if t["name"].startswith(f"[{spec_id}]")]
    assert len(found) == 1, spec_id
    return found[0]


# --- auditd 규칙 -------------------------------------------------------------------------------

def test_audit_rules_do_not_trace_every_execve(security_rendered):
    for case, out in security_rendered.items():
        lines = rule_lines(out["audit"])  # 주석은 제외
        assert not any("execve" in ln for ln in lines), case
        assert not any(ln.startswith("-a ") for ln in lines), case  # syscall 규칙 전수 추적 없음


def test_audit_rules_keep_meaningful_events(security_rendered):
    lines = rule_lines(security_rendered["default"]["audit"])
    for expected in ("-D", "-w /etc/shadow -p wa -k identity", "-w /etc/pam.d/ -p wa -k auth_config",
                     "-w /etc/sudoers.d/ -p wa -k sudo_config", "-w /etc/ssh/sshd_config -p wa -k sshd_config",
                     "-w /etc/docker/ -p wa -k container_config"):
        assert expected in lines
    assert lines[0] == "-D"


def test_audit_rules_are_small(security_rendered):
    assert len(rule_lines(security_rendered["default"]["audit"])) < 30


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


# --- fail2ban banaction ------------------------------------------------------------------------

def test_fail2ban_jail_keeps_sshd_defaults(security_rendered):
    text = security_rendered["default"]["fail2ban"]
    assert text.startswith("[sshd]\nenabled = true\n")
    assert "maxretry = 5" in text and "findtime = 10m" in text and "bantime = 1h" in text


def test_fail2ban_banaction_is_not_firewall_for_unmanaged_hosts(security_rendered):
    text = security_rendered["unmanaged_firewall"]["fail2ban"]
    assert "banaction = dummy" in text and "banaction_allports = dummy" in text
    for word in ("iptables", "firewalld", "nftables", "ufw"):
        assert word not in text


def test_fail2ban_banaction_is_left_to_the_distro_for_managed_hosts(security_rendered):
    assert "banaction" not in security_rendered["managed_firewall"]["fail2ban"]


def test_fail2ban_banaction_default_derives_from_firewall_group():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    env = Environment()
    env.filters["bool"] = bool
    expr = env.compile_expression(defaults["fail2ban_banaction"].strip("{} "))
    assert expr(security_firewall_managed=False) == "dummy"
    assert expr(security_firewall_managed=True) == ""


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
    assert _task("SEC-054")["notify"] == "Restart systemd-journald"
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
