"""sshd 출발지 제한(Match Address) 테스트 (Spec #364 / Ticket-4, #371).

렌더링은 #372의 공유 helper(`tests/security_render.py`)의 `shared_render()`로 프로세스당 한 번만 한다(템플릿·케이스는 그 표에 있다).
태스크 구조와 런북은 파일을 읽어 검사한다(ansible-playbook을 테스트마다 돌리지 않으므로 slow가 아니다).
방화벽 체인은 건드리지 않는다는 것(`firewall_unmanaged`에서도 같은 동작)도 구조로 확인한다.
"""
import re
from pathlib import Path

import pytest
import yaml

from security_render import ROOT_DIR, shared_render
from security_render import flat_tasks as _flat
from security_render import security_task as _task
from runbook_helpers import runbook_section

pytestmark = pytest.mark.xdist_group("security-render")

ROLE = ROOT_DIR / "roles" / "security"
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "ssh-source-restriction.md"


@pytest.fixture(scope="session")
def ssh_rendered():
    return shared_render()


def _defaults():
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))


# --- 렌더링 ------------------------------------------------------------------------------------

def test_match_block_denies_everyone_outside_the_allowed_sources(ssh_rendered):
    text = ssh_rendered["ssh_source_two"]["sshd_source"]
    assert "Match Address *,!127.0.0.1,!::1,!192.0.2.0/24,!198.51.100.7/32" in text
    assert re.search(r"^\s+DenyUsers \*$", text, re.M)


def test_ipv6_sources_are_negated_too(ssh_rendered):
    assert "Match Address *,!127.0.0.1,!::1,!2001:db8::/32" in ssh_rendered["ssh_source_v6"]["sshd_source"]


def test_rendering_has_exactly_one_match_line_and_no_allow_all(ssh_rendered):
    for case in ("ssh_source_two", "ssh_source_v6"):
        text = ssh_rendered[case]["sshd_source"]
        assert len(re.findall(r"^Match ", text, re.M)) == 1
        assert "AllowUsers" not in text


# --- 태스크 구조 --------------------------------------------------------------------------------

def test_the_allowed_list_defaults_to_empty_and_holds_no_values():
    d = _defaults()
    assert d["ssh_source_restriction_allowed_sources"] == []
    assert d["ssh_allowed_source_ips"] == []  # 기존 변수는 그대로(방화벽 전용)


def test_validation_rejects_malformed_entries():
    t = _task("SEC-070")
    assert "ansible.builtin.assert" in t
    assert "ssh_source_restriction_allowed_sources" in yaml.safe_dump(t)
    assert t["when"] and "raw" in str(t["when"])


def test_block_is_written_with_sshd_validation_and_restart_handler():
    t = _task("SEC-071")
    args = t["ansible.builtin.blockinfile"]
    assert args["path"] == "/etc/ssh/sshd_config"
    assert "sshd -t -f %s" in args["validate"]
    assert t["notify"] == "Restart sshd"
    assert "'absent'" in args["state"] and "'present'" in args["state"]  # 빈 목록이면 제거(롤백)


def test_guard_checks_the_connecting_source_and_rolls_the_block_back_on_failure():
    guard = _task("SEC-072")
    assert "sshd -T -C" in yaml.safe_dump(guard)
    assert guard["changed_when"] is False
    rescue = _task("SEC-073")
    assert rescue["ansible.builtin.blockinfile"]["state"] == "absent"
    abort = _task("SEC-074")
    assert "ansible.builtin.fail" in abort
    # 가드·롤백은 같은 block/rescue 안에 있다
    top = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    holder = [t for t in top if "block" in t and any(x.get("name", "").startswith("[SEC-071]") for x in t["block"])]
    assert len(holder) == 1
    assert {x["name"][:9] for x in holder[0]["rescue"]} == {"[SEC-073]", "[SEC-074]"}


def test_ssh_source_tasks_are_independent_of_the_firewall_gate_and_raw_path():
    top = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    gated = [t for t in top if "security_firewall_managed" in str(t.get("when", ""))]
    for t in gated:
        assert not any(x.get("name", "").startswith(f"[SEC-07") for x in _flat([t]))
    for spec in ("SEC-070", "SEC-071", "SEC-072"):
        assert "_raw_path_effective" in str(_task(spec).get("when", "")) or any(
            "_raw_path_effective" in str(t.get("when", "")) for t in top if "block" in t and any(x.get("name", "").startswith(f"[{spec}]") for x in _flat([t])))


def test_ssh_source_tasks_do_not_touch_firewall_state():
    for spec in ("SEC-070", "SEC-071", "SEC-072", "SEC-073", "SEC-074"):
        dumped = yaml.safe_dump(_task(spec))
        assert not re.search(r"firewall|ufw|iptables|nft|\bzone\b", dumped, re.I), spec


# --- 런북 ---------------------------------------------------------------------------------------

def _text():
    return RUNBOOK.read_text(encoding="utf-8")


def _section(title):
    return runbook_section(RUNBOOK, title)


def test_runbook_explains_the_relation_to_ssh_allowed_source_ips():
    s = _section("1. 기존 ssh_allowed_source_ips와의 관계")
    assert "ssh_allowed_source_ips" in s and "ssh_source_restriction_allowed_sources" in s
    assert "방화벽" in s and "firewall_unmanaged" in s and "대체" in s


def test_runbook_has_the_lockout_prevention_steps_in_order():
    s = _section("3. 적용 순서(락아웃 방지)")
    for needle in ("별도 세션", "sshd -t", "sshd -T -C", "임시", "영구", "재부팅", "롤백"):
        assert needle in s, needle
    assert s.index("임시") < s.index("영구")
    assert s.index("sshd -t") < s.index("영구")


def test_runbook_has_snapshot_negative_test_rollback_and_audit_link():
    assert "collect-security-baseline.sh" in _section("2. 적용 전 준비")
    assert "비공개 경로" in _section("4. 허용·거부 시험")
    assert "ssh_source_restriction_allowed_sources" in _section("5. 롤백")
    assert "Host Audit" in _section("6. 사후 점검과 Host Audit 연계")


def test_runbook_is_public_safe_and_indexed():
    text = _text()
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert "runbooks/ssh-source-restriction.md" in (ROOT_DIR / "docs" / "INDEX.md").read_text(encoding="utf-8")
