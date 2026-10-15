"""방화벽 관리 제외 그룹 firewall_unmanaged (#220).

security 역할을 localhost에서 ansible-playbook --check로 실제 실행해 태스크별 결과를 본다.
raw 경로(CentOS 6/7)는 --check에서 스킵되므로 구조 검사로 따로 보증한다.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
TASKS = ROOT_DIR / "roles" / "security" / "tasks" / "main.yml"
GATE = "security_firewall_managed | bool"
FIREWALL = re.compile(r"firewall|ufw|iptables|masquerade|\bzone\b|default network interface", re.I)


def _walk(tasks, gated=False):
    """(task, 게이트 안에 있는가)를 중첩 block까지 평탄화한다."""
    for t in tasks:
        when = t.get("when")
        whens = when if isinstance(when, list) else [when]
        inner_gated = gated or GATE in whens
        if "block" in t:
            yield from _walk(t["block"], inner_gated)
        else:
            yield t, gated


def _flat():
    return list(_walk(yaml.safe_load(TASKS.read_text(encoding="utf-8"))))


def test_every_firewall_task_sits_behind_the_gate():
    tasks = _flat()
    firewall = [(t, g) for t, g in tasks if FIREWALL.search(yaml.safe_dump(t))]
    assert len(firewall) > 40, "방화벽 태스크를 찾지 못했다"
    assert [t["name"] for t, g in firewall if not g] == []


def test_non_firewall_tasks_are_not_gated():
    assert [t["name"] for t, g in _flat() if g and not FIREWALL.search(yaml.safe_dump(t))] == []


def test_default_derives_from_group_membership():
    from jinja2 import Environment
    defaults = yaml.safe_load((ROOT_DIR / "roles/security/defaults/main.yml").read_text(encoding="utf-8"))
    expr = Environment().compile_expression(defaults["security_firewall_managed"].strip("{} "))
    assert expr(group_names=["servers"]) is True
    assert expr(group_names=["servers", "firewall_unmanaged"]) is False


def _firewall_names():
    return {t["name"] for t, g in _flat() if g}


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    if shutil.which("ansible-playbook") is None:
        pytest.skip("ansible-playbook not installed")
    d = tmp_path_factory.mktemp("fw")
    (d / "inv.yml").write_text(yaml.safe_dump({"all": {
        "vars": {
            "ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_os_family": "RedHat", "ansible_distribution": "Rocky",
            "ansible_distribution_version": "9.4", "ansible_distribution_major_version": "9",
            "ansible_default_ipv4": {"interface": "eth0"},
        },
        "children": {
            "servers": {"hosts": {"plain": {}, "fw": {}}},
            "firewall_unmanaged": {"hosts": {"fw": {}}},
        },
    }}))
    (d / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "servers", "gather_facts": False, "become": False,
        "ignore_errors": True, "roles": ["security"],
    }]))
    res = subprocess.run(
        ["ansible-playbook", "-C", "-i", str(d / "inv.yml"), str(d / "play.yml")],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300, cwd=str(ROOT_DIR),
        env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_ROLES_PATH": str(ROOT_DIR / "roles"),
             "ANSIBLE_DISPLAY_SKIPPED_HOSTS": "true", "ANSIBLE_LOCALHOST_WARNING": "False",
             "ANSIBLE_DEPRECATION_WARNINGS": "False"},
    )
    assert "PLAY RECAP" in res.stdout, res.stdout + res.stderr
    return _parse(res.stdout)


def _parse(out):
    """{태스크 이름: {호스트: 결과 종류 목록}}"""
    result, task = {}, None
    for line in out.splitlines():
        m = re.match(r"TASK \[security : (.*?)\] \*+$", line)
        if m:
            task = result.setdefault(m.group(1), {})
            continue
        m = re.match(r"(ok|changed|skipping|fatal): \[(\w+)\]", line)
        if m and task is not None:
            task.setdefault(m.group(2), []).append(m.group(1))
    return result


def test_unmanaged_host_gets_no_firewall_task(run):
    firewall = _firewall_names()
    assert firewall <= set(run)
    ran = {n: run[n]["fw"] for n in firewall if set(run[n].get("fw", [])) - {"skipping"}}
    assert ran == {}


def test_unmanaged_host_still_gets_the_other_security_tasks(run):
    other = {n: r for n, r in run.items() if n not in _firewall_names()}
    assert any(set(r.get("fw", [])) - {"skipping"} for r in other.values())
    assert {n: r.get("fw") for n, r in other.items() if r.get("fw") != r.get("plain")} == {}


def test_host_outside_the_group_keeps_firewall_tasks(run):
    selected = [n for n in _firewall_names() if set(run[n].get("plain", [])) - {"skipping"}]
    assert any("[SEC-005]" in n for n in selected)
