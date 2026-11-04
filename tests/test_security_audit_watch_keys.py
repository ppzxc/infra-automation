"""security 역할의 파일 감시 키 4개(auditd 설정·syslog 설정·authorized_keys·방화벽 영구 설정) 테스트(Spec #433 / Ticket-4, #430).

규칙 렌더링은 세션당 한 번인 공유 렌더링(`tests/security_render.py`)을 읽는다(`ansible-playbook`을 테스트마다 돌리지 않으므로 `slow`가 아니다).
없는 경로 거르기(SEC-082~SEC-085)는 태스크 구조와, 태스크가 쓰는 식·셸 명령을 가짜 입력으로 돌려 본다.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

from security_render import ROOT_DIR, rule_lines, security_task, security_tasks, shared_render

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from raw_provisioning import raw_exists_found, raw_ssh_key_exists_cmd  # noqa: E402

pytestmark = pytest.mark.xdist_group("security-render")

WATCH_KEYS = ("audit_config", "syslog_config", "ssh_keys", "firewall_config")


@pytest.fixture(scope="session")
def security_rendered():
    return shared_render()


# --- 규칙 렌더링 ----------------------------------------------------------------------------------

def test_audit_rules_watch_the_four_audit_watch_keys_for_the_existing_paths(security_rendered):
    lines = rule_lines(security_rendered["watch_keys"]["audit"])
    for expected in ("-w /etc/audit/ -p wa -k audit_config",
                     "-w /etc/rsyslog.conf -p wa -k syslog_config", "-w /etc/rsyslog.d/ -p wa -k syslog_config",
                     "-w /root/.ssh/authorized_keys -p wa -k ssh_keys", "-w /home/alice/.ssh/authorized_keys -p wa -k ssh_keys",
                     "-w /etc/firewalld/ -p wa -k firewall_config"):
        assert expected in lines, expected


def test_a_json_string_fact_renders_the_same_lines_as_a_list(security_rendered):
    """set_fact의 결과는 Ansible 버전에 따라 JSON 문자열로 남는다. 템플릿은 두 형태를 같게 읽는다."""
    lines = rule_lines(security_rendered["watch_keys_as_json"]["audit"])
    assert "-w /etc/audit/ -p wa -k audit_config" in lines and "-w /root/.ssh/authorized_keys -p wa -k ssh_keys" in lines


def test_audit_watch_keys_are_absent_until_the_existence_probe_has_run(security_rendered):
    """팩트가 없으면(탐지 태스크가 건너뛴 경우)·남은 경로가 없으면 감시 키 줄을 만들지 않는다. 없는 경로에 watch를 걸면 규칙 적재가 실패하기 때문이다."""
    for case in ("default", "watch_keys_none_exist"):
        text = security_rendered[case]["audit"]
        for key in WATCH_KEYS:
            assert f"-k {key}" not in text, (case, key)


def test_audit_rules_have_no_malformed_watch_line_in_any_case(security_rendered):
    for case, out in security_rendered.items():
        for line in rule_lines(out.get("audit", "")):
            if line.startswith("-w "):
                path = line.split()[1]
                assert path.startswith("/") and "~" not in path, (case, line)
            assert line != "-w  -p wa -k", case


def test_audit_watch_keys_are_write_and_attribute_watches_without_read(security_rendered):
    """읽기(r)까지 감시하면 sshd가 authorized_keys를 읽을 때마다 기록된다. 변경(w)과 속성(a)만 본다."""
    lines = [ln for ln in rule_lines(security_rendered["watch_keys"]["audit"]) if any(f"-k {k}" in ln for k in WATCH_KEYS)]
    assert len(lines) == 6
    assert all(" -p wa " in ln for ln in lines), lines


def test_the_four_keys_leave_the_existing_watch_keys_untouched(security_rendered):
    lines = rule_lines(security_rendered["watch_keys"]["audit"])
    for expected in ("-w /etc/shadow -p wa -k identity", "-w /etc/pam.d/ -p wa -k auth_config",
                     "-w /etc/ssh/sshd_config -p wa -k sshd_config", "-w /etc/docker/ -p wa -k container_config"):
        assert expected in lines, expected


# --- 후보 경로(역할 기본 변수) -----------------------------------------------------------------------

def test_the_watch_key_candidates_always_include_root_even_with_an_empty_account_list(security_rendered):
    for case in ("ssh_accounts_empty", "default"):
        paths = json.loads(security_rendered[case]["watch_key_paths"])
        assert paths["ssh_keys"] == ["~root/.ssh/authorized_keys"], case


def test_the_watch_key_candidates_add_the_designated_accounts_once(security_rendered):
    paths = json.loads(security_rendered["ssh_accounts_two"]["watch_key_paths"])
    assert paths["ssh_keys"] == ["~root/.ssh/authorized_keys", "~alice/.ssh/authorized_keys", "~bob/.ssh/authorized_keys"]
    paths = json.loads(security_rendered["ssh_accounts_duplicate_root"]["watch_key_paths"])
    assert paths["ssh_keys"] == ["~root/.ssh/authorized_keys", "~alice/.ssh/authorized_keys"]


def test_the_watch_key_candidates_name_exactly_the_four_keys_and_their_paths(security_rendered):
    paths = json.loads(security_rendered["default"]["watch_key_paths"])
    assert set(paths) == set(WATCH_KEYS)
    assert paths["audit_config"] == ["/etc/audit/"]
    assert paths["syslog_config"] == ["/etc/rsyslog.conf", "/etc/rsyslog.d/"]
    assert paths["firewall_config"] == ["/etc/firewalld/"]


# --- 없는 경로 거르기: 모듈 경로(SEC-082·SEC-083) ----------------------------------------------------

def _order(spec_id):
    names = [t["name"] for t in security_tasks()]
    return names.index(next(n for n in names if n.startswith(f"[{spec_id}]")))


def test_the_existence_filter_runs_before_the_rules_are_deployed():
    assert _order("SEC-082") < _order("SEC-083") < _order("SEC-012")
    assert _order("SEC-084") < _order("SEC-085") < _order("SEC-035")


def test_the_module_probe_stats_every_candidate_path_and_is_read_only():
    task = security_task("SEC-082")
    assert task["ansible.builtin.stat"]["path"] == "{{ item.1 }}"
    assert "audit_watch_key_paths" in yaml.safe_dump(task["loop"]) and "subelements" in yaml.safe_dump(task["loop"])
    assert task["register"] == "security_audit_watch_key_stat"
    assert any("_raw_path_effective" in w for w in task["when"] if isinstance(w, str)) or "_raw_path_effective" in str(task["when"])


def _env():
    """태스크의 식을 Ansible 밖에서 돌리는 Jinja 환경(Ansible 필터 중 식이 쓰는 것만 더한다)."""
    env = Environment()
    env.filters["to_json"] = json.dumps
    env.filters["raw_exists_found"] = raw_exists_found
    return env


def _stat_result(key, path, exists, real_path=None):
    stat = {"exists": exists}
    if exists:
        stat["path"] = real_path or path
    return {"item": [{"key": key, "value": [path]}, path], "stat": stat}


def _filter_module_fact(results):
    expr = security_task("SEC-083")["ansible.builtin.set_fact"]["_audit_watch_key_paths_effective"]
    return json.loads(_env().from_string(expr).render(security_audit_watch_key_stat={"results": results}))


def test_the_module_filter_keeps_only_existing_paths_with_the_home_the_system_resolved():
    fact = _filter_module_fact([
        _stat_result("audit_config", "/etc/audit/", True),
        _stat_result("firewall_config", "/etc/firewalld/", False),
        _stat_result("ssh_keys", "~root/.ssh/authorized_keys", True, "/root/.ssh/authorized_keys"),
        _stat_result("ssh_keys", "~alice/.ssh/authorized_keys", True, "/srv/home/alice/.ssh/authorized_keys"),
        _stat_result("ssh_keys", "~ghost/.ssh/authorized_keys", False),
    ])
    assert fact == [
        {"key": "audit_config", "path": "/etc/audit/"},
        {"key": "ssh_keys", "path": "/root/.ssh/authorized_keys"},
        {"key": "ssh_keys", "path": "/srv/home/alice/.ssh/authorized_keys"},
    ]


def test_the_module_filter_leaves_an_empty_list_when_nothing_exists():
    assert _filter_module_fact([_stat_result("firewall_config", "/etc/firewalld/", False)]) == []
    assert _filter_module_fact([]) == []


# --- 없는 경로 거르기: CentOS 6/7 raw 경로(SEC-084·SEC-085) -------------------------------------------

def test_the_raw_probe_is_read_only_and_runs_only_on_the_raw_path():
    probe = security_task("SEC-084")
    assert "ansible.builtin.raw" in probe and probe["changed_when"] is False and probe["failed_when"] is False
    assert probe["register"] == "security_audit_watch_key_raw"
    set_fact = security_task("SEC-085")
    assert "ansible.builtin.set_fact" in set_fact and "_audit_watch_key_paths_effective" in set_fact["ansible.builtin.set_fact"]
    # 두 태스크는 raw 경로 블록 안에 있어 모듈 경로 호스트에서는 실행되지 않는다(블록의 when).
    block = next(t for t in yaml.safe_load((ROOT_DIR / "roles" / "security" / "tasks" / "main.yml").read_text(encoding="utf-8"))
                 if t.get("block") and any(str(b.get("name", "")).startswith("[SEC-084]") for b in t["block"]))
    assert "_raw_path_effective" in str(block["when"])


def _run(cmd, env_path=None):
    env = dict(os.environ)
    if env_path:
        env["PATH"] = env_path + os.pathsep + env["PATH"]
    return subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=30)


def test_the_raw_probe_finds_fixed_paths_and_each_accounts_home_from_the_system(tmp_path):
    fixed = tmp_path / "audit"
    fixed.mkdir()
    missing = tmp_path / "firewalld"
    home = tmp_path / "srv-home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("x\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # 가짜 getent: alice만 있고 그 홈은 시스템이 정한 경로(/home 밖)다.
    (bin_dir / "getent").write_text(f'#!/bin/sh\n[ "$2" = alice ] && echo "alice:x:1000:1000::{home}:/bin/bash"\nexit 0\n', encoding="utf-8")
    (bin_dir / "getent").chmod(0o755)
    cmd = raw_ssh_key_exists_cmd([str(fixed), str(missing)], ["root", "alice", "ghost"])
    res = _run(cmd, str(bin_dir))
    assert res.returncode == 0, res.stderr
    assert sorted(raw_exists_found(res.stdout)) == sorted([str(fixed), str(home / ".ssh" / "authorized_keys")])


def test_the_raw_probe_survives_an_account_name_with_shell_metacharacters(tmp_path):
    marker = tmp_path / "pwned"
    cmd = raw_ssh_key_exists_cmd([], [f"x; touch {marker}"])
    res = _run(cmd)
    assert res.returncode == 0 and not marker.exists()


def test_the_raw_fact_keeps_each_found_path_under_its_key():
    expr = security_task("SEC-085")["ansible.builtin.set_fact"]["_audit_watch_key_paths_effective"]
    stdout = "__RAW_EXISTS__ /etc/audit/\n__RAW_EXISTS__ /etc/rsyslog.d/\n__RAW_EXISTS__ /home/alice/.ssh/authorized_keys\n__RAW_EXISTS__ /root/.ssh/authorized_keys\r\n"
    fixed = {"audit_config": ["/etc/audit/"], "syslog_config": ["/etc/rsyslog.conf", "/etc/rsyslog.d/"], "firewall_config": ["/etc/firewalld/"]}
    out = _env().from_string(expr).render(
        security_audit_watch_key_raw={"stdout": stdout}, audit_watch_key_paths=dict(fixed, ssh_keys=["~root/.ssh/authorized_keys"]))
    got = json.loads(out)
    assert {(e["key"], e["path"]) for e in got} == {
        ("audit_config", "/etc/audit/"), ("syslog_config", "/etc/rsyslog.d/"),
        ("ssh_keys", "/home/alice/.ssh/authorized_keys"), ("ssh_keys", "/root/.ssh/authorized_keys")}


# --- 에이전트만 설치된 호스트에는 영향이 없다 ---------------------------------------------------------

def test_the_new_tasks_have_the_same_gates_as_the_rules_deployment_they_feed():
    """새 태스크는 감사 규칙 배포(SEC-012/SEC-035)와 같은 조건에서만 돌고, 규칙 배포는 이 변경으로 대상이 넓어지지 않는다."""
    assert security_task("SEC-082")["when"] == security_task("SEC-012")["when"]
    assert security_task("SEC-083")["when"] == security_task("SEC-012")["when"]
    raw = yaml.safe_load((ROOT_DIR / "roles" / "security" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    block = next(t for t in raw if t.get("block") and any(str(b.get("name", "")).startswith("[SEC-035]") for b in t["block"]))
    assert {b["name"][:9] for b in block["block"]} >= {"[SEC-084]", "[SEC-085]", "[SEC-035]"}


def test_only_the_provisioning_entry_points_run_the_security_role():
    """감사 규칙은 security 역할만 배포한다. 에이전트만 설치하는 playbook(host_agents*)·점검 playbook(host_audit*)은 이 역할을 쓰지 않는다.
    agents_only 호스트는 provision_excluded 그룹이라 Semaphore의 Host Provisioning(provision_hosts.yml) 사전 검증이 접속 전에 거부한다."""
    users = sorted(p.name for p in (ROOT_DIR / "playbooks").glob("*.yml") if "role: security" in p.read_text(encoding="utf-8"))
    assert users == ["maintenance.yml", "site.yml"], users
    assert "provision_excluded" in (ROOT_DIR / "playbooks" / "provision_hosts.yml").read_text(encoding="utf-8")
