"""auditd 규칙 변경이 재부팅 없이 적재되는지 본다 (#424).

systemd의 auditd 유닛은 `RefuseManualStop=yes`라 `service ... state=restarted`가 거부되는데, 옛 `Restart auditd` 핸들러는
`failed_when: false`로 그 실패를 숨겼다. 규칙 파일은 배포돼도 커널에는 올라가지 않았다.

실제 역할의 `SEC-082`/`SEC-083` 태스크와 `Restart auditd` 핸들러 묶음을 그대로 꺼내 가짜 `auditctl`/`augenrules`가 PATH에 있는
호스트들에 한 번에 돌린다(세션당 한 번, 호스트 하나가 시나리오 하나). 호스트를 건드리지 않는다.
- 이 머신에는 auditd가 없으므로 가짜 명령이 `auditctl -l`(적재 상태 파일을 출력)과 `augenrules --load`(규칙 파일을 상태 파일로 복사)를 흉내 낸다.
- 공개 저장소라 가짜 경로만 쓴다.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from security_render import ROOT_DIR, flat_tasks, shared_render

pytestmark = pytest.mark.xdist_group("security-audit-reload")

ROLE = ROOT_DIR / "roles" / "security"
AUDITCTL = """#!/bin/sh
PATH=/usr/bin:/bin
echo "auditctl $*" >> "$FAKE_STATE/calls"
[ "$1" = "-l" ] || exit 2
[ -s "$FAKE_STATE/loaded" ] && cat "$FAKE_STATE/loaded" || echo "No rules"
"""
# 규칙 줄(-w/-a)만 상태 파일로 복사한다. FAKE_AUGEN=fail이면 실패, noop이면 성공이라 하면서 아무것도 적재하지 않는다.
AUGENRULES = """#!/bin/sh
PATH=/usr/bin:/bin
echo "augenrules $*" >> "$FAKE_STATE/calls"
case "$FAKE_AUGEN" in
  fail) echo "Error sending add rule data request (Rule exists)" >&2; exit 1 ;;
  noop) exit 0 ;;
esac
grep -E '^-(w|a) ' "$FAKE_RULES" > "$FAKE_STATE/loaded"
"""
STALE = "-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S execve -F key=exec_log\n-a always,exit -F arch=b32 -S execve -F key=exec_log\n"

# 호스트(시나리오) -> (적재 상태 `auditctl -l`로 읽히는 것, augenrules 동작, auditctl이 설치돼 있는가)
SCENARIOS = {
    "clean": ("declared", "ok", True),
    "stale": (STALE, "ok", True),
    "norules": ("", "ok", True),
    "loadfails": (STALE, "fail", True),
    "silentnoop": (STALE, "noop", True),
    "noaudit": ("", "ok", False),
}


def _handlers():
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    return [h for h in handlers if "Restart auditd" in (h.get("name"), h.get("listen"))]


def _tasks():
    tasks = list(flat_tasks(yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))))
    return [t for t in tasks if t.get("name", "").startswith(("[SEC-082]", "[SEC-083]"))]


def _recap(output):
    result = {}
    for host, ok, changed, unreachable, failed in re.findall(
            r"^(\w+)\s*: ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", output, re.M):
        result[host] = {"ok": int(ok), "changed": int(changed), "failed": int(failed) + int(unreachable)}
    return result


def _run(workdir, check):
    declared = shared_render()["default"]["audit"]
    inventory = {"all": {"hosts": {}}}
    for name, (loaded, augen, installed) in SCENARIOS.items():
        host_dir = workdir / name
        (host_dir / "bin").mkdir(parents=True)
        (host_dir / "state").mkdir()
        (host_dir / "rules").write_text(declared, encoding="utf-8")  # 이미 배포된 파일(스탠드인 SEC-012가 바꾸지 않는다)
        (host_dir / "rules").chmod(0o600)
        (host_dir / "state" / "loaded").write_text(declared if loaded == "declared" else loaded, encoding="utf-8")
        if installed:
            for cmd, body in (("auditctl", AUDITCTL), ("augenrules", AUGENRULES)):
                (host_dir / "bin" / cmd).write_text(body)
                (host_dir / "bin" / cmd).chmod(0o755)
        inventory["all"]["hosts"][name] = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
            "fake_dir": str(host_dir), "fake_augen": augen,
        }
    (workdir / "inventory.yml").write_text(yaml.safe_dump(inventory), encoding="utf-8")
    (workdir / "templates").mkdir()
    (workdir / "templates" / "audit.rules.j2").symlink_to(ROLE / "templates" / "audit.rules.j2")
    play = [{
        "hosts": "all", "gather_facts": False, "become": False,
        "vars": {"ansible_os_family": "RedHat", "_raw_path_effective": False},
        # PATH를 가짜 bin 하나로 한정해 `noaudit` 호스트에는 auditctl이 정말 없게 한다.
        "environment": {"PATH": "{{ fake_dir }}/bin:/nonexistent", "FAKE_STATE": "{{ fake_dir }}/state",
                        "FAKE_RULES": "{{ fake_dir }}/rules", "FAKE_AUGEN": "{{ fake_augen }}"},
        "tasks": [
            # [SEC-012] 스탠드인: 같은 템플릿을 같은 방식으로 배포하고 바뀌면 같은 핸들러를 부른다.
            {"name": "stand-in SEC-012", "ansible.builtin.template": {"src": "audit.rules.j2", "dest": "{{ fake_dir }}/rules", "mode": "0600"},
             "register": "security_audit_rules_result", "notify": "Restart auditd"},
            *_tasks(),
        ],
        "handlers": _handlers(),
    }]
    (workdir / "play.yml").write_text(yaml.safe_dump(play), encoding="utf-8")
    cmd = ["ansible-playbook", "-i", str(workdir / "inventory.yml"), str(workdir / "play.yml")]
    if check:
        cmd.append("--check")
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=workdir, timeout=300,
                         env=dict(os.environ, ANSIBLE_NOCOLOR="1", ANSIBLE_CONFIG=str(ROOT_DIR / "ansible.cfg"),
                                  ANSIBLE_BECOME="false", ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"),
                                  ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins")))
    recap = _recap(res.stdout)
    assert set(recap) == set(SCENARIOS), res.stdout + res.stderr
    calls = {n: (workdir / n / "state" / "calls").read_text().splitlines() if (workdir / n / "state" / "calls").exists() else []
             for n in SCENARIOS}
    loaded = {n: (workdir / n / "state" / "loaded").read_text() for n in SCENARIOS}
    return {"recap": recap, "calls": calls, "loaded": loaded, "out": res.stdout + res.stderr, "declared": declared}


@pytest.fixture(scope="session")
def apply_run():
    return _run(Path(tempfile.mkdtemp(prefix="audit-reload-apply-")), check=False)


@pytest.fixture(scope="session")
def check_run():
    return _run(Path(tempfile.mkdtemp(prefix="audit-reload-check-")), check=True)


def test_stale_loaded_rules_are_replaced_without_a_restart(apply_run):
    # 파일은 이미 최신(스탠드인이 바꾸지 않는다)인데 적재 상태만 낡은 호스트: 적재 drift만으로 다시 적재해야 한다.
    for host in ("stale", "norules"):
        assert apply_run["recap"][host]["failed"] == 0, apply_run["out"]
        assert "augenrules --load" in apply_run["calls"][host], host
        assert not any("restart" in c for c in apply_run["calls"][host]), host
        assert "exec_log" not in apply_run["loaded"][host], host
        assert "-k identity" in apply_run["loaded"][host], host


def test_already_loaded_rules_are_left_alone(apply_run):
    assert apply_run["recap"]["clean"] == {"ok": apply_run["recap"]["clean"]["ok"], "changed": 0, "failed": 0}
    assert "augenrules --load" not in apply_run["calls"]["clean"]


def test_a_failed_load_fails_the_play(apply_run):
    assert apply_run["recap"]["loadfails"]["failed"] > 0, apply_run["out"]
    assert "Rule exists" in apply_run["out"]


def test_a_load_that_exits_zero_but_leaves_rules_stale_fails_the_play(apply_run):
    # augenrules의 종료 코드만 믿지 않는다: 적재 뒤 auditctl -l을 다시 읽어 확인한다.
    assert apply_run["recap"]["silentnoop"]["failed"] > 0, apply_run["out"]
    assert "exec_log" in apply_run["out"]


def test_hosts_without_the_audit_package_are_skipped_silently(apply_run):
    assert apply_run["recap"]["noaudit"]["failed"] == 0, apply_run["out"]
    assert apply_run["calls"]["noaudit"] == []
    assert apply_run["recap"]["noaudit"]["changed"] == 0


def test_check_mode_reports_load_drift_without_changing_anything(check_run):
    # Host Audit Configuration Drift(--check)에서 적재 drift가 changed 태스크로 보인다. 적재도, 실패도 없다.
    assert check_run["recap"]["clean"]["changed"] == 0
    for host in ("stale", "norules", "silentnoop", "loadfails"):
        assert check_run["recap"][host]["changed"] == 1, (host, check_run["out"])
        assert check_run["recap"][host]["failed"] == 0, (host, check_run["out"])
        assert "augenrules" not in " ".join(check_run["calls"][host]), host
        assert check_run["loaded"][host] != check_run["declared"], host
    assert check_run["recap"]["noaudit"]["changed"] == 0


# --- 정의만 읽는 검사(ADR-0013): 옛 결함이 되돌아오지 않게 한다 -------------------------------

def test_auditd_load_handlers_do_not_restart_the_service_or_swallow_failures():
    handlers = _handlers()
    assert [h["name"] for h in handlers][0] == "Restart auditd"
    for handler in handlers:
        assert "ansible.builtin.service" not in handler, handler["name"]  # RefuseManualStop=yes라 거부된다
        assert handler.get("failed_when") is not False, handler["name"]
    load = handlers[0]
    assert load["ansible.builtin.command"] == "augenrules --load"
    assert "_raw_path_effective" in str(load["when"])
    # 종료 코드만 믿지 않고 적재 결과를 다시 읽어 비교하는 핸들러가 이어서 listen한다.
    assert any(h.get("listen") == "Restart auditd" and "assert" in " ".join(h) for h in handlers)


def test_loaded_rules_probe_is_read_only_and_feeds_the_load_handler():
    probe = next(t for t in _tasks() if t["name"].startswith("[SEC-083]"))
    assert "read-only" in probe["name"] and probe["check_mode"] is False
    assert probe["notify"] == "Restart auditd" and "failed_when" not in probe
    assert "audit_rules_drift" in probe["changed_when"]
    tools = next(t for t in _tasks() if t["name"].startswith("[SEC-082]"))
    assert "read-only" in tools["name"] and tools["check_mode"] is False and tools["failed_when"] is False
