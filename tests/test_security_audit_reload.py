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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from security_render import ROOT_DIR, flat_tasks, shared_render

pytestmark = pytest.mark.xdist_group("security-audit-reload")

ROLE = ROOT_DIR / "roles" / "security"
# FAKE_AUDITCTL: ok(기본) | listfail(`-s`는 되지만 `-l`이 실패) | nokernel(`-s`·`-l` 모두 실패: 커널 audit 없음·컨테이너)
AUDITCTL = """#!/bin/sh
PATH=/usr/bin:/bin
echo "auditctl $*" >> "$FAKE_STATE/calls"
case "$1" in
  -s) [ "$FAKE_AUDITCTL" = nokernel ] && { echo "Error - audit support not in kernel" >&2; exit 1; }; echo "enabled 1"; exit 0 ;;
  -l) case "$FAKE_AUDITCTL" in listfail|nokernel) echo "Error - audit support not in kernel" >&2; exit 1 ;; esac ;;
  *) exit 2 ;;
esac
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
cat "$FAKE_RULESD"/*.rules | grep -E '^-(w|a) ' > "$FAKE_STATE/loaded"
"""
# 이 역할 밖의 rules.d 파일(하드닝 프로파일 등). augenrules는 이것도 합쳐 적재한다.
EXTRA = "-D\n-b 8192\n-w /etc/hosts -p wa -k hosts_change\n-a always,exit -F arch=b64 -S mount -k mounts\n"
EXTRA_LOADED = "-w /etc/hosts -p wa -k hosts_change\n-a always,exit -F arch=b64 -S mount -F key=mounts\n"
STALE = "-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S execve -F key=exec_log\n-a always,exit -F arch=b32 -S execve -F key=exec_log\n"

# 호스트(시나리오) -> (적재 상태 `auditctl -l`로 읽히는 것, augenrules 동작, auditctl이 설치돼 있는가, 다른 rules.d 파일이 있는가)
SCENARIOS = {
    "clean": ("declared", "ok", True, False),
    "stale": (STALE, "ok", True, False),
    "norules": ("", "ok", True, False),
    "loadfails": (STALE, "fail", True, False),
    "silentnoop": (STALE, "noop", True, False),
    "noaudit": ("", "ok", False, False),
    # 다른 rules.d 파일이 있고 이미 합쳐서 적재된 정상 상태: drift가 아니다(매 실행 재적재·실패하면 안 된다).
    "extrafile": ("declared+extra", "ok", True, True),
    # 다른 파일이 있는데 적재 상태에는 그 규칙이 없다: 합쳐서 다시 적재하면 맞는다.
    "extrastale": ("declared", "ok", True, True),
    # 도구는 있는데 커널 audit을 조회할 수 없는 호스트(커널 audit 비활성·컨테이너): 적재 단계를 건너뛰고 역할은 실패하지 않는다.
    "nokernel": ("", "ok", True, False),
    # 규칙 파일이 바뀌어 핸들러가 불려도 조회할 수 없는 호스트는 적재를 시도하지 않는다.
    "nokernelnewfile": ("", "ok", True, False),
    # `auditctl -s`는 되는데 `-l`만 실패: 상태를 알 수 없으므로 drift로 보지 않고(재적재 안 함) 역할도 실패시키지 않는다.
    "listfails": ("", "ok", True, False),
    # 파일이 바뀌어 적재했는데(augenrules 종료 코드 0) 그 뒤 `-l`을 읽지 못한다: 적재 결과를 확인할 수 없으니 실패로 드러낸다.
    "readbackfails": ("", "ok", True, False),
}
# 시나리오별 가짜 auditctl 동작과, 이미 배포된 규칙 파일이 낡았는가(스탠드인 SEC-012가 바꿔 핸들러를 부른다)
AUDITCTL_MODE = {"nokernel": "nokernel", "nokernelnewfile": "nokernel", "listfails": "listfail", "readbackfails": "listfail"}
OLD_FILE = {"nokernelnewfile", "readbackfails"}


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
    declared = shared_render()["secret_paths"]["audit"]  # 시크릿 감시 경로(가짜)가 들어 있는 규칙
    inventory = {"all": {"hosts": {}}}
    for name, (loaded, augen, installed, extra) in SCENARIOS.items():
        host_dir = workdir / name
        (host_dir / "bin").mkdir(parents=True)
        (host_dir / "bin" / "cat").symlink_to(shutil.which("cat"))  # 조회 스크립트가 쓴다. PATH를 가짜 bin 하나로 한정하므로 직접 둔다.
        (host_dir / "state").mkdir()
        (host_dir / "rules.d").mkdir()
        # 이미 배포된 파일(스탠드인 SEC-012가 바꾸지 않는다). OLD_FILE 시나리오만 낡은 파일이라 스탠드인이 바꾸고 핸들러를 부른다.
        (host_dir / "rules.d" / "overseer.rules").write_text("-w /etc/passwd -p wa -k identity\n" if name in OLD_FILE else declared, encoding="utf-8")
        (host_dir / "rules.d" / "overseer.rules").chmod(0o600)
        (host_dir / "rules.d" / "10-base.rules").write_text("-D\n-b 8192\n-f 1\n", encoding="utf-8")  # 배포판 기본 파일
        if extra:
            (host_dir / "rules.d" / "50-extra.rules").write_text(EXTRA, encoding="utf-8")
        loaded_text = {"declared": declared, "declared+extra": declared + EXTRA_LOADED}.get(loaded, loaded)
        (host_dir / "state" / "loaded").write_text(loaded_text, encoding="utf-8")
        if installed:
            for cmd, body in (("auditctl", AUDITCTL), ("augenrules", AUGENRULES)):
                (host_dir / "bin" / cmd).write_text(body)
                (host_dir / "bin" / cmd).chmod(0o755)
        inventory["all"]["hosts"][name] = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
            "fake_dir": str(host_dir), "fake_augen": augen, "fake_auditctl": AUDITCTL_MODE.get(name, "ok"),
        }
    (workdir / "inventory.yml").write_text(yaml.safe_dump(inventory), encoding="utf-8")
    (workdir / "templates").mkdir()
    (workdir / "templates" / "audit.rules.j2").symlink_to(ROLE / "templates" / "audit.rules.j2")
    play = [{
        "hosts": "all", "gather_facts": False, "become": False,
        "vars": {"ansible_os_family": "RedHat", "_raw_path_effective": False, "security_audit_rules_dir": "{{ fake_dir }}/rules.d",
                 "audit_watch_paths": ["/srv/example/app.secrets.env", "/srv/example/other.key"],
                 "audit_container_config_paths": ["/etc/docker/", "/srv/example/compose/"]},
        "vars_files": [str(ROLE / "vars" / "main.yml")],
        # PATH를 가짜 bin 하나로 한정해 `noaudit` 호스트에는 auditctl이 정말 없게 한다.
        "environment": {"PATH": "{{ fake_dir }}/bin:/nonexistent", "FAKE_STATE": "{{ fake_dir }}/state",
                        "FAKE_RULESD": "{{ fake_dir }}/rules.d", "FAKE_AUGEN": "{{ fake_augen }}",
                        "FAKE_AUDITCTL": "{{ fake_auditctl }}"},
        "tasks": [
            # [SEC-012] 스탠드인: 같은 템플릿을 같은 방식으로 배포하고 바뀌면 같은 핸들러를 부른다.
            {"name": "stand-in SEC-012", "ansible.builtin.template": {"src": "audit.rules.j2", "dest": "{{ fake_dir }}/rules.d/overseer.rules", "mode": "0600"},
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
    # 실행 로그(Semaphore)에는 시크릿 감시 경로가 남지 않는다: 건수와 키 이름만 나온다.
    assert "적재 안 됨" in apply_run["out"] and "건(키:" in apply_run["out"]
    assert "/srv/example" not in apply_run["out"] and "secrets.env" not in apply_run["out"]


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


def test_a_host_whose_kernel_audit_cannot_be_queried_is_skipped_not_failed(apply_run, check_run):
    # 도구는 있는데 `auditctl -l`이 실패하는 호스트(커널 audit 비활성·컨테이너)에서 role 전체가 실패하면 안 된다. 적재 단계를 건너뛴다.
    for run in (apply_run, check_run):
        for host in ("nokernel", "nokernelnewfile"):
            assert run["recap"][host]["failed"] == 0, (host, run["out"])
            assert not any(c.startswith("augenrules") for c in run["calls"][host]), host
        assert run["recap"]["nokernel"]["changed"] == 0


def test_a_failing_auditctl_list_is_unknown_not_drift_and_not_a_failure(apply_run, check_run):
    for run in (apply_run, check_run):
        assert run["recap"]["listfails"]["failed"] == 0, run["out"]
        assert run["recap"]["listfails"]["changed"] == 0
        assert not any(c.startswith("augenrules") for c in run["calls"]["listfails"])


def test_a_load_that_cannot_be_read_back_is_still_a_failure(apply_run):
    # 이 역할이 규칙 파일을 바꿔 적재했는데 확인할 수 없으면 조용히 성공으로 끝나지 않는다(#424 수용 기준: 적재 결과가 드러난다).
    assert "augenrules --load" in apply_run["calls"]["readbackfails"]
    assert apply_run["recap"]["readbackfails"]["failed"] > 0, apply_run["out"]


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
    assert probe["notify"] == "Restart auditd" and probe["failed_when"] is False   # 조회 실패는 알 수 없음(실패도 drift도 아님)
    assert "rc" in " ".join(probe["changed_when"])
    assert "audit_rules_probe_drift" in " ".join(probe["changed_when"])
    tools = next(t for t in _tasks() if t["name"].startswith("[SEC-082]"))
    assert "read-only" in tools["name"] and tools["check_mode"] is False and tools["failed_when"] is False


def test_rules_from_other_rules_d_files_are_not_drift(apply_run, check_run):
    # augenrules는 rules.d/*.rules를 모두 합쳐 적재한다. 이 역할 밖 파일의 규칙이 적재돼 있어도 정상이다.
    for run in (apply_run, check_run):
        assert run["recap"]["extrafile"]["failed"] == 0, run["out"]
        assert run["recap"]["extrafile"]["changed"] == 0
        assert "augenrules --load" not in run["calls"]["extrafile"]


def test_other_rules_d_files_are_loaded_together_with_ours(apply_run):
    assert apply_run["recap"]["extrastale"]["failed"] == 0, apply_run["out"]
    assert "augenrules --load" in apply_run["calls"]["extrastale"]
    assert "hosts_change" in apply_run["loaded"]["extrastale"] and "-k identity" in apply_run["loaded"]["extrastale"]


# --- 명세가 근거와 한계를 정직하게 적는다(라운드 2 리뷰) ----------------------------------------------

SPEC = (ROOT_DIR / "docs" / "security.md").read_text(encoding="utf-8")


def test_the_spec_cites_why_augenrules_load_reloads_an_up_to_date_merged_file_and_what_was_not_measured():
    assert "No change" in SPEC and "try_load" in SPEC                      # augenrules 소스: 변경 없음 분기에서도 적재한다
    assert "파일 최신·커널 낡음" in SPEC and "#436" in SPEC.split("파일 최신·커널 낡음", 1)[1][:400]   # 호스트 패키지 버전에서의 확인은 #436


def test_the_spec_states_the_syscall_comparison_scope_and_its_limits():
    section = SPEC.split("**비교 기준(근사)**", 1)[1].split("\n", 1)[0]
    assert "arch" in section and "syscall" in section and "한쪽 방향" in section
    assert "-C" in section and "필터" in section                              # 필터만 다른 줄은 못 잡는 한계
    assert "시스템 호출 목록·arch는 비교하지 않는다" not in section


def test_the_spec_states_that_a_kernel_that_cannot_be_queried_skips_loading_and_that_raw_filters_evidence_paths():
    assert "auditctl -s" in SPEC and "SEC-094" in SPEC and "SEC-095" in SPEC
    assert "raw 경로(`SEC-035`)에는 이 거르기가 없고" not in SPEC
