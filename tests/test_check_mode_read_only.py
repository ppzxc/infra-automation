"""check 모드 읽기 전용 보장 (ADR-0009 §1, #117).

Host Audit의 Configuration Drift 점검은 provisioning·Host Agents Config를 `--check`로 돌린다.
`check_mode: false`인 태스크는 --check에서도 실제로 실행되므로, 관리 대상 호스트의 상태를
바꾸지 않는 태스크에만 허용한다. 다음 중 하나여야 한다:

1. 조회 전용 모듈 (READ_ONLY_MODULES: stat, getent, find, slurp, *_facts, assert 등)
2. 컨트롤러에서만 실행 — 태스크의 `delegate_to: localhost`, 플레이의 `connection: local`
   또는 `hosts: localhost`, 혹은 CONTROLLER_TASK_FILES에 등록된 컨트롤러 전용 태스크 파일
3. 태스크 이름에 `read-only`를 표시한 raw/command/shell 조회 (예: "(raw, read-only)").
   표시는 "이 명령은 호스트에 쓰지 않는다"는 작성자의 선언이며 리뷰 대상이다.

그 밖의 `check_mode: false` 태스크가 들어오면 이 테스트가 실패한다.
"""
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent

READ_ONLY_MODULES = {
    f"ansible.builtin.{m}"
    for m in (
        "stat", "getent", "find", "slurp", "setup", "package_facts", "service_facts",
        "assert", "debug", "set_fact", "include_vars", "fail",
    )
}
QUERY_MODULES = {"ansible.builtin.raw", "ansible.builtin.command", "ansible.builtin.shell"}
READ_ONLY_MARKER = "read-only"
CONTROLLER_HOSTS = {"localhost", "127.0.0.1"}

# 플레이 정의 밖(include_role/tasks_from)에서 컨트롤러 전용으로만 호출되는 태스크 파일.
CONTROLLER_TASK_FILES = {
    # playbooks/host_agents_maintenance.yml이 connection: local로 호출한다.
    "roles/backup/tasks/maintenance.yml",
    # playbooks/openobserve_config.yml (hosts: localhost, connection: local) 전용 롤.
    "roles/openobserve_config/tasks/main.yml",
    # playbooks/host_audit.yml의 보고서 플레이(hosts: localhost)가 report.yml을 거쳐 호출한다.
    # 하위 실행 자체가 --check라 호스트를 바꾸지 않는다(Configuration Drift, #124).
    "roles/host_audit/tasks/drift.yml",
    "roles/host_audit/tasks/drift_subrun.yml",
}

TASK_KEYWORDS = {
    "name", "when", "check_mode", "changed_when", "failed_when", "register", "delegate_to",
    "run_once", "become", "become_user", "tags", "loop", "loop_control", "no_log", "vars",
    "environment", "args", "ignore_errors", "until", "retries", "delay", "notify", "listen",
    "connection", "timeout", "throttle", "any_errors_fatal", "delegate_facts", "diff",
    "module_defaults", "collections", "block", "rescue", "always",
}


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _module_of(task):
    mods = [k for k in task if k not in TASK_KEYWORDS and not k.startswith("with_")]
    return mods[0] if mods else None


def _violation(task, controller):
    """Return a reason string if a check_mode: false task may change a managed host."""
    if controller or str(task.get("delegate_to", "")) in CONTROLLER_HOSTS:
        return None
    module = _module_of(task)
    if module in READ_ONLY_MODULES:
        return None
    if module in QUERY_MODULES and READ_ONLY_MARKER in str(task.get("name", "")):
        return None
    return f"{module} without a read-only guarantee"


def find_violations(tasks, controller=False, inherited=None, where="<inline>"):
    """Walk a task list (blocks included) and list check_mode: false tasks that may write."""
    found = []
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        check_mode = task.get("check_mode", inherited)
        if "block" in task:
            for key in ("block", "rescue", "always"):
                found += find_violations(task.get(key), controller, check_mode, where)
            continue
        if check_mode is False:
            reason = _violation(task, controller)
            if reason:
                found.append(f"{where}: {task.get('name', '<unnamed>')} — {reason}")
    return found


def _repo_violations():
    found = []
    for path in sorted([*ROOT_DIR.glob("roles/**/*.yml"), *ROOT_DIR.glob("playbooks/**/*.yml")]):
        rel = path.relative_to(ROOT_DIR).as_posix()
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            continue
        if "hosts" in data[0] or "import_playbook" in data[0] or "ansible.builtin.import_playbook" in data[0]:
            for play in data:
                if not isinstance(play, dict) or "hosts" not in play:
                    continue
                controller = play.get("connection") == "local" or play.get("hosts") in CONTROLLER_HOSTS
                for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                    found += find_violations(play.get(key), controller, play.get("check_mode"), rel)
        else:
            found += find_violations(data, rel in CONTROLLER_TASK_FILES, None, rel)
    return found


def test_every_check_mode_false_task_is_read_only():
    violations = _repo_violations()
    assert not violations, (
        "check_mode: false tasks must not change a managed host (ADR-0009 §1). "
        f"Use a read-only module, run it on the controller, or mark a query '{READ_ONLY_MARKER}':\n"
        + "\n".join(violations)
    )


def test_checker_rejects_writing_tasks():
    tasks = [
        {"name": "write repo", "ansible.builtin.yum_repository": {"name": "x"}, "check_mode": False},
        {"name": "refresh cache", "ansible.builtin.command": "dnf makecache", "check_mode": False},
        {"block": [{"name": "nested copy", "ansible.builtin.copy": {"dest": "/x"}}], "check_mode": False},
    ]
    assert len(find_violations(tasks)) == 3


def test_checker_accepts_read_only_tasks():
    tasks = [
        {"name": "stat", "ansible.builtin.stat": {"path": "/x"}, "check_mode": False},
        {"name": "probe (raw, read-only)", "ansible.builtin.raw": "cat /etc/os-release", "check_mode": False},
        {"name": "fetch", "ansible.builtin.get_url": {}, "delegate_to": "localhost", "check_mode": False},
        {"name": "makecache", "ansible.builtin.command": "dnf makecache"},  # runs only in normal mode
    ]
    assert find_violations(tasks) == []
    assert find_violations([{"name": "w", "ansible.builtin.copy": {}, "check_mode": False}], controller=True) == []


def test_docker_repo_and_cache_do_not_write_under_check():
    tasks = yaml.safe_load((ROOT_DIR / "roles/docker_engine/tasks/main.yml").read_text(encoding="utf-8"))
    by_id = {t["name"].split("]")[0] + "]": t for t in tasks if isinstance(t, dict) and "name" in t}
    assert by_id["[DOC-004]"].get("check_mode") is not False
    cache = by_id["[DOC-004-CACHE]"]
    assert cache.get("check_mode") is not False
    assert any("ansible_check_mode" in str(c) for c in cache["when"])
    assert "ansible_check_mode" in str(by_id["[DOC-009]"].get("ignore_errors", ""))
