"""접속 해석 플레이북의 구조 계약 (Spec #511 / Ticket-12, #523). 빠른 정적 검사.

동작은 `test_connection_resolution.py`(통합)와 `test_openbao_connection.py`(결정 규칙)가 본다. 여기서는 진입점 모양,
임시 키 처리의 check_mode, 폐지한 손잡이가 없는지, common 역할의 키 재배포 방지(COMMON-015)만 본다.
"""
from pathlib import Path

import pytest
import yaml
from jinja2.nativetypes import NativeEnvironment

ROOT_DIR = Path(__file__).resolve().parent.parent
RESOLVE = ROOT_DIR / "playbooks" / "common" / "resolve_connection.yml"
CLEANUP = ROOT_DIR / "playbooks" / "common" / "cleanup_connection.yml"
SITE = ROOT_DIR / "playbooks" / "site.yml"
COMMON_TASKS = ROOT_DIR / "roles" / "common" / "tasks" / "main.yml"

IMPORT = "ansible.builtin.import_playbook"
OLD_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyBlob old@laptop"
NEW_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewKeyBlob new@laptop"


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_controller_plays_never_escalate_privileges():
    for path in (RESOLVE, CLEANUP):
        play = _load(path)[0]
        assert play["connection"] == "local" and play["become"] is False


def test_controller_credential_tasks_run_in_check_mode_too():
    tasks = _load(RESOLVE)[0]["tasks"]
    names = ["Create temporary SSH private key file for admin user if key provided",
             "Write admin SSH private key to temporary file",
             "Strip passphrase from temporary admin SSH key if passphrase defined",
             "Create temporary SSH private key file for bootstrap user if key provided",
             "Write bootstrap SSH private key to temporary file",
             "Strip passphrase from temporary bootstrap SSH key if passphrase defined",
             "Create temporary SSH private key files for via hops",
             "Write via hop SSH private keys to temporary files",
             "Probe SSH connection using primary admin user credentials"]
    for name in names:
        task = next((t for t in tasks if t.get("name") == name), None)
        assert task is not None, name
        assert task.get("check_mode") is False, name
    for task in _load(CLEANUP)[0]["tasks"]:
        assert task.get("check_mode") is False, task["name"]


def test_tasks_that_carry_secrets_are_no_log():
    tasks = {t["name"]: t for t in _load(RESOLVE)[0]["tasks"]}
    for name in ("Acquire the OpenBao client token once for the whole play",
                 "Resolve the Asset document, admin and bootstrap connections and admin accounts in one pass",
                 "Take the admin connection (Endpoint, login, become, via) and the bootstrap connection (same Endpoint, bootstrap Credential)",
                 "Write admin SSH private key to temporary file", "Write bootstrap SSH private key to temporary file",
                 "Write via hop SSH private keys to temporary files", "Create temporary SSH private key files for via hops",
                 "Configure connection parameters from the active connection"):
        assert tasks[name].get("no_log") is True, name


def test_the_connection_is_resolved_by_one_lookup_per_host_not_by_repeated_lookups():
    """호스트당 해석은 lookup 하나다(같은 문서를 요약·전체·관리 계정마다 다시 읽지 않는다)."""
    text = RESOLVE.read_text(encoding="utf-8")
    assert text.count("lookup('openbao_host_connection'") == 1
    for retired in ("lookup('openbao_connection'", "lookup('openbao_admin_accounts'", "_primary_admin_user"):
        assert retired not in text, retired


def test_the_secret_bearing_resolution_bundle_is_emptied_after_it_is_taken_apart():
    tasks = _load(RESOLVE)[0]["tasks"]
    last = next(i for i, t in enumerate(tasks) if t["name"].startswith("Take the admin connection"))
    assert tasks[last]["ansible.builtin.set_fact"]["_host_res"] == {} and tasks[last]["no_log"] is True
    later = yaml.safe_dump(tasks[last + 1:])
    assert "_host_res" not in later


def test_secret_free_summaries_are_never_no_log():
    """요약 태스크는 비밀이 없다: no_log를 달면 운영자가 실패 사유를 볼 수 없다."""
    task = next(t for t in _load(RESOLVE)[0]["tasks"] if t["name"].startswith("Summarize the admin and bootstrap connections"))
    assert not task.get("no_log")


def test_hop_key_paths_are_recorded_before_any_key_is_written():
    names = [t["name"] for t in _load(RESOLVE)[0]["tasks"]]
    assert names.index("Record the via hop temporary key paths") < names.index("Write via hop SSH private keys to temporary files")


def test_the_token_is_acquired_once_per_play():
    task = next(t for t in _load(RESOLVE)[0]["tasks"] if t["name"].startswith("Acquire the OpenBao client token"))
    assert task["run_once"] is True


def test_the_playbook_has_no_retired_knobs_or_paths():
    text = RESOLVE.read_text(encoding="utf-8")
    for retired in ("openbao_namespace", "openbao_mount", "openbao_hosts_prefix", "openbao_users_prefix", "_local_openbao",
                    "VAULT_NAMESPACE", "VAULT_MOUNT", "OPENBAO_", "target_admin_users", "BOOTSTRAP_USER", "bootstrap_user",
                    "uri:", "_host_kv_dict", "/secret/", "users/"):
        assert retired not in text, retired


def test_site_imports_shared_connection_plays_with_always_tag_and_requires_access():
    plays = _load(SITE)
    assert [p[IMPORT] for p in plays if IMPORT in p] == ["common/resolve_connection.yml", "common/cleanup_connection.yml"]
    for p in plays:
        if IMPORT in p:
            assert p["tags"] == ["always"]
    assert plays[0]["vars"]["connection_requires_access"] is True


def test_shared_connection_plays_honour_target_hosts_narrowing():
    for path in (RESOLVE, CLEANUP):
        assert _load(path)[0]["hosts"] == "{{ connection_hosts | default(target_hosts | default('servers:loadbalancers')) }}"


def test_remote_python_is_always_usr_bin_python3():
    task = next(t for t in _load(RESOLVE)[0]["tasks"] if t["name"].startswith("Configure connection parameters"))
    assert task["ansible.builtin.set_fact"]["ansible_python_interpreter"] == "/usr/bin/python3"
    assert "ansible_python_interpreter" not in (_load(RESOLVE)[0].get("vars") or {})
    assert _load(SITE)[1]["vars"]["ansible_python_interpreter"] == "/usr/bin/python3"
    assert "interpreter_python = auto_silent" in (ROOT_DIR / "ansible.cfg").read_text(encoding="utf-8")


# --- common role: never redeploy a key that is also revoked (idempotency) -------------------------------------------

def _render(expr, ctx):
    env = NativeEnvironment()
    env.filters["from_yaml"] = lambda s: yaml.safe_load(s)
    env.filters["combine"] = lambda d1, d2: {**d1, **d2}
    return env.from_string(expr).render(**ctx)


@pytest.mark.parametrize("key, revoked, expect_deploy", [
    (NEW_KEY, [], True),
    (OLD_KEY, [OLD_KEY], False),
    (OLD_KEY + "\n", ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyBlob other-comment"], False),
    (NEW_KEY, [OLD_KEY], True),
])
def test_common015_skips_a_key_that_is_also_revoked(key, revoked, expect_deploy):
    """A key listed in both accounts[].keys and accounts[].revoked_keys (rotation lag, or a static inventory
    definition) must never be (re)deployed by COMMON-015, or it flip-flops `changed` against COMMON-022 on every run."""
    task = next(t for t in _load(COMMON_TASKS) if t.get("name", "").startswith("[COMMON-015]"))
    ctx = {"item": (({"name": "u", "revoked_keys": revoked}), key)}
    for name, expr in task["vars"].items():
        ctx[name] = _render(expr, ctx)
    results = [_render("{{ " + cond + " }}", ctx) for cond in task["when"] if "_key_fp" in cond or "_revoked_fps" in cond]
    assert all(results) is expect_deploy
