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


STAGE = ROOT_DIR / "playbooks" / "common" / "stage_ssh_key.yml"


def _flat_tasks(tasks):
    for t in tasks:
        yield t
        for key in ("block", "always", "rescue"):
            yield from _flat_tasks(t.get(key) or [])


def test_controller_credential_tasks_run_in_check_mode_too():
    for task in _flat_tasks(_load(STAGE)):
        if not ({"ansible.builtin.set_fact", "ansible.builtin.fail"} & set(task)) and "block" not in task:
            assert task.get("check_mode") is False, task["name"]
    for task in _load(CLEANUP)[0]["tasks"]:
        assert task.get("check_mode") is False, task["name"]
    plays = list(_flat_tasks(_load(RESOLVE)[0]["tasks"]))
    probe = next(t for t in plays if t.get("name") == "Probe SSH connection using primary admin user credentials")
    assert probe.get("check_mode") is False


def test_key_staging_is_one_helper_used_for_admin_bootstrap_and_hops_and_passphrase_is_not_in_argv():
    text = RESOLVE.read_text(encoding="utf-8")
    assert text.count("ansible.builtin.include_tasks: stage_ssh_key.yml") == 3
    assert "ansible.builtin.tempfile" not in text and "ssh-keygen" not in text
    stage = STAGE.read_text(encoding="utf-8")
    assert stage.count("ansible.builtin.tempfile") == 1 and stage.count("ssh-keygen") >= 1
    assert " -P " not in stage and "SSH_ASKPASS_REQUIRE" in stage
    paths = _flat_tasks(_load(STAGE))
    record = next(i for i, t in enumerate(_flat_tasks(_load(STAGE))) if t["name"].startswith("Record the temporary key path"))
    write = next(i for i, t in enumerate(_flat_tasks(_load(STAGE))) if t["name"].startswith("Write the SSH private key"))
    assert record < write       # 경로를 먼저 남긴다(뒤 단계가 실패해도 cleanup이 지운다)
    assert all(t.get("no_log") is True for t in paths if t["name"].startswith(("Write the SSH private key", "Remove the passphrase")))


def test_tasks_that_carry_secrets_are_no_log():
    tasks = {t["name"]: t for t in list(_flat_tasks(_load(RESOLVE)[0]["tasks"]))}
    for name in ("Acquire the OpenBao client token once for the whole play",
                 "Resolve the Asset document, admin and bootstrap connections and admin accounts in one pass",
                 "Take apart the resolution bundle (Asset document, access names, admin accounts, connections, secret-free summaries) and drop it",
                 "Configure connection parameters from the active connection"):
        assert tasks[name].get("no_log") is True, name


def test_the_connection_is_resolved_by_one_lookup_per_host_not_by_repeated_lookups():
    """호스트당 해석은 lookup 하나다(같은 문서를 요약·전체·관리 계정마다 다시 읽지 않는다)."""
    text = RESOLVE.read_text(encoding="utf-8")
    assert text.count("lookup('openbao_host_connection'") == 1
    for retired in ("lookup('openbao_connection'", "_primary_admin_user"):
        assert retired not in text, retired


def test_the_secret_bearing_resolution_bundle_is_taken_apart_and_emptied_in_one_task():
    tasks = list(_flat_tasks(_load(RESOLVE)[0]["tasks"]))
    take = next(t for t in tasks if t["name"].startswith("Take apart the resolution bundle"))
    facts = take["ansible.builtin.set_fact"]
    assert facts["_host_res"] == {} and take["no_log"] is True
    assert {"_admin_conn", "_boot_conn", "_admin_summary", "_boot_summary", "_asset_doc", "_admin_accounts"} <= set(facts)
    before = tasks[:tasks.index(take)]
    assert [t for t in before if "_host_res" in yaml.safe_dump(t) and not t["name"].startswith("Resolve the Asset document")] == []
    assert "_host_res" not in yaml.safe_dump(tasks[tasks.index(take) + 1:])


def test_the_proxy_command_is_built_once_and_both_the_probe_and_the_common_args_use_it():
    text = RESOLVE.read_text(encoding="utf-8")
    assert text.count("openbao_ssh_proxy_command(") == 1 and "openbao_ssh_common_args" not in text
    assert text.count("_ssh_proxy_command") >= 3


def test_the_token_is_acquired_once_per_play():
    task = next(t for t in list(_flat_tasks(_load(RESOLVE)[0]["tasks"])) if t["name"].startswith("Acquire the OpenBao client token"))
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


def test_remote_python_defaults_to_usr_bin_python3_and_only_the_validated_asset_key_overrides_it():
    task = next(t for t in list(_flat_tasks(_load(RESOLVE)[0]["tasks"])) if t["name"].startswith("Configure connection parameters"))
    assert "openbao_python_interpreter" in task["ansible.builtin.set_fact"]["ansible_python_interpreter"]
    assert "_access.python_interpreter" in task["ansible.builtin.set_fact"]["ansible_python_interpreter"]
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
