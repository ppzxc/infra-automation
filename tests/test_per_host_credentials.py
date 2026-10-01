"""Per-host account credentials, explicit account removal and key revocation (#26).

The expressions are pulled verbatim from Play 1 and rendered with a NativeEnvironment
(Ansible evaluates templated vars to native types); one ansible-playbook run executes
the real tasks with extra vars to cover variable precedence.
"""
import json
import shutil
import subprocess

import pytest
import yaml
from jinja2.nativetypes import NativeEnvironment
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RESOLVE = ROOT_DIR / "playbooks" / "common" / "resolve_connection.yml"
PLAYBOOKS = [RESOLVE]
COMMON_TASKS = ROOT_DIR / "roles" / "common" / "tasks" / "main.yml"

OLD_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyBlob old@laptop"
NEW_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewKeyBlob new@laptop"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyBlob host@only"


def _play1_tasks(playbook):
    with open(playbook, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)[0]["tasks"]


def _task(playbook, prefix):
    for task in _play1_tasks(playbook):
        if task.get("name", "").startswith(prefix):
            return task
    raise AssertionError(f"task '{prefix}' missing in {playbook}")


def _jinja_env():
    env = NativeEnvironment()
    env.filters["from_yaml"] = lambda s: yaml.safe_load(s)
    env.filters["combine"] = lambda d1, d2: {**d1, **d2}
    return env


def _render(expr, ctx):
    return _jinja_env().from_string(expr).render(**ctx)


def _run_task(task, ctx):
    """Render a set_fact task: its vars in order, then every fact."""
    ctx = dict(ctx)
    for name, expr in (task.get("vars") or {}).items():
        ctx[name] = _render(expr, ctx) if isinstance(expr, str) else expr
    return {k: _render(v, ctx) for k, v in task["ansible.builtin.set_fact"].items()}


def _kv(data, status=200):
    return {"status": status, "json": {"data": {"data": data}}}


# --- removed_users resolution -------------------------------------------------

@pytest.mark.parametrize("playbook", PLAYBOOKS)
@pytest.mark.parametrize("host_kv, run_var, expected", [
    ({}, None, []),
    (None, None, []),
    ({"removed_users": ["olduser"]}, None, ["olduser"]),
    ({"removed_users": "olduser"}, None, ["olduser"]),
    ({"removed_users": ["olduser"]}, "legacy1, legacy2", ["olduser", "legacy1", "legacy2"]),
    ({}, '["legacy1","olduser"]', ["legacy1", "olduser"]),
    ({"removed_users": ["olduser", " "]}, ["olduser", "legacy1"], ["olduser", "legacy1"]),
])
def test_removed_users_union(playbook, host_kv, run_var, expected):
    task = _task(playbook, "Resolve accounts to remove")
    ctx = {}
    if host_kv is not None:
        ctx["_host_kv_dict"] = host_kv
    if run_var is not None:
        ctx["target_removed_users"] = run_var
    assert _run_task(task, ctx)["_removed_users"] == expected
    assert "removed_users" not in task["ansible.builtin.set_fact"], "extra vars outrank set_fact; use an internal fact"


# --- per-host credential overrides ---------------------------------------------

def _overrides(playbook, results):
    task = _task(playbook, "Build per-host user credential overrides")
    return _run_task(task, {"_openbao_host_users_resp": {"results": results}})


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_host_overrides_keep_only_credential_fields_by_presence(playbook):
    facts = _overrides(playbook, [
        dict(_kv({"ssh_private_key": "HOSTKEY", "ssh_passphrase": "", "ansible_host": "x"}), item="svcadm"),
        dict({"status": 404}, item="ppzxc"),
        dict({"status": 403}, item="other"),
        {"item": "skipped", "skipped": True},
    ])
    # Present-but-empty ssh_passphrase is kept: it clears the inherited passphrase.
    assert facts["_host_user_overrides"] == {"svcadm": {"ssh_private_key": "HOSTKEY", "ssh_passphrase": ""}}
    assert facts["_host_user_overrides_denied"] == ["other"]


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_primary_admin_entry_merges_host_override_over_global(playbook):
    task = _task(playbook, "Parse admin and bootstrap user secrets")
    ctx = {
        "_primary_admin_user": "svcadm",
        "_bootstrap_user": "root",
        "_effective_admin_user_resp": _kv({"ssh_private_key": "GLOBALKEY", "ssh_passphrase": "globalpass", "password": "gpw"}),
        "_effective_bootstrap_user_resp": _kv({"password": "rootpw"}),
        "_host_user_overrides": {"svcadm": {"ssh_private_key": "HOSTKEY", "ssh_passphrase": ""}},
    }
    entry = _run_task(task, ctx)["_admin_user_entry"]
    assert entry["ssh_private_key"] == "HOSTKEY"
    assert entry["ssh_passphrase"] == ""  # host cleared it; unencrypted host key is not re-decrypted
    assert entry["password"] == "gpw"  # not overridden -> inherited

    ctx["_host_user_overrides"] = {}
    entry = _run_task(task, ctx)["_admin_user_entry"]
    assert (entry["ssh_private_key"], entry["ssh_passphrase"]) == ("GLOBALKEY", "globalpass")


# --- accounts list ---------------------------------------------------------------

def _accounts(playbook, admins, globals_, overrides, removed):
    task = _task(playbook, "Build accounts list for common role")
    ctx = {
        "_normalized_admin_users": admins,
        "_openbao_all_admins_resp": {"results": [dict(_kv(globals_[u]), item=u) for u in admins if u in globals_]},
        "_host_user_overrides": overrides,
        "_removed_users": removed,
    }
    return {a["name"]: a for a in _run_task(task, ctx)["accounts"]}


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_accounts_use_host_public_key_and_union_revocations(playbook):
    accs = _accounts(
        playbook,
        ["svcadm", "ppzxc"],
        {
            "svcadm": {"ssh_public_key": NEW_KEY, "revoked_keys": [OLD_KEY]},
            "ppzxc": {"ssh_public_key": NEW_KEY},
        },
        {"ppzxc": {"ssh_public_key": HOST_KEY, "revoked_keys": OLD_KEY}},
        [],
    )
    assert accs["svcadm"]["keys"] == [NEW_KEY]
    assert accs["svcadm"]["revoked_keys"] == [OLD_KEY]
    assert accs["ppzxc"]["keys"] == [HOST_KEY]
    assert accs["ppzxc"]["revoked_keys"] == [OLD_KEY]
    assert all(a.get("state", "present") == "present" for a in accs.values())


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_host_cannot_unrevoke_a_globally_revoked_key(playbook):
    """revoked_keys is the union of global + host values; a host clearing its own list
    doesn't remove a key that users/<user> already revoked. Actually NOT deploying a
    key that's also revoked is COMMON-015's job (single source of truth, see its own
    test) -- this task only has to carry both 'keys' and 'revoked_keys' through untouched,
    without filtering them against each other and duplicating that rule here too."""
    accs = _accounts(
        playbook,
        ["svcadm"],
        {"svcadm": {"ssh_public_key": OLD_KEY + "\n", "revoked_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyBlob other-comment"]}},
        {"svcadm": {"revoked_keys": []}},
        [],
    )
    assert accs["svcadm"]["keys"] == [OLD_KEY]  # trimmed; deploy-time filtering happens in COMMON-015
    assert len(accs["svcadm"]["revoked_keys"]) == 1


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_host_only_public_key_applies_even_without_a_global_users_entry(playbook):
    """Regression test: hosts/<host>/users/<user> must win even when users/<user> doesn't
    exist at all (404) for a brand-new, host-KV-only account -- not just when it exists
    and the host merely overrides it."""
    accs = _accounts(
        playbook,
        ["newsvc"],
        {},  # no global users/<user> entry at all for "newsvc" (404 case)
        {"newsvc": {"ssh_public_key": HOST_KEY}},
        [],
    )
    assert accs["newsvc"]["keys"] == [HOST_KEY]
    assert accs["newsvc"]["revoked_keys"] == []


@pytest.mark.parametrize("playbook", PLAYBOOKS)
def test_removed_users_rendered_absent(playbook):
    accs = _accounts(playbook, ["svcadm"], {"svcadm": {"ssh_public_key": NEW_KEY}}, {}, ["olduser"])
    assert accs["olduser"]["state"] == "absent"
    assert accs["svcadm"].get("state", "present") == "present"


# --- safety refusal ----------------------------------------------------------------

@pytest.mark.parametrize("playbook", PLAYBOOKS)
@pytest.mark.parametrize("removed, ok", [
    (["olduser"], True),
    ([], True),
    (["svcadm"], False),        # connection (primary admin) user
    (["root"], False),          # _bootstrap_user
    (["centos"], False),        # bootstrap entry username (actual bootstrap login)
    (["ppzxc"], False),         # also declared in admin_users: contradictory
])
def test_removal_refuses_connection_bootstrap_and_declared_admins(playbook, removed, ok):
    task = _task(playbook, "Refuse removal of connection, bootstrap or declared admin users")
    ctx = {
        "_removed_users": removed,
        "_primary_admin_user": "svcadm",
        "_normalized_admin_users": ["svcadm", "ppzxc"],
        "_bootstrap_user": "root",
        "_bootstrap_user_entry": {"username": "centos"},
    }
    for name, expr in task["vars"].items():
        ctx[name] = _render(expr, ctx)
    results = [_render("{{ " + cond + " }}", ctx) for cond in task["ansible.builtin.assert"]["that"]]
    assert all(results) is ok


# --- common role: never redeploy a key that is also revoked (idempotency) --------

def _common_role_task(prefix):
    with open(COMMON_TASKS, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)
    for task in tasks:
        if task.get("name", "").startswith(prefix):
            return task
    raise AssertionError(f"task '{prefix}' missing in {COMMON_TASKS}")


@pytest.mark.parametrize("key, revoked, expect_deploy", [
    (NEW_KEY, [], True),
    (OLD_KEY, [OLD_KEY], False),
    (OLD_KEY + "\n", ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyBlob other-comment"], False),
    (NEW_KEY, [OLD_KEY], True),
])
def test_common015_skips_a_key_that_is_also_revoked(key, revoked, expect_deploy):
    """A key listed in both accounts[].keys and accounts[].revoked_keys (rotation lag,
    or a static inventory definition) must never be (re)deployed by COMMON-015, or it
    flip-flops `changed` against COMMON-022 on every run."""
    task = _common_role_task("[COMMON-015]")
    ctx = {"item": (({"name": "u", "revoked_keys": revoked}), key)}
    for name, expr in task["vars"].items():
        ctx[name] = _render(expr, ctx)
    results = [_render("{{ " + cond + " }}", ctx) for cond in task["when"] if "_key_fp" in cond or "_revoked_fps" in cond]
    assert all(results) is expect_deploy


# --- real ansible-playbook run with extra vars ------------------------------------

@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed")
@pytest.mark.parametrize("extra_var_value", [
    "legacy1,legacy2",              # Semaphore-style comma string
    '["legacy1","legacy2"]',        # Semaphore-style JSON array string
])
def test_tasks_execute_under_ansible_with_extra_vars(tmp_path, extra_var_value):
    names = [
        "Resolve accounts to remove",
        "Build per-host user credential overrides",
        "Parse admin and bootstrap user secrets",
        "Refuse removal of connection, bootstrap or declared admin users",
        "Build accounts list for common role",
    ]
    tasks = [_task(RESOLVE, n) for n in names]
    out = tmp_path / "out"
    tasks.append({
        "name": "Dump result",
        "ansible.builtin.copy": {
            "content": "{{ {'accounts': accounts, 'admin': _admin_user_entry} | to_json }}",
            "dest": f"{out}-{{{{ inventory_hostname }}}}.json",
            "mode": "0600",
        },
    })
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "become": False, "tasks": tasks,
    }]))

    common = {
        "_normalized_admin_users": ["svcadm"],
        "_primary_admin_user": "svcadm",
        "_bootstrap_user": "root",
        "_effective_admin_user_resp": _kv({"ssh_private_key": "GLOBALKEY", "ssh_passphrase": "gp"}),
        "_effective_bootstrap_user_resp": _kv({"password": "rootpw"}),
        "_openbao_all_admins_resp": {"results": [dict(_kv({"ssh_public_key": NEW_KEY, "revoked_keys": [OLD_KEY]}), item="svcadm")]},
        "_openbao_host_users_resp": {"results": [dict(_kv({"ssh_private_key": "HOSTKEY", "ssh_passphrase": ""}), item="svcadm")]},
    }
    inventory = {"all": {"hosts": {
        "good": dict(common, _host_kv_dict={"removed_users": ["olduser"]}),
        "bad": dict(common, _host_kv_dict={"removed_users": ["svcadm"]}),
    }}}
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inventory))

    import os
    res = subprocess.run(
        ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml"),
         "-e", f"target_removed_users={extra_var_value}"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120,
        env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_STDOUT_CALLBACK": "default",
             "ANSIBLE_DEPRECATION_WARNINGS": "False", "ANSIBLE_LOCALHOST_WARNING": "False"},
        cwd=str(ROOT_DIR),
    )
    assert res.returncode != 0, res.stdout
    assert "REMOVED-USER-CONFLICT" in res.stdout
    assert not Path(f"{out}-bad.json").exists()

    result = json.loads(Path(f"{out}-good.json").read_text())
    accs = {a["name"]: a for a in result["accounts"]}
    assert {n for n, a in accs.items() if a.get("state") == "absent"} == {"olduser", "legacy1", "legacy2"}
    assert accs["svcadm"]["keys"] == [NEW_KEY]
    assert accs["svcadm"]["revoked_keys"] == [OLD_KEY]
    assert (result["admin"]["ssh_private_key"], result["admin"]["ssh_passphrase"]) == ("HOSTKEY", "")


# --- removed_users: facts consumed by later tasks must be promoted -------------

@pytest.mark.parametrize("playbook", PLAYBOOKS)
@pytest.mark.parametrize("host_kv, run_var, invalid", [
    ({}, None, False),
    ({"removed_users": ["olduser"]}, "legacy1", False),
    ({"removed_users": {"a": 1}}, None, True),
    ({}, {"a": 1}, True),
])
def test_removed_users_follow_up_tasks_see_promoted_facts(playbook, host_kv, run_var, invalid):
    """Regression: task-level vars are invisible to later tasks (undefined at runtime)."""
    resolve = _task(playbook, "Resolve accounts to remove")
    ctx = {"_host_kv_dict": host_kv}
    if run_var is not None:
        ctx["target_removed_users"] = run_var
    facts = _run_task(resolve, ctx)
    assert facts["_removed_users_shape_invalid"] is invalid
    for name in ("_removed_users_detail", "_kv_removed_source", "_run_removed_source"):
        assert name in facts

    # Every promoted-name reference in the follow-up tasks resolves from facts alone.
    for prefix in ("Warn when removed_users", "Log accounts resolved for removal"):
        follow = _task(playbook, prefix)
        assert not follow.get("vars"), f"{prefix}: relies on facts, not task vars"
        text = json.dumps(follow)
        for name in ("_removed_users_shape_invalid", "_removed_users_detail",
                     "_kv_removed_source", "_run_removed_source"):
            if name in text:
                assert name in resolve["ansible.builtin.set_fact"], f"{name} not promoted"
