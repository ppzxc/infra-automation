"""Host Provisioning must target explicitly named hosts only.

Semaphore runs playbooks/provision_hosts.yml against the shared inventory, so a
missing ``target_hosts`` must never fall back to every server and load balancer.
Static tests pin the structure; behavior tests run ansible-playbook against a
throwaway inventory (the pre-flight play runs on localhost only, so a failure
happens before any host is contacted).
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
PROVISION = ROOT_DIR / "playbooks" / "provision_hosts.yml"

pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

INVENTORY = """\
all:
  children:
    servers:
      hosts:
        ns0001: {ansible_host: 192.0.2.1}
        ns0002: {ansible_host: 192.0.2.2}
        ns0003: {ansible_host: 192.0.2.3}
        ns0004: {ansible_host: 192.0.2.4}
        ns0005: {ansible_host: 192.0.2.5}
        ns0006: {ansible_host: 192.0.2.6}
    loadbalancers:
      hosts:
        lb0001: {ansible_host: 192.0.2.10}
"""


ALLOWED_ALL = "".join(
    f"        ns000{i}: {{}}\n" for i in range(1, 7)
) + "        lb0001: {}\n"
ALLOWED_GROUP = "    provision_allowed:\n      hosts:\n" + ALLOWED_ALL


def _plays():
    return yaml.safe_load(PROVISION.read_text(encoding="utf-8"))


def _import_index(plays):
    return next(i for i, p in enumerate(plays) if "ansible.builtin.import_playbook" in p)


# ---------------------------------------------------------------- static ----

def test_preflight_play_runs_on_localhost_before_site_import():
    plays = _plays()
    idx = _import_index(plays)
    assert idx >= 1, "pre-flight play must come before import_playbook"
    pre = plays[idx - 1]
    assert pre["hosts"] == "localhost"
    assert pre.get("gather_facts") is False
    text = PROVISION.read_text(encoding="utf-8")
    for token in ("target_hosts", "provision_max_hosts", "groups['all']"):
        assert token in text
    assert "always" in pre.get("tags", []), "pre-flight must not be skippable with --tags"
    assert "지정" in text  # Korean failure message


def test_site_yml_default_target_is_kept_for_cli():
    text = (ROOT_DIR / "playbooks" / "site.yml").read_text(encoding="utf-8")
    assert "default('servers:loadbalancers')" in text


# -------------------------------------------------------------- behavior ----

@pytest.fixture(scope="module")
def inv(tmp_path_factory):
    d = tmp_path_factory.mktemp("provision")
    f = d / "hosts.yml"
    f.write_text(INVENTORY + ALLOWED_GROUP)
    return f


@pytest.fixture(scope="module")
def preflight_only(tmp_path_factory):
    """provision_hosts.yml with the import_playbook removed: only the pre-flight."""
    plays = _plays()
    d = tmp_path_factory.mktemp("preflight")
    f = d / "preflight.yml"
    f.write_text(yaml.safe_dump(plays[: _import_index(plays)]))
    return f


def run(playbook, inv, *args, **extra):
    cmd = ["ansible-playbook", "-i", str(inv), str(playbook), *args]
    for k, v in extra.items():
        cmd += ["-e", f"{k}={v}"]
    env = {**os.environ, "ANSIBLE_NOCOLOR": "1"}
    return subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, env=env, timeout=120)


def assert_rejected(r):
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert "target_hosts" in out, out
    # Failed in the localhost pre-flight, before the connection-resolution play.
    assert "Controller Pre-flight" not in out, out
    assert "Provision Baseline" not in out, out


def test_missing_target_hosts_is_rejected(inv):
    assert_rejected(run(PROVISION, inv))


@pytest.mark.parametrize("value", ["", " ", ","])
def test_empty_target_hosts_is_rejected(inv, value):
    assert_rejected(run(PROVISION, inv, target_hosts=f"'{value}'"))


@pytest.mark.parametrize("value", [
    "servers", "loadbalancers", "all", "ungrouped",
    "ns0001:ns0002", "!ns0001", "ns0001:&servers", "ns*", "ns0001,ns0002:ns0003",
    "ns0001 ns0002", "ns0001,,ns0002", "ns0001,",
    "ns9999", "ns0001,ns9999", "servers,ns0001",
])
def test_invalid_target_hosts_is_rejected(inv, value):
    assert_rejected(run(PROVISION, inv, target_hosts=f"'{value}'"))


def test_more_than_max_hosts_is_rejected(inv):
    assert_rejected(run(PROVISION, inv, target_hosts="ns0001,ns0002,ns0003,ns0004,ns0005,ns0006"))


def test_max_hosts_can_be_raised_explicitly(inv, preflight_only):
    r = run(preflight_only, inv, target_hosts="ns0001,ns0002,ns0003,ns0004,ns0005,ns0006",
            provision_max_hosts=6)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("value", ["ns0001", "ns0001,ns0002", "ns0001,lb0001"])
def test_valid_target_hosts_pass_preflight(inv, preflight_only, value):
    r = run(preflight_only, inv, target_hosts=value)
    assert r.returncode == 0, r.stdout + r.stderr


def test_valid_target_hosts_limit_provisioning_to_named_hosts(inv):
    r = run(PROVISION, inv, "--list-hosts", target_hosts="ns0001,ns0002")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "ns0001" in out and "ns0002" in out
    for other in ("ns0003", "ns0006", "lb0001"):
        assert other not in out


# ------------------------------------------------------ provision_excluded ----

@pytest.fixture(scope="module")
def inv_excluded(tmp_path_factory):
    d = tmp_path_factory.mktemp("provision_excluded")
    f = d / "hosts.yml"
    f.write_text(INVENTORY + ALLOWED_GROUP + "    provision_excluded:\n      hosts:\n        ns0002: {}\n")
    return f


def test_provision_excluded_host_is_rejected_before_connecting(inv_excluded):
    r = run(PROVISION, inv_excluded, target_hosts="ns0001,ns0002")
    assert_rejected(r)
    assert "provision_excluded" in r.stdout + r.stderr


def test_provision_excluded_does_not_block_other_hosts(inv_excluded, preflight_only):
    r = run(preflight_only, inv_excluded, target_hosts="ns0001,ns0003")
    assert r.returncode == 0, r.stdout + r.stderr


def test_provision_excluded_group_name_is_not_a_valid_target(inv_excluded):
    assert_rejected(run(PROVISION, inv_excluded, target_hosts="provision_excluded"))


def test_missing_provision_excluded_group_passes(inv, preflight_only):
    r = run(preflight_only, inv, target_hosts="ns0001")
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------- provision_allowed ----

def _write_inv(tmp_path_factory, name, extra):
    d = tmp_path_factory.mktemp(name)
    f = d / "hosts.yml"
    f.write_text(INVENTORY + extra)
    return f


def _assert_not_allowed(r, *listed, unlisted=()):
    assert_rejected(r)
    out = r.stdout + r.stderr
    assert "허용 목록(provision_allowed)에 없는 호스트" in out, out
    for h in listed:
        assert h in out.split("허용 목록(provision_allowed)에 없는 호스트", 1)[1], out
    for h in unlisted:
        assert h not in out.split("허용 목록(provision_allowed)에 없는 호스트", 1)[1].split("\n\n")[0], out


def test_missing_provision_allowed_group_denies_everything(tmp_path_factory):
    f = _write_inv(tmp_path_factory, "no_allowed", "")
    _assert_not_allowed(run(PROVISION, f, target_hosts="ns0001"), "ns0001")


def test_empty_provision_allowed_group_denies_everything(tmp_path_factory):
    f = _write_inv(tmp_path_factory, "empty_allowed", "    provision_allowed:\n      hosts: {}\n")
    _assert_not_allowed(run(PROVISION, f, target_hosts="ns0001"), "ns0001")


def test_host_outside_provision_allowed_is_rejected(tmp_path_factory):
    f = _write_inv(tmp_path_factory, "other_allowed",
                   "    provision_allowed:\n      hosts:\n        ns0003: {}\n")
    _assert_not_allowed(run(PROVISION, f, target_hosts="ns0001"), "ns0001")


def test_subset_of_provision_allowed_passes(tmp_path_factory, preflight_only):
    f = _write_inv(tmp_path_factory, "subset_allowed",
                   "    provision_allowed:\n      hosts:\n        ns0001: {}\n        ns0002: {}\n")
    r = run(preflight_only, f, target_hosts="ns0001")
    assert r.returncode == 0, r.stdout + r.stderr


def test_allowed_and_excluded_host_is_rejected(tmp_path_factory):
    f = _write_inv(tmp_path_factory, "allowed_excluded",
                   "    provision_allowed:\n      hosts:\n        ns0001: {}\n        ns0002: {}\n"
                   "    provision_excluded:\n      hosts:\n        ns0002: {}\n")
    r = run(PROVISION, f, target_hosts="ns0002")
    assert_rejected(r)
    assert "provision_excluded" in r.stdout + r.stderr


def test_mixed_targets_list_only_the_not_allowed_hosts(tmp_path_factory):
    f = _write_inv(tmp_path_factory, "mixed_allowed",
                   "    provision_allowed:\n      hosts:\n        ns0001: {}\n")
    r = run(PROVISION, f, target_hosts="ns0001,ns0002")
    _assert_not_allowed(r, "ns0002", unlisted=("ns0001",))
