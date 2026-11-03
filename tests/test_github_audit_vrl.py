"""github_audit_semantics VRL function (ADR-0008, Spec #399 / Ticket-3, test seam 2: the vrl CLI).

Records are what OpenObserve hands the function after flattening: ``service.name`` -> ``service_name``, the header attributes
of the collector contract (``header.X-Github-Event`` ...) -> ``header_x_github_event`` (the function also accepts the unlowered
and the dotted spelling), ``body`` is the webhook JSON text. Only fake organisations, users and ids (docs.github.com example level).
Set ``VRL_BIN`` (or put ``vrl`` on PATH); the tests skip without it.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
VRL_DIR = ROOT_DIR / "roles" / "openobserve_config" / "files" / "vrl"
GITHUB_VRL = VRL_DIR / "github_audit_semantics.vrl"
SECURITY_VRL = VRL_DIR / "security_semantics.vrl"
FORTIGATE_VRL = VRL_DIR / "fortigate_semantics.vrl"
VRL_BIN = os.environ.get("VRL_BIN") or shutil.which("vrl")

pytestmark = pytest.mark.skipif(not VRL_BIN, reason="vrl CLI not available (set VRL_BIN)")

ORG = {"login": "example-org", "id": 1}
REPO = {"name": "example-repo", "full_name": "example-org/example-repo", "id": 2}
ALICE = {"login": "alice-example", "id": 11}
BOB = {"login": "bob-example", "id": 12}
DELIVERY = "11111111-2222-3333-4444-555555555555"


def _apply(tmp_path, record, program=GITHUB_VRL):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(record) + "\n")
    res = subprocess.run([VRL_BIN, "--input", str(src), "--program", str(program), "--print-object", "--quiet"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def _rec(event, payload, **extra):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    rec = {"service_name": "github-audit", "host_name": "collector01", "body": body,
           "header_x_github_event": event, "header_x_github_delivery": DELIVERY, "header_x_github_hook_id": "123456789"}
    rec.update(extra)
    return rec


def _added(before, after):
    return {k: v for k, v in after.items() if before.get(k) != v}


def _fields(payload, event, action=None, **extra):
    p = dict(payload, sender=ALICE, organization=ORG)
    if action:
        p["action"] = action
    return _rec(event, p, **extra)


COMMON = {"github_delivery_id": DELIVERY, "github_hook_id": "123456789",
          "github_actor": "alice-example", "github_actor_ghost": False, "github_org": "example-org"}
TEAM = {"name": "Justice League", "slug": "justice-league", "id": 3}
FULL = "example-org/example-repo"

# every event of the confirmed list (facts.md section 1): payload, action, repository, target, target type
CASES = {
    "repository": ({"repository": REPO}, "archived", FULL, FULL, "repository"),
    "public": ({"repository": REPO}, None, FULL, FULL, "repository"),
    "team": ({"team": TEAM}, "created", None, "justice-league", "team"),
    "repository_ruleset": ({"repository": REPO, "repository_ruleset": {"id": 4, "name": "protect-main"}}, "edited",
                           FULL, "protect-main", "ruleset"),
    "personal_access_token_request": ({"personal_access_token_request": {"id": 5, "owner": BOB}}, "approved", None, "bob-example", "user"),
    "meta": ({"hook_id": 123456789, "hook": {"type": "Organization", "id": 123456789}}, "deleted", None, "123456789", "hook"),
    "organization": ({"membership": {"user": BOB, "role": "member"}}, "member_added", None, "bob-example", "user"),
    "member": ({"repository": REPO, "member": BOB}, "added", FULL, "bob-example", "user"),
    "membership": ({"member": BOB, "scope": "team", "team": TEAM}, "added", None, "bob-example", "user"),
    "org_block": ({"blocked_user": BOB}, "blocked", None, "bob-example", "user"),
    "branch_protection_rule": ({"repository": REPO, "rule": {"id": 6, "name": "main"}}, "created", FULL, "main", "branch_rule"),
    "deploy_key": ({"repository": REPO, "key": {"id": 7, "title": "ci-deploy-key"}}, "created", FULL, "ci-deploy-key", "deploy_key"),
    "custom_property": ({"definition": {"property_name": "environment"}}, "created", None, "environment", "custom_property"),
}


@pytest.mark.parametrize("event", sorted(CASES))
def test_every_confirmed_event_gets_event_action_actor_org_repository_and_target(tmp_path, event):
    payload, action, repo, target, target_type = CASES[event]
    rec = _fields(payload, event, action)
    expected = dict(COMMON, github_event=event, github_target=target, github_target_type=target_type)
    if action:
        expected["github_action"] = action
    if repo:
        expected["github_repo"] = repo
    if event == "membership":
        expected["github_team"] = "justice-league"
    assert _added(rec, _apply(tmp_path, rec)) == expected


def test_the_event_list_is_the_thirteen_confirmed_events():
    assert len(CASES) == 13


def test_organization_events_use_the_membership_invitation_or_user_as_target(tmp_path):
    rec = _fields({"invitation": {"login": "carol-example", "id": 13}}, "organization", "member_invited")
    assert _apply(tmp_path, rec)["github_target"] == "carol-example"
    rec = _fields({"user": BOB}, "organization", "member_removed")
    assert _apply(tmp_path, rec)["github_target"] == "bob-example"


@pytest.mark.parametrize("stem", ["header_x_github_", "header_X_Github_", "header.X-Github-"])
def test_event_delivery_and_hook_come_from_the_contracted_header_attribute_names(tmp_path, stem):
    sep = "-" if "-" in stem else "_"
    rec = _fields({"repository": REPO}, "x", "archived")
    for k in ("header_x_github_event", "header_x_github_delivery", "header_x_github_hook_id"):
        del rec[k]
    rec[stem + "event"] = "repository"
    rec[stem + "delivery"] = "aaaaaaaa-0000-0000-0000-000000000001"
    rec[stem + "hook" + sep + "id"] = "42"
    out = _apply(tmp_path, rec)
    assert (out["github_event"], out["github_delivery_id"], out["github_hook_id"]) == ("repository", "aaaaaaaa-0000-0000-0000-000000000001", "42")


def test_a_header_value_still_wrapped_in_an_array_is_read_as_its_single_string(tmp_path):
    rec = _fields({"repository": REPO}, "repository", "created", header_x_github_delivery=["abc-1"])
    assert _apply(tmp_path, rec)["github_delivery_id"] == "abc-1"


def test_original_body_and_every_existing_field_are_never_modified(tmp_path):
    rec = _fields(CASES["member"][0], "member", "added", severity=0, _timestamp=1700000000000000,
                  event_action="keep-me", user_name="keep-me-too")
    out = _apply(tmp_path, rec)
    for k, v in rec.items():
        assert out[k] == v, k


@pytest.mark.parametrize("sender", [{"login": "ghost", "id": 10137}, None], ids=["ghost-login", "no-sender"])
def test_an_unknown_actor_is_marked_ghost(tmp_path, sender):
    payload = {"action": "deleted", "repository": REPO, "organization": ORG}
    if sender:
        payload["sender"] = sender
    out = _apply(tmp_path, _rec("repository", payload))
    assert out["github_actor_ghost"] is True and out["github_event"] == "repository"
    assert out.get("github_actor", "ghost") == "ghost"


def test_a_known_actor_is_not_ghost(tmp_path):
    out = _apply(tmp_path, _fields({"repository": REPO}, "repository", "created"))
    assert out["github_actor_ghost"] is False and out["github_actor"] == "alice-example"


def test_unreadable_target_structure_still_yields_the_common_fields(tmp_path):
    out = _apply(tmp_path, _fields({"member": "not-an-object"}, "member", "added"))
    assert out["github_event"] == "member" and "github_target" not in out and out["github_org"] == "example-org"


@pytest.mark.parametrize("rec", [
    _rec("repository", "not json at all"),
    _rec("repository", '["a", "list"]'),
    _rec("repository", ""),
    _rec("some_new_event", {"action": "created", "sender": ALICE}),
    _rec("ping", {"zen": "Keep it logically awesome.", "sender": ALICE}),
    {"service_name": "github-audit", "body": json.dumps({"action": "created", "sender": ALICE})},
], ids=["not-json", "json-list", "empty-body", "unknown-event", "ping", "no-event-header"])
def test_non_json_unknown_event_and_headerless_records_pass_through_unchanged(tmp_path, rec):
    assert _apply(tmp_path, rec) == rec


@pytest.mark.parametrize("rec", [
    {"service_name": "fortigate-syslog", "body": json.dumps({"sender": ALICE}), "header_x_github_event": "repository"},
    {"service_name": "switch-syslog", "body": json.dumps({"sender": ALICE}), "header_x_github_event": "member"},
    {"process_executable_name": "sshd", "body": json.dumps({"sender": ALICE}), "header_x_github_event": "member"},
    {"body": json.dumps({"sender": ALICE}), "header_x_github_event": "member"},
], ids=["fortigate", "switch", "server-log", "no-service"])
def test_other_services_are_not_touched_even_when_the_body_looks_like_a_webhook(tmp_path, rec):
    assert _apply(tmp_path, rec) == rec


def test_the_dotted_service_name_attribute_is_accepted(tmp_path):
    rec = _fields({"repository": REPO}, "repository", "created")
    del rec["service_name"]
    rec["service.name"] = "github-audit"
    assert _apply(tmp_path, rec)["github_event"] == "repository"


@pytest.mark.parametrize("program", [SECURITY_VRL, FORTIGATE_VRL], ids=["security_semantics", "fortigate_semantics"])
def test_existing_functions_leave_github_audit_records_unchanged(tmp_path, program):
    rec = _fields(CASES["member"][0], "member", "added")
    assert _apply(tmp_path, rec, program=program) == rec


def test_chained_after_the_existing_functions_the_github_fields_are_added_to_the_same_record(tmp_path):
    rec = _fields(CASES["member"][0], "member", "added")
    out = _apply(tmp_path, _apply(tmp_path, _apply(tmp_path, rec, SECURITY_VRL), FORTIGATE_VRL))
    assert out == _apply(tmp_path, rec)
