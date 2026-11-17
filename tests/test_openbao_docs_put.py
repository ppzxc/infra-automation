"""`openbao_docs put` — 검증 후 쓰기 (#516, Spec #511 / Ticket-5).

공용 가짜 OpenBao(tests/openbao_fake.py)와 `openbao_docs.main`을 프로세스 안에서 돌려 외부 동작만 본다.
프롬프트(getpass)와 확인(input)은 표준 입력 계층을 바꿔 끼운다. 가짜 값만 쓴다.
"""
import getpass
import importlib.util
from pathlib import Path

import pytest
import yaml

from openbao_fake import FakeOpenBao

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("openbao_docs", ROOT / "scripts" / "openbao_docs.py")
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)

ASSET = {"description": "Fake server", "type": "server",
         "isms": {"department": "Fake Dept", "owner_role": "Fake Owner", "admin_role": "Fake Admin",
                  "asset_importance": "H"},
         "access": {"admin_credentials": ["admin01"]}}
ENDPOINTS = {"ssh": {"protocol": "ssh", "address": "192.0.2.11", "port": 22, "credential": "admin01"}}
CRED = {"type": "password", "username": "admin01", "password": "fake-pw-0001"}


@pytest.fixture
def fake():
    with FakeOpenBao() as f:
        yield f


@pytest.fixture
def run(fake, monkeypatch, tmp_path, capsys):
    """put을 돌린다. answers: 확인 입력, secrets: {필드: 프롬프트로 줄 값}. (종료 코드, 표준출력, 표준오류)."""
    for k, v in fake.env().items():
        monkeypatch.setenv(k, v)
    prompted = []

    def go(doc, content, *, merge=False, answers=("y",), secrets=None, extra=(), on_confirm=None):
        f = tmp_path / "in.yml"
        f.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
        queue = list(answers)

        def fake_input(prompt=""):
            if on_confirm:
                on_confirm()
            return queue.pop(0) if queue else "n"

        def fake_getpass(prompt="", *a, **k):
            field = prompt.rsplit(":", 1)[0].strip().split()[-1]
            prompted.append(field)
            return (secrets or {})[field]

        monkeypatch.setattr("builtins.input", fake_input)
        monkeypatch.setattr(getpass, "getpass", fake_getpass)
        argv = ["put", doc, str(f), *(["--merge"] if merge else []), *extra]
        rc = docs.main(argv)
        out = capsys.readouterr()
        return rc, out.out, out.err
    go.prompted = prompted
    return go


def seed_asset(fake, ns="ns0001", creds=("admin01",)):
    fake.set("inventory", f"assets/{ns}", ASSET)
    for c in creds:
        fake.set("secrets", f"assets/{ns}/credentials/{c}", CRED)


# ---- 쓰기와 cas ---------------------------------------------------------------------------------------------------

def test_new_document_is_written_with_cas_zero(fake, run):
    seed_asset(fake, creds=("admin01",))
    fake.remove("inventory", "assets/ns0001")
    rc, _, _ = run("inventory/assets/ns0001", ASSET)
    assert rc == 0
    [w] = fake.writes()
    assert w.body["options"] == {"cas": 0} and w.body["data"] == ASSET


def test_existing_document_is_written_with_current_version_as_cas(fake, run):
    seed_asset(fake)
    fake.set("inventory", "assets/ns0001", ASSET)  # 버전 2
    new = dict(ASSET, description="Changed")
    rc, _, _ = run("inventory/assets/ns0001", new)
    assert rc == 0
    [w] = fake.writes()
    assert w.body["options"] == {"cas": 2}
    assert fake.get("inventory", "assets/ns0001") == (new, 3)


def test_concurrent_modification_fails_without_overwriting(fake, run):
    seed_asset(fake)
    theirs = dict(ASSET, description="Theirs")
    rc, _, err = run("inventory/assets/ns0001", dict(ASSET, description="Mine"),
                     on_confirm=lambda: fake.set("inventory", "assets/ns0001", theirs))
    assert rc == 1 and "conflict" in err
    assert fake.get("inventory", "assets/ns0001")[0] == theirs


def test_patch_is_never_used_and_whole_document_is_written(fake, run):
    seed_asset(fake)
    rc, _, _ = run("inventory/assets/ns0001", {"description": "Merged"}, merge=True)
    assert rc == 0
    assert {r.method for r in fake.requests if r.doc and "assets/ns0001" == r.doc} <= {"GET", "POST"}
    [w] = fake.writes()
    assert w.body["data"] == dict(ASSET, description="Merged")


def test_merged_result_is_validated_as_a_whole_and_invalid_is_not_written(fake, run):
    seed_asset(fake)
    rc, out, _ = run("inventory/assets/ns0001", {"isms": {"asset_importance": "toaster"}}, merge=True)
    assert rc == 1 and fake.writes() == []
    assert "inventory/assets/ns0001\t#/isms/asset_importance\t" in out and "toaster" not in out


def test_schema_violation_is_refused_and_output_has_no_values(fake, run):
    rc, out, err = run("inventory/assets/ns0009", dict(ASSET, ansible_host="fake-leak-value-1"))
    assert rc == 1 and fake.writes() == []
    assert "fake-leak-value-1" not in out + err and "additionalProperties" in out


def test_unknown_document_path_is_refused(fake, run):
    rc, out, _ = run("inventory/nothing/here", {"a": 1})
    assert rc == 1 and fake.writes() == [] and "no_schema" in out


# ---- 확인과 차이 표시 -----------------------------------------------------------------------------------------------

def test_changed_keys_are_shown_and_declining_writes_nothing(fake, run):
    seed_asset(fake)
    rc, out, _ = run("inventory/assets/ns0001", dict(ASSET, description="Changed"), answers=("n",))
    assert rc == 1 and fake.writes() == []
    assert "#/description" in out and "#/type" not in out


def test_no_change_writes_nothing_and_succeeds(fake, run):
    seed_asset(fake)
    rc, out, _ = run("inventory/assets/ns0001", ASSET, answers=())
    assert rc == 0 and fake.writes() == []


def test_secret_fields_show_only_changed_never_values(fake, run, tmp_path):
    seed_asset(fake)
    rc, out, err = run("secrets/assets/ns0001/credentials/admin01",
                       {"type": "password", "username": "admin01", "password": None},
                       secrets={"password": "fake-new-pw-0002"})
    assert rc == 0
    assert "#/password" in out and "fake-new-pw-0002" not in out + err and "fake-pw-0001" not in out + err
    assert fake.get("secrets", "assets/ns0001/credentials/admin01")[0]["password"] == "fake-new-pw-0002"


# ---- 비밀 입력 ----------------------------------------------------------------------------------------------------

def test_secret_value_comes_only_from_prompt_not_from_env_or_argv(fake, run, monkeypatch):
    monkeypatch.setenv("PASSWORD", "fake-env-value")
    monkeypatch.setenv("OPENBAO_PASSWORD", "fake-env-value")
    seed_asset(fake, creds=())
    rc, _, _ = run("secrets/assets/ns0001/credentials/admin01",
                   {"type": "password", "username": "admin01", "password": None},
                   secrets={"password": "fake-prompted-1"})
    assert rc == 0 and run.prompted == ["password"]
    assert fake.get("secrets", "assets/ns0001/credentials/admin01")[0]["password"] == "fake-prompted-1"


@pytest.mark.parametrize("flag", ["--password", "--value", "--secret"])
def test_command_line_does_not_accept_secret_values(fake, run, flag):
    with pytest.raises(SystemExit) as e:
        run("secrets/assets/ns0001/credentials/admin01", {"type": "password", "password": None},
            extra=(flag, "fake-argv-value"))
    assert e.value.code == 2 and fake.writes() == []


def test_literal_secret_in_yaml_is_refused_without_echo(fake, run):
    rc, out, err = run("secrets/assets/ns0001/credentials/admin01",
                       {"type": "password", "username": "admin01", "password": "fake-in-file-3"})
    assert rc == 1 and fake.writes() == []
    assert "secret_value_in_file" in out and "fake-in-file-3" not in out + err


def test_private_key_is_read_from_a_file_path(fake, run, tmp_path):
    key = tmp_path / "key"
    key.write_text("-----BEGIN FAKE KEY-----\nline2\n-----END FAKE KEY-----\n")
    rc, out, _ = run("secrets/assets/ns0001/credentials/admin01",
                     {"type": "ssh_key", "username": "admin01", "private_key": str(key)})
    assert rc == 0 and run.prompted == []
    stored = fake.get("secrets", "assets/ns0001/credentials/admin01")[0]
    assert stored["private_key"] == key.read_text() and "FAKE KEY" not in out


def test_unreadable_private_key_path_fails_without_write(fake, run, tmp_path):
    rc, _, err = run("secrets/assets/ns0001/credentials/admin01",
                     {"type": "ssh_key", "username": "admin01", "private_key": str(tmp_path / "missing")})
    assert rc == 1 and fake.writes() == []


def test_secret_merge_keeps_unlisted_fields_and_prompts_only_listed(fake, run):
    fake.set("secrets", "assets/ns0001/credentials/admin01",
             {"type": "ssh_key", "username": "admin01", "private_key": "fake-key-body", "passphrase": "fake-pp-1"})
    rc, _, _ = run("secrets/assets/ns0001/credentials/admin01", {"passphrase": None}, merge=True,
                   secrets={"passphrase": "fake-pp-2"})
    assert rc == 0 and run.prompted == ["passphrase"]
    assert fake.get("secrets", "assets/ns0001/credentials/admin01")[0] == {
        "type": "ssh_key", "username": "admin01", "private_key": "fake-key-body", "passphrase": "fake-pp-2"}


# ---- 참조 검사 ----------------------------------------------------------------------------------------------------

def test_endpoint_with_missing_credential_is_refused_until_credential_exists(fake, run):
    seed_asset(fake, creds=())
    rc, out, _ = run("inventory/assets/ns0001/endpoints", ENDPOINTS)
    assert rc == 1 and fake.writes() == [] and "credential_missing" in out
    fake.set("secrets", "assets/ns0001/credentials/admin01", CRED)
    rc, _, _ = run("inventory/assets/ns0001/endpoints", ENDPOINTS)
    assert rc == 0 and len(fake.writes()) == 1


def test_asset_access_naming_missing_credential_is_refused(fake, run):
    rc, out, _ = run("inventory/assets/ns0001", ASSET)
    assert rc == 1 and "access_credential_missing" in out and fake.writes() == []


def test_via_cycle_through_another_document_is_refused(fake, run):
    seed_asset(fake)
    fake.set("inventory", "assets/ns0002/endpoints",
             {"ssh": dict(ENDPOINTS["ssh"], via="ns0001/ssh", credential="admin01")})
    fake.set("secrets", "assets/ns0002/credentials/admin01", CRED)
    rc, out, _ = run("inventory/assets/ns0001/endpoints", {"ssh": dict(ENDPOINTS["ssh"], via="ns0002/ssh")})
    assert rc == 1 and "via_cycle" in out and fake.writes() == []


def test_via_to_missing_endpoint_is_refused(fake, run):
    seed_asset(fake)
    rc, out, _ = run("inventory/assets/ns0001/endpoints", {"ssh": dict(ENDPOINTS["ssh"], via="ns0077/ssh")})
    assert rc == 1 and "via_missing" in out


def test_already_broken_reference_in_the_written_document_only_warns(fake, run):
    seed_asset(fake)
    broken = {"ssh": ENDPOINTS["ssh"], "web": {"protocol": "https", "address": "192.0.2.12", "port": 443,
                                                  "credential": "ghost"}}
    fake.set("inventory", "assets/ns0001/endpoints", broken)
    changed = {"ssh": dict(ENDPOINTS["ssh"], port=2222), "web": broken["web"]}
    rc, out, err = run("inventory/assets/ns0001/endpoints", changed)
    assert rc == 0 and len(fake.writes()) == 1
    assert "credential_missing" in err  # 경고는 표준오류


def test_other_documents_that_are_already_broken_do_not_block(fake, run):
    seed_asset(fake)
    fake.set("inventory", "assets/ns0002/endpoints", {"ssh": dict(ENDPOINTS["ssh"], credential="ghost")})
    rc, _, _ = run("inventory/assets/ns0001/endpoints", {"ssh": dict(ENDPOINTS["ssh"], via="ns0002/ssh")})
    assert rc == 0 and len(fake.writes()) == 1


# ---- 접속 ---------------------------------------------------------------------------------------------------------

def test_server_denial_reports_status_only(fake, run):
    seed_asset(fake)
    fake.deny("inventory", "assets/ns0001")
    rc, out, err = run("inventory/assets/ns0001", ASSET)
    assert rc == 1 and fake.writes() == [] and "403" in err


def test_feature_doc_is_indexed_and_explains_validate_put_and_onboarding_order():
    text = (ROOT / "docs" / "openbao_docs.md").read_text(encoding="utf-8")
    assert "openbao_docs.md" in (ROOT / "docs" / "INDEX.md").read_text(encoding="utf-8")
    for needle in ("`validate`", "`put`", "Credential 먼저, Endpoint 다음", "cas", "getpass"):
        assert needle in text
    assert text.index("secrets/assets/<ns>/credentials") < text.index("inventory/assets/<ns>/endpoints")


# ---- 코드 리뷰 반영 ------------------------------------------------------------------------------------------------

def test_soft_deleted_document_can_be_recreated_with_its_remaining_version(fake, run):
    seed_asset(fake)
    fake.soft_delete("inventory", "assets/ns0001")
    rc, _, _ = run("inventory/assets/ns0001", ASSET)
    assert rc == 0 and fake.writes()[-1].body["options"] == {"cas": 1}


def test_closed_stdin_cancels_cleanly(fake, run):
    seed_asset(fake)

    def eof():
        raise EOFError
    rc, _, err = run("inventory/assets/ns0001", dict(ASSET, description="Y"), on_confirm=eof)
    assert rc == 1 and fake.writes() == []


def test_invalid_document_is_refused_before_any_secret_prompt(fake, run):
    rc, _, _ = run("secrets/assets/ns0001/credentials/admin01",
                   {"type": "password", "usernme": "typo", "password": None}, secrets={"password": "fake-x"})
    assert rc == 1 and run.prompted == [] and fake.writes() == []


def test_empty_prompted_value_is_refused(fake, run):
    rc, _, _ = run("secrets/assets/ns0001/credentials/admin01",
                   {"type": "password", "username": "admin01", "password": None}, secrets={"password": ""})
    assert rc == 1 and fake.writes() == []


def test_empty_namespace_variable_falls_back_to_default(fake, run, monkeypatch):
    monkeypatch.setenv("VAULT_NAMESPACE", "")
    seed_asset(fake)
    rc, _, _ = run("inventory/assets/ns0001", dict(ASSET, description="Z"))
    assert rc == 0
    assert {r.namespace for r in fake.requests if r.doc and r.method == "POST"} == {"infra"}
