"""접속 해석 공용 읽기 지점의 결정 규칙 (Spec #511 / Ticket-12, #523).

결정 함수(`resolve`·`admin_accounts`)는 문서를 돌려주는 `read` 함수만 받는 순수 함수라서 가짜 서버 없이 직접 시험한다.
데이터는 `tests/fixtures/openbao_docs/valid`(가짜 값만)다. 읽기 지점(`openbao_doc`) 자체는 공용 가짜 OpenBao로 시험한다.
"""
import copy
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "lookup_plugins"))
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import openbao_validation as ov  # noqa: E402
from openbao_connection import ConnectionError_, admin_accounts, preference_list, resolve  # noqa: E402
from openbao_ssh import openbao_connection_summary, openbao_ssh_common_args, openbao_ssh_proxy_command  # noqa: E402

VALID = ROOT_DIR / "tests" / "fixtures" / "openbao_docs" / "valid"


@pytest.fixture
def store():
    return copy.deepcopy(ov.load_tree(VALID))


def reader(store):
    def read(doc, required=True):
        if doc in store:
            return store[doc]
        if required:
            raise ConnectionError_("문서 없음: %s" % doc)
        return {}
    return read


# --- Endpoint 선택 ---------------------------------------------------------------------------------------------------

def test_first_registered_endpoint_of_the_preference_list_is_chosen(store):
    r = reader(store)
    assert resolve(r, "ns0003", ["ssh", "telnet"])["endpoint"] == "ssh"
    assert resolve(r, "ns0003", ["telnet", "ssh"])["endpoint"] == "telnet"
    assert resolve(r, "ns0003", ["https", "telnet", "ssh"])["endpoint"] == "telnet"  # 등록 안 된 https는 건너뛴다


def test_no_registered_endpoint_in_the_preference_list_is_an_error(store):
    with pytest.raises(ConnectionError_, match="선호 순서"):
        resolve(reader(store), "ns0001", ["telnet", "https"])


def test_selection_does_not_look_at_reachability_so_there_is_no_failover(store):
    # 선택은 문서만 본다. ssh가 등록돼 있으면 telnet이 아무리 멀쩡해도 ssh 하나만 돌려준다.
    out = resolve(reader(store), "ns0003", ["ssh", "telnet"])
    assert (out["endpoint"], out["protocol"], out["port"]) == ("ssh", "ssh", 22)


# --- 로그인 규칙과 비밀번호 접속 예외 ---------------------------------------------------------------------------------

def test_identity_logs_in_with_the_automation_key_and_keeps_the_password_for_become_only(store):
    out = resolve(reader(store), "ns0001", ["ssh"])
    assert out["login"] == {"mode": "identity", "username": "admin01",
                            "private_key": "/fake/path/to/automation_key"}
    assert out["become"] == {"method": "sudo", "password": "fake-pw-admin01"}
    assert out["password_auth_exception"] is False
    assert "password" not in out["login"]


def test_without_identity_the_credential_logs_in_with_its_own_secret_and_is_a_password_exception(store):
    out = resolve(reader(store), "ns0002", ["ssh"])
    assert out["login"] == {"mode": "password", "username": "root", "password": "fake-pw-root-0008"}
    assert out["password_auth_exception"] is True


def test_an_automation_passphrase_travels_with_the_identity_key(store):
    store["secrets/automation/ssh"]["passphrase"] = "fake-pass-automation"
    assert resolve(reader(store), "ns0001", ["ssh"])["login"]["passphrase"] == "fake-pass-automation"


def test_an_ssh_key_credential_without_identity_logs_in_with_its_own_key(store):
    store["inventory/assets/ns0001/endpoints"]["ssh"].pop("identity")
    out = resolve(reader(store), "ns0001", ["ssh"])
    assert out["login"] == {"mode": "key", "username": "admin01", "private_key": "/fake/path/to/key",
                            "passphrase": "fake-pass-0002"}
    assert out["password_auth_exception"] is True       # 판정은 identity 유무만 본다


def test_a_credential_name_override_logs_in_with_that_credentials_own_secret_even_on_an_identity_endpoint(store):
    out = resolve(reader(store), "ns0001", ["ssh"], credential="root")
    assert out["credential"] == "root"
    assert out["login"] == {"mode": "password", "username": "root", "password": "fake-pw-root-0001"}
    assert out["become"] == {"method": "sudo", "password": "fake-pw-root-0001"}


def test_overriding_with_the_endpoints_own_credential_keeps_the_identity_login(store):
    assert resolve(reader(store), "ns0001", ["ssh"], credential="admin01")["login"]["mode"] == "identity"


def test_identity_needs_a_username_on_the_credential(store):
    store["secrets/assets/ns0001/credentials/admin01"] = {"type": "password", "password": "fake-pw"}
    with pytest.raises(ConnectionError_, match="username"):
        resolve(reader(store), "ns0001", ["ssh"])


# --- become ----------------------------------------------------------------------------------------------------------

def test_su_takes_the_become_credentials_password(store):
    assert resolve(reader(store), "ns0002", ["ssh"])["become"] == {"method": "su", "password": "fake-pw-root-0008"}


def test_enable_takes_the_enable_credentials_password(store):
    out = resolve(reader(store), "ns0003", ["ssh"])
    assert out["become"] == {"method": "enable", "password": "fake-pw-enable-0011"}


def test_an_endpoint_without_become_has_no_become_result(store):
    assert resolve(reader(store), "ns0003", ["telnet"])["become"] == {}


def test_su_without_any_password_is_an_error(store):
    store["inventory/assets/ns0002/endpoints"]["ssh"]["become"].pop("credential")
    store["secrets/assets/ns0002/credentials/root"] = {"type": "ssh_key", "username": "root", "private_key": "/k"}
    with pytest.raises(ConnectionError_, match="su"):
        resolve(reader(store), "ns0002", ["ssh"])


# --- via 체인 --------------------------------------------------------------------------------------------------------

def test_via_becomes_a_hop_using_the_hop_endpoints_default_credential_and_identity(store):
    out = resolve(reader(store), "ns0003", ["ssh"])
    (hop,) = out["via"]
    assert (hop["asset"], hop["endpoint"], hop["address"], hop["port"]) == ("ns0001", "ssh", "192.0.2.11", 22)
    assert hop["login"] == {"mode": "identity", "username": "admin01", "private_key": "/fake/path/to/automation_key"}


def test_multi_hop_chain_is_listed_controller_side_first(store):
    out = resolve(reader(store), "ns0004", ["https"])
    assert [(h["asset"], h["endpoint"]) for h in out["via"]] == [("ns0001", "ssh"), ("ns0003", "ssh")]
    assert out["via"][1]["login"]["mode"] == "password"      # 경유지도 자기 기본 Credential을 쓴다
    assert out["login"]["mode"] == "token"


def test_a_via_cycle_is_an_error(store):
    store["inventory/assets/ns0001/endpoints"]["ssh"]["via"] = "ns0004/https"
    with pytest.raises(ConnectionError_, match="순환"):
        resolve(reader(store), "ns0004", ["https"])


def test_a_missing_via_target_is_an_error(store):
    store["inventory/assets/ns0003/endpoints"]["ssh"]["via"] = "ns0099/ssh"
    with pytest.raises(ConnectionError_, match="ns0099"):
        resolve(reader(store), "ns0003", ["ssh"])


# --- ProxyCommand ----------------------------------------------------------------------------------------------------

def _hop(asset, address, port, user):
    return {"asset": asset, "endpoint": "ssh", "protocol": "ssh", "address": address, "port": port,
            "login": {"mode": "identity", "username": user, "private_key": "ignored"}}


def test_two_hop_proxy_command_nests_each_hops_user_port_and_key():
    import shlex
    hops = [_hop("a", "192.0.2.21", 2201, "u1"), _hop("b", "192.0.2.22", 2202, "u2")]
    cmd = openbao_ssh_proxy_command(hops, ["/k/1", "/k/2"], "192.0.2.30", 22)
    fixed = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "IdentitiesOnly=yes"]
    inner = ["ssh", "-W", "192.0.2.22:2202"] + fixed + ["-i", "/k/1", "-p", "2201", "u1@192.0.2.21"]
    outer = ["ssh", "-W", "192.0.2.30:22"] + fixed + ["-i", "/k/2", "-p", "2202", "u2@192.0.2.22",
                                                       "-o", "ProxyCommand=" + shlex.join(inner)]
    assert shlex.split(cmd) == outer


def test_common_args_wrap_the_proxy_command_and_are_empty_without_hops():
    assert openbao_ssh_common_args([], [], "192.0.2.30", 22) == ""
    args = openbao_ssh_common_args([_hop("a", "192.0.2.21", 22, "u1")], ["/k/1"], "192.0.2.30", 22)
    assert args.startswith("-o 'ProxyCommand=") and "192.0.2.21" in args


def test_a_password_hop_is_refused_by_the_ssh_proxy_builder():
    hop = _hop("a", "192.0.2.21", 22, "u1")
    hop["login"] = {"mode": "password", "username": "u1", "password": "fake"}
    with pytest.raises(Exception, match="키 로그인"):
        openbao_ssh_proxy_command([hop], [None], "192.0.2.30", 22)


# --- 관리 계정 -------------------------------------------------------------------------------------------------------

def test_admin_accounts_take_operator_keys_and_the_automation_public_key(store):
    store["inventory/assets/ns0001"]["access"]["admin_credentials"] = ["admin01", "root"]
    store["secrets/assets/ns0001/credentials/root"]["username"] = "alice"
    accounts = admin_accounts(reader(store), "ns0001", ["ssh"])
    assert [a["name"] for a in accounts] == ["admin01", "alice"]
    assert accounts[0]["keys"] == ["ssh-ed25519 AAAAFAKEAUTOMATIONKEY automation@example.test"]
    assert accounts[0]["revoked_keys"] == []
    assert accounts[1]["keys"] == ["ssh-ed25519 AAAAFAKEKEYBODYFORTESTSONLY alice@example.test"]
    assert accounts[1]["revoked_keys"] == ["ssh-ed25519 AAAAFAKEREVOKEDKEYBODY alice-old@example.test"]
    assert all(a["tier"] == "admin" for a in accounts)


def test_an_admin_without_an_operator_document_is_an_error_not_a_default(store):
    store["inventory/assets/ns0001"]["access"]["admin_credentials"] = ["root"]
    with pytest.raises(ConnectionError_, match="operators/root"):
        admin_accounts(reader(store), "ns0001", ["ssh"])


# --- 읽기 지점(openbao_doc.Reader) -----------------------------------------------------------------------------------

import openbao_doc  # noqa: E402
from openbao_doc import NAMESPACE, OpenBaoError, Reader  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_login_cache(monkeypatch):
    openbao_doc._LOGIN_CACHE.clear()
    for name in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_NAMESPACE", "VAULT_MOUNT"):
        monkeypatch.delenv(name, raising=False)


def _vars(fake, **extra):
    return {"vault_addr": fake.url, "vault_role_id": "fake-role", "vault_secret_id": "fake-secret", **extra}


def test_reader_sends_the_infra_namespace_and_the_mount_path_and_ignores_namespace_overrides(fake_openbao, monkeypatch):
    monkeypatch.setenv("VAULT_NAMESPACE", "other/ns")
    monkeypatch.setenv("VAULT_MOUNT", "secret")
    doc = Reader(_vars(fake_openbao, vault_namespace="x", vault_mount="y")).read("inventory/assets/ns0001")
    assert doc["type"] == "server"
    (read,) = fake_openbao.reads()
    assert (read.namespace, read.mount, read.doc) == (NAMESPACE, "inventory", "assets/ns0001")


def test_a_missing_document_fails_unless_the_caller_says_it_is_optional(fake_openbao):
    reader = Reader(_vars(fake_openbao))
    with pytest.raises(OpenBaoError, match="inventory/assets/ns0099"):
        reader.read("inventory/assets/ns0099")
    assert reader.read("inventory/assets/ns0099", required=False) == {}


def test_a_denied_document_always_fails_and_never_echoes_the_response(fake_openbao):
    fake_openbao.deny("secrets", "automation/ssh")
    with pytest.raises(OpenBaoError) as err:
        Reader(_vars(fake_openbao)).read("secrets/automation/ssh", required=False)
    assert "403" in str(err.value) and "permission denied" not in str(err.value)


def test_unknown_mounts_are_refused_before_any_request(fake_openbao):
    with pytest.raises(OpenBaoError, match="마운트"):
        Reader(_vars(fake_openbao)).read("secret/hosts/ns0001")
    assert fake_openbao.requests == []


def test_a_token_from_one_login_serves_every_later_read(fake_openbao):
    token = Reader(_vars(fake_openbao)).token()
    shared = _vars(fake_openbao, _vault_token=token)
    for doc in ("inventory/assets/ns0001", "inventory/assets/ns0002/endpoints"):
        Reader(shared).read(doc)
    assert len(fake_openbao.logins()) == 1


def test_openbao_fixture_answers_without_any_network_and_is_the_only_source():
    fixture = {"inventory/assets/ns0001": {"type": "server"}}
    reader = Reader({"openbao_fixture": fixture, "vault_addr": "http://127.0.0.1:1"})
    assert reader.token() == ""
    assert reader.read("inventory/assets/ns0001") == {"type": "server"}
    with pytest.raises(OpenBaoError, match="필수 문서"):
        reader.read("secrets/automation/ssh")


def test_default_fixture_documents_all_match_the_index():
    from openbao_fake import default_store
    for path in default_store():
        assert ov.resolve_schema(path) is not None, path


def test_admin_accounts_also_refuse_an_unregistered_preference(store):
    with pytest.raises(ConnectionError_, match="선호 순서"):
        admin_accounts(reader(store), "ns0001", ["https"])


def test_the_connection_summary_carries_no_secret(store):
    summary = openbao_connection_summary(resolve(reader(store), "ns0004", ["https"]))
    text = repr(summary)
    for secret in ("fake-api-0012", "fake-pw", "/fake/path"):
        assert secret not in text
    assert summary["login_mode"] == "token" and [h["asset"] for h in summary["via"]] == ["ns0001", "ns0003"]


def test_an_ssh_login_without_a_username_is_an_error_not_the_controller_user(store):
    store["secrets/assets/ns0002/credentials/root"] = {"type": "password", "password": "fake-pw"}
    with pytest.raises(ConnectionError_, match="ns0002/root.*username"):
        resolve(reader(store), "ns0002", ["ssh"])


def test_a_document_missing_a_required_key_names_the_document_not_a_key_error(store):
    store["secrets/automation/ssh"] = {"public_key": "ssh-ed25519 AAAAFAKE"}
    with pytest.raises(ConnectionError_, match="secrets/automation/ssh.*private_key"):
        resolve(reader(store), "ns0001", ["ssh"])
    store["inventory/assets/ns0002/endpoints"]["ssh"]["become"] = {"credential": "root"}
    with pytest.raises(ConnectionError_, match="become.*method"):
        resolve(reader(store), "ns0002", ["ssh"])


def test_an_endpoint_missing_address_names_the_endpoint(store):
    store["inventory/assets/ns0001/endpoints"]["ssh"].pop("address")
    with pytest.raises(ConnectionError_, match="ns0001/endpoints.*address"):
        resolve(reader(store), "ns0001", ["ssh"])
    store["inventory/assets/ns0003/endpoints"]["ssh"]["via"] = "ns0001/ssh"
    store["inventory/assets/ns0001/endpoints"]["ssh"]["address"] = "192.0.2.11"
    store["inventory/assets/ns0001/endpoints"]["ssh"].pop("port")
    with pytest.raises(ConnectionError_, match="ns0001/endpoints.*port"):
        resolve(reader(store), "ns0003", ["ssh"])


def test_a_string_preference_is_split_on_commas_not_into_characters():
    assert preference_list("ssh, telnet") == ["ssh", "telnet"]
    assert preference_list(["ssh"]) == ["ssh"]


def test_a_credential_override_on_an_endpoint_without_a_default_credential_names_the_endpoint(store):
    store["inventory/assets/ns0001/endpoints"]["ssh"].pop("credential")
    with pytest.raises(ConnectionError_, match="ns0001/endpoints.*credential"):
        resolve(reader(store), "ns0001", ["ssh"], credential="root")
