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
from openbao_connection import ConnectionError_, admin_accounts, host_connections, preference_list, resolve  # noqa: E402
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
    assert out["password_auth_exception"] is False      # 키로 로그인하면 비밀번호 접속 예외가 아니다(MON-020 게이트가 통과시키면 안 된다)


def test_a_password_login_on_an_identity_endpoint_override_is_not_a_password_exception(store):
    """Endpoint가 identity면 bootstrap Credential을 비밀번호로 쓰는 조회도 예외가 아니다(예외는 identity 없는 Endpoint만)."""
    out = resolve(reader(store), "ns0001", ["ssh"], credential="root")
    assert out["login"]["mode"] == "password" and out["password_auth_exception"] is False


def test_a_non_ssh_endpoint_is_never_a_password_exception(store):
    assert resolve(reader(store), "ns0004", ["https"])["password_auth_exception"] is False


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
    fixed = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "IdentitiesOnly=yes"]
    inner = ["ssh", "-W", "192.0.2.22:2202"] + fixed + ["-i", "/k/1", "-p", "2201", "u1@192.0.2.21"]
    outer = ["ssh", "-W", "192.0.2.30:22"] + fixed + ["-i", "/k/2", "-p", "2202", "u2@192.0.2.22",
                                                       "-o", "ProxyCommand=" + shlex.join(inner)]
    assert shlex.split(cmd) == outer


def test_every_hop_has_a_connect_timeout_and_a_proxy_command_without_hops_is_a_clear_error():
    hops = [{"asset": "a", "endpoint": "ssh", "address": "192.0.2.1", "port": 22, "login": {"mode": "key", "username": "u"}}]
    assert "ConnectTimeout=5" in openbao_ssh_proxy_command(hops, ["/k"], "192.0.2.30", 22)
    with pytest.raises(Exception, match="경유지가 하나 이상"):
        openbao_ssh_proxy_command([], [], "192.0.2.30", 22)


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
    for name in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_NAMESPACE", "VAULT_MOUNT", "VAULT_SKIP_VERIFY",
                 "VAULT_CACERT"):
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


def test_a_plain_token_is_never_a_way_in_only_approle_or_the_shared_login_token(fake_openbao, monkeypatch):
    """VAULT_TOKEN·vault_token 대체 경로는 없다(Spec #511 user story 41). 운영자 토큰은 scripts/ 쪽 도구만 쓴다."""
    monkeypatch.setenv("VAULT_TOKEN", "operator-token")
    only_token = {"vault_addr": fake_openbao.url, "vault_token": "operator-token"}
    with pytest.raises(OpenBaoError, match="AppRole"):
        Reader(only_token).read("inventory/assets/ns0001")
    assert fake_openbao.requests == []
    with pytest.raises(OpenBaoError, match="AppRole"):
        Reader({"vault_addr": fake_openbao.url}).token()


def test_https_certificates_are_verified_unless_the_variable_or_env_turns_it_off(monkeypatch):
    assert Reader({}).verify is True
    assert Reader({"vault_validate_certs": False}).verify is False
    assert Reader({"vault_validate_certs": "false"}).verify is False
    assert Reader({"vault_validate_certs": "true"}).verify is True
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
    assert Reader({}).verify is False


def test_a_private_ca_is_given_by_variable_or_env_not_by_turning_verification_off(monkeypatch):
    assert Reader({"vault_cacert": "/etc/pki/ca.pem"}).cacert == "/etc/pki/ca.pem"
    monkeypatch.setenv("VAULT_CACERT", "/etc/pki/env-ca.pem")
    assert Reader({}).cacert == "/etc/pki/env-ca.pem"


def test_an_unreadable_ca_file_is_an_openbao_error_not_a_raw_exception():
    reader = Reader({"vault_addr": "https://127.0.0.1:1", "vault_cacert": "/nonexistent/ca.pem",
                     "vault_role_id": "r", "vault_secret_id": "s"})
    with pytest.raises(OpenBaoError, match="CA"):
        reader.read("inventory/assets/ns0001")


def test_a_ca_file_that_is_not_pem_is_an_openbao_error_naming_the_file(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    reader = Reader({"vault_addr": "https://127.0.0.1:1", "vault_cacert": str(bad),
                     "vault_role_id": "r", "vault_secret_id": "s"})
    with pytest.raises(OpenBaoError, match="bad.pem"):
        reader.read("inventory/assets/ns0001")


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


def test_host_connections_equal_the_separate_resolutions_and_read_each_document_once(store):
    reads = []

    def counting(doc, required=True):
        reads.append(doc)
        return reader(store)(doc, required)

    memo = {}

    def memoized(doc, required=True):          # Reader.read와 같은 규칙: 읽은 문서는 다시 읽지 않는다
        if doc not in memo:
            memo[doc] = counting(doc, required)
        return memo[doc]

    out = host_connections(memoized, "ns0001", ["ssh"])
    admin = store["inventory/assets/ns0001"]["access"]["admin_credentials"][0]
    assert out["admin"] == resolve(reader(store), "ns0001", ["ssh"], credential=admin)
    assert out["admin_accounts"] == admin_accounts(reader(store), "ns0001", ["ssh"])
    assert out["asset"] == store["inventory/assets/ns0001"] and out["admin_credential"] == admin
    assert len(reads) == len(set(reads))


def test_host_connections_without_an_access_clause_use_the_default_credential_and_have_no_bootstrap(store):
    store["inventory/assets/ns0001"].pop("access")
    out = host_connections(reader(store), "ns0001", ["ssh"])
    assert out["admin_credential"] == "" and out["bootstrap"] == {} and out["admin_accounts"] == []
    assert out["admin"] == resolve(reader(store), "ns0001", ["ssh"])


def test_host_connections_stop_before_resolving_when_a_provisioning_target_has_no_access_clause(store):
    store["inventory/assets/ns0001"].pop("access")
    with pytest.raises(ConnectionError_, match=r"ACCESS-MISSING.*ns0001"):
        host_connections(reader(store), "ns0001", ["ssh"], requires_access=True)
    store["inventory/assets/ns0001"]["access"] = {"admin_credentials": ["admin01"]}          # bootstrap이 없어도 실패
    with pytest.raises(ConnectionError_, match="ACCESS-MISSING"):
        host_connections(reader(store), "ns0001", ["ssh"], requires_access=True)


def test_host_connections_without_accounts_do_not_need_the_operator_documents(store):
    store["inventory/assets/ns0001"]["access"]["admin_credentials"] = ["admin01", "root"]
    store.pop("inventory/operators/root", None)
    out = host_connections(reader(store), "ns0001", ["ssh"], with_accounts=False)
    assert out["admin_accounts"] == [] and out["admin"]["credential"] == "admin01"
    store["inventory/assets/ns0001"]["access"]["admin_credentials"] = ["root", "admin01"]
    with pytest.raises(ConnectionError_, match="operators/root"):
        host_connections(reader(store), "ns0001", ["ssh"])               # 기본(프로비저닝)은 그대로 필수다


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


@pytest.mark.parametrize("bad", ["", ",", [], {"a": 1}, 7])
def test_a_bad_preference_is_a_readable_error(bad):
    with pytest.raises(ConnectionError_, match="preference"):
        preference_list(bad)
