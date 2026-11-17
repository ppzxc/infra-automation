"""공용 읽기 지점의 토큰 만료 복구와 실패 사유 노출 (Spec #511 / Ticket-12, 최종 리뷰 2·3번).

* 플레이 첫머리에서 받아 `_vault_token`으로 넘긴 토큰은 AppRole token_ttl(30분)이 지나면 403이 된다. 읽기 지점은 이때 AppRole로
  한 번 다시 로그인해 같은 읽기를 되풀이한다(정책이 막은 403은 다시 로그인해도 같은 403이라 그대로 실패한다).
* `no_log: true` 태스크는 실패 사유를 가린다. 읽기 지점은 실패 사유(문서 경로·HTTP 상태, 비밀 없음)를 no_log와 무관한 표시 채널로
  한 번 더 낸다.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "lookup_plugins"))

import openbao_doc  # noqa: E402
from openbao_doc import OpenBaoError, Reader  # noqa: E402


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    openbao_doc._LOGIN_CACHE.clear()
    for name in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_SKIP_VERIFY", "VAULT_CACERT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def shown(monkeypatch):
    lines = []
    monkeypatch.setattr(openbao_doc.display, "error", lambda msg, *a, **k: lines.append(msg))
    return lines


def _vars(fake, **extra):
    return {"vault_addr": fake.url, "vault_role_id": "fake-role", "vault_secret_id": "fake-secret", **extra}


# --- 토큰 만료 복구 ---------------------------------------------------------------------------------------------------

def test_an_expired_shared_token_is_replaced_by_one_fresh_login_and_the_read_is_repeated(fake_openbao, shown):
    reader = Reader(_vars(fake_openbao, _vault_token="expired-token"))
    assert reader.read("inventory/assets/ns0001")["type"] == "server"
    assert len(fake_openbao.logins()) == 1
    assert [r.token for r in fake_openbao.reads()] == ["expired-token", "approle-issued"]
    assert shown == []                      # 복구된 403은 운영자에게 보이지 않는다


def test_the_renewed_token_serves_the_later_reads_of_the_same_reader(fake_openbao):
    reader = Reader(_vars(fake_openbao, _vault_token="expired-token"))
    reader.read("inventory/assets/ns0001")
    reader.read("inventory/assets/ns0002")
    assert len(fake_openbao.logins()) == 1
    assert [r.token for r in fake_openbao.reads()] == ["expired-token", "approle-issued", "approle-issued"]


def test_a_policy_denial_is_not_hidden_by_the_retry_it_logs_in_once_and_fails_with_the_status(fake_openbao, shown):
    fake_openbao.deny("secrets", "automation/ssh")
    reader = Reader(_vars(fake_openbao, _vault_token="approle-issued"))
    with pytest.raises(OpenBaoError, match="403"):
        reader.read("secrets/automation/ssh")
    assert len(fake_openbao.logins()) == 1
    assert len(shown) == 1 and "secrets/automation/ssh" in shown[0] and "403" in shown[0]


def test_when_the_renewal_login_fails_the_original_denied_document_is_still_named(fake_openbao, shown):
    fake_openbao.approle = False
    fake_openbao.raw("POST", "/v1/auth/approle/login", {"errors": ["denied"]}, status=400)
    fake_openbao.set("inventory", "assets/ns0001", {"description": "d"})
    fake_openbao.token = "valid-only"             # 공유 토큰은 403, 새 로그인은 400
    with pytest.raises(OpenBaoError, match=r"inventory/assets/ns0001.*403"):
        Reader(_vars(fake_openbao, _vault_token="expired-token")).read("inventory/assets/ns0001")
    assert any("inventory/assets/ns0001" in line and "403" in line for line in shown)


def test_a_fresh_login_that_is_denied_is_not_retried(fake_openbao):
    fake_openbao.deny("secrets", "automation/ssh")
    with pytest.raises(OpenBaoError):
        Reader(_vars(fake_openbao)).read("secrets/automation/ssh")
    assert len(fake_openbao.logins()) == 1 and len(fake_openbao.reads()) == 1


def test_a_shared_token_without_approle_credentials_cannot_renew_and_fails(fake_openbao, shown):
    reader = Reader({"vault_addr": fake_openbao.url, "_vault_token": "expired-token"})
    with pytest.raises(OpenBaoError, match="403"):
        reader.read("inventory/assets/ns0001")
    assert fake_openbao.logins() == []
    assert len(shown) == 1


# --- 실패 사유 표시 ---------------------------------------------------------------------------------------------------

def test_failures_are_shown_with_the_document_path_and_status_only(fake_openbao, shown):
    fake_openbao.deny("inventory", "assets/ns0001")
    with pytest.raises(OpenBaoError):
        Reader(_vars(fake_openbao)).read("inventory/assets/ns0001")
    (line,) = shown
    assert "inventory/assets/ns0001" in line and "403" in line
    for secret in ("fake-role", "fake-secret", "permission denied", "approle-issued"):
        assert secret not in line


def test_connection_errors_are_shown_too(shown):
    with pytest.raises(OpenBaoError, match="접속 실패"):
        Reader({"vault_addr": "http://127.0.0.1:1", "vault_role_id": "r", "vault_secret_id": "s"}).read("inventory/assets/ns0001")
    assert len(shown) == 1 and "접속 실패" in shown[0]


def test_a_missing_required_document_is_shown(fake_openbao, shown):
    with pytest.raises(OpenBaoError, match="ns0099"):
        Reader(_vars(fake_openbao)).read("inventory/assets/ns0099")
    assert len(shown) == 1 and "inventory/assets/ns0099" in shown[0]


def test_an_optional_missing_document_shows_nothing(fake_openbao, shown):
    assert Reader(_vars(fake_openbao)).read("inventory/assets/ns0099", required=False) == {}
    assert shown == []


def test_a_missing_login_credential_is_shown(shown):
    with pytest.raises(OpenBaoError, match="인증 정보"):
        Reader({"vault_addr": "http://127.0.0.1:1"}).read("inventory/assets/ns0001")
    assert len(shown) == 1


def test_a_process_login_is_preferred_over_the_stale_shared_token_so_the_403_is_not_repeated(fake_openbao):
    first = Reader(_vars(fake_openbao, _vault_token="expired-token"))
    first.read("inventory/assets/ns0001")                 # 403 뒤 재로그인(캐시에 새 토큰)
    second = Reader(_vars(fake_openbao, _vault_token="expired-token"))
    second.read("inventory/assets/ns0002")
    assert len(fake_openbao.logins()) == 1
    assert [r.token for r in fake_openbao.reads()] == ["expired-token", "approle-issued", "approle-issued"]


def test_the_reader_module_is_one_copy_shared_by_every_lookup_as_the_ansible_loader_sees_them():
    import sys
    from ansible.plugins.loader import lookup_loader
    for name in ("openbao_doc", "openbao_connection", "openbao_host_connection"):
        assert lookup_loader.get(name) is not None, name
    copies = [m for m in sys.modules if m.split(".")[-1] == "_openbao_reader"]
    assert copies == ["_openbao_reader"], copies                       # 이름을 달리해 두 번 올라간 사본이 없다
    shared = sys.modules["_openbao_reader"]
    assert openbao_doc.Reader is shared.Reader and openbao_doc._LOGIN_CACHE is shared._LOGIN_CACHE
    assert sys.modules["openbao_connection"].Reader is shared.Reader


def test_a_denied_login_is_shown_once(fake_openbao, shown):
    fake_openbao.approle = False
    fake_openbao.raw("POST", "/v1/auth/approle/login", {"errors": ["denied"]}, status=403)
    with pytest.raises(OpenBaoError, match="로그인"):
        Reader(_vars(fake_openbao)).read("inventory/assets/ns0001")
    assert len(shown) == 1 and "로그인" in shown[0]


def test_a_reader_reads_each_document_over_http_once(fake_openbao):
    reader = Reader(_vars(fake_openbao))
    assert reader.read("inventory/assets/ns0001") == reader.read("inventory/assets/ns0001")
    reader.read("inventory/assets/ns0099", required=False)
    reader.read("inventory/assets/ns0099", required=False)       # 없는 문서는 기억하지 않는다
    assert [r.doc for r in fake_openbao.reads()] == ["assets/ns0001", "assets/ns0099", "assets/ns0099"]


def test_a_caller_that_changes_a_returned_document_does_not_change_later_reads(fake_openbao):
    reader = Reader(_vars(fake_openbao))
    first = reader.read("inventory/assets/ns0001")
    first["access"] = "mutated"
    first.pop("description", None)
    again = reader.read("inventory/assets/ns0001")
    assert again["access"] != "mutated" and "description" in again


def test_connection_resolution_failures_are_shown_with_the_reason_and_no_secret(fake_openbao, shown, monkeypatch):
    import openbao_host_connection as ohc
    lines = []
    monkeypatch.setattr(ohc.display, "error", lambda msg, *a, **k: lines.append(msg))
    lookup = ohc.LookupModule()
    lookup._templar = None
    with pytest.raises(Exception, match="선호 순서"):
        lookup.run(["ns0001"], variables=_vars(fake_openbao), preference=["https"])
    assert len(lines) == 1 and "선호 순서" in lines[0] and "fake-secret" not in lines[0]


def test_quiet_lookups_show_nothing_and_do_not_leak_into_the_next_lookup(fake_openbao, shown):
    lookup = openbao_doc.LookupModule()
    lookup._templar = None
    fake_openbao.deny("inventory", "assets/ns0001")
    with pytest.raises(OpenBaoError):
        lookup.run(["inventory/assets/ns0001"], variables=_vars(fake_openbao), quiet=True, required=False)
    assert shown == []                       # ERROR 수준으로는 내지 않는다
    with pytest.raises(OpenBaoError):
        lookup.run(["inventory/assets/ns0001"], variables=_vars(fake_openbao))
    assert len(shown) == 1


def test_quiet_failures_are_still_available_at_verbose_level(fake_openbao, monkeypatch):
    lines = []
    monkeypatch.setattr(openbao_doc.display, "vv", lambda msg, *a, **k: lines.append(msg))
    fake_openbao.deny("inventory", "assets/ns0001")
    lookup = openbao_doc.LookupModule()
    lookup._templar = None
    with pytest.raises(OpenBaoError):
        lookup.run(["inventory/assets/ns0001"], variables=_vars(fake_openbao), quiet=True)
    assert len(lines) == 1 and "inventory/assets/ns0001" in lines[0] and "403" in lines[0]


def test_every_tolerant_openbao_doc_call_in_the_roles_is_quiet():
    """errors='ignore'·'warn' 호출은 quiet=true를 함께 준다(이중 ERROR 줄 방지). 기본 strict 호출에는 quiet이 없다."""
    import re
    for path in (ROOT_DIR / "roles").rglob("*.yml"):
        for call in re.findall(r"openbao_doc'[^}]*?\)", path.read_text(encoding="utf-8")):
            tolerant = "errors='ignore'" in call or "errors='warn'" in call
            assert tolerant == ("quiet=true" in call), (str(path), call)


def test_a_no_log_task_still_tells_the_operator_why_it_failed(fake_openbao, tmp_path):
    """실제 ansible-playbook: no_log 태스크의 결과는 가려지지만 실패 사유(경로·상태)는 출력에 남고 비밀은 없다."""
    fake_openbao.deny("secrets", "automation/ssh")
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "tasks": [
        {"ansible.builtin.set_fact": {"x": "{{ lookup('openbao_doc', 'secrets/automation/ssh') }}"}, "no_log": True}]}]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump(play))
    env = dict(os.environ, VAULT_ADDR=fake_openbao.url, VAULT_ROLE_ID="fake-role", VAULT_SECRET_ID="fake-secret")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120, env=env)
    out = res.stdout + res.stderr
    assert res.returncode != 0
    assert "secrets/automation/ssh" in out and "403" in out
    for secret in ("fake-secret", "approle-issued"):
        assert secret not in out
