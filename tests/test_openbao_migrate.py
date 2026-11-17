"""일회용 이전 스크립트 `scripts/openbao_migrate.py` 대응표 단위 테스트 (#521, Spec #511).

임시 테스트다. 옛 구조(`infra/prod/host`)를 지울 때 스크립트와 함께 지운다. 가짜 옛 문서만 쓰고 OpenBao 실서버에 접속하지 않는다.
CLI 테스트는 옛·새 네임스페이스를 가짜 서버 둘로 흉내 낸다.
"""
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from openbao_fake import FakeOpenBao

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "openbao_migrate.py"
SCHEMA_DIR = ROOT / "schemas" / "openbao"

spec = importlib.util.spec_from_file_location("openbao_migrate", CLI)
om = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ROOT / "scripts"))
spec.loader.exec_module(om)

import openbao_validation as ov  # noqa: E402

SECRET_VALUES = ["pw-admin-0001", "pw-bk-0002", "pw-net-0003", "tok-fg-0005", "cf-0006", "ingest-0001", "rk-0001",
                 "rs-0001", "restic-0001", "o2-pass-0010", "hook-secret-0011", "gh-token-0012", "alert-url-0013"]


def old_docs():
    return {
        # 서버(프로비저닝: 키 접속)
        "hosts/ns0001": {
            "description": "Fake server one", "host_type": "SERVER", "hostname": "ns0001", "fqdn": "ns0001.example.test",
            "domain": "example.test", "isms_target": True, "isms_group_asset_name": "", "isms_personal_info_system": False,
            "isms_department": "Fake Dept", "isms_owner_role": "Fake Owner", "isms_admin_role": "Fake Admin",
            "isms_asset_importance": "H", "admin_users": ["admin01"], "public_ip": "192.0.2.10", "ansible_port": "2222",
            "host_agents_allow_password_auth": False,
        },
        "hosts/ns0001/agents": {
            "o2_ingest_token": "ingest-0001", "rustfs_access_key": "rk-0001", "rustfs_secret_key": "rs-0001",
            "restic_password": "restic-0001", "host_agents_environment": "prod", "backup_extra_paths": ["/srv/fake"],
            "otel_container_logs": True, "github_webhook_port": "9000", "github_webhook_secret": "hook-secret-0011",
        },
        # 서버(레거시: 비밀번호 접속, bootstrap 계정)
        "hosts/ns0002": {
            "description": "Fake legacy", "host_type": "SERVER", "domain": "example.test", "admin_users": "admin01",
            "bootstrap_user": "bk", "public_ip": "192.0.2.11", "host_agents_allow_password_auth": True,
            "isms_target": False, "isms_group_asset_name": "g", "isms_personal_info_system": False,
        },
        "hosts/ns0002/users/bk": {"username": "bk", "type": "PASSWORD", "password": "pw-bk-0002"},
        "hosts/ns0002/users/root": {"username": "root", "type": "PASSWORD", "password": "unreferenced-root"},
        # 스위치: 직접 ssh
        "hosts/ns0003": {
            "description": "Fake switch", "host_type": "SWITCH", "fqdn": "ns0003.example.test", "ansible_host": "192.0.2.20",
            "ansible_port": 22, "ansible_user": "netadmin", "ansible_password": "pw-net-0003", "connection_type": "ssh",
        },
        # 스위치: 경유
        "hosts/ns0004": {
            "description": "Fake switch jump", "host_type": "SWITCH", "ansible_host": "192.0.2.21", "ansible_port": "22",
            "ansible_user": "netadmin", "ansible_password": "pw-net-0003", "connection_type": "jump_ssh",
            "bastion_host": "ns0003",
        },
        # 방화벽: hosts + fortigate 합치기
        "hosts/ns0005": {"description": "Fake fw", "host_type": "FIREWALL"},
        "fortigate/ns0005": {"ansible_host": "192.0.2.30", "ansible_port": "8443", "api_token": "tok-fg-0005",
                             "fqdn": "ns0005.example.test"},
        # FUNA 노드: domain 예외
        "hosts/ns0006": {
            "description": "Fake funa node", "host_type": "SERVER", "domain": "other.test", "admin_users": ["admin01"],
            "public_ip": "192.0.2.40", "host_agents_allow_password_auth": False, "CLOUDFLARE_API_TOKEN": "cf-0006",
            "cloudflare_api_token": "dup", "FUNA_NODE_NAME": "node-a", "FUNA_NODE_EXTERNAL_HOSTNAME": "a.example.test",
            "FUNA_NODE_EXTERNAL_WILDCARD_HOSTNAME": "*.a.example.test", "FUNA_NOTIFICATION_HEADER": "hdr",
        },
        # bootstrap 흡수(ssh 키)
        "hosts/ns0007": {"description": "Fake boot", "host_type": "SERVER", "admin_users": ["admin01"],
                         "bootstrap_user": "bootkey", "public_ip": "192.0.2.50", "host_agents_allow_password_auth": True},
        "hosts/ns0007/bootstrap": {"username": "bootkey", "type": "SSH", "ssh_private_key": "KEY-BOOT",
                                   "ssh_public_key": "PUB-BOOT", "ssh_passphrase": "pp-boot", "password": "pw-boot"},
        # 전역 계정: 자동화 키 + Operator + 승격 비밀번호
        "users/admin01": {"username": "admin01", "type": "SSH", "password": "pw-admin-0001",
                          "ssh_private_key": "KEY-AUTO", "ssh_public_key": "PUB-AUTO", "ssh_passphrase": ""},
        "users/root": {"username": "root", "type": "PASSWORD", "password": "pw-root-global"},
        "agents/openobserve": {
            "api_user": "o2admin", "api_password": "o2-admin-pass", "controller_ingest_token": "Y3VzZXI6Y3Bhc3M=",
            "o2_endpoint": "https://o2.example.test", "normal_sources": ["192.0.2.250"],
            "alert_webhook_plain_url": "https://alert.example.test/plain/alert-url-0013",
            "alert_webhook_url": "https://alert.example.test/json", "alert_webhook_token": "t", "alert_webhook_auth_header": "h",
        },
        "agents/rustfs": {"maintenance_access_key": "mk", "maintenance_secret_key": "ms",
                          "rustfs_endpoint": "https://rustfs.example.test"},
        "agents/host_audit": {"storage_access_key": "sk", "storage_secret_key": "ss", "mail_from": "noreply@example.test",
                              "mail_from_name": "Fake Audit", "mail_to": "a@example.test, b@example.test"},
        "agents/github-webhook-watch": {
            "github_token": "gh-token-0012", "github_org": "fake-org", "hook_url": "https://hooks.example.test/x",
            "o2_org": "fake-o2", "o2_endpoint": "https://o2.example.test", "o2_ingest_user": "ingest",
            "o2_ingest_password": "o2-pass-0010",
        },
        "clusters/funa": {"FUNA_SERVICE_NAME": "fake-funa", "FUNA_HEALTH_CHECK_URI": "/health", "TZ": "Asia/Seoul",
                          "FUNA_NOTIFICATION_SMTP_PORT": "25"},
        "clusters/funa/proxy": {"DB_PASSWORD": "dbp", "FUNA_ADMIN_TOKEN": "adm"},
        "clusters/funa/vrrp": {"FUNA_NOTIFICATION_SMTP_PASSWORD": "sp", "FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN": "bt"},
    }


SKIP = ["hosts/ns0002/users/root", "switches/"]


@pytest.fixture(scope="module")
def plan():
    return om.build_new(old_docs(), SKIP)


def test_asset_document_gets_metadata_isms_access_agents_and_drops_computed_keys(plan):
    assert plan.store["inventory/assets/ns0001"] == {
        "description": "Fake server one", "type": "SERVER",
        "isms": {"target": True, "group_asset_name": "", "personal_info_system": False, "department": "Fake Dept",
                 "owner_role": "Fake Owner", "admin_role": "Fake Admin", "asset_importance": "H"},
        "access": {"admin_credentials": ["admin01"]},
        "agents": {"backup": {"extra_paths": ["/srv/fake"]}, "otel": {"container_logs": True},
                   "github_webhook": {"port": "9000"}},
    }


def test_agent_secrets_use_new_key_names_and_environment_is_dropped(plan):
    assert plan.store["secrets/assets/ns0001/agents"] == {
        "ingest_token": "ingest-0001", "rustfs_access_key": "rk-0001", "rustfs_secret_key": "rs-0001",
        "restic_password": "restic-0001", "webhook_secret": "hook-secret-0011"}


def test_provisioned_server_endpoint_uses_automation_identity_and_global_account_password(plan):
    assert plan.store["inventory/assets/ns0001/endpoints"] == {
        "ssh": {"protocol": "ssh", "address": "192.0.2.10", "port": 2222, "credential": "admin01",
                "identity": "automation", "become": {"method": "sudo"}}}
    assert plan.store["secrets/assets/ns0001/credentials/admin01"] == {
        "type": "password", "username": "admin01", "password": "pw-admin-0001"}


def test_password_auth_server_logs_in_with_bootstrap_credential_without_identity(plan):
    assert plan.store["inventory/assets/ns0002"]["access"] == {"admin_credentials": ["admin01"],
                                                               "bootstrap_credential": "bk"}
    assert plan.store["inventory/assets/ns0002/endpoints"] == {
        "ssh": {"protocol": "ssh", "address": "192.0.2.11", "port": 22, "credential": "bk", "become": {"method": "sudo"}}}
    assert plan.store["secrets/assets/ns0002/credentials/bk"] == {
        "type": "password", "username": "bk", "password": "pw-bk-0002"}


def test_unreferenced_account_documents_and_soft_deleted_switches_are_not_moved(plan):
    assert "secrets/assets/ns0002/credentials/root" not in plan.store
    assert not any("switches" in p for p in plan.store)


def test_old_bootstrap_document_is_absorbed_into_an_ssh_key_credential(plan):
    assert plan.store["secrets/assets/ns0007/credentials/bootkey"] == {
        "type": "ssh_key", "username": "bootkey", "private_key": "KEY-BOOT", "passphrase": "pp-boot", "password": "pw-boot"}
    assert "credential" in plan.store["inventory/assets/ns0007/endpoints"]["ssh"]
    assert "identity" not in plan.store["inventory/assets/ns0007/endpoints"]["ssh"]


def test_network_device_login_becomes_endpoint_and_credential_with_enable_escalation(plan):
    assert plan.store["inventory/assets/ns0003/endpoints"] == {
        "ssh": {"protocol": "ssh", "address": "192.0.2.20", "port": 22, "credential": "netadmin",
                "become": {"method": "enable"}}}
    assert plan.store["secrets/assets/ns0003/credentials/netadmin"] == {
        "type": "password", "username": "netadmin", "password": "pw-net-0003"}


def test_jump_connection_becomes_via_to_bastion_endpoint(plan):
    assert plan.store["inventory/assets/ns0004/endpoints"]["ssh"]["via"] == "ns0003/ssh"


def test_fortigate_document_merges_into_same_asset_as_https_endpoint_and_api_credential(plan):
    assert plan.store["inventory/assets/ns0005/endpoints"] == {
        "https": {"protocol": "https", "address": "192.0.2.30", "port": 8443, "credential": "api"}}
    assert plan.store["secrets/assets/ns0005/credentials/api"] == {"type": "api_token", "token": "tok-fg-0005"}
    assert plan.store["inventory/assets/ns0005"] == {"description": "Fake fw", "type": "FIREWALL"}


def test_funa_node_keys_and_cloudflare_token_go_to_asset_and_its_credential(plan):
    assert plan.store["inventory/assets/ns0006"]["funa"] == {
        "node_name": "node-a", "node_external_hostname": "a.example.test",
        "node_external_wildcard_hostname": "*.a.example.test", "notification_header": "hdr"}
    assert plan.store["secrets/assets/ns0006/credentials/cloudflare"] == {"type": "api_token", "token": "cf-0006"}


def test_domain_majority_becomes_common_and_only_exceptions_keep_a_domain(plan):
    assert plan.store["inventory/config/common"] == {"domain": "example.test"}
    assert plan.store["inventory/assets/ns0006"]["domain"] == "other.test"
    assert "domain" not in plan.store["inventory/assets/ns0001"]


def test_services_config_and_permission_documents(plan):
    s = plan.store
    assert s["inventory/services/openobserve"] == {"url": "https://o2.example.test"}
    assert s["inventory/services/rustfs"] == {"url": "https://rustfs.example.test"}
    assert s["inventory/services/github"] == {"url": "https://api.github.com", "org": "fake-org"}
    assert s["secrets/services/openobserve/admin"] == {"username": "o2admin", "password": "o2-admin-pass"}
    assert s["secrets/services/openobserve/ingest"] == {"username": "ingest", "password": "o2-pass-0010"}
    assert s["secrets/services/rustfs/maintenance"] == {"access_key": "mk", "secret_key": "ms"}
    assert s["secrets/services/rustfs/audit_reports"] == {"access_key": "sk", "secret_key": "ss"}
    assert s["secrets/services/alert/notify"] == {"url": "https://alert.example.test/plain/alert-url-0013"}
    assert s["secrets/services/github/org_hooks_read"] == {"token": "gh-token-0012"}
    assert s["inventory/config/host_audit"] == {"mail_recipients": ["a@example.test", "b@example.test"],
                                                "mail_sender": "noreply@example.test", "mail_sender_display_name": "Fake Audit"}
    assert s["inventory/config/openobserve_config"] == {"normal_sources": ["192.0.2.250"]}
    assert s["inventory/config/github_webhook_watch"] == {"hook_url": "https://hooks.example.test/x",
                                                          "github_org": "fake-org", "o2_org": "fake-o2"}


def test_funa_cluster_keys_are_lowercased_without_funa_prefix(plan):
    assert plan.store["inventory/services/funa"] == {"service_name": "fake-funa", "health_check_uri": "/health",
                                                     "tz": "Asia/Seoul", "notification_smtp_port": "25"}
    assert plan.store["secrets/services/funa/proxy"] == {"db_password": "dbp", "admin_token": "adm"}
    assert plan.store["secrets/services/funa/vrrp"] == {"notification_smtp_password": "sp",
                                                        "notification_naver_works_bot_token": "bt"}


def test_global_ssh_key_becomes_automation_identity_and_operator(plan):
    assert plan.store["secrets/automation/ssh"] == {"private_key": "KEY-AUTO", "public_key": "PUB-AUTO"}
    assert plan.store["inventory/operators/admin01"] == {"public_keys": ["PUB-AUTO"]}


def test_other_json_alert_keys_and_unused_keys_are_not_carried(plan):
    flat = json.dumps(plan.store)
    for gone in ("alert_webhook_token", "https://alert.example.test/json", "dup", "unreferenced-root", "ns0001.example.test"):
        assert gone not in flat


def test_every_new_document_passes_the_shared_validation(plan):
    assert plan.errors == []
    assert ov.validate_store(plan.store, SCHEMA_DIR) == []


def test_unmapped_key_is_an_error_naming_document_and_key_only():
    old = old_docs()
    old["hosts/ns0001"]["mystery_key"] = "leak-me-0099"
    plan = om.build_new(old, SKIP)
    assert [e for e in plan.errors if "mystery_key" in e]
    assert "leak-me-0099" not in " ".join(plan.errors)


def test_extra_skip_entry_for_a_single_key_silences_that_key():
    old = old_docs()
    old["hosts/ns0001"]["mystery_key"] = "x"
    assert om.build_new(old, SKIP + ["hosts/ns0001:mystery_key"]).errors == []


def test_ingest_account_can_be_taken_from_the_controller_token():
    plan = om.build_new(old_docs(), SKIP, ingest_source="controller_token")
    assert plan.store["secrets/services/openobserve/ingest"] == {"username": "cuser", "password": "cpass"}


# ---- CLI: 쓰기·재실행·보고서 -----------------------------------------------------------------------------------

@pytest.fixture
def servers():
    with FakeOpenBao(namespace="infra/prod/host") as old, FakeOpenBao(namespace="infra") as new:
        for path, data in old_docs().items():
            old.set("secret", path, data)
        yield old, new


def run_cli(servers, tmp_path, *extra, old_data=None):
    old, new = servers
    skip = tmp_path / "skip.yml"
    skip.write_text("\n".join("- " + s for s in SKIP) + "\n")
    token = tmp_path / "token"
    token.write_text("bao-test-token\n")
    return subprocess.run(
        [sys.executable, str(CLI), "--old-addr", old.url, "--new-addr", new.url, "--skip-file", str(skip),
         "--token-file", str(token), *extra], capture_output=True, text=True)


def test_dry_run_validates_and_writes_nothing(servers, tmp_path):
    r = run_cli(servers, tmp_path, "--dry-run")
    assert r.returncode == 0, r.stderr
    assert servers[1].writes() == []
    assert "dry-run" in r.stdout


def test_real_run_writes_every_document_with_cas_zero_and_reports_hash_matches(servers, tmp_path):
    r = run_cli(servers, tmp_path)
    assert r.returncode == 0, r.stderr
    new = servers[1]
    writes = {(w.mount + "/" + w.doc) for w in new.writes()}
    assert "inventory/assets/ns0001" in writes and "secrets/automation/ssh" in writes
    assert "MISMATCH" not in r.stdout and "match" in r.stdout
    assert any(l.startswith("secrets/assets/ns0001/credentials/admin01") for l in r.stdout.splitlines())


def test_output_never_contains_any_secret_value(servers, tmp_path):
    r = run_cli(servers, tmp_path)
    for secret in SECRET_VALUES + ["KEY-AUTO", "KEY-BOOT", "cpass", "o2-admin-pass"]:
        assert secret not in r.stdout + r.stderr


def test_rerun_skips_identical_documents_and_writes_nothing_more(servers, tmp_path):
    run_cli(servers, tmp_path)
    before = len(servers[1].writes())
    r = run_cli(servers, tmp_path)
    assert r.returncode == 0, r.stderr
    assert len(servers[1].writes()) == before
    assert "skipped" in r.stdout


def test_rerun_with_a_differing_document_shows_key_names_only_and_leaves_it(servers, tmp_path):
    run_cli(servers, tmp_path)
    new = servers[1]
    new.set("inventory", "assets/ns0001", {"description": "someone edited", "extra": "leak-me-0077"})
    before = len(new.writes())
    r = run_cli(servers, tmp_path)
    assert r.returncode == 2
    assert len(new.writes()) == before
    assert "inventory/assets/ns0001" in r.stdout and "extra" in r.stdout
    assert "leak-me-0077" not in r.stdout + r.stderr and "someone edited" not in r.stdout + r.stderr


def test_any_validation_failure_means_nothing_is_written(servers, tmp_path):
    old, new = servers
    broken = copy.deepcopy(old_docs()["hosts/ns0001"])
    del broken["description"]
    old.set("secret", "hosts/ns0001", broken)
    r = run_cli(servers, tmp_path)
    assert r.returncode == 1
    assert new.writes() == []
    assert "inventory/assets/ns0001" in r.stdout + r.stderr


def test_old_namespace_is_read_with_that_namespace_header_only(servers, tmp_path):
    run_cli(servers, tmp_path, "--dry-run")
    old, new = servers
    assert old.reads() and all(r.namespace == "infra/prod/host" for r in old.requests)
    assert all(r.namespace == "infra" for r in new.requests)


# ---- 리뷰 반영: 경계 사례 -----------------------------------------------------------------------------------------

def test_host_level_account_keeps_its_own_ssh_key():
    old = old_docs()
    old["hosts/ns0002/users/bk"] = {"username": "bk", "type": "SSH", "password": "pw-bk-0002", "ssh_private_key": "KEY-BK"}
    plan = om.build_new(old, SKIP)
    assert plan.store["secrets/assets/ns0002/credentials/bk"]["private_key"] == "KEY-BK"
    assert plan.store["secrets/assets/ns0002/credentials/bk"]["type"] == "ssh_key"


def test_unknown_key_in_an_account_document_is_an_error():
    old = old_docs()
    old["hosts/ns0002/users/bk"]["api_key"] = "leak-me-0088"
    plan = om.build_new(old, SKIP)
    assert any("hosts/ns0002/users/bk" in e and "api_key" in e for e in plan.errors)
    assert "leak-me-0088" not in " ".join(plan.errors)


def test_server_with_ansible_user_is_still_a_server_endpoint():
    old = old_docs()
    old["hosts/ns0001"]["ansible_user"] = "admin01"
    plan = om.build_new(old, SKIP)
    assert plan.store["inventory/assets/ns0001/endpoints"]["ssh"]["identity"] == "automation"
    assert plan.store["inventory/assets/ns0001/endpoints"]["ssh"]["become"] == {"method": "sudo"}


def test_keys_that_normalise_to_the_same_name_are_a_collision_error():
    old = old_docs()
    old["clusters/funa"]["FUNA_TZ"] = "x"
    plan = om.build_new(old, SKIP)
    assert any("key_collision" in e for e in plan.errors)


def test_account_document_without_host_document_is_an_error():
    old = old_docs()
    old["hosts/ns0999/users/bk"] = {"username": "bk", "type": "PASSWORD", "password": "x"}
    assert any("ns0999" in e and "no_host_document" in e for e in om.build_new(old, SKIP).errors)


def test_bad_skip_file_is_an_exit_code_not_a_traceback(servers, tmp_path):
    old, new = servers
    skip = tmp_path / "skip.yml"
    skip.write_text("hosts/ns0001: x\n")
    token = tmp_path / "token"
    token.write_text("t\n")
    r = subprocess.run([sys.executable, str(CLI), "--old-addr", old.url, "--new-addr", new.url, "--skip-file", str(skip),
                        "--token-file", str(token)], capture_output=True, text=True)
    assert r.returncode == 4 and "Traceback" not in r.stderr


def test_cas_conflict_on_an_unreadable_document_stops_instead_of_reporting_a_difference(servers, tmp_path):
    new = servers[1]
    new._docs[("inventory", "assets/ns0001")] = (404, {"errors": []})  # 소프트 삭제: 읽으면 404, cas는 실패
    r = run_cli(servers, tmp_path)
    assert r.returncode == 4 and "소프트 삭제" in r.stderr


def test_hash_report_flags_a_value_missing_after_write():
    plan = om.build_new(old_docs(), SKIP)
    actual = {path: copy.deepcopy(data) for path, data in plan.store.items()}
    del actual["secrets/assets/ns0001/agents"]["restic_password"]
    lines, bad = om.hash_report(plan, actual)
    assert bad == 1 and any(l.endswith("restic_password\tabsent") for l in lines)


def test_public_key_on_a_host_level_account_and_revoked_keys_without_public_key_are_errors():
    old = old_docs()
    old["hosts/ns0002/users/bk"]["ssh_public_key"] = "PUB-BK"
    old["users/root"]["revoked_keys"] = ["OLD"]
    errors = " ".join(om.build_new(old, SKIP).errors)
    assert "hosts/ns0002/users/bk" in errors and "users/root\trevoked_keys_without_public_key" in errors


def test_incomplete_ingest_account_and_server_without_address_are_errors():
    old = old_docs()
    del old["agents/github-webhook-watch"]["o2_ingest_password"]
    del old["hosts/ns0001"]["public_ip"]
    errors = " ".join(om.build_new(old, SKIP).errors)
    assert "ingest_account_incomplete" in errors and "hosts/ns0001\tno_address" in errors


def test_bootstrap_document_goes_to_the_bootstrap_credential_only():
    old = old_docs()
    old["hosts/ns0007"]["admin_users"] = ["admin01", "other"]
    old["users/other"] = {"username": "other", "type": "PASSWORD", "password": "pw-other"}
    plan = om.build_new(old, SKIP)
    assert plan.store["secrets/assets/ns0007/credentials/other"] == {"type": "password", "username": "other", "password": "pw-other"}
    assert plan.store["secrets/assets/ns0007/credentials/admin01"]["type"] == "password"
