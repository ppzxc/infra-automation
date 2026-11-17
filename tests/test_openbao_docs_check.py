"""`openbao_docs.py check`(Periodic Check) 판정 (#519, Spec #511 §7·§8).

실제 서버에 접속하지 않는다. 공용 가짜 OpenBao(tests/openbao_fake.py), 가짜 Semaphore API, 알림 수신기를 로컬에 띄우고
CLI를 서브프로세스로 돌려 종료 코드·알림 본문·출력만 본다. 값은 모두 가짜다.
"""
import json
import socket
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from openbao_fake import FakeOpenBao

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "openbao_docs.py"
FIXTURES = ROOT / "tests" / "fixtures" / "openbao_docs" / "valid"
TOFU = ROOT / "tofu" / "openbao"

SEMAPHORE_TOKEN = "fake-semaphore-inventory-token"
OPENBAO_TOKEN = "fake-periodic-check-token"
SECRET_LIKE = "S3cr3t-FAKE-value-9f2c"  # 위반 문서에 심어 출력·알림에 나오는지 본다
ROLES = ["applier", "provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit",
         "network_backup", "github_webhook_watch", "periodic_check", "agent_session"]
HOSTS = ["ns0001", "ns0002", "ns0003", "ns0004"]


def iso(delta_days):
    t = datetime.now(timezone.utc) + timedelta(days=delta_days)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"  # OpenBao는 나노초 정밀도로 준다


class Recorder:
    """Semaphore API 가짜와 알림 수신기를 겸한다."""

    def __init__(self, hosts):
        self.hosts = hosts
        self.auth = []
        self.alerts = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                outer.auth.append(self.headers.get("Authorization"))
                if self.headers.get("Authorization") != "Bearer " + SEMAPHORE_TOKEN:
                    return self._json(401, {})
                if self.path == "/api/projects":
                    return self._json(200, [{"id": 1}, {"id": 2}])
                if self.path == "/api/project/1/inventory":
                    body = "all:\n  children:\n    servers:\n      hosts:\n" + \
                           "".join("        %s: {}\n" % h for h in outer.hosts)
                    return self._json(200, [{"id": 1, "type": "static-yaml", "inventory": body}])
                if self.path == "/api/project/2/inventory":
                    return self._json(200, [{"id": 2, "type": "file", "inventory": "inventory/x.ini"}])
                self._json(404, {})

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                outer.alerts.append((self.path, self.headers.get("Content-Type"), self.rfile.read(n).decode()))
                self._json(200, {})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def load_valid(fake, rec):
    """valid fixture 트리를 가짜 서버에 올린다. 알림·Semaphore 주소는 로컬 수신기로 바꾼다."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import openbao_validation as ov
    for doc, data in ov.load_tree(FIXTURES).items():
        mount, path = doc.split("/", 1)
        if doc == "secrets/services/alert/notify":
            data = {"url": rec.url + "/notify-hook"}
        elif doc == "inventory/services/semaphore":
            data = {"url": rec.url}
        elif doc == "secrets/services/semaphore/inventory_read":
            data = {"token": SEMAPHORE_TOKEN}
        fake.set(mount, path, data)


def healthy_routes(fake, secret_id_days=100):
    policies = sorted(p.stem for p in (TOFU / "policies").glob("*.hcl"))
    fake.raw("LIST", "sys/policies/acl", {"data": {"keys": policies + ["default", "root"]}})
    fake.raw("LIST", "auth/approle/role", {"data": {"keys": list(ROLES)}})
    fake.raw("GET", "sys/mounts", {"data": {"inventory/": {}, "secrets/": {}, "sys/": {}, "identity/": {},
                                               "cubbyhole/": {}}})
    fake.raw("GET", "sys/auth", {"data": {"approle/": {}, "userpass/": {}, "token/": {}}})
    for role in ROLES:
        fake.raw("LIST", "auth/approle/role/%s/secret-id" % role, {"data": {"keys": ["acc-" + role]}})
        fake.raw("POST", "auth/approle/role/%s/secret-id-accessor/lookup" % role,
                 {"data": {"expiration_time": iso(secret_id_days)}})


@pytest.fixture
def env():
    rec = Recorder(HOSTS)
    fake = FakeOpenBao(namespace="infra", token=OPENBAO_TOKEN)
    load_valid(fake, rec)
    healthy_routes(fake)
    yield fake, rec
    fake.close()
    rec.close()


def run(fake, extra_env=None):
    environ = {"PATH": "/usr/bin:/bin", "VAULT_ADDR": fake.url, "VAULT_TOKEN": OPENBAO_TOKEN,
               "VAULT_NAMESPACE": "infra"}
    environ.update(extra_env or {})
    return subprocess.run([sys.executable, str(CLI), "check", "--tofu-dir", str(TOFU)],
                          capture_output=True, text=True, env=environ)


def alert_text(rec):
    assert len(rec.alerts) == 1, rec.alerts
    return rec.alerts[0][2]


def test_healthy_passes_silently_and_reads_semaphore_with_its_own_token(env):
    fake, rec = env
    r = run(fake)
    assert r.returncode == 0, r.stderr
    assert rec.alerts == []
    assert set(rec.auth) == {"Bearer " + SEMAPHORE_TOKEN}  # inventory_read 토큰만 쓴다(OpenBao 토큰이 아니다)


def test_schema_violation_fails_and_alert_names_doc_and_rule_without_values(env):
    fake, rec = env
    fake.set("inventory", "assets/ns0001", {"description": SECRET_LIKE, "type": "server", "bogus_key": SECRET_LIKE})
    r = run(fake)
    assert r.returncode == 1
    body = alert_text(rec)
    assert "inventory/assets/ns0001" in body and "additionalProperties" in body
    for text in (body, r.stdout, r.stderr):
        assert SECRET_LIKE not in text
    assert rec.alerts[0][0] == "/notify-hook" and rec.alerts[0][1].startswith("text/plain")


def test_secret_document_violation_hides_value_too(env):
    fake, rec = env
    fake.set("secrets", "services/openobserve/admin", {"username": "u", "password": SECRET_LIKE, "extra": SECRET_LIKE})
    r = run(fake)
    assert r.returncode == 1
    for text in (alert_text(rec), r.stdout, r.stderr):
        assert SECRET_LIKE not in text


def test_reference_violation_fails(env):
    fake, rec = env
    fake.remove("secrets", "assets/ns0001/credentials/root")
    r = run(fake)
    assert r.returncode == 1
    assert "inventory/assets/ns0001\t#/access/bootstrap_credential\taccess_credential_missing" in alert_text(rec)


def test_host_only_in_semaphore_inventory_fails(env):
    fake, rec = env
    rec.hosts = HOSTS + ["ns9999"]
    r = run(fake)
    assert r.returncode == 1
    assert "inventory/assets/ns9999\t#\tinventory_missing_asset" in alert_text(rec)


def test_recent_orphan_asset_only_warns_in_log(env):
    fake, rec = env
    rec.hosts = HOSTS[:3]  # ns0004는 Asset 문서만 있다. 수정한 지 29일
    fake.set("inventory", "assets/ns0004", fake_doc(fake, "assets/ns0004"), updated_time=iso(-29))
    r = run(fake)
    assert r.returncode == 0
    assert rec.alerts == []
    assert "inventory/assets/ns0004" in r.stderr and "orphan_asset" in r.stderr


def test_orphan_asset_untouched_for_over_30_days_fails(env):
    fake, rec = env
    rec.hosts = HOSTS[:3]
    fake.set("inventory", "assets/ns0004", fake_doc(fake, "assets/ns0004"), updated_time=iso(-31))
    r = run(fake)
    assert r.returncode == 1
    assert "inventory/assets/ns0004\t#\torphan_asset_stale" in alert_text(rec)


def fake_doc(fake, path):
    return fake._docs[("inventory", path)][1]["data"]["data"]


def test_secret_id_expiring_within_30_days_fails(env):
    fake, rec = env
    fake.raw("POST", "auth/approle/role/provision/secret-id-accessor/lookup",
             {"data": {"expiration_time": iso(10)}})
    r = run(fake)
    assert r.returncode == 1
    assert "auth/approle/role/provision\t#\tsecret_id_expiring" in alert_text(rec)


def test_secret_id_with_more_than_30_days_left_passes(env):
    fake, rec = env
    fake.raw("POST", "auth/approle/role/provision/secret-id-accessor/lookup",
             {"data": {"expiration_time": iso(31)}})
    assert run(fake).returncode == 0


def test_secret_id_without_expiry_passes(env):
    fake, rec = env
    fake.raw("POST", "auth/approle/role/provision/secret-id-accessor/lookup", {"data": {"expiration_time": ""}})
    assert run(fake).returncode == 0


@pytest.mark.parametrize("route, doc", [
    (("LIST", "sys/policies/acl", "policy"), "sys/policies/acl/hand-made"),
    (("LIST", "auth/approle/role", "role"), "auth/approle/role/hand-made"),
    (("GET", "sys/mounts", "mount"), "sys/mounts/hand-made"),
    (("GET", "sys/auth", "mount"), "sys/auth/hand-made"),
])
def test_object_missing_from_opentofu_code_is_detected(env, route, doc):
    fake, rec = env
    method, path, _ = route
    body = fake._raw[(method, path)][1]
    if "keys" in body["data"]:
        body["data"]["keys"].append("hand-made")
    else:
        body["data"]["hand-made/"] = {}
    r = run(fake)
    assert r.returncode == 1
    assert doc + "\t#\tnot_in_opentofu" in alert_text(rec)


def test_tofu_object_missing_from_server_is_not_a_failure(env):
    fake, rec = env  # 코드에는 있고 서버에는 없는 것은 plan이 잡는다. 점검 대상은 코드에 없는 것이다
    fake._raw[("LIST", "auth/approle/role")][1]["data"]["keys"].remove("agent_session")
    assert run(fake).returncode == 0


def test_unreachable_semaphore_fails_and_alerts(env):
    fake, rec = env
    with socket.socket() as sock:  # 방금 닫은 로컬 포트는 즉시 연결 거부된다
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    fake.set("inventory", "services/semaphore", {"url": "http://127.0.0.1:%d" % port})
    r = run(fake)
    assert r.returncode == 1
    assert "semaphore_unreachable" in alert_text(rec)


def test_unreadable_document_fails_with_rule_name(env):
    fake, rec = env
    fake.deny("inventory", "assets/ns0002")
    r = run(fake)
    assert r.returncode == 1
    assert "inventory/assets/ns0002\t#\tread_failed" in alert_text(rec)


def test_missing_connection_settings_is_usage_error(env):
    fake, rec = env
    r = subprocess.run([sys.executable, str(CLI), "check", "--tofu-dir", str(TOFU)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 2


def test_approle_login_is_used_without_token():
    rec = Recorder(HOSTS)
    with FakeOpenBao(namespace="infra", approle=True) as fake:
        load_valid(fake, rec)
        healthy_routes(fake)
        fake._raw[("POST", "auth/approle/login")] = (200, {"auth": {"client_token": "approle-issued"}})
        r = subprocess.run([sys.executable, str(CLI), "check", "--tofu-dir", str(TOFU)], capture_output=True,
                           text=True, env={"PATH": "/usr/bin:/bin", "VAULT_ADDR": fake.url, "VAULT_NAMESPACE": "infra",
                                            "VAULT_ROLE_ID": "fake-role", "VAULT_SECRET_ID": "fake-secret"})
        assert r.returncode == 0, r.stderr
        assert len(fake.logins()) == 1
    rec.close()


def test_failed_inventory_listing_does_not_flood_missing_asset_failures(env):
    fake, rec = env
    fake.raw("LIST", "inventory/metadata", {"errors": []}, status=500)
    assert run(fake).returncode == 1
    body = alert_text(rec)
    assert "inventory/\t#\tlist_failed" in body and "inventory_missing_asset" not in body


def test_failed_role_listing_is_reported_not_skipped(env):
    fake, rec = env
    fake.raw("LIST", "auth/approle/role", {"errors": []}, status=500)
    assert run(fake).returncode == 1
    assert "auth/approle/role\t#\tsecret_id_lookup_failed" in alert_text(rec)


def test_soft_deleted_document_is_ignored_not_read_failed(env):
    fake, rec = env
    fake.set("inventory", "assets/ns0004", fake_doc(fake, "assets/ns0004"))
    rec.hosts = HOSTS[:3]
    fake.soft_delete("inventory", "assets/ns0004")
    r = run(fake)
    assert r.returncode == 0, r.stdout


def test_old_secret_id_during_rotation_does_not_alert():
    sys.path.insert(0, str(ROOT / "scripts"))
    import openbao_check as oc

    class Stub:  # 옛 secret_id는 5일, 새것은 150일 남았다
        def request(self, method, path, body=None):
            if method == "LIST":
                return {"data": {"keys": ["old", "new"]}}
            return {"data": {"expiration_time": iso(5 if body["secret_id_accessor"] == "old" else 150)}}

    assert oc.check_secret_ids(Stub(), ["provision"], datetime.now(timezone.utc)) == []


def test_yaml_hosts_only_come_from_inventory_structure():
    sys.path.insert(0, str(ROOT / "scripts"))
    import openbao_check as oc
    text = "all:\n  vars:\n    hosts: [not-a-host]\n  children:\n    g:\n      hosts:\n        ns0001: {}\n"
    assert oc.parse_inventory_hosts(text, "static-yaml") == {"ns0001"}


def test_expected_objects_are_read_from_the_real_opentofu_code():
    sys.path.insert(0, str(ROOT / "scripts"))
    import openbao_check as oc
    expected = oc.expected_from_tofu(TOFU)
    assert expected["roles"] == set(ROLES)
    assert expected["mounts"] == {"inventory", "secrets"}
    assert expected["auth"] == {"userpass", "approle"}
    assert {"applier", "periodic-check", "operator", "agent-session"} <= expected["policies"]


def test_managed_approles_list_equals_the_role_policy_keys_in_the_tf_code():
    import re
    tf = (TOFU / "approles.tf").read_text(encoding="utf-8")
    listed = set(re.findall(r'"([^"]+)"', re.search(r"managed_approles\s*=\s*\[(.*?)\]", tf, re.S).group(1)))
    family = re.search(r"family_policies\s*=\s*\{(.*?)\n  \}", tf, re.S).group(1)
    keys = set(re.findall(r"^    (\w+)\s*=\s*\[", family, re.M)) | {"host_audit"}      # role_policies = merge(family_policies, {host_audit})
    assert listed == keys


def test_an_unreadable_tofu_structure_fails_clearly_instead_of_reporting_everything_unmanaged(tmp_path):
    sys.path.insert(0, str(ROOT / "scripts"))
    import openbao_check as oc
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "x.hcl").write_text('path "inventory/data/x" {\n  capabilities = ["read"]\n}\n')
    (tmp_path / "main.tf").write_text("# 구조가 바뀌어 role·마운트가 없다\n")
    with pytest.raises(OSError, match="읽지 못했다"):
        oc.expected_from_tofu(tmp_path)


def test_secret_id_zero_expiry_time_means_no_expiry(env):
    fake, rec = env
    fake.raw("POST", "auth/approle/role/provision/secret-id-accessor/lookup",
             {"data": {"expiration_time": "0001-01-01T00:00:00Z"}})
    assert run(fake).returncode == 0


def test_wrong_tofu_dir_is_usage_error_not_false_alert(env):
    fake, rec = env
    environ = {"PATH": "/usr/bin:/bin", "VAULT_ADDR": fake.url, "VAULT_TOKEN": OPENBAO_TOKEN, "VAULT_NAMESPACE": "infra"}
    r = subprocess.run([sys.executable, str(CLI), "check", "--tofu-dir", str(ROOT / "nope")], capture_output=True,
                       text=True, env=environ)
    assert r.returncode == 2 and rec.alerts == []


def test_unreadable_document_does_not_cascade_into_reference_failures(env):
    fake, rec = env
    fake.deny("secrets", "assets/ns0001/credentials/root")
    assert run(fake).returncode == 1
    body = alert_text(rec)
    assert "read_failed" in body and "missing" not in body


def test_orphan_with_unreadable_update_time_is_labelled_so(env):
    fake, rec = env
    rec.hosts = HOSTS[:3]
    fake.set("inventory", "assets/ns0004", fake_doc(fake, "assets/ns0004"), updated_time="garbage")
    assert run(fake).returncode == 1
    assert "inventory/assets/ns0004\t#\torphan_metadata_unreadable" in alert_text(rec)


def test_unexpected_semaphore_response_shape_is_unreachable(env):
    fake, rec = env
    rec.hosts = None  # 가짜가 본문을 만들다 실패해 연결이 끊긴다
    r = run(fake)
    assert r.returncode == 1 and "semaphore_unreachable" in alert_text(rec)


def test_failed_secrets_listing_still_alerts_with_partial_store(env):
    fake, rec = env
    fake.raw("LIST", "secrets/metadata/assets", {"errors": []}, status=500)
    assert run(fake).returncode == 1
    body = alert_text(rec)  # alert/notify 문서가 목록에서 빠져도 이미 읽은 문서로 알림이 간다
    assert "secrets/assets/\t#\tlist_failed" in body and "semaphore_config_missing" not in body


def test_unexpected_response_shape_is_reported_not_a_traceback(env):
    fake, rec = env
    fake.raw("POST", "auth/approle/role/provision/secret-id-accessor/lookup", ["not", "a", "dict"])
    r = run(fake)
    assert r.returncode == 1 and "Traceback" not in r.stderr
    assert "check_internal_error" in alert_text(rec)
