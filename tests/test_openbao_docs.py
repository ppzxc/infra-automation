"""OpenBao 문서 스키마·index.yml·`openbao_docs validate` (#515, Spec #511).

OpenBao에 접속하지 않는다. 로컬 fixture 트리(`tests/fixtures/openbao_docs/`, 가짜 값만)를 검증 모듈과 CLI에 먹여
외부 동작(어떤 문서가 어떤 규칙 이름으로 거부되는가, 출력에 값이 나오는가)만 본다.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas" / "openbao"
FIXTURES = ROOT / "tests" / "fixtures" / "openbao_docs"
CLI = ROOT / "scripts" / "openbao_docs.py"

spec = importlib.util.spec_from_file_location("openbao_validation", ROOT / "scripts" / "openbao_validation.py")
ov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ov)

INVALID_CASES = sorted(p.name for p in (FIXTURES / "invalid").iterdir() if p.is_dir())


def run_cli(*args):
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True)


def expected_lines(case):
    text = (FIXTURES / "invalid" / case / "expected.txt").read_text()
    return sorted(line for line in text.splitlines() if line.strip())


def all_schema_files():
    return sorted(SCHEMA_DIR.rglob("*.schema.json"))


# ---- 정적 계약: 스키마 · index.yml -------------------------------------------------------------------------------

@pytest.mark.parametrize("path", all_schema_files(), ids=lambda p: str(p.relative_to(SCHEMA_DIR)))
def test_schema_conforms_to_metaschema_2020_12(path):
    schema = json.loads(path.read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("path", all_schema_files(), ids=lambda p: str(p.relative_to(SCHEMA_DIR)))
def test_every_object_forbids_extra_keys(path):
    def objects(node, pointer):
        if isinstance(node, dict):
            if node.get("type") == "object":
                yield pointer, node
            for k, v in node.items():
                yield from objects(v, pointer + "/" + k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from objects(v, "%s/%d" % (pointer, i))

    found = list(objects(json.loads(path.read_text()), ""))
    assert found
    for pointer, node in found:
        assert node.get("additionalProperties") is False, "%s%s" % (path.name, pointer)


def test_index_points_every_pattern_at_an_existing_schema():
    entries = ov.load_index(SCHEMA_DIR)
    assert entries, "index.yml이 비어 있다"
    for pattern, rel in entries:
        assert (SCHEMA_DIR / rel).is_file(), "%s -> %s" % (pattern, rel)


def test_every_schema_file_is_used_by_the_index():
    used = {rel for _, rel in ov.load_index(SCHEMA_DIR)}
    present = {str(p.relative_to(SCHEMA_DIR)) for p in all_schema_files()}
    assert present == used


def test_index_covers_every_document_kind_of_the_skeleton():
    paths = [
        "inventory/assets/ns0001", "inventory/assets/ns0001/endpoints", "secrets/assets/ns0001/credentials/root",
        "secrets/assets/ns0001/agents", "inventory/services/openobserve", "inventory/services/rustfs",
        "inventory/services/funa", "inventory/services/semaphore",
        "secrets/services/openobserve/admin", "secrets/services/openobserve/ingest",
        "secrets/services/rustfs/maintenance", "secrets/services/rustfs/audit_reports",
        "secrets/services/alert/notify",
        "secrets/services/funa/proxy", "secrets/services/funa/vrrp", "secrets/services/semaphore/inventory_read",
        "secrets/services/forgejo/idc_access_bot", "secrets/services/forgejo/idc_access_bot_login",
        "secrets/services/gws/directory_read",
        "secrets/automation/ssh", "inventory/operators/alice", "inventory/config/common",
        "inventory/config/host_audit", "inventory/config/openobserve_config",
        "inventory/config/log_review",
    ]
    for p in paths:
        assert ov.resolve_schema(p, SCHEMA_DIR) is not None, p


def test_unknown_document_path_has_no_schema():
    assert ov.resolve_schema("inventory/assets/ns0001/extra/deep", SCHEMA_DIR) is None
    assert ov.resolve_schema("secrets/nothing", SCHEMA_DIR) is None


# ---- 통과 fixture --------------------------------------------------------------------------------------------------

def test_valid_fixture_tree_passes_validation_and_references():
    store = ov.load_tree(FIXTURES / "valid")
    assert store, "valid fixture가 비었다"
    assert ov.validate_store(store, SCHEMA_DIR) == []


def test_valid_fixture_covers_every_document_kind():
    kinds = {ov.resolve_schema(p, SCHEMA_DIR) for p in ov.load_tree(FIXTURES / "valid")}
    assert kinds == {rel for _, rel in ov.load_index(SCHEMA_DIR)}


def test_valid_fixture_has_via_chain_and_all_credential_types():
    store = ov.load_tree(FIXTURES / "valid")
    endpoints = [e for p, d in store.items() if p.endswith("/endpoints") for e in d.values()]
    assert any("via" in e for e in endpoints)
    assert {"su", "enable", "sudo"} <= {e["become"]["method"] for e in endpoints if "become" in e}
    types = {d["type"] for p, d in store.items() if "/credentials/" in p}
    assert types == {"password", "ssh_key", "api_token"}


# ---- 실패 fixture: 문서 경로 + JSON 포인터 + 규칙 이름 -----------------------------------------------------------------

@pytest.mark.parametrize("case", INVALID_CASES)
def test_invalid_fixture_is_rejected_with_path_pointer_rule(case):
    store = ov.load_tree(FIXTURES / "invalid" / case)
    got = sorted(v.format() for v in ov.validate_store(store, SCHEMA_DIR))
    assert got == expected_lines(case)


def test_invalid_cases_cover_the_rejection_rules():
    rules = {line.split("\t")[2] for case in INVALID_CASES for line in expected_lines(case)}
    assert {"additionalProperties", "required", "enum", "type", "oneOf", "no_schema",
            "via_missing", "via_cycle", "credential_missing", "become_credential_missing",
            "access_credential_missing"} <= rules


def test_retired_legacy_keys_are_rejected():
    for key in ("ansible_host", "ansible_port", "ansible_user", "bootstrap_user", "public_ip", "ip", "host",
                "hostname", "fqdn"):
        asset = {"description": "x", key: "1"}
        got = ov.validate_document("inventory/assets/ns0001", asset, SCHEMA_DIR)
        assert [v.rule for v in got] == ["additionalProperties"], key
    endpoint = {"ssh": {"protocol": "ssh", "address": "192.0.2.1", "port": 22, "credential": "root",
                        "ansible_host": "x"}}
    got = ov.validate_document("inventory/assets/ns0001/endpoints", endpoint, SCHEMA_DIR)
    assert [v.rule for v in got] == ["additionalProperties"]


# ---- 출력에 값이 나오지 않는다 ---------------------------------------------------------------------------------------

def leaf_strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from leaf_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from leaf_strings(v)
    elif isinstance(node, str):
        yield node


def test_invalid_fixtures_contain_secret_looking_values():
    values = {s for case in INVALID_CASES for d in ov.load_tree(FIXTURES / "invalid" / case).values()
              for s in leaf_strings(d) if s.startswith("fake-")}
    assert len(values) >= 3


@pytest.mark.parametrize("case", INVALID_CASES)
def test_cli_output_never_contains_fixture_values(case):
    root = FIXTURES / "invalid" / case
    res = run_cli("validate", str(root))
    assert res.returncode == 1
    out = res.stdout + res.stderr
    for d in ov.load_tree(root).values():
        for s in leaf_strings(d):
            if s.startswith("fake-") or s.startswith("192.0.2."):
                assert s not in out, (case, "값이 출력에 나왔다")
    assert sorted(line for line in res.stdout.splitlines() if "\t" in line) == expected_lines(case)


def test_cli_exits_zero_for_valid_tree():
    res = run_cli("validate", str(FIXTURES / "valid"))
    assert res.returncode == 0, res.stdout + res.stderr


def test_secret_documents_accept_prompt_placeholders_for_values(tmp_path):
    """secrets/ YAML은 필드 이름만 적는다(값은 null). 검증은 값 자리를 채워진 것으로 본다."""
    doc = tmp_path / "secrets" / "assets" / "ns0001" / "credentials" / "root.yml"
    doc.parent.mkdir(parents=True)
    doc.write_text("type: password\nusername: root\npassword:\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 0, res.stdout


def test_cli_reports_unreadable_yaml_without_content(tmp_path):
    doc = tmp_path / "inventory" / "config" / "common.yml"
    doc.parent.mkdir(parents=True)
    doc.write_text("domain: [fake-broken\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 1
    assert "fake-broken" not in res.stdout + res.stderr
    assert "yaml_parse" in res.stdout


# ---- 리뷰 반영: 빈 루트·null 범위·깨진 문서 경유·스키마 오류 --------------------------------------------------------

def test_cli_rejects_a_root_without_documents(tmp_path):
    assert run_cli("validate", str(tmp_path)).returncode == 2


def test_only_secret_fields_may_be_left_null_for_prompting(tmp_path):
    doc = tmp_path / "secrets" / "assets" / "ns0001" / "credentials" / "root.yml"
    doc.parent.mkdir(parents=True)
    doc.write_text("type: password\nusername:\npassword:\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 1
    assert res.stdout.strip().split("\t") == ["secrets/assets/ns0001/credentials/root", "#/username", "type"]


def test_via_into_a_schema_invalid_document_is_not_reported_as_missing():
    store = {
        "inventory/assets/ns0001/endpoints": {"ssh": {"protocol": "ssh", "address": "192.0.2.1", "port": 22,
                                                     "credential": "root", "via": "ns0002/ssh"}},
        "inventory/assets/ns0002/endpoints": {"ssh": {"protocol": "ssh", "address": "192.0.2.2", "port": "x",
                                                     "credential": "root"}},
        "secrets/assets/ns0001/credentials/root": {"type": "password", "password": "fake-pw-1"},
        "secrets/assets/ns0002/credentials/root": {"type": "password", "password": "fake-pw-2"},
    }
    got = [v.format() for v in ov.validate_store(store, SCHEMA_DIR)]
    assert got == ["inventory/assets/ns0002/endpoints\t#/ssh/port\ttype"]


def test_cli_exits_2_on_broken_index(tmp_path):
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "index.yml").write_text('"inventory/config/common": missing.schema.json\n')
    res = run_cli("validate", str(FIXTURES / "valid"), "--schemas", str(schemas))
    assert res.returncode == 2
    assert "Traceback" not in res.stderr


def _tree(tmp_path, rel, text):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)


def test_non_string_keys_are_a_violation_not_a_crash(tmp_path):
    _tree(tmp_path, "inventory/assets/ns0001/endpoints.yml", "22:\n  protocol: ssh\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 1
    assert res.stdout.strip() == "inventory/assets/ns0001/endpoints\t#\tnon_string_key"


def test_duplicate_keys_and_yaml_extension_are_violations(tmp_path):
    _tree(tmp_path, "inventory/config/common.yml", "domain: a.example.test\ndomain: b.example.test\n")
    _tree(tmp_path, "inventory/config/host_audit.yaml", "mail_sender: x@example.test\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 1
    assert sorted(res.stdout.splitlines()) == ["inventory/config/common\t#\tyaml_parse",
                                               "inventory/config/host_audit\t#\tyaml_parse"]


def test_directory_named_like_a_document_does_not_crash(tmp_path):
    (tmp_path / "inventory" / "config" / "common.yml").mkdir(parents=True)
    assert run_cli("validate", str(tmp_path)).stdout.strip() == "inventory/config/common\t#\tyaml_parse"


def test_names_with_a_trailing_newline_are_rejected():
    got = ov.validate_document("inventory/assets/ns0001/endpoints",
                               {"ssh\n": {"protocol": "ssh", "address": "192.0.2.1", "port": 22, "credential": "root"}},
                               SCHEMA_DIR)
    assert [v.rule for v in got] == ["additionalProperties"]


def test_yaml_anchors_merge_keys_and_unhashable_keys_do_not_crash(tmp_path):
    _tree(tmp_path, "inventory/config/common.yml", "base: &b {x: 1}\nmerged:\n  <<: *b\n  y: 2\ndomain: a.example.test\n")
    _tree(tmp_path, "inventory/config/host_audit.yml", "? [a]\n: 1\n")
    res = run_cli("validate", str(tmp_path))
    assert res.returncode == 1
    assert sorted(res.stdout.splitlines()) == ["inventory/config/common\t#\tadditionalProperties",
                                               "inventory/config/host_audit\t#\tyaml_parse"]


def test_one_and_true_are_distinct_keys_not_duplicates(tmp_path):
    _tree(tmp_path, "inventory/config/common.yml", "1: a\ntrue: b\n")
    assert run_cli("validate", str(tmp_path)).stdout.strip() == "inventory/config/common\t#\tnon_string_key"


# ---- 의존성 ------------------------------------------------------------------------------------------------------

def test_jsonschema_is_a_test_dependency():
    assert "jsonschema" in (ROOT / "requirements-test.txt").read_text()


# ---- GWS 디렉터리 읽기 문서(Spec #630) --------------------------------------------------------------------------------

@pytest.mark.parametrize("doc", [
    {"sa_json": "x"},                                             # customer_id 없음
    {"customer_id": "C0"},                                        # sa_json 없음
    {"sa_json": "", "customer_id": "C0"},                         # 빈 문자열
    {"sa_json": {"type": "service_account"}, "customer_id": "C0"},  # 객체가 아니라 문자열이어야 한다
    {"sa_json": "x", "customer_id": "C0", "extra": "1"},          # 알 수 없는 키
])
def test_gws_directory_read_rejects_malformed_documents(doc):
    assert ov.validate_store({"secrets/services/gws/directory_read": doc}, SCHEMA_DIR) != []


def test_gws_directory_read_accepts_the_two_required_string_keys():
    doc = {"sa_json": "{\"fake\": true}", "customer_id": "C0fake"}
    assert ov.validate_store({"secrets/services/gws/directory_read": doc}, SCHEMA_DIR) == []
