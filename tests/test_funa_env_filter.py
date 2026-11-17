"""funa_env 필터(#222, #524): 새 구조 문서(snake_case 저장 키) → dotenv 파일 내용. 오류는 이름만 말하고 값은 말하지 않는다."""
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from funa_env import HEADER, funa_env_doc_path, funa_env_resolve  # noqa: E402

KEY_MAP = {"node_external_hostname": "FUNA_NODE_EXTERNAL_HOSTNAME", "tz": "TZ", "service_name": "FUNA_SERVICE_NAME",
           "db_password": "DB_PASSWORD", "bot_token": "FUNA_BOT_TOKEN", "extra": "FUNA_EXTRA"}
NODE_REQUIRED = ["node_external_hostname"]
ASSET, CLUSTER, PROXY, VRRP, CRED = ("inventory/assets/+", "inventory/services/funa", "secrets/services/funa/proxy",
                                     "secrets/services/funa/vrrp", "secrets/assets/+/credentials/+")
DOCS = {
    ASSET: {"description": "Fake", "funa": {"node_external_hostname": "n1.example.test"}},
    CLUSTER: {"tz": "Asia/Seoul", "service_name": "funa"},
    PROXY: {"db_password": "passw0rd"},
    VRRP: {"bot_token": "vrrp-secret"},
    CRED: {"type": "api_token", "token": "cf-secret"},
}


def resolve(docs=None):
    return funa_env_resolve(DOCS if docs is None else docs, KEY_MAP, NODE_REQUIRED, "CLOUDFLARE_API_TOKEN", "n1", "cloudflare")


def test_doc_path_fills_plus_with_host_then_credential():
    assert funa_env_doc_path(ASSET, "n1", "cloudflare") == "inventory/assets/n1"
    assert funa_env_doc_path(CRED, "n1", "cloudflare") == "secrets/assets/n1/credentials/cloudflare"
    assert funa_env_doc_path(PROXY, "n1", "cloudflare") == PROXY


def test_stored_keys_become_env_names_and_files_hold_only_their_own_values():
    out = resolve()
    assert out["errors"] == []
    assert "TZ=Asia/Seoul\n" in out["cluster"] and "FUNA_NODE_EXTERNAL_HOSTNAME=n1.example.test\n" in out["cluster"]
    assert "description" not in out["cluster"]
    assert "DB_PASSWORD=passw0rd\n" in out["proxy"] and "CLOUDFLARE_API_TOKEN=cf-secret\n" in out["proxy"]
    assert out["vrrp"] == HEADER + "FUNA_BOT_TOKEN=vrrp-secret\n"
    assert "cf-secret" not in out["cluster"] + out["vrrp"] and "vrrp-secret" not in out["proxy"]


def test_output_is_deterministic():
    assert resolve() == resolve()


@pytest.mark.parametrize("value, line", [
    ("plain-1.2/x", "FUNA_EXTRA=plain-1.2/x\n"),
    ("two words", "FUNA_EXTRA='two words'\n"),
    ("a$b#c", "FUNA_EXTRA='a$b#c'\n"),
    ("", "FUNA_EXTRA=\n"),
])
def test_values_are_quoted_only_when_needed(value, line):
    assert line in resolve({**DOCS, CLUSTER: {"tz": "x", "extra": value}})["cluster"]


@pytest.mark.parametrize("path, docs_patch, expect", [
    ("missing node section", {ASSET: {"description": "Fake"}}, "inventory/assets/n1: required key funa is missing"),
    ("missing node key", {ASSET: {"funa": {}}}, "inventory/assets/n1: required key funa.node_external_hostname is missing"),
    ("unmapped cluster key", {CLUSTER: {"tz": "x", "nope": "v"}}, "inventory/services/funa: nope has no environment variable mapping"),
    ("unmapped secret key", {PROXY: {"db_password": "x", "nope": "v"}}, "secrets/services/funa/proxy: nope has no environment variable mapping"),
    ("no token", {CRED: {"type": "api_token"}}, "secrets/assets/n1/credentials/cloudflare: required key token is missing"),
    ("nested", {CLUSTER: {"tz": "x", "extra": {"a": 1}}}, "FUNA_EXTRA is not a single scalar value"),
    ("newline", {CLUSTER: {"tz": "x", "extra": "a\nb"}}, "FUNA_EXTRA contains a line break"),
    ("quote", {CLUSTER: {"tz": "x", "extra": "it's"}}, "FUNA_EXTRA contains a single quote"),
    ("node overrides cluster", {ASSET: {"funa": {"node_external_hostname": "x", "tz": "UTC"}}}, "inventory/assets/n1: TZ is also set by the service document inventory/services/funa"),
    ("secret in cluster", {CLUSTER: {"tz": "x", "db_password": "v"}}, "DB_PASSWORD is also in the non-secret cluster values"),
])
def test_errors_name_the_problem(path, docs_patch, expect):
    out = resolve({**DOCS, **docs_patch})
    assert any(expect in e for e in out["errors"]), out["errors"]
    assert out["cluster"] == out["proxy"] == out["vrrp"] == ""


def test_errors_never_contain_values():
    docs = {**DOCS, CLUSTER: {"tz": "x", "extra": "line\nsecret-value", "nope": "nope-secret"},
            PROXY: {"db_password": "it's-secret", "dup": {"a": "nested-secret"}}}
    text = " ".join(resolve(docs)["errors"])
    assert text
    for value in ("secret-value", "nope-secret", "it's-secret", "nested-secret", "cf-secret"):
        assert value not in text


@pytest.mark.parametrize("source, path, key", [
    (CLUSTER, "inventory/services/funa", "extra"),
    (PROXY, "secrets/services/funa/proxy", "db_password"),
    (VRRP, "secrets/services/funa/vrrp", "bot_token"),
])
@pytest.mark.parametrize("value", ["${LEAKVAL}", "${LEAKVAL:-x}", "pre-${LEAKVAL}-post"])
def test_shell_reference_is_rejected_by_path_and_key_only(source, path, key, value):
    out = resolve({**DOCS, source: {**DOCS[source], key: value}})
    assert "%s: %s contains a shell reference" % (path, KEY_MAP[key]) in out["errors"], out["errors"]
    assert "LEAKVAL" not in " ".join(out["errors"])
    assert out["cluster"] == out["proxy"] == out["vrrp"] == ""


def test_shell_reference_in_the_node_section_and_the_credential_is_rejected():
    node = resolve({**DOCS, ASSET: {"funa": {"node_external_hostname": "${LEAKVAL}"}}})
    assert "inventory/assets/n1: FUNA_NODE_EXTERNAL_HOSTNAME contains a shell reference" in node["errors"]
    cred = resolve({**DOCS, CRED: {"type": "api_token", "token": "${LEAKVAL}"}})
    assert "secrets/assets/n1/credentials/cloudflare: CLOUDFLARE_API_TOKEN contains a shell reference" in cred["errors"]


@pytest.mark.parametrize("value", ["pa$word", "ends-with$", "$", "$NAME", "a$$b"])
def test_dollar_without_brace_passes(value):
    out = resolve({**DOCS, PROXY: {"db_password": value}})
    assert out["errors"] == []
    assert "DB_PASSWORD='%s'\n" % value in out["proxy"]
