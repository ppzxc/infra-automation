"""funa_env 필터(#222): OpenBao 값 → dotenv 파일 내용, 오류는 이름만 말하고 값은 말하지 않는다."""
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from funa_env import HEADER, funa_env_kv_by_key, funa_env_resolve  # noqa: E402

NODE_KEYS = ["FUNA_NODE_EXTERNAL_HOSTNAME"]
KV = {
    "node": {"FUNA_NODE_EXTERNAL_HOSTNAME": "n1.example.test", "ansible_password": "ssh-secret"},
    "cluster": {"TZ": "Asia/Seoul", "FUNA_SERVICE_NAME": "funa"},
    "proxy": {"CLOUDFLARE_API_TOKEN": "cf-secret", "DB_PASSWORD": "passw0rd"},
    "vrrp": {"BOT_TOKEN": "vrrp-secret"},
}


def resolve(kv=None, **over):
    kv = dict(KV if kv is None else kv)
    return funa_env_resolve(kv, NODE_KEYS, over.get("cluster_req", ["TZ"]),
                            over.get("proxy_req", ["CLOUDFLARE_API_TOKEN"]), over.get("vrrp_req", []),
                            "clusters/funa", "hosts/n1")


def test_files_hold_only_their_own_values():
    out = resolve()
    assert out["errors"] == []
    assert "TZ=Asia/Seoul\n" in out["cluster"]
    assert "FUNA_NODE_EXTERNAL_HOSTNAME=n1.example.test\n" in out["cluster"]
    assert "ansible_password" not in out["cluster"] and "ssh-secret" not in out["cluster"]
    assert "CLOUDFLARE_API_TOKEN=cf-secret\n" in out["proxy"] and "vrrp-secret" not in out["proxy"]
    assert out["vrrp"] == HEADER + "BOT_TOKEN=vrrp-secret\n"
    assert "cf-secret" not in out["cluster"] + out["vrrp"]


def test_output_is_deterministic():
    assert resolve() == resolve()


@pytest.mark.parametrize("value, line", [
    ("plain-1.2/x", "K=plain-1.2/x\n"),
    ("two words", "K='two words'\n"),
    ("a$b#c", "K='a$b#c'\n"),
    ("", "K=\n"),
])
def test_values_are_quoted_only_when_needed(value, line):
    kv = {**KV, "cluster": {"TZ": "x", "K": value}}
    assert line in resolve(kv)["cluster"]


@pytest.mark.parametrize("path, kv_patch, expect", [
    ("missing node path", {"node": None}, "hosts/n1: OpenBao path does not exist"),
    ("missing cluster path", {"cluster": None}, "clusters/funa: OpenBao path does not exist"),
    ("missing proxy path", {"proxy": None}, "clusters/funa/proxy: OpenBao path does not exist"),
    ("missing node key", {"node": {}}, "hosts/n1: required key FUNA_NODE_EXTERNAL_HOSTNAME is missing"),
    ("missing cluster key", {"cluster": {}}, "clusters/funa: required key TZ is missing"),
    ("empty required", {"cluster": {"TZ": ""}}, "clusters/funa: required key TZ is missing"),
    ("empty vrrp", {"vrrp": {}}, "clusters/funa/vrrp: no keys"),
    ("bad name", {"cluster": {"TZ": "x", "bad-name": "v"}}, "'bad-name' is not a valid environment variable name"),
    ("nested", {"cluster": {"TZ": "x", "N": {"a": 1}}}, "N is not a single scalar value"),
    ("newline", {"cluster": {"TZ": "x", "N": "a\nb"}}, "N contains a line break"),
    ("quote", {"cluster": {"TZ": "x", "N": "it's"}}, "N contains a single quote"),
    ("secret in cluster", {"cluster": {"TZ": "x", "DB_PASSWORD": "v"}}, "DB_PASSWORD is also in the non-secret cluster values"),
])
def test_errors_name_the_problem(path, kv_patch, expect):
    out = resolve({**KV, **kv_patch})
    assert any(expect in e for e in out["errors"]), out["errors"]
    assert out["cluster"] == out["proxy"] == out["vrrp"] == ""


def test_errors_never_contain_values():
    kv = {**KV, "cluster": {"TZ": "x", "N": "line\nsecret-value", "Q": "it's-secret"},
          "proxy": {"CLOUDFLARE_API_TOKEN": "cf-secret", "dup": {"a": "nested-secret"}}}
    text = " ".join(resolve(kv)["errors"])
    assert text
    for value in ("secret-value", "it's-secret", "cf-secret", "nested-secret"):
        assert value not in text


def test_kv_by_key_maps_status_to_data_or_none():
    results = [
        {"item": {"key": "node"}, "status": 200, "json": {"data": {"data": {"A": "1"}}}},
        {"item": {"key": "cluster"}, "status": 404, "json": {"errors": []}},
        {"item": {"key": "proxy"}, "status": 404},
    ]
    assert funa_env_kv_by_key(results) == {"node": {"A": "1"}, "cluster": None, "proxy": None}
    assert funa_env_kv_by_key(None) == {}
