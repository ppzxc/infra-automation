"""공용 가짜 OpenBao(tests/openbao_fake.py)의 동작(Spec #511 / Ticket-3). 가짜 값만 쓴다."""
import json
import urllib.error
import urllib.request

import pytest

from openbao_fake import APPROLE_TOKEN, FakeOpenBao


def _get(fake, path, headers=None):
    req = urllib.request.Request(fake.url + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


@pytest.fixture
def fake():
    with FakeOpenBao() as f:
        yield f


def test_registered_document_is_served_by_mount_and_path_and_unknown_is_404(fake):
    fake.set("m1", "a/b", {"k": "v"})
    assert _get(fake, "/v1/m1/data/a/b")[1]["data"]["data"] == {"k": "v"}
    assert _get(fake, "/v1/m2/data/a/b")[0] == 404
    fake.remove("m1", "a/b")
    assert _get(fake, "/v1/m1/data/a/b")[0] == 404


def test_denied_document_is_403(fake):
    fake.deny("m1", "x")
    assert _get(fake, "/v1/m1/data/x")[0] == 403


def test_namespace_header_is_checked():
    with FakeOpenBao(namespace="ns/a") as f:
        f.set("m", "d", {})
        assert _get(f, "/v1/m/data/d")[0] == 403
        assert _get(f, "/v1/m/data/d", {"X-Vault-Namespace": "ns/b"})[0] == 403
        assert _get(f, "/v1/m/data/d", {"X-Vault-Namespace": "ns/a"})[0] == 200


def test_requests_are_recorded_with_mount_doc_token_and_namespace(fake):
    _get(fake, "/v1/m/data/p/q", {"X-Vault-Token": "t", "X-Vault-Namespace": "n"})
    (r,) = fake.reads()
    assert (r.mount, r.doc, r.token, r.namespace) == ("m", "p/q", "t", "n")


def test_approle_login_issues_a_token_that_reads_require():
    with FakeOpenBao(approle=True) as f:
        f.set("m", "d", {})
        assert _get(f, "/v1/m/data/d")[0] == 403
        req = urllib.request.Request(f.url + "/v1/auth/approle/login", data=b"{}", method="POST")
        assert json.load(urllib.request.urlopen(req))["auth"]["client_token"] == APPROLE_TOKEN
        assert _get(f, "/v1/m/data/d", {"X-Vault-Token": APPROLE_TOKEN})[0] == 200
        assert len(f.logins()) == 1


def test_index_and_schema_checks_are_off_by_default_and_switchable(fake):
    fake.set("m", "anything", {})
    _get(fake, "/v1/m/data/anything")
    assert fake.violations == []
    seen = []
    with FakeOpenBao(index_patterns=["m/ok/*"], schema_check=lambda m, d, data: seen.append((m, d))) as f:
        f.set("m", "ok/1", {})
        _get(f, "/v1/m/data/ok/1")
        _get(f, "/v1/m/data/other")
        assert f.violations == [("m", "other")] and seen == [("m", "ok/1")]


def test_list_and_metadata_and_raw_routes(fake):
    fake.set("m1", "a/b", {"k": "v"}, updated_time="2026-01-02T03:04:05.123456789Z").set("m1", "c", {})
    assert _get(fake, "/v1/m1/metadata/?list=true")[1]["data"]["keys"] == ["a/", "c"]
    assert _get(fake, "/v1/m1/metadata/a?list=true")[1]["data"]["keys"] == ["b"]
    assert _get(fake, "/v1/m1/metadata/a/b")[1]["data"]["updated_time"] == "2026-01-02T03:04:05.123456789Z"
    assert _get(fake, "/v1/m1/metadata/zzz")[0] == 404
    fake.raw("GET", "sys/mounts", {"data": {"m1/": {}}})
    assert _get(fake, "/v1/sys/mounts")[1]["data"] == {"m1/": {}}
