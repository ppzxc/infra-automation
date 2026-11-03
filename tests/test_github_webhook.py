"""GitHub org webhook receiver path (Spec #399 / Ticket-2) against a real otelcol-contrib binary.

The rendered config of a host with ``otel_github_webhook: true`` is run through ``otelcol-contrib`` (the receiver port
and the secrets come from the rendered ``secrets.env``; the exporters are file exporters, see ``tests/otelcol_harness.py``).
Only fake values and GitHub's official test vector are used: secret ``It's a Secret to Everybody``, payload
``Hello, World!``. The repository is public, so no real address, port, path or organization appears here.
"""

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "filter_plugins"))
import otelcol_harness as h  # noqa: E402
import test_host_agents as base  # noqa: E402
from host_agents import (  # noqa: E402
    host_agents_github_webhook,
    host_agents_github_webhook_gateway_errors,
    host_agents_resolve_inputs,
)

VERSION = "0.161.0"            # the webhook receiver ships from 0.161.0; CentOS 6/7 (0.119.0) are out of scope
ROOT = Path(__file__).resolve().parent.parent
# GitHub's official test vector (docs: "Validating webhook deliveries")
SECRET = "It's a Secret to Everybody"
PAYLOAD = b"Hello, World!"
SIGNATURE = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
LEGACY_SHA1 = "sha1=01dd1f1e4b4c0a8bb7bd7e1a0f5b2f3e0c6a1f00"      # any sha1 value: the receiver must not honor it
PATH = "/hook-dummy-0123456789abcdef"
BRIDGE_ADDRESS = "192.0.2.77"                                        # TEST-NET-1
FAKE = {"address": BRIDGE_ADDRESS, "port": "18443", "path": PATH, "secret": SECRET, "network": "net-dummy"}
INPUTS = {"otel_docker_metrics": False, "otel_github_webhook": True,
          "otel_logs": [{"path": "/var/log/secure", "stream": "security_logs", "service": "auth"}]}
HEADERS = {"X-GitHub-Event": "ping", "X-GitHub-Delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
           "X-GitHub-Hook-ID": "123456789", "X-Hub-Signature-256": SIGNATURE, "Content-Type": "application/json"}


def _render(tmp_path, enabled=True, **over):
    over.setdefault("host_agents_os_path", "modern")
    over.setdefault("host_agents_inputs", dict(INPUTS, otel_github_webhook=enabled))
    over.setdefault("host_agents_github_webhook", FAKE if enabled else {})
    cfg, _ = base._render_config(tmp_path, **over)
    return cfg, _read_env(tmp_path / "secrets.env")


def _read_env(path):
    """systemd EnvironmentFile rules: KEY=value, or KEY="..." where only backslash, double quote, backtick and dollar are escapes."""
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if value.startswith('"'):
                assert value.endswith('"') and len(value) >= 2
                value = re.sub(r'\\([\\"`$])', r"\1", value[1:-1])
            out[key] = value
    return out


def _harness(tmp_path, **env_over):
    cfg, env = _render(tmp_path)
    harness = h.OtlpHarness(tmp_path, cfg, receiver="webhook_event/github", env=dict(env, **env_over))
    harness.env["GITHUB_WEBHOOK_ENDPOINT"] = f"127.0.0.1:{harness.port}"      # the fake bridge address is not on this machine
    return harness, cfg


def _sign(body, secret=SECRET):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _records(harness):
    return harness.read("otlphttp/security_logs", "logs")


def _text(value):
    return value if isinstance(value, str) else json.dumps(value)


def test_official_test_vector_signature_is_what_the_helper_computes():
    assert _sign(PAYLOAD) == SIGNATURE


def test_valid_signature_is_accepted_and_joins_the_security_logs_stream_as_github_audit(tmp_path):
    binary = h.binary(VERSION)
    harness, _ = _harness(tmp_path)
    with harness.running(binary) as col:
        assert col.post(PATH, PAYLOAD, HEADERS) == 200
        col.wait_for("otlphttp/security_logs", "logs", 1)
    (record,) = _records(harness)
    assert record["_attrs"]["log_type"] == "security_logs"
    assert record["_res"]["service.name"] == "github-audit"
    assert PAYLOAD.decode() in _text(record["body"])


@pytest.mark.parametrize("case", ["wrong-signature", "no-signature", "sha1-legacy-only", "tampered-body"])
def test_unsigned_or_forged_requests_are_rejected_with_401_and_never_recorded(tmp_path, case):
    binary = h.binary(VERSION)
    harness, _ = _harness(tmp_path)
    headers, body = dict(HEADERS), PAYLOAD
    if case == "wrong-signature":
        headers["X-Hub-Signature-256"] = _sign(PAYLOAD, "another secret")
    elif case == "no-signature":
        del headers["X-Hub-Signature-256"]
    elif case == "sha1-legacy-only":
        del headers["X-Hub-Signature-256"]
        headers["X-Hub-Signature"] = LEGACY_SHA1
    else:
        body = b"Hello, World?"
    with harness.running(binary) as col:
        assert col.post(PATH, body, headers) == 401
        col.settle()
    assert _records(harness) == []


def test_oversized_body_and_wrong_path_are_rejected_and_never_recorded(tmp_path):
    binary = h.binary(VERSION)
    harness, cfg = _harness(tmp_path)
    limit = cfg["receivers"]["webhook_event/github"]["max_request_size"]
    big = b"x" * (limit + 1)
    with harness.running(binary) as col:
        status = col.post(PATH, big, dict(HEADERS, **{"X-Hub-Signature-256": _sign(big)}))
        assert status == col.CONNECTION_REFUSED_BY_PEER or status >= 400      # a 4xx, or the receiver cut the connection first
        assert col.post(PATH + "-other", PAYLOAD, HEADERS) == 404
        col.settle()
    assert _records(harness) == []


def test_event_delivery_and_hook_headers_come_out_under_the_contracted_attribute_names(tmp_path):
    binary = h.binary(VERSION)
    harness, _ = _harness(tmp_path)
    with harness.running(binary) as col:
        assert col.post(PATH, PAYLOAD, HEADERS) == 200
        col.wait_for("otlphttp/security_logs", "logs", 1)
    (record,) = _records(harness)
    assert record["_attrs"]["header.X-Github-Event"] == "ping"
    assert record["_attrs"]["header.X-Github-Delivery"] == HEADERS["X-GitHub-Delivery"]
    assert record["_attrs"]["header.X-Github-Hook-Id"] == "123456789"
    assert SIGNATURE not in json.dumps(record["_attrs"])               # the signature is not kept


def test_the_header_attribute_names_are_pinned_in_the_docs():
    text = (ROOT / "docs" / "monitoring.md").read_text(encoding="utf-8")
    for name in ("header.X-Github-Event", "header.X-Github-Delivery", "header.X-Github-Hook-Id"):
        assert name in text


def test_an_empty_webhook_secret_fails_collector_validation(tmp_path):
    binary = h.binary(VERSION)
    harness, _ = _harness(tmp_path, GITHUB_WEBHOOK_SECRET="")
    res = subprocess.run([binary, "validate", f"--config={harness.path}"], capture_output=True, text=True,
                         env=dict(harness.env, PATH="/usr/bin:/bin"))
    assert res.returncode != 0 and "secret" in res.stderr + res.stdout


def test_receiver_bind_values_come_only_from_the_private_env_file_and_the_bridge_address_is_not_a_wildcard(tmp_path):
    cfg, env = _render(tmp_path)
    receiver = cfg["receivers"]["webhook_event/github"]
    assert receiver["endpoint"] == "${env:GITHUB_WEBHOOK_ENDPOINT}"
    assert receiver["path"] == "${env:GITHUB_WEBHOOK_PATH}"
    assert env["GITHUB_WEBHOOK_ENDPOINT"] == f"{BRIDGE_ADDRESS}:{FAKE['port']}"
    assert env["GITHUB_WEBHOOK_PATH"] == PATH and env["GITHUB_WEBHOOK_SECRET"] == SECRET
    text = yaml.safe_dump(cfg)
    assert BRIDGE_ADDRESS not in text and PATH not in text and SECRET not in text      # nothing private in the config
    assert not env["GITHUB_WEBHOOK_ENDPOINT"].startswith(("0.0.0.0", "127.", "localhost", ":"))


def _seconds(duration):
    return float(duration[:-2]) / 1000 if duration.endswith("ms") else float(duration.rstrip("s"))


def test_receiver_timeouts_are_well_above_the_500ms_default_and_inside_githubs_10s_limit(tmp_path):
    cfg, _ = _render(tmp_path)
    receiver = cfg["receivers"]["webhook_event/github"]
    for key in ("read_timeout", "write_timeout"):
        assert 2 <= _seconds(str(receiver[key])) < 10


def test_feature_off_by_default_renders_no_webhook_receiver_pipeline_secret_or_unit_ordering(tmp_path):
    cfg, env = _render(tmp_path, enabled=False)
    assert not any("webhook" in k or "github" in k for k in cfg["receivers"])
    assert not any("github" in k for k in cfg["service"]["pipelines"])
    assert not any("github" in k for k in cfg.get("processors", {}))
    assert not any(k.startswith("GITHUB") for k in env)
    assert set(env) == {"O2_BASIC_AUTH"}


def _unit(tmp_path, enabled):
    vars_ = yaml.safe_load((base.ROLE / "defaults" / "main.yml").read_text())
    vars_.update(yaml.safe_load((base.ROLE / "vars" / "main.yml").read_text()))
    vars_["host_agents_inputs"] = dict(INPUTS, otel_github_webhook=enabled)
    (tmp_path / "unit-vars.yml").write_text(yaml.safe_dump(vars_))
    (tmp_path / "unit.yml").write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(tmp_path / "unit-vars.yml")],
        "tasks": [{"ansible.builtin.template": {"src": str(base.ROLE / "templates" / "otelcol-contrib.service.j2"),
                                                 "dest": str(tmp_path / "unit.service")}}]}]))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "unit.yml")], capture_output=True,
                         text=True, stdin=subprocess.DEVNULL, cwd=ROOT, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    return (tmp_path / "unit.service").read_text()


def test_unit_starts_after_docker_and_restarts_on_failure_only_where_the_receiver_is_on(tmp_path):
    on = _unit(tmp_path, True)
    after = re.search(r"^After=(.*)$", on, re.M).group(1).split()
    assert "docker.service" in after and "network.target" in after
    # docker stop/restart reach the collector (PartOf: a bridge recreation rebinds the socket) and docker start brings it back up
    # (docker.service.wants via [Install]): after `systemctl stop docker` + `start docker` collection must not stay down
    assert re.search(r"^PartOf=docker.service$", on, re.M)
    assert "docker.service" in re.search(r"^WantedBy=(.*)$", on, re.M).group(1).split()
    assert re.search(r"^Restart=(always|on-failure)$", on, re.M)
    (tmp_path / "off").mkdir()
    off = _unit(tmp_path / "off", False)
    assert "docker" not in off and re.search(r"^WantedBy=multi-user.target$", off, re.M)


# ---- deploy-time input checks (filters; no binary needed) -----------------------------------------------------------

def _resolve(**kv):
    required = {"o2_ingest_token": "t", "rustfs_access_key": "a", "rustfs_secret_key": "s", "restic_password": "p"}
    kv = dict(required, **kv)
    return host_agents_resolve_inputs(kv, [], [], [], "hosts/h/agents")


def _kv(**over):
    return dict({"otel_github_webhook": True, "github_webhook_address": BRIDGE_ADDRESS, "github_webhook_port": "18443",
                 "github_webhook_path": PATH, "github_webhook_secret": SECRET, "github_webhook_network": "net-dummy"}, **over)


def test_webhook_is_off_by_default_and_needs_no_inputs_then():
    res = _resolve()
    assert res["errors"] == [] and res["otel_github_webhook"] is False


def test_enabled_webhook_with_complete_inputs_is_valid_and_the_values_are_resolved_separately():
    res = _resolve(**_kv())
    assert res["errors"] == [] and res["otel_github_webhook"] is True
    assert host_agents_github_webhook(_kv()) == FAKE
    assert SECRET not in json.dumps(res) and PATH not in json.dumps(res)         # the merged inputs carry no private value


@pytest.mark.parametrize("key", ["address", "port", "path", "secret", "network"])
@pytest.mark.parametrize("blank", ["", "  ", None])
def test_enabled_webhook_fails_when_any_required_input_is_blank(key, blank):
    errors = _resolve(**_kv(**{f"github_webhook_{key}": blank}))["errors"]
    assert len(errors) == 1 and f"github_webhook_{key}" in errors[0]
    assert SECRET not in errors[0] and PATH not in errors[0]


@pytest.mark.parametrize("override", [{"github_webhook_address": "0.0.0.0"}, {"github_webhook_address": "127.0.0.1"},
                                      {"github_webhook_address": "localhost"}, {"github_webhook_port": "70000"},
                                      {"github_webhook_port": "http"}, {"github_webhook_path": "no-leading-slash"}])
def test_enabled_webhook_rejects_wildcard_loopback_and_malformed_values(override):
    assert len(_resolve(**_kv(**override))["errors"]) == 1


@pytest.mark.parametrize("inspected, ok", [(BRIDGE_ADDRESS + "\n", True), ("192.0.2.78\n", False), ("", False),
                                           ("<no value>\n", False)])
def test_docker_network_gateway_must_equal_the_configured_bind_address(inspected, ok):
    errors = host_agents_github_webhook_gateway_errors(inspected, BRIDGE_ADDRESS)
    assert (errors == []) is ok


def test_repository_defaults_hold_no_value_for_the_bind_address_port_path_or_secret():
    text = "\n".join((base.ROLE / d / "main.yml").read_text() for d in ("defaults", "vars"))
    for key in ("address", "port", "path", "secret", "network"):
        assert not re.search(rf"^\s*\S*github_webhook_{key}\s*:", text, re.M)


# ---- review fixes ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("secret", ['quote"and\\backslash', "dollar$and`tick", SECRET, "p@ss word!~"])
def test_secrets_with_systemd_special_characters_survive_the_env_file_and_still_verify(tmp_path, secret):
    binary = h.binary(VERSION)
    cfg, env = _render(tmp_path, host_agents_github_webhook=dict(FAKE, secret=secret))
    assert env["GITHUB_WEBHOOK_SECRET"] == secret
    harness = h.OtlpHarness(tmp_path, cfg, receiver="webhook_event/github", env=env)
    harness.env["GITHUB_WEBHOOK_ENDPOINT"] = f"127.0.0.1:{harness.port}"
    with harness.running(binary) as col:
        assert col.post(PATH, PAYLOAD, dict(HEADERS, **{"X-Hub-Signature-256": _sign(PAYLOAD, secret)})) == 200


@pytest.mark.parametrize("secret", ["line\nbreak", "tab\there", "café", "sep arator", "nul\x00", "del\x7f"])
def test_secret_outside_printable_ascii_is_rejected_without_echoing_it(secret):
    errors = _resolve(**_kv(github_webhook_secret=secret))["errors"]
    assert len(errors) == 1 and "github_webhook_secret" in errors[0] and secret not in errors[0]


@pytest.mark.parametrize("port", ["٣٤", "123456", "0", "65536", "-1", "1 2", ""])
def test_port_must_be_ascii_digits_within_1_to_65535(port):
    assert len(_resolve(**_kv(github_webhook_port=port))["errors"]) == 1


@pytest.mark.parametrize("path", ["/", "//", "/a//b", "/a/../b", "/..", "/a/./b", "/a/", "/a b", "/a\n"])
def test_path_rejects_root_empty_dot_and_dotdot_segments(path):
    assert len(_resolve(**_kv(github_webhook_path=path))["errors"]) == 1


def test_path_with_ordinary_segments_is_accepted():
    assert _resolve(**_kv(github_webhook_path="/hooks/abc-123_x.y/z"))["errors"] == []


@pytest.mark.parametrize("os_path, ok", [("modern", True), ("legacy_el6", False), ("legacy_el7", False)])
def test_enabling_the_webhook_on_a_legacy_host_fails_input_validation(os_path, ok):
    required = {"o2_ingest_token": "t", "rustfs_access_key": "a", "rustfs_secret_key": "s", "restic_password": "p"}
    res = host_agents_resolve_inputs(dict(required, **_kv()), [], [], [], "hosts/h/agents", os_path=os_path)
    assert (res["errors"] == []) is ok
    off = host_agents_resolve_inputs(dict(required), [], [], [], "hosts/h/agents", os_path=os_path)
    assert off["errors"] == []                                   # off hosts are never affected


def test_the_env_variable_names_are_defined_once_in_a_role_variable():
    for rel in ("tasks/main.yml", "tasks/agents_input.yml", "templates/otelcol-contrib.yaml.j2",
                "templates/secrets.env.j2", "templates/otelcol-contrib.service.j2"):
        assert "GITHUB_WEBHOOK_" not in (base.ROLE / rel).read_text(), rel
    names = yaml.safe_load((base.ROLE / "vars" / "main.yml").read_text())["otel_github_webhook_env"]
    assert {v["name"] for v in names.values()} == {"GITHUB_WEBHOOK_ENDPOINT", "GITHUB_WEBHOOK_PATH", "GITHUB_WEBHOOK_SECRET"}


def test_renamed_env_variables_flow_through_config_and_secrets_file(tmp_path):
    env_vars = yaml.safe_load((base.ROLE / "vars" / "main.yml").read_text())["otel_github_webhook_env"]
    renamed = {k: dict(v, name=v["name"].replace("GITHUB_WEBHOOK", "GH_HOOK")) for k, v in env_vars.items()}
    cfg, env = _render(tmp_path, otel_github_webhook_env=renamed)
    assert cfg["receivers"]["webhook_event/github"]["endpoint"] == "${env:GH_HOOK_ENDPOINT}"
    assert {"GH_HOOK_ENDPOINT", "GH_HOOK_PATH", "GH_HOOK_SECRET"} <= set(env) and not any(k.startswith("GITHUB") for k in env)


# ---- the gateway assertion runs in the input-validation step, before any change (real tasks, fake docker) ---------------

def _fake_docker(tmp_path, monkeypatch, gateway, rc=0):
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    log = tmp_path / "docker-calls.log"
    script = bin_dir / "docker"
    script.write_text(f'#!/bin/sh\necho "$@" >> {log}\n[ {rc} -eq 0 ] && echo "{gateway}"\nexit {rc}\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log


def _run_gateway_play(tmp_path, kv, os_path="modern"):
    marker = tmp_path / "later-change-ran"
    fixture = {"host": kv, "openobserve": base.SHARED_O2, "rustfs": base.SHARED_RUSTFS}
    later = [{"name": "stands for the binary delivery and the rule removal", "ansible.builtin.file":
              {"path": str(marker), "state": "touch", "mode": "0600"}, "check_mode": False}]
    res, _ = base._run_input_tasks(tmp_path, ["good"], "http://127.0.0.1:1", extra_tasks=later,
                                   extra_vars={"host_agents_kv_fixture": fixture, "host_agents_os_path": os_path})
    return res, marker


def _host_kv(**over):
    return dict(base.REQUIRED, **_kv(**over))


def test_matching_gateway_lets_the_play_continue(tmp_path, monkeypatch):
    log = _fake_docker(tmp_path, monkeypatch, BRIDGE_ADDRESS)
    res, marker = _run_gateway_play(tmp_path, _host_kv())
    assert res.returncode == 0, res.stdout + res.stderr
    assert marker.exists()
    call = log.read_text().split()
    assert call[:2] == ["network", "inspect"] and call[-1] == "net-dummy"


@pytest.mark.parametrize("case", ["other-gateway", "docker-fails"])
def test_gateway_mismatch_or_docker_failure_stops_the_host_before_any_later_change(tmp_path, monkeypatch, case):
    _fake_docker(tmp_path, monkeypatch, "192.0.2.78" if case == "other-gateway" else "", rc=0 if case == "other-gateway" else 1)
    res, marker = _run_gateway_play(tmp_path, _host_kv())
    assert res.returncode != 0 and not marker.exists()
    assert "게이트웨이" in res.stdout + res.stderr and BRIDGE_ADDRESS not in res.stdout + res.stderr


def test_docker_is_not_called_when_the_webhook_is_off(tmp_path, monkeypatch):
    log = _fake_docker(tmp_path, monkeypatch, "192.0.2.78")
    res, marker = _run_gateway_play(tmp_path, dict(base.REQUIRED))
    assert res.returncode == 0 and marker.exists() and not log.exists()


def test_docs_describe_the_docker_restart_coupling_and_the_gateway_recheck_procedure():
    text = (ROOT / "docs" / "monitoring.md").read_text(encoding="utf-8")
    assert "PartOf=docker.service" in text and "게이트웨이 변경 뒤 재확인" in text
    assert "docker.service.wants" in text and "stop" in text and "start docker" in text
