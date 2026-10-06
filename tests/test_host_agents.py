"""Host Agents entry point (ADR-0006, Spec #38 / Ticket-2).

* host_agents.yml / site.yml / maintenance.yml structure.
* OS probe classification (sample os-release / redhat-release / uname outputs).
* Agents KV resolution: the real ``agents_input.yml`` task file is executed with
  ``ansible-playbook`` against a fake OpenBao HTTP server, in normal and check mode.
"""

import hashlib
import json
import subprocess
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from host_agents import (  # noqa: E402
    host_agents_glob_regex,
    host_agents_os_probe_cmd,
    host_agents_parse_os_probe,
    host_agents_resource_attributes,
    host_agents_resolve_inputs,
    host_agents_secrets,
)

PLAYBOOKS = ROOT_DIR / "playbooks"
ROLE = ROOT_DIR / "roles" / "monitoring"
IMPORT = "ansible.builtin.import_playbook"


# --------------------------------------------------------------------------
# Playbook structure
# --------------------------------------------------------------------------

def _plays(name):
    return yaml.safe_load((PLAYBOOKS / name).read_text(encoding="utf-8"))


def _role_names(play):
    return [r["role"] if isinstance(r, dict) else r for r in play.get("roles", [])]


def test_host_agents_playbook_structure():
    plays = _plays("host_agents.yml")
    assert [p.get(IMPORT) for p in plays] == [
        "common/resolve_connection.yml", None, "common/cleanup_connection.yml"]
    for p in (plays[0], plays[2]):
        assert p["tags"] == ["always"]
        assert p["vars"]["connection_hosts"] == "{{ target_hosts | default('servers') }}:&servers"
    agents = plays[1]
    assert agents["hosts"] == "{{ target_hosts | default('servers') }}:&servers"
    assert agents["serial"] == "25%"
    assert agents["gather_facts"] is False
    assert _role_names(agents) == ["monitoring", "backup"]


def test_shared_connection_plays_accept_connection_hosts_override():
    for name in ("resolve_connection.yml", "cleanup_connection.yml"):
        hosts = yaml.safe_load((PLAYBOOKS / "common" / name).read_text(encoding="utf-8"))[0]["hosts"]
        assert hosts == "{{ connection_hosts | default(target_hosts | default('servers:loadbalancers')) }}"


@pytest.mark.parametrize("playbook", ["site.yml", "maintenance.yml"])
def test_monitoring_is_not_applied_by_site_or_maintenance(playbook):
    for play in _plays(playbook):
        assert "monitoring" not in _role_names(play)


def _listed_hosts(extra):
    inv = {"all": {"children": {"servers": {"hosts": {"a": None, "b": None}},
                                "loadbalancers": {"hosts": {"c": None}}}}}
    return inv, extra


@pytest.mark.parametrize("target, expected", [
    (None, {"a", "b"}),
    ("b", {"b"}),
    ("c", set()),              # loadbalancers can never be reached
    ("loadbalancers", set()),
])
def test_target_hosts_narrows_but_never_widens_beyond_servers(tmp_path, target, expected):
    inv = {"all": {"children": {"servers": {"hosts": {"a": {}, "b": {}}},
                                "loadbalancers": {"hosts": {"c": {}}}}}}
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"),
           str(PLAYBOOKS / "host_agents.yml"), "--list-hosts"]
    if target:
        cmd += ["-e", f"target_hosts={target}"]
    out = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                         cwd=ROOT_DIR, timeout=120).stdout
    plays = out.split("play #")[1:]
    assert len(plays) == 3
    for play in plays:  # resolve, agents and cleanup all see the same host set
        listed = {ln.strip() for ln in play.splitlines()
                  if ln.startswith("      ") and "TAGS" not in ln}
        assert listed == expected


def test_role_tags_wired():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    for imp in main[:2]:
        assert imp["tags"] == ["always"]
    blocks = {b["name"]: set(b["tags"]) for b in main[2:] if "block" in b}
    assert blocks == {
        "Install agents and clean legacy exporter": {"agents_install", "otel"},
        "Apply otelcol configuration": {"agents_config", "otel"},
        "Enable otelcol service": {"agents_install", "otel"},
    }
    inner = {t["name"].split("]")[0].lstrip("[") for b in main[2:] if "block" in b for t in b["block"] if "name" in t}
    assert {"MON-011", "MON-001", "MON-003"} <= inner
    config = next(b for b in main if b["name"] == "Apply otelcol configuration")
    assert config["block"][0]["name"].startswith("[MON-060]")
    assert any(t["name"].startswith("[MON-004]") for t in config["block"])
    agents = _plays("host_agents.yml")[1]
    assert agents["roles"][0]["tags"] == ["otel"]
    assert agents["roles"][1]["tags"] == ["backup"]


def test_probe_and_kv_tasks_run_before_any_change():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    assert [t["ansible.builtin.import_tasks"] for t in main[:2]] == ["probe.yml", "agents_input.yml"]
    probe = yaml.safe_load((ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))
    assert probe[0]["name"].startswith("[MON-020]")            # provisioned assert first
    assert "site.yml" in probe[0]["ansible.builtin.assert"]["fail_msg"]
    raw = next(t for t in probe if "ansible.builtin.raw" in t and t["name"].startswith("[MON-021]"))
    assert raw["check_mode"] is False and raw["changed_when"] is False
    for t in probe:
        if t["name"].startswith(("[MON-023]", "[MON-024]", "[MON-027]")):
            assert t["when"] == "host_agents_os_path == 'modern'"
        if t["name"].startswith("[MON-023]"):
            assert t["check_mode"] is False and t["changed_when"] is False


# --------------------------------------------------------------------------
# OS probe classification
# --------------------------------------------------------------------------

def _probe(os_release="", redhat="", uname="x86_64", noise="", machine_id=""):
    return (f"{noise}\n__HOST_AGENTS_OS_RELEASE__\n{os_release}\n"
            f"__HOST_AGENTS_REDHAT_RELEASE__\n{redhat}\n__HOST_AGENTS_MACHINE_ID__\n{machine_id}\n"
            f"__HOST_AGENTS_UNAME_M__\n{uname}\n")


ROCKY9 = 'NAME="Rocky Linux"\nVERSION="9.3 (Blue Onyx)"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.3"\nPRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"'
ROCKY8 = 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.9"\nPRETTY_NAME="Rocky Linux 8.9 (Green Obsidian)"'
UBUNTU = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.4 LTS"'
DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian'
CENTOS7 = 'NAME="CentOS Linux"\nVERSION="7 (Core)"\nID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="7"\nPRETTY_NAME="CentOS Linux 7 (Core)"'


@pytest.mark.parametrize("args, path, family, distro, major, arch", [
    (dict(os_release=ROCKY9, redhat="Rocky Linux release 9.3 (Blue Onyx)"), "modern", "RedHat", "Rocky", "9", "amd64"),
    (dict(os_release=ROCKY8, redhat="Rocky Linux release 8.9 (Green Obsidian)", uname="aarch64"), "modern", "RedHat", "Rocky", "8", "arm64"),
    (dict(os_release=UBUNTU), "modern", "Debian", "Ubuntu", "22", "amd64"),
    (dict(os_release=DEBIAN), "modern", "Debian", "Debian", "12", "amd64"),
    (dict(os_release=CENTOS7, redhat="CentOS Linux release 7.9.2009 (Core)"), "legacy_el7", "RedHat", "CentOS", "7", "amd64"),
    (dict(redhat="CentOS release 6.10 (Final)"), "legacy_el6", "RedHat", "CentOS", "6", "amd64"),
    (dict(redhat="CentOS release 6.10 (Final)", uname="i686"), "legacy_el6", "RedHat", "CentOS", "6", "i686"),
])
def test_os_probe_classification(args, path, family, distro, major, arch):
    facts = host_agents_parse_os_probe(_probe(noise="Last login: Mon Sep 28", **args))
    assert (facts["path"], facts["family"], facts["distribution"],
            facts["major_version"], facts["arch"], facts["type"]) == (path, family, distro, major, arch, "linux")
    assert facts["description"]


def test_os_probe_versions_and_description():
    facts = host_agents_parse_os_probe(_probe(os_release=CENTOS7, redhat="CentOS Linux release 7.9.2009 (Core)"))
    assert facts["version"] == "7.9.2009" and facts["description"] == "CentOS Linux 7 (Core)"
    facts = host_agents_parse_os_probe(_probe(redhat="CentOS release 6.10 (Final)"))
    assert facts["version"] == "6.10" and facts["description"] == "CentOS release 6.10 (Final)"


MACHINE_ID = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize("args, os_id", [
    (dict(os_release=ROCKY9, redhat="Rocky Linux release 9.3 (Blue Onyx)"), "rocky"),
    (dict(os_release=UBUNTU), "ubuntu"),
    (dict(os_release=CENTOS7, redhat="CentOS Linux release 7.9.2009 (Core)"), "centos"),
    (dict(redhat="CentOS release 6.10 (Final)"), "centos"),
    (dict(redhat="Red Hat Enterprise Linux Server release 6.10 (Santiago)"), "rhel"),
])
def test_os_probe_derives_an_os_release_style_id(args, os_id):
    assert host_agents_parse_os_probe(_probe(**args))["os_id"] == os_id


def test_os_probe_reads_machine_id_only_when_well_formed():
    assert host_agents_parse_os_probe(_probe(os_release=UBUNTU, machine_id=MACHINE_ID.upper()))["machine_id"] == MACHINE_ID
    for bad in ("", "not-a-machine-id", MACHINE_ID[:-1]):
        assert host_agents_parse_os_probe(_probe(os_release=UBUNTU, machine_id=bad))["machine_id"] == ""
    # CentOS 6 has no /etc/machine-id: the section is empty and uname still parses
    el6 = host_agents_parse_os_probe(_probe(redhat="CentOS release 6.10 (Final)", uname="x86_64"))
    assert el6["machine_id"] == "" and el6["arch"] == "amd64"


@pytest.mark.parametrize("output", ["", "no markers at all", _probe(), _probe(os_release='ID=alpine\nVERSION_ID=3.19')])
def test_os_probe_rejects_unclassifiable_hosts(output):
    with pytest.raises(ValueError):
        host_agents_parse_os_probe(output)


def test_os_probe_command_runs_and_parses_on_this_host():
    out = subprocess.run(["sh", "-c", host_agents_os_probe_cmd()], capture_output=True, text=True).stdout
    facts = host_agents_parse_os_probe(out)
    assert facts["path"] == "modern" and facts["arch"] in ("amd64", "arm64")


# --------------------------------------------------------------------------
# Agents KV merge / validation (filter contract)
# --------------------------------------------------------------------------

STANDARD = ["/var/log/messages", "/var/log/secure", "/var/log/audit/audit.log", "/var/log/cron*"]
SECURITY = ["/var/log/secure", "/var/log/audit/audit.log"]
MANDATORY = ["/etc", "/var/spool/cron", "/usr/local/bin"]
REQUIRED = {"o2_ingest_token": "tok-o2-ingest-0001", "rustfs_access_key": "rfs-access-0002",
            "rustfs_secret_key": "rfs-secret-0003", "restic_password": "restic-pass-0004"}


SERVICES = {"/var/log/messages": "syslog", "/var/log/secure": "auth", "/var/log/audit/audit.log": "audit",
            "/var/log/cron*": "cron"}


def _resolve(**kv):
    return host_agents_resolve_inputs(dict(REQUIRED, **kv), STANDARD, SECURITY, MANDATORY, "hosts/h/agents",
                                      service_map=SERVICES)


def test_absent_overrides_mean_git_standard_only():
    res = _resolve()
    assert res["errors"] == []
    assert res["otel_logs"] == [
        {"path": "/var/log/messages", "stream": "system_logs", "service": "syslog"},
        {"path": "/var/log/secure", "stream": "security_logs", "service": "auth"},
        {"path": "/var/log/audit/audit.log", "stream": "security_logs", "service": "audit"},
        {"path": "/var/log/cron*", "stream": "system_logs", "service": "cron"}]
    assert res["backup_paths"] == MANDATORY
    assert (res["otel_docker_metrics"], res["backup_exclude_paths"], res["backup_pre_hooks"]) == (False, [], [])


def test_extra_lists_are_appended_and_exclude_lists_subtracted():
    res = _resolve(
        otel_extra_logs=["/opt/app/*.log", {"path": "/srv/x.log", "stream": "system_logs"}],
        otel_exclude_logs=["/var/log/cron*"],
        backup_extra_paths=["/home", "/data"],
        backup_exclude_paths=["/etc/cache", "*.tmp"],
        backup_pre_hooks=["pg_dump db > /var/backups/db.sql"],
        otel_docker_metrics="true")
    assert res["errors"] == []
    paths = [(l["path"], l["stream"]) for l in res["otel_logs"]]
    assert ("/var/log/cron*", "system_logs") not in paths
    assert paths[-2:] == [("/opt/app/*.log", "app_logs"), ("/srv/x.log", "system_logs")]
    assert res["backup_paths"] == MANDATORY + ["/home", "/data"]
    assert res["backup_exclude_paths"] == ["/etc/cache", "*.tmp"]      # sub-paths of mandatory dirs stay allowed
    assert res["backup_pre_hooks"] == ["pg_dump db > /var/backups/db.sql"]
    assert res["otel_docker_metrics"] is True


@pytest.mark.parametrize("missing", sorted(REQUIRED))
@pytest.mark.parametrize("blank", [None, ""])
def test_missing_required_key_is_an_error_naming_key_and_path(missing, blank):
    res = host_agents_resolve_inputs(dict(REQUIRED, **{missing: blank}), STANDARD, SECURITY, MANDATORY, "hosts/h/agents")
    assert len(res["errors"]) == 1 and missing in res["errors"][0] and "hosts/h/agents" in res["errors"][0]


def test_secrets_are_never_part_of_the_merged_result():
    res = _resolve()
    assert not any(v in json.dumps(res) for v in REQUIRED.values())
    assert not set(REQUIRED) & set(res)
    assert host_agents_secrets(dict(REQUIRED, otel_extra_logs=["/x"])) == REQUIRED


@pytest.mark.parametrize("kv_key, entry, item", [
    ("otel_exclude_logs", "/var/log/secure", "/var/log/secure"),
    ("otel_exclude_logs", "/var/log/audit/audit.log", "/var/log/audit/audit.log"),
    ("backup_exclude_paths", "/etc", "/etc"),
    ("backup_exclude_paths", "/etc/", "/etc/"),
    ("backup_exclude_paths", "/etc/**", "/etc/**"),
    ("backup_exclude_paths", "/var/spool/cron", "/var/spool/cron"),
    ("backup_exclude_paths", "/usr/local", "/usr/local"),   # ancestor of a mandatory path
    ("backup_exclude_paths", "/", "/"),
    ("otel_exclude_logs", "/var/log/secure/", "/var/log/secure/"),
    ("otel_exclude_logs", "/var/log//secure", "/var/log//secure"),
    ("otel_exclude_logs", "/var/log/audit", "/var/log/audit"),          # parent dir of audit.log
    ("otel_exclude_logs", "/var/log/audit/*", "/var/log/audit/*"),
    ("otel_exclude_logs", "/var/log/sec*", "/var/log/sec*"),
])
def test_non_excludable_exclude_fails_naming_path_and_key(kv_key, entry, item):
    res = _resolve(**{kv_key: [entry]})
    assert len(res["errors"]) == 1
    assert kv_key in res["errors"][0] and item in res["errors"][0] and "hosts/h/agents" in res["errors"][0]


@pytest.mark.parametrize("kv", [
    {"otel_docker_metrics": "maybe"}, {"otel_exclude_logs": "not-json"}, {"otel_exclude_logs": {"a": 1}},
    {"otel_extra_logs": [{"path": "relative.log"}]}, {"otel_extra_logs": [{"path": "/x", "stream": "backup_logs"}]},
    {"otel_extra_logs": [42]}, {"backup_extra_paths": ["relative"]}, {"backup_pre_hooks": [1]},
])
def test_malformed_optional_values_are_errors_not_silently_ignored(kv):
    assert _resolve(**kv)["errors"]


def test_non_security_glob_exclude_removes_matching_standard_logs():
    res = _resolve(otel_exclude_logs=["/var/log/mess*"])
    assert res["errors"] == []
    assert "/var/log/messages" not in [l["path"] for l in res["otel_logs"]]


@pytest.mark.parametrize("shared", [{}, {"a": ""}, None])
def test_empty_shared_secret_is_an_error(shared):
    res = host_agents_resolve_inputs(dict(REQUIRED), STANDARD, SECURITY, MANDATORY, "p", {"rustfs": shared})
    assert res["errors"] == ["공유 시크릿 누락 또는 비어 있음: agents/rustfs"]


def test_json_encoded_string_lists_are_accepted():
    assert _resolve(backup_extra_paths='["/data"]')["backup_paths"] == MANDATORY + ["/data"]


# --------------------------------------------------------------------------
# agents_input.yml executed under ansible-playbook against a fake OpenBao
# --------------------------------------------------------------------------

GOOD = dict(REQUIRED, otel_docker_metrics=True, otel_extra_logs=["/opt/app/*.log"])
BAD_EXCLUDE = dict(REQUIRED, backup_exclude_paths=["/etc"])
MISSING = {k: v for k, v in REQUIRED.items() if k != "restic_password"}
SHARED_O2 = {"controller_token": "shared-o2"}
SHARED_RUSTFS = {"maintenance_access_key": "shared-rfs"}


class _FakeOpenBao(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):  # noqa: N802
        status, body = self.routes.get(self.path, (404, {"errors": []}))
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _kv(data):
    return 200, {"data": {"data": data, "metadata": {"version": 1}}}


@pytest.fixture
def openbao():
    server = HTTPServer(("127.0.0.1", 0), _FakeOpenBao)
    _FakeOpenBao.routes = {
        "/v1/secret/data/hosts/good/agents": _kv(GOOD),
        "/v1/secret/data/hosts/bare/agents": _kv(REQUIRED),
        "/v1/secret/data/hosts/badexclude/agents": _kv(BAD_EXCLUDE),
        "/v1/secret/data/hosts/missing/agents": _kv(MISSING),
        "/v1/secret/data/hosts/nokv/agents": (404, {"errors": []}),
        "/v1/secret/data/hosts/denied/agents": (403, {"errors": ["permission denied"]}),
        "/v1/secret/data/agents/openobserve": _kv(SHARED_O2),
        "/v1/secret/data/agents/rustfs": _kv(SHARED_RUSTFS),
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _run_input_tasks(tmp_path, hosts, addr, check=False, extra_vars=None, token="tok", extra_tasks=None,
                     with_backup_defaults=False, environment="production"):
    role_vars = {} if environment is None else {"host_agents_environment": environment}
    for f in ("defaults", "vars"):
        role_vars.update(yaml.safe_load((ROLE / f / "main.yml").read_text(encoding="utf-8")))
    if with_backup_defaults:
        role_vars.update(yaml.safe_load((ROLE.parent / "backup" / "defaults" / "main.yml").read_text(encoding="utf-8")))
    tasks = [{"ansible.builtin.import_tasks": str(ROLE / "tasks" / "agents_input.yml")}]
    tasks.append({
        "name": "Dump result",
        "ansible.builtin.copy": {
            "content": "{{ {'inputs': host_agents_inputs, 'secrets': host_agents_secrets,"
                       " 'shared': host_agents_shared_secrets, 'attrs': host_agents_resource_attrs} | to_json }}",
            "dest": f"{tmp_path}/out-{{{{ inventory_hostname }}}}.json", "mode": "0600"},
        "check_mode": False,
    })
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "become": False,
        "vars": role_vars, "tasks": tasks + (extra_tasks or [])}]))
    inv = {"all": {"hosts": {h: {"_vault_token": token} for h in hosts}, "vars": {"vault_addr": addr}}}
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml"), "-e", "vault_namespace=''"]
    if check:
        cmd.append("--check")
    for k, v in (extra_vars or {}).items():
        cmd += ["-e", json.dumps({k: v})]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR)
    return res, {h: json.loads((tmp_path / f"out-{h}.json").read_text())
                 for h in hosts if (tmp_path / f"out-{h}.json").exists()}


@pytest.mark.parametrize("environment, ok", [(None, False), ("prod", False), ("production", True), ("staging", True)])
@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_environment_is_validated_before_any_change_in_both_modes(tmp_path, openbao, check, environment, ok):
    res, out = _run_input_tasks(tmp_path, ["bare"], openbao, check=check, environment=environment)
    assert (res.returncode == 0) is ok and (set(out) == {"bare"}) is ok
    if ok:
        assert out["bare"]["attrs"]["attributes"]["deployment.environment.name"] == environment
    else:
        assert "bare: 리소스 속성 검증 실패" in res.stdout + res.stderr and "host_agents_environment" in res.stdout + res.stderr


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_agents_kv_resolution_under_ansible(tmp_path, openbao, check):
    hosts = ["good", "bare", "badexclude", "missing"]
    res, out = _run_input_tasks(tmp_path, hosts, openbao, check=check)
    text = res.stdout + res.stderr
    assert set(out) == {"good", "bare"}                       # invalid hosts fail before any later task
    assert "badexclude: Host Agents 입력 검증 실패" in text and "backup_exclude_paths" in text and "/etc" in text
    assert "hosts/badexclude/agents" in text
    assert "missing: Host Agents 입력 검증 실패" in text and "필수 키 누락: restic_password" in text
    assert res.returncode != 0
    assert out["good"]["secrets"] == REQUIRED
    assert out["good"]["shared"] == {"openobserve": SHARED_O2, "rustfs": SHARED_RUSTFS}
    assert out["good"]["inputs"]["otel_docker_metrics"] is True
    assert out["good"]["inputs"]["otel_logs"][-1] == {"path": "/opt/app/*.log", "stream": "app_logs", "service": "app"}
    services = {l["path"]: l["service"] for l in out["bare"]["inputs"]["otel_logs"]}
    assert services["/var/log/secure"] == "auth" and services["/var/log/audit/audit.log"] == "audit"
    assert out["good"]["attrs"]["attributes"]["deployment.environment.name"] == "production"
    bare = out["bare"]["inputs"]
    assert bare["errors"] == [] and bare["otel_docker_metrics"] is False
    assert {l["path"] for l in bare["otel_logs"] if l["stream"] == "security_logs"} >= {
        "/var/log/secure", "/var/log/audit/audit.log"}
    for secret in REQUIRED.values():                          # secrets never reach the console
        assert secret not in text


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("host", ["denied"])
def test_openbao_error_fails_the_host_in_normal_and_check_mode(tmp_path, openbao, check, host):
    res, out = _run_input_tasks(tmp_path, [host], openbao, check=check)
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in res.stdout + res.stderr and "403" in res.stdout + res.stderr


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_unreachable_openbao_fails_the_host(tmp_path, check):
    res, out = _run_input_tasks(tmp_path, ["good"], "http://127.0.0.1:1", check=check)
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in res.stdout + res.stderr


def test_missing_kv_secret_fails_naming_all_required_keys(tmp_path, openbao):
    res, out = _run_input_tasks(tmp_path, ["nokv"], openbao)
    assert res.returncode != 0 and out == {}
    for key in REQUIRED:
        assert f"필수 키 누락: {key}" in res.stdout + res.stderr


def test_missing_vault_token_fails_instead_of_previewing_incomplete_config(tmp_path, openbao):
    res, out = _run_input_tasks(tmp_path, ["good"], openbao, token="", check=True)
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in res.stdout + res.stderr


def test_missing_shared_secret_fails_the_host(tmp_path, openbao):
    _FakeOpenBao.routes["/v1/secret/data/agents/rustfs"] = (404, {"errors": []})
    res, out = _run_input_tasks(tmp_path, ["good"], openbao)
    assert res.returncode != 0 and out == {}
    assert "공유 시크릿 누락 또는 비어 있음: agents/rustfs" in res.stdout + res.stderr


def test_fixture_seam_skips_openbao_entirely(tmp_path):
    fixture = {"host": REQUIRED, "openobserve": SHARED_O2, "rustfs": SHARED_RUSTFS}
    res, out = _run_input_tasks(tmp_path, ["good"], "http://127.0.0.1:1", extra_vars={"host_agents_kv_fixture": fixture})
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["good"]["secrets"] == REQUIRED and out["good"]["inputs"]["errors"] == []


def test_unprovisioned_host_fails_pointing_at_site_yml(tmp_path):
    tasks = yaml.safe_load((ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))[:1]
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "tasks": tasks}]))
    (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": {
        "fresh": {"_is_already_provisioned": False}, "undef": {}, "ready": {"_is_already_provisioned": True}}}}))
    res = subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    text = res.stdout + res.stderr
    assert "fresh: 접속 계정으로 SSH 접속할 수 없는" in text and "undef: 접속 계정으로 SSH 접속할 수 없는" in text
    assert "ready: 접속 계정" not in text and "admin_users" in text and "site.yml" in text
    assert res.returncode != 0


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_probe_tasks_set_os_facts_with_and_without_pregathered_facts(tmp_path, check):
    """MON-020..025 against the local host: same facts whether or not setup ran first."""
    tasks = yaml.safe_load((ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))
    tasks.append({"name": "Dump", "ansible.builtin.copy": {
        "content": "{{ {'path': host_agents_os_path, 'family': host_agents_os_family,"
                   " 'dist': host_agents_os_distribution, 'arch': host_agents_os_arch,"
                   " 'facts': ansible_facts | length > 0} | to_json }}",
        "dest": f"{tmp_path}/out-{{{{ inventory_hostname }}}}.json", "mode": "0600"}, "check_mode": False})
    (tmp_path / "play.yml").write_text(yaml.safe_dump([
        {"hosts": "cold", "gather_facts": False, "connection": "local", "become": False, "tasks": tasks},
        {"hosts": "warm", "gather_facts": True, "connection": "local", "become": False, "tasks": tasks}]))
    (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": {
        h: {"_is_already_provisioned": True, "ansible_python_interpreter": sys.executable} for h in ("cold", "warm")}}}))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")] + (["--check"] if check else [])
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR)
    assert res.returncode == 0, res.stdout + res.stderr
    cold, warm = (json.loads((tmp_path / f"out-{h}.json").read_text()) for h in ("cold", "warm"))
    assert cold == warm and cold["path"] == "modern" and cold["facts"] is True


# --------------------------------------------------------------------------
# Pinned binary delivery (Ticket-3): deliver_binary.yml + switch_binary.yml executed for real
# --------------------------------------------------------------------------

def _make_release(tmp_path, version):
    """Fake release tarball; bytes are kept stable so repeated runs see the same SHA256."""
    tgz = tmp_path / f"fake-agent_{version}_linux_amd64.tar.gz"
    if not tgz.exists():
        src = tmp_path / f"src-{version}"
        src.mkdir(exist_ok=True)
        exe = src / "fake-agent"
        exe.write_text(f"#!/bin/sh\necho v{version}\n")
        exe.chmod(0o755)
        with tarfile.open(tgz, "w:gz") as t:
            t.add(exe, arcname="fake-agent")
    return tgz, hashlib.sha256(tgz.read_bytes()).hexdigest()


def _id(flag):
    return subprocess.run(["id", flag], capture_output=True, text=True).stdout.strip()


def _deliver(tmp_path, version, sha=None, check=False):
    tgz, real = _make_release(tmp_path, version)
    tasks = ROLE / "tasks"
    call_vars = {"_deliver_agent": "fake-agent", "_deliver_binary": "fake-agent",
                 "_deliver_version": version, "_deliver_url": f"file://{tgz}",
                 "_deliver_sha256": sha or real, "_deliver_handler": "Restart fake"}
    pb = tmp_path / "deliver.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"host_agents_os_arch": "amd64", "host_agents_cache_dir": str(tmp_path / "cache"),
                 "host_agents_install_root": str(tmp_path / "opt"),
                 "host_agents_bin_dir": str(tmp_path / "bin"),
                 "host_agents_owner": _id("-un"), "host_agents_group": _id("-gn")},
        "tasks": [{"ansible.builtin.include_tasks": str(tasks / f), "vars": call_vars}
                  for f in ("deliver_binary.yml", "switch_binary.yml")],
        "handlers": [{"name": "Restart fake", "ansible.builtin.debug": {"msg": "HANDLER-RAN"}}],
    }]))
    (tmp_path / "bin").mkdir(exist_ok=True)
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check", "--diff"] if check else [])
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          cwd=ROOT_DIR, timeout=180)


def _link_version(tmp_path):
    return (tmp_path / "bin" / "fake-agent").readlink().parent.name


def _kept(tmp_path):
    return sorted(p.name for p in (tmp_path / "opt" / "fake-agent").iterdir() if p.is_dir())


def test_delivery_installs_versioned_dir_and_symlink(tmp_path):
    r = _deliver(tmp_path, "1.0.0")
    assert r.returncode == 0, r.stdout + r.stderr
    link = tmp_path / "bin" / "fake-agent"
    assert link.is_symlink()
    assert link.readlink() == tmp_path / "opt" / "fake-agent" / "1.0.0" / "fake-agent"
    assert "HANDLER-RAN" in r.stdout
    again = _deliver(tmp_path, "1.0.0")            # idempotent: no change, no restart
    assert again.returncode == 0 and "changed=0" in again.stdout
    assert "HANDLER-RAN" not in again.stdout


def test_delivery_checksum_mismatch_fails_before_any_install(tmp_path):
    r = _deliver(tmp_path, "1.0.0", sha="0" * 64)
    assert r.returncode != 0
    assert not (tmp_path / "bin" / "fake-agent").exists()
    assert not (tmp_path / "opt" / "fake-agent" / "1.0.0").exists()


def test_delivery_upgrade_keeps_only_previous_version(tmp_path):
    for v in ("1.0.0", "1.1.0", "1.2.0"):
        assert _deliver(tmp_path, v).returncode == 0
    assert _kept(tmp_path) == ["1.1.0", "1.2.0"]
    assert _link_version(tmp_path) == "1.2.0"


def test_delivery_rerun_of_current_version_keeps_the_previous_version(tmp_path):
    for v in ("1.0.0", "1.1.0", "1.1.0"):
        assert _deliver(tmp_path, v).returncode == 0
    assert _kept(tmp_path) == ["1.0.0", "1.1.0"]


def test_delivery_preserves_preexisting_regular_file_binary(tmp_path):
    legacy = tmp_path / "bin" / "fake-agent"
    legacy.parent.mkdir()
    legacy.write_text("old-0.108.0")
    r = _deliver(tmp_path, "1.0.0")
    assert r.returncode == 0, r.stdout + r.stderr
    assert legacy.is_symlink()
    assert (tmp_path / "opt" / "fake-agent" / "legacy-fake-agent").read_text() == "old-0.108.0"


def test_delivery_check_mode_reports_version_change_without_changing_host(tmp_path):
    assert _deliver(tmp_path, "1.0.0").returncode == 0
    r = _deliver(tmp_path, "1.1.0", check=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "fake-agent/1.0.0/fake-agent" in r.stdout and "fake-agent/1.1.0/fake-agent" in r.stdout
    assert _link_version(tmp_path) == "1.0.0"
    assert not (tmp_path / "opt" / "fake-agent" / "1.1.0" / "fake-agent").exists()


def test_config_is_validated_by_the_new_binary_before_the_symlink_switches():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    flat = []

    def walk(items):
        for t in items:
            flat.append(t)
            walk(t.get("block", []))
    walk(tasks)
    names = [t.get("name", "") for t in flat]
    order = {k: next(i for i, n in enumerate(names) if k in n) for k in ("MON-003", "MON-004-CONF", "MON-054")}
    assert order["MON-003"] < order["MON-004-CONF"] < order["MON-054"]
    conf = flat[order["MON-004-CONF"]]["ansible.builtin.template"]["validate"]
    assert "host_agents_install_root" in conf and "host_agents_versions" in conf   # new versioned binary
    assert "/usr/local/bin/otelcol-contrib" not in conf                             # never the old symlink


def test_otelcol_pinned_version_table_is_consistent():
    v = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
    ver = v["host_agents_versions"]["default"]["otelcol_contrib"]
    sums = v["host_agents_checksums"]["otelcol_contrib"][ver]
    assert set(sums) == {"amd64", "arm64"}
    assert all(len(h) == 64 and int(h, 16) >= 0 for h in sums.values())
    assert ver != "0.108.0"


# --------------------------------------------------------------------------
# Collection config (Ticket-4): template rendered with Ansible's own Jinja environment
def test_extra_logs_carry_a_service_name_defaulting_to_the_stream():
    res = _resolve(otel_extra_logs=["/opt/app/*.log", {"path": "/srv/x.log", "stream": "system_logs", "service": "x-svc"},
                                    {"path": "/srv/y.log", "stream": "security_logs"}])
    assert res["errors"] == []
    extra = {l["path"]: l["service"] for l in res["otel_logs"][len(STANDARD):]}
    assert extra == {"/opt/app/*.log": "app", "/srv/x.log": "x-svc", "/srv/y.log": "security"}


@pytest.mark.parametrize("bad", [{"path": "/x.log", "service": "Bad Name"}, {"path": "/x.log", "service": 7},
                                 {"path": "/x.log", "service": ""}, "/var/log/[ab].log", '/var/log/a"b.log'])
def test_extra_logs_reject_a_bad_service_or_unsupported_glob(bad):
    assert _resolve(otel_extra_logs=[bad])["errors"]


def test_every_standard_log_path_has_a_service_name():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    mapped = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))["otel_log_services"]
    assert not set(defaults["otel_system_logs"]) - set(mapped), "otel_log_services가 otel_system_logs의 경로를 빠뜨렸습니다"


@pytest.mark.parametrize("glob, regex", [
    ("/var/log/secure", "^/var/log/secure$"), ("/var/log/cron*", "^/var/log/cron[^/]*$"),
    ("/var/log/auth.log", "^/var/log/auth[.]log$"), ("/opt/**/x?.log", "^/opt/.*/x[^/][.]log$")])
def test_glob_regex_is_anchored_and_has_no_backslash(glob, regex):
    assert host_agents_glob_regex(glob) == regex and "\\" not in regex


# --------------------------------------------------------------------------
# Resource attributes (ADR-0006 §2.3)
# --------------------------------------------------------------------------

OS_FACTS = {"machine_id": MACHINE_ID, "arch": "amd64", "type": "linux", "os_id": "rocky", "version": "9.3",
            "description": "Rocky Linux 9.3"}


def test_resource_attributes_use_otel_names_and_the_inventory_hostname():
    res = host_agents_resource_attributes("ns0266", "production", OS_FACTS, "39.116.31.43")
    assert res["errors"] == [] and res["omitted"] == []
    assert res["attributes"] == {
        "host.name": "ns0266", "host.id": MACHINE_ID, "host.ip": "39.116.31.43", "host.arch": "amd64",
        "os.type": "linux", "os.name": "rocky", "os.version": "9.3", "os.description": "Rocky Linux 9.3",
        "deployment.environment.name": "production"}


@pytest.mark.parametrize("env", [None, "", "prod", "PRODUCTION", "dev", " "])
def test_environment_is_mandatory_and_limited_to_the_semconv_vocabulary(env):
    res = host_agents_resource_attributes("h1", env, OS_FACTS, "192.0.2.1")
    assert res["errors"] and "deployment.environment.name" not in res["attributes"]


@pytest.mark.parametrize("env", ["production", "staging", "development", "test", " staging "])
def test_every_vocabulary_value_is_accepted(env):
    assert host_agents_resource_attributes("h1", env, OS_FACTS, "192.0.2.1")["errors"] == []


def test_host_id_and_host_ip_are_left_out_and_named_when_unavailable():
    facts = dict(OS_FACTS, machine_id="")
    for ip in (None, "", "not-an-ip", "web-01.example"):
        res = host_agents_resource_attributes("el6", "production", facts, ip)
        assert res["errors"] == [] and res["omitted"] == ["host.id", "host.ip"]
        assert "host.id" not in res["attributes"] and "host.ip" not in res["attributes"]
        assert res["attributes"]["host.name"] == "el6"


# --------------------------------------------------------------------------

def _render_config(tmp_path, **over):
    vars_ = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    vars_.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8")))
    vars_.update({
        "inventory_hostname": "h1", "host_agents_os_type": "linux", "host_agents_os_description": "Rocky Linux 9",
        "host_agents_journald": False, "o2_endpoint": "https://o2.example:5080", "o2_org": "default",
        "host_agents_secrets": {"o2_ingest_token": "s3cr3t-token"},
        "host_agents_resource_attrs": host_agents_resource_attributes("h1", "production", OS_FACTS, "192.0.2.10"),
        "host_agents_inputs": {"otel_docker_metrics": False, "otel_logs": [
            {"path": "/var/log/secure", "stream": "security_logs", "service": "auth"},
            {"path": "/var/log/audit/audit.log", "stream": "security_logs", "service": "audit"},
            {"path": "/var/log/messages", "stream": "system_logs", "service": "syslog"},
            {"path": "/var/log/app/*.log", "stream": "app_logs", "service": "app"}]},
    })
    vars_.update(over)
    (tmp_path / "vars.yml").write_text(yaml.safe_dump(vars_))
    pb = tmp_path / "render.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(tmp_path / "vars.yml")],
        "tasks": [{"ansible.builtin.template": {"src": str(ROLE / "templates" / "otelcol-contrib.yaml.j2"),
                                                 "dest": str(tmp_path / "config.yaml")}},
                  {"ansible.builtin.template": {"src": str(ROLE / "templates" / "secrets.env.j2"),
                                                 "dest": str(tmp_path / "secrets.env")}}]}]))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    return yaml.safe_load((tmp_path / "config.yaml").read_text()), (tmp_path / "config.yaml").read_text()


def test_config_routes_logs_by_stream_to_otlphttp_with_stream_name(tmp_path):
    cfg, _ = _render_config(tmp_path)
    for stream in ("security_logs", "system_logs", "app_logs", "backup_logs"):
        exp = cfg["exporters"][f"otlphttp/{stream}"]
        assert exp["endpoint"] == "https://o2.example:5080/api/default"
        assert exp["headers"]["stream-name"] == stream
        assert exp["headers"]["Authorization"] == "Basic ${env:O2_BASIC_AUTH}"
        q = exp["sending_queue"]
        assert q["storage"] == "file_storage" and q["sizer"] == "bytes" and q["block_on_overflow"] is True
        assert exp["retry_on_failure"]["max_elapsed_time"] == 0
        assert cfg["service"]["pipelines"][f"logs/{stream}"]["exporters"] == [f"otlphttp/{stream}"]
    assert {c["pipelines"][0] for c in cfg["connectors"]["routing/logs"]["table"]} == {
        "logs/security_logs", "logs/system_logs", "logs/backup_logs"}
    assert cfg["connectors"]["routing/logs"]["default_pipelines"] == ["logs/app_logs"]
    assert not any(k.startswith("otlp/") for k in cfg["exporters"])            # no legacy gRPC exporter


def test_config_filelog_checkpoints_and_start_at_end(tmp_path):
    cfg, _ = _render_config(tmp_path)
    for stream in ("security_logs", "system_logs", "app_logs"):
        rcv = cfg["receivers"][f"filelog/{stream}"]
        assert rcv["storage"] == "file_storage" and rcv["start_at"] == "end"
        assert rcv["attributes"]["log_type"] == stream
    assert cfg["extensions"]["file_storage"]["compaction"]["on_rebound"] is True
    # only service.name is stamped (resource-level add); the body is never parsed or rewritten
    ops = cfg["receivers"]["filelog/security_logs"]["operators"]
    assert {op["type"] for op in ops} == {"add"} and {op["field"] for op in ops} == {'resource["service.name"]'}


def test_config_stamps_service_name_per_log_file_group_keeping_receiver_ids(tmp_path):
    cfg, _ = _render_config(tmp_path)
    # the file_storage checkpoint key is the receiver id: it must stay one receiver per stream
    assert {k for k in cfg["receivers"] if k.startswith("filelog/")} == {
        "filelog/security_logs", "filelog/system_logs", "filelog/app_logs", "filelog/backup_logs"}
    ops = {op["value"]: op["if"] for op in cfg["receivers"]["filelog/security_logs"]["operators"]}
    assert ops == {"auth": 'attributes["log.file.path"] matches "^/var/log/secure$"',
                   "audit": 'attributes["log.file.path"] matches "^/var/log/audit/audit[.]log$"'}
    assert cfg["receivers"]["filelog/backup_logs"]["operators"][-1] == {
        "type": "add", "field": 'resource["service.name"]', "value": "backup"}


def test_config_backup_logs_pipeline_parses_json_and_keeps_the_raw_body(tmp_path):
    cfg, _ = _render_config(tmp_path)
    rcv = cfg["receivers"]["filelog/backup_logs"]
    assert rcv["include"] == ["/var/log/host-agents/backup.jsonl"]
    assert rcv["storage"] == "file_storage" and rcv["start_at"] == "end"
    assert rcv["attributes"]["log_type"] == "backup_logs"
    op, service = rcv["operators"]
    assert service["field"] == 'resource["service.name"]' and service["value"] == "backup"
    assert op["type"] == "json_parser" and op["parse_from"] == "body" and op["parse_to"] == "attributes"
    assert "preserve_to" not in op and op["timestamp"]["parse_from"] == "attributes.ts"
    assert "filelog/backup_logs" in cfg["service"]["pipelines"]["logs/in"]["receivers"]
    assert cfg["service"]["pipelines"]["logs/backup_logs"]["exporters"] == ["otlphttp/backup_logs"]
    assert cfg["exporters"]["otlphttp/backup_logs"]["headers"]["stream-name"] == "backup_logs"
    assert "logs/backup_logs" in {c["pipelines"][0] for c in cfg["connectors"]["routing/logs"]["table"]}


def test_config_metrics_pipeline_is_separate_droppable_and_60s(tmp_path):
    cfg, _ = _render_config(tmp_path)
    assert cfg["receivers"]["hostmetrics"]["collection_interval"] == "60s"
    assert set(cfg["receivers"]["hostmetrics"]["scrapers"]) == {
        "cpu", "memory", "load", "filesystem", "disk", "network", "paging", "processes"}
    metrics = cfg["service"]["pipelines"]["metrics/host"]
    assert metrics["exporters"] == ["otlphttp/metrics"]
    assert metrics["processors"] == ["memory_limiter", "resource/host", "resource/hostmetrics", "batch"]
    mq = cfg["exporters"]["otlphttp/metrics"]["sending_queue"]
    assert mq["block_on_overflow"] is False and "storage" not in mq


def test_config_optional_receivers_are_off_by_default(tmp_path):
    cfg, _ = _render_config(tmp_path)
    assert {"journald", "docker_stats", "otlp"}.isdisjoint(cfg["receivers"])
    on, _ = _render_config(tmp_path, host_agents_journald=True, otel_otlp_enabled=True,
                           host_agents_inputs={"otel_docker_metrics": True, "otel_logs": [
                               {"path": "/var/log/secure", "stream": "security_logs", "service": "auth"}]})
    assert {"journald", "docker_stats", "otlp"} <= set(on["receivers"])
    assert on["receivers"]["otlp"]["protocols"]["grpc"]["endpoint"] == "127.0.0.1:4317"   # loopback only
    pipes = on["service"]["pipelines"]
    assert pipes["metrics/docker"]["receivers"] == ["docker_stats"]
    assert "resource/docker" in pipes["metrics/docker"]["processors"]
    # app metrics arriving over OTLP keep the service.name their SDK set: no service.name processor on that pipeline
    assert pipes["metrics/otlp"]["receivers"] == ["otlp"]
    assert not {"resource/hostmetrics", "resource/docker"} & set(pipes["metrics/otlp"]["processors"])
    assert {"metrics/docker", "metrics/otlp"}.isdisjoint(cfg["service"]["pipelines"])


def test_config_sets_host_identity_and_never_contains_the_token(tmp_path):
    cfg, text = _render_config(tmp_path, o2_ca_file="/etc/ca.pem")
    attrs = {a["key"]: a["value"] for a in cfg["processors"]["resource/host"]["attributes"]}
    assert attrs == host_agents_resource_attributes("h1", "production", OS_FACTS, "192.0.2.10")["attributes"]
    assert attrs["deployment.environment.name"] == "production" and attrs["host.id"] == MACHINE_ID
    assert {a["action"] for a in cfg["processors"]["resource/host"]["attributes"]} == {"upsert"}
    assert "s3cr3t-token" not in text
    assert cfg["exporters"]["otlphttp/metrics"]["tls"]["ca_file"] == "/etc/ca.pem"
    import base64
    env = (tmp_path / "secrets.env").read_text()
    assert f"O2_BASIC_AUTH={base64.b64encode(b'default:s3cr3t-token').decode()}" in env


def test_secrets_env_task_is_private_and_undiffed():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    flat = []

    def walk(items):
        for t in items:
            flat.append(t)
            walk(t.get("block", []))
    walk(main)
    env = next(t for t in flat if t.get("name", "").startswith("[MON-065]"))
    assert env["ansible.builtin.template"]["mode"] == "0600"
    assert env["no_log"] is True and env["diff"] is False
    unit_task = next(t for t in flat if t.get("name", "").startswith("[MON-005]"))["ansible.builtin.template"]
    unit = (ROLE / "templates" / unit_task["src"]).read_text(encoding="utf-8")
    assert "EnvironmentFile=" in unit and "CAP_DAC_READ_SEARCH" in unit and "User={{ otelcol_user }}" in unit


def test_docker_group_is_added_only_via_lookup_and_rsyslog_probes_both_paths():
    text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "[MON-067]" in text and "otel_docker_group" in text
    assert "/usr/sbin/rsyslogd, /sbin/rsyslogd" in text
    consts = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
    assert consts["host_agents_log_streams"] == ["security_logs", "system_logs", "app_logs", "backup_logs"]


# --------------------------------------------------------------------------
# raw_upload.yml (#46): the real task file under ansible-playbook on a local
# connection; a fake `scp` on PATH stands in for the network copy.
# --------------------------------------------------------------------------

def _run_raw_upload(tmp_path, vars_, check=False, scp_ok=True):
    import getpass
    import os
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "scp.log"
    scp = bindir / "scp"
    scp.write_text('#!/bin/sh\necho "$@" >> %s\n'
                   'for a; do last="$a"; done\n'
                   'src=""; for a; do prev="$src"; src="$a"; done\n'
                   '[ "%s" = ok ] || exit 1\n'
                   'cp "$prev" "${last#*:}"\n' % (log, "ok" if scp_ok else "fail"))
    scp.chmod(0o755)
    sshpass = bindir / "sshpass"
    sshpass.write_text('#!/bin/sh\nif [ "$1" = "-V" ]; then echo "sshpass 1.09"; exit 0; fi\n'
                       'echo "ENV=$SSHPASS ARGS=$*" >> %s/sshpass.log\nshift; shift\nexec "$@"\n' % tmp_path)
    sshpass.chmod(0o755)
    play = [{
        "hosts": "localhost", "gather_facts": False, "connection": "local", "become": False,
        "vars": {"ansible_user": getpass.getuser(), "ansible_host": "127.0.0.1", "ansible_port": 2222,
                 "ansible_ssh_private_key_file": "/tmp/secret-key-path"},
        "tasks": [{"ansible.builtin.include_tasks": str(ROLE / "tasks" / "raw_upload.yml"), "vars": vars_}],
        "handlers": [{"name": "H", "ansible.builtin.debug": {"msg": "handler-ran"}}],
    }]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump(play))
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]), ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"),
               ANSIBLE_NOCOLOR="1")
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check"] if check else [])
    res = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=ROOT_DIR)
    return res, log


def _owner_group():
    import getpass
    import grp
    import os
    return getpass.getuser(), grp.getgrgid(os.getgid()).gr_name


def _bin_vars(tmp_path, content=b"payload-bin"):
    own, grp_ = _owner_group()
    src = tmp_path / "cache-bin"
    src.write_bytes(content)
    return {"_raw_src": str(src), "_raw_dest": str(tmp_path / "installed"),
            "_raw_sha256": hashlib.sha256(content).hexdigest(), "_raw_owner": own,
            "_raw_group": grp_, "_raw_mode": "0755", "_raw_handler": "H"}


def test_raw_upload_binary_uses_resolved_connection_and_is_idempotent(tmp_path):
    v = _bin_vars(tmp_path)
    res, log = _run_raw_upload(tmp_path, v)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (tmp_path / "installed").read_bytes() == b"payload-bin"
    argline = log.read_text()
    assert "-P 2222" in argline and "127.0.0.1:" in argline and "/tmp/secret-key-path" in argline
    log.unlink()
    res2, log2 = _run_raw_upload(tmp_path, v)
    assert res2.returncode == 0 and "changed=0" in res2.stdout, res2.stdout
    assert not log2.exists()  # sentinel matched -> no second upload


def test_raw_upload_hash_mismatch_fails_and_keeps_target(tmp_path):
    v = _bin_vars(tmp_path)
    v["_raw_sha256"] = "0" * 64
    (tmp_path / "installed").write_bytes(b"old")
    res, _ = _run_raw_upload(tmp_path, v)
    assert res.returncode != 0
    assert (tmp_path / "installed").read_bytes() == b"old"


def test_raw_upload_check_mode_probes_but_never_uploads(tmp_path):
    v = _bin_vars(tmp_path)
    res, log = _run_raw_upload(tmp_path, v, check=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not log.exists() and not (tmp_path / "installed").exists()
    assert "would upload via scp and install" in res.stdout


def test_raw_small_file_check_mode_prints_diff_but_never_secret_content(tmp_path):
    own, grp_ = _owner_group()
    plain, secret = tmp_path / "app.conf", tmp_path / "secrets.env"
    plain.write_text("level=old\n")
    secret.write_text("TOKEN=old-secret-value\n")
    base = {"_raw_owner": own, "_raw_group": grp_, "_raw_mode": "0600"}
    res, _ = _run_raw_upload(tmp_path, dict(base, _raw_dest=str(plain), _raw_content="level=new\n"), check=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "-level=old" in res.stdout and "+level=new" in res.stdout
    assert plain.read_text() == "level=old\n"
    res, _ = _run_raw_upload(tmp_path, dict(base, _raw_dest=str(secret), _raw_content="TOKEN=new-secret-value\n",
                                            _raw_secret=True), check=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "old-secret-value" not in res.stdout and "new-secret-value" not in res.stdout
    assert "secret content hidden" in res.stdout and "would change" in res.stdout
    assert secret.read_text() == "TOKEN=old-secret-value\n"


def test_raw_small_file_push_is_idempotent_and_notifies(tmp_path):
    own, grp_ = _owner_group()
    dest = tmp_path / "app.conf"
    v = {"_raw_owner": own, "_raw_group": grp_, "_raw_mode": "0640",
         "_raw_dest": str(dest), "_raw_content": "k=v\n", "_raw_handler": "H"}
    res, _ = _run_raw_upload(tmp_path, v)
    assert res.returncode == 0, res.stdout + res.stderr
    assert dest.read_text() == "k=v\n" and "handler-ran" in res.stdout
    res2, _ = _run_raw_upload(tmp_path, v)
    assert "changed=0" in res2.stdout and "handler-ran" not in res2.stdout


def test_raw_upload_cleans_staging_when_scp_fails(tmp_path):
    v = _bin_vars(tmp_path)
    res, _ = _run_raw_upload(tmp_path, v, scp_ok=False)
    assert res.returncode != 0
    assert "MON-108" in res.stdout and not (tmp_path / "installed").exists()
    assert not list(__import__("pathlib").Path("/var/tmp").glob("installed.*.raw.upload"))


def test_raw_upload_without_key_and_without_password_still_fails_before_any_upload(tmp_path):
    """키도 비밀번호도 없으면(= 허용 플래그만 있고 자격증명이 비어 있는 경우 포함) 업로드 전에 명확히 실패한다."""
    v = _bin_vars(tmp_path)
    v["ansible_ssh_private_key_file"] = ""
    v["ansible_password"] = ""
    res, _ = _run_raw_upload(tmp_path, v)
    text = res.stdout + res.stderr
    assert res.returncode != 0 and not (tmp_path / "sshpass.log").exists()
    assert "비밀번호" in text or "password" in text.lower()


def test_raw_upload_password_connection_uses_sshpass_and_hides_the_password(tmp_path):
    """호스트별 허용 호스트: 키 없이 ansible_password만 있으면 sshpass -e로 올리고 비밀번호는 로그/인자에 없다."""
    v = _bin_vars(tmp_path)
    v["ansible_ssh_private_key_file"] = ""
    v["ansible_password"] = "Sup3r-Secret-PW"
    res, _ = _run_raw_upload(tmp_path, v)
    text = res.stdout + res.stderr
    log = (tmp_path / "sshpass.log").read_text()
    assert "ENV=Sup3r-Secret-PW" in log and "Sup3r-Secret-PW" not in log.split("ARGS=")[1]
    assert "Sup3r-Secret-PW" not in text


# --- 엔드포인트 해석: Extra variables / group_vars(A) > OpenBao agents/*(B) > 역할 기본값 -------------------------
_EFFECTIVE_KEYS = ("o2_endpoint", "o2_org", "o2_ca_file", "rustfs_endpoint", "rustfs_bucket", "rustfs_region", "rustfs_ca_file")
_ENDPOINTS_O2 = {"controller_ingest_token": "ctl-token", "o2_endpoint": "https://o2.bao.invalid:5080",
                 "o2_org": "acme", "o2_ca_file": "/etc/pki/o2-ca.pem"}
_ENDPOINTS_RUSTFS = {"maintenance_access_key": "m-access", "rustfs_endpoint": "https://rfs.bao.invalid:9000",
                     "rustfs_region": "kr-1", "rustfs_ca_file": "/etc/pki/rfs-ca.pem"}


def _effective(tmp_path, openbao, extra_vars=None, host="good"):
    dump = {"name": "Dump effective endpoints", "check_mode": False, "ansible.builtin.copy": {
        "content": "{{ {" + ", ".join("'%s': %s" % (k, k) for k in _EFFECTIVE_KEYS) + "} | to_json }}",
        "dest": f"{tmp_path}/eff.json", "mode": "0600"}}
    res, _ = _run_input_tasks(tmp_path, [host], openbao, extra_vars=extra_vars, extra_tasks=[dump],
                              with_backup_defaults=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads((tmp_path / "eff.json").read_text())


def test_endpoints_come_from_openbao_when_not_set_elsewhere(tmp_path, openbao):
    _FakeOpenBao.routes["/v1/secret/data/agents/openobserve"] = _kv(_ENDPOINTS_O2)
    _FakeOpenBao.routes["/v1/secret/data/agents/rustfs"] = _kv(_ENDPOINTS_RUSTFS)
    eff = _effective(tmp_path, openbao)
    assert eff == {"o2_endpoint": "https://o2.bao.invalid:5080", "o2_org": "acme", "o2_ca_file": "/etc/pki/o2-ca.pem",
                   "rustfs_endpoint": "https://rfs.bao.invalid:9000", "rustfs_bucket": "backup-prod-good",
                   "rustfs_region": "kr-1", "rustfs_ca_file": "/etc/pki/rfs-ca.pem"}


def test_extra_vars_win_over_openbao_endpoints(tmp_path, openbao):
    _FakeOpenBao.routes["/v1/secret/data/agents/openobserve"] = _kv(_ENDPOINTS_O2)
    _FakeOpenBao.routes["/v1/secret/data/agents/rustfs"] = _kv(_ENDPOINTS_RUSTFS)
    eff = _effective(tmp_path, openbao, extra_vars={"o2_endpoint": "https://o2.extra.invalid:5080",
                                                    "rustfs_bucket": "extra-bucket"})
    assert eff["o2_endpoint"] == "https://o2.extra.invalid:5080" and eff["rustfs_bucket"] == "extra-bucket"
    assert eff["o2_org"] == "acme" and eff["rustfs_endpoint"] == "https://rfs.bao.invalid:9000"


def test_endpoint_defaults_apply_when_openbao_has_none(tmp_path, openbao):
    eff = _effective(tmp_path, openbao)
    assert eff == {"o2_endpoint": "", "o2_org": "default", "o2_ca_file": "", "rustfs_endpoint": "",
                   "rustfs_bucket": "backup-prod-good", "rustfs_region": "", "rustfs_ca_file": ""}


def test_bucket_follows_the_naming_rule_per_host_and_can_be_overridden_in_the_host_kv(tmp_path, openbao):
    _FakeOpenBao.routes["/v1/secret/data/hosts/special/agents"] = _kv(dict(REQUIRED, rustfs_bucket="backup-prod-special-a"))
    assert _effective(tmp_path, openbao, host="special")["rustfs_bucket"] == "backup-prod-special-a"
    assert _effective(tmp_path, openbao, host="good")["rustfs_bucket"] == "backup-prod-good"


def test_bucket_prefix_variable_changes_the_naming_rule(tmp_path, openbao):
    eff = _effective(tmp_path, openbao, extra_vars={"rustfs_bucket_prefix": "backup-stg"})
    assert eff["rustfs_bucket"] == "backup-stg-good"


def test_shared_openbao_bucket_key_is_ignored(tmp_path, openbao):
    """공용 agents/rustfs의 rustfs_bucket은 더는 쓰지 않는다 — 호스트별 버킷만 허용(실수로 공용 버킷에 쌓이지 않게)."""
    _FakeOpenBao.routes["/v1/secret/data/agents/rustfs"] = _kv(dict(_ENDPOINTS_RUSTFS, rustfs_bucket="shared-bucket"))
    assert _effective(tmp_path, openbao)["rustfs_bucket"] == "backup-prod-good"


def _run_mon020(tmp_path, hosts):
    tasks = yaml.safe_load((ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))[:2]
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "tasks": tasks}]))
    (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": hosts}}))
    return subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)


def test_password_auth_exception_is_allowed_only_for_hosts_that_opt_in_in_their_kv(tmp_path):
    res = _run_mon020(tmp_path, {
        "optin": {"_is_already_provisioned": False, "_host_kv_dict": {"host_agents_allow_password_auth": True}},
        "optin_str": {"_is_already_provisioned": False, "_host_kv_dict": {"host_agents_allow_password_auth": "true"}},
        "optout": {"_is_already_provisioned": False, "_host_kv_dict": {"host_agents_allow_password_auth": False}},
        "nokv": {"_is_already_provisioned": False}})
    text = res.stdout + res.stderr
    assert "optin: 접속 계정" not in text and "optin_str: 접속 계정" not in text
    assert "optout: 접속 계정으로 SSH 접속할 수 없는" in text and "nokv: 접속 계정으로 SSH 접속할 수 없는" in text
    assert "host_agents_allow_password_auth" in text


def test_password_auth_exception_leaves_an_audit_warning_only_where_it_applies(tmp_path):
    res = _run_mon020(tmp_path, {
        "optin": {"_is_already_provisioned": False, "_host_kv_dict": {"host_agents_allow_password_auth": True}},
        "keyed": {"_is_already_provisioned": True, "_host_kv_dict": {"host_agents_allow_password_auth": True}}})
    text = res.stdout + res.stderr
    assert res.returncode == 0, text
    assert "PASSWORD-AUTH-EXCEPTION optin" in text and "PASSWORD-AUTH-EXCEPTION keyed" not in text
