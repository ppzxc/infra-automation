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
    host_agents_os_probe_cmd,
    host_agents_parse_os_probe,
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
    assert _role_names(agents) == ["monitoring"]


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
    blocks = {b["name"]: set(b["tags"]) for b in main[2:]}
    assert blocks == {
        "Install agents and clean legacy exporter": {"agents_install", "otel"},
        "Apply otelcol configuration": {"agents_config", "otel"},
        "Enable otelcol service": {"agents_install", "otel"},
    }
    inner = {t["name"].split("]")[0].lstrip("[") for b in main[2:] for t in b["block"] if "name" in t}
    assert {"MON-011", "MON-001", "MON-003"} <= inner
    config = next(b for b in main if b["name"] == "Apply otelcol configuration")
    assert config["block"][0]["name"].startswith("[MON-004]")
    agents = _plays("host_agents.yml")[1]
    assert agents["roles"][0]["tags"] == ["otel"]


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

def _probe(os_release="", redhat="", uname="x86_64", noise=""):
    return (f"{noise}\n__HOST_AGENTS_OS_RELEASE__\n{os_release}\n"
            f"__HOST_AGENTS_REDHAT_RELEASE__\n{redhat}\n__HOST_AGENTS_UNAME_M__\n{uname}\n")


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


def _resolve(**kv):
    return host_agents_resolve_inputs(dict(REQUIRED, **kv), STANDARD, SECURITY, MANDATORY, "hosts/h/agents")


def test_absent_overrides_mean_git_standard_only():
    res = _resolve()
    assert res["errors"] == []
    assert res["otel_logs"] == [
        {"path": "/var/log/messages", "stream": "system_logs"},
        {"path": "/var/log/secure", "stream": "security_logs"},
        {"path": "/var/log/audit/audit.log", "stream": "security_logs"},
        {"path": "/var/log/cron*", "stream": "system_logs"}]
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
SHARED_RUSTFS = {"maintenance_key": "shared-rfs"}


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


def _run_input_tasks(tmp_path, hosts, addr, check=False, extra_vars=None, token="tok", extra_tasks=None):
    role_vars = {}
    for f in ("defaults", "vars"):
        role_vars.update(yaml.safe_load((ROLE / f / "main.yml").read_text(encoding="utf-8")))
    tasks = [{"ansible.builtin.import_tasks": str(ROLE / "tasks" / "agents_input.yml")}]
    tasks.append({
        "name": "Dump result",
        "ansible.builtin.copy": {
            "content": "{{ {'inputs': host_agents_inputs, 'secrets': host_agents_secrets,"
                       " 'shared': host_agents_shared_secrets} | to_json }}",
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
    assert out["good"]["inputs"]["otel_logs"][-1] == {"path": "/opt/app/*.log", "stream": "app_logs"}
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
    assert "fresh: site.yml로 프로비저닝되지 않은" in text and "undef: site.yml로 프로비저닝되지 않은" in text
    assert "ready: site.yml" not in text and "site.yml을 먼저 실행" in text
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
