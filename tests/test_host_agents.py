"""Host Agents entry point (ADR-0006, Spec #38 / Ticket-2; Spec #511 / Ticket-14).

* host_agents.yml / site.yml / maintenance.yml structure.
* OS probe classification (sample os-release / redhat-release / uname outputs).
* Agents input resolution: the real ``agents_input.yml`` task file is executed with
  ``ansible-playbook`` against the shared fake OpenBao (tests/openbao_fake.py), in normal and check mode.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from openbao_fake import APPROLE_TOKEN

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from host_agents import (  # noqa: E402
    host_agents_glob_regex,
    host_agents_os_probe_cmd,
    host_agents_parse_os_probe,
    host_agents_resource_attributes,
    host_agents_resolve_inputs,
    host_agents_secrets,
    host_agents_tcpcheck_targets,
)

PLAYBOOKS = ROOT_DIR / "playbooks"
ROLE = ROOT_DIR / "roles" / "monitoring"
IMPORT = "ansible.builtin.import_playbook"


# --------------------------------------------------------------------------
# Playbook structure
# --------------------------------------------------------------------------

HOST_AGENTS_PATTERN = r"{{ target_hosts | default('servers') | regex_replace('\s*,\s*', ':') }}:&servers:!host_agents_excluded"


def _list_hosts(tmp_path, playbook, inventory, *extra):
    inv = tmp_path / "inv.yml"
    inv.write_text(yaml.safe_dump(inventory))
    res = subprocess.run(["ansible-playbook", "-i", str(inv), str(PLAYBOOKS / playbook), "--list-hosts", *extra],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    plays = res.stdout.split("play #")[1:]
    return [sorted(l.strip() for l in p.split("hosts (", 1)[1].splitlines()[1:] if l.strip() and ":" not in l)
            for p in plays]


_EXCLUDED_INV = {"all": {"children": {
    "servers": {"hosts": {"ns0001": {}, "ns0002": {}, "ns0003": {}}},
    "host_agents_excluded": {"hosts": {"ns0002": {}}}}}}


@pytest.mark.parametrize("playbook", ["host_agents.yml", "host_agents_maintenance.yml"])
def test_hosts_in_host_agents_excluded_are_never_targeted(tmp_path, playbook):
    """host_agents_excluded 그룹의 호스트는 Deploy·Config·Repo Maintenance 모든 play(연결 해석·정리 포함)에서 빠진다."""
    plays = _list_hosts(tmp_path, playbook, _EXCLUDED_INV)
    assert plays and all(hosts == ["ns0001", "ns0003"] for hosts in plays)
    # target_hosts로 직접 지정해도 제외가 우선한다.
    plays = _list_hosts(tmp_path, playbook, _EXCLUDED_INV, "-e", "target_hosts=ns0002")
    assert all(hosts == [] for hosts in plays)


@pytest.mark.parametrize("playbook", ["host_agents.yml", "host_agents_maintenance.yml"])
@pytest.mark.parametrize("target", ["ns0001,ns0002,ns0003,lb01", "ns0001, ns0002, ns0003, lb01",
                                    "ns0001:ns0002:ns0003:lb01"])
def test_multi_host_target_keeps_the_servers_and_exclusion_filter_on_every_host(tmp_path, playbook, target):
    """Survey에 쉼표로 여러 대를 넣어도 모든 호스트에 servers 교집합·제외가 걸린다.

    쉼표가 있으면 Ansible은 패턴을 쉼표로만 나누므로, 뒤에 ':&servers:!host_agents_excluded'를 이어 붙이면
    마지막 호스트에만 필터가 붙어 그 호스트는 빠지고 앞 호스트는 제외 그룹이어도 대상이 된다(#266)."""
    inv = {"all": {"children": {**_EXCLUDED_INV["all"]["children"], "loadbalancers": {"hosts": {"lb01": {}}}}}}
    plays = _list_hosts(tmp_path, playbook, inv, "-e", json.dumps({"target_hosts": target}))  # Semaphore Survey와 같은 JSON
    assert plays and all(hosts == ["ns0001", "ns0003"] for hosts in plays)


@pytest.mark.parametrize("playbook", ["host_agents.yml", "host_agents_maintenance.yml"])
def test_inventory_without_the_excluded_group_targets_every_server(tmp_path, playbook):
    """그룹을 정의하지 않은 인벤토리(기존 Semaphore 인벤토리)도 그대로 servers 전체를 대상으로 한다."""
    inv = {"all": {"children": {"servers": {"hosts": {"ns0001": {}, "ns0002": {}}}}}}
    plays = _list_hosts(tmp_path, playbook, inv)
    assert plays and all(hosts == ["ns0001", "ns0002"] for hosts in plays)


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
        assert p["vars"]["connection_hosts"] == HOST_AGENTS_PATTERN
    agents = plays[1]
    assert agents["hosts"] == HOST_AGENTS_PATTERN
    assert agents["serial"] == "25%"
    assert agents["gather_facts"] is False
    assert _role_names(agents) == ["monitoring", "backup"]


@pytest.mark.parametrize("tasks_file", ["main.yml", "legacy.yml"])
def test_every_otel_block_is_gated_by_enable_otelcol(tasks_file):
    """otel 태그 블록은 모두 enable_otelcol로 막힌다 — Host Agents Backup Only 호스트에는 otelcol 단계가 하나도 돌지 않는다."""
    tasks = yaml.safe_load((ROLE / "tasks" / tasks_file).read_text(encoding="utf-8"))
    otel = [t for t in tasks if "otel" in (t.get("tags") or []) and "always" not in (t.get("tags") or [])]
    assert otel
    for t in otel:
        when = t.get("when") or []
        assert any("enable_otelcol" in w for w in ([when] if isinstance(when, str) else when)), t["name"]


def test_enable_otelcol_follows_backup_only_group_membership():
    default = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))["enable_otelcol"]
    assert default == "{{ 'host_agents_backup_only' not in group_names }}"


def test_shared_connection_plays_accept_connection_hosts_override():
    for name in ("resolve_connection.yml", "cleanup_connection.yml"):
        hosts = yaml.safe_load((PLAYBOOKS / "common" / name).read_text(encoding="utf-8"))[0]["hosts"]
        assert hosts == "{{ connection_hosts | default(target_hosts | default('servers:loadbalancers')) }}"


@pytest.mark.parametrize("playbook", ["site.yml"])
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

def _probe(os_release="", redhat="", uname="x86_64", noise="", machine_id="", timezone=""):
    return (f"{noise}\n__HOST_AGENTS_OS_RELEASE__\n{os_release}\n"
            f"__HOST_AGENTS_REDHAT_RELEASE__\n{redhat}\n__HOST_AGENTS_MACHINE_ID__\n{machine_id}\n"
            f"__HOST_AGENTS_TIMEZONE__\n{timezone}\n"
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


@pytest.mark.parametrize("timezone, expected", [
    ("/usr/share/zoneinfo/Asia/Seoul", "Asia/Seoul"),                      # systemd family: /etc/localtime link target
    ("/usr/share/zoneinfo/Etc/UTC", "Etc/UTC"),
    ("/usr/share/zoneinfo/America/Argentina/Buenos_Aires", "America/Argentina/Buenos_Aires"),
    ('# The time zone of the machine\nZONE="Asia/Seoul"\nUTC=true\nARC=false', "Asia/Seoul"),   # EL6 /etc/sysconfig/clock
    ("ZONE=UTC", "UTC"),
    ("/usr/share/zoneinfo/Asia/Seoul\nZONE=\"Europe/Paris\"", "Asia/Seoul"),   # the link wins
    ("", ""),                                                              # EL6 copy of the file, no clock file
    ("/etc/localtime-weird", ""),
    ('ZONE="../../etc/passwd"', ""),                                       # never trust a path-like value
    ('ZONE="Asia/Seoul; rm -rf /"', ""),
])
def test_os_probe_reads_the_host_timezone_from_localtime_link_or_sysconfig_clock(timezone, expected):
    os_release, redhat = (ROCKY9, "Rocky Linux release 9.3 (Blue Onyx)")
    assert host_agents_parse_os_probe(_probe(os_release=os_release, redhat=redhat, timezone=timezone))["timezone"] == expected


def test_os_probe_without_a_timezone_section_yields_empty_timezone():
    out = "__HOST_AGENTS_OS_RELEASE__\n%s\n__HOST_AGENTS_UNAME_M__\nx86_64\n" % UBUNTU
    assert host_agents_parse_os_probe(out)["timezone"] == ""


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
REQUIRED = {"ingest_token": "tok-o2-ingest-0001", "rustfs_access_key": "rfs-access-0002",
            "rustfs_secret_key": "rfs-secret-0003", "restic_password": "restic-pass-0004"}


SERVICES = {"/var/log/messages": "syslog", "/var/log/secure": "auth", "/var/log/audit/audit.log": "audit",
            "/var/log/cron*": "cron"}


_SECRET_KEYS = set(REQUIRED) | {"webhook_secret"}
_LABELS = {"otel_exclude_logs": "agents.otel.exclude_logs", "backup_exclude_paths": "agents.backup.exclude_paths",
           "otel_app_telemetry": "agents.otel.app_telemetry"}


def _stored(flat):
    """테스트가 쓰는 평면 키(`backup_extra_paths`, `otel_*`, 비밀)를 저장 형태(agents 절, 비밀 문서)로 나눈다."""
    agents, secrets = {}, {}
    for key, value in flat.items():
        if key in _SECRET_KEYS or key == "github_webhook_secret":
            secrets["webhook_secret" if key == "github_webhook_secret" else key] = value
            continue
        for prefix, section in (("backup_", "backup"), ("otel_", "otel"), ("github_webhook_", "github_webhook")):
            if key.startswith(prefix):
                agents.setdefault(section, {})[key[len(prefix):]] = value
                break
    return agents, secrets


def _filter(flat, *args, **kwargs):
    agents, secrets = _stored(flat)
    return host_agents_resolve_inputs(agents, secrets, *args, **kwargs)


def _resolve(**kv):
    return _filter(dict(REQUIRED, **kv), STANDARD, SECURITY, MANDATORY, "inventory/assets/h", service_map=SERVICES)


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
    assert res["backup_sqlite_snapshots"] == []
    assert res["otel_container_logs"] is False
    assert res["otel_app_telemetry"] is False


def test_app_telemetry_flag_is_opt_in_and_accepts_string_booleans():
    assert _resolve(otel_app_telemetry="true")["otel_app_telemetry"] is True
    assert _resolve(otel_app_telemetry=True)["otel_app_telemetry"] is True
    assert _resolve(otel_app_telemetry="false")["otel_app_telemetry"] is False


def test_app_telemetry_flag_that_is_not_boolean_fails_naming_the_key():
    res = _resolve(otel_app_telemetry="maybe")
    assert len(res["errors"]) == 1 and "agents.otel.app_telemetry" in res["errors"][0] and "maybe" in res["errors"][0]


def test_container_logs_flag_is_opt_in_and_accepts_string_booleans():
    assert _resolve(otel_container_logs="true")["otel_container_logs"] is True
    assert _resolve(otel_container_logs=True)["otel_container_logs"] is True
    assert _resolve(otel_container_logs="false")["otel_container_logs"] is False


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
    res = _filter(dict(REQUIRED, **{missing: blank}), STANDARD, SECURITY, MANDATORY, "inventory/assets/h")
    assert len(res["errors"]) == 1 and missing in res["errors"][0] and "secrets/assets/<ns>/agents" in res["errors"][0]


def test_otelcol_only_keys_are_not_required_when_otel_is_disabled():
    kv = {k: v for k, v in REQUIRED.items() if k != "ingest_token"}
    assert _filter(kv, STANDARD, SECURITY, MANDATORY, "p", otel_enabled=False)["errors"] == []
    res = _filter(dict(kv, restic_password=""), STANDARD, SECURITY, MANDATORY, "p", otel_enabled=False)
    assert res["errors"] == ["필수 키 누락: restic_password (OpenBao secrets/assets/<ns>/agents)"]


def test_secrets_are_never_part_of_the_merged_result():
    res = _resolve()
    assert not any(v in json.dumps(res) for v in REQUIRED.values())
    assert not set(REQUIRED) & set(res)
    assert host_agents_secrets(dict(REQUIRED, webhook_secret="hook-0009", extra="/x")) == REQUIRED


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
    assert _LABELS[kv_key] in res["errors"][0] and item in res["errors"][0] and "inventory/assets/h" in res["errors"][0]


@pytest.mark.parametrize("kv", [
    {"otel_docker_metrics": "maybe"}, {"otel_container_logs": "maybe"}, {"otel_app_telemetry": "maybe"}, {"otel_exclude_logs": "not-json"}, {"otel_exclude_logs": {"a": 1}},
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
    res = _filter(dict(REQUIRED), STANDARD, SECURITY, MANDATORY, "p", {"rustfs": shared})
    assert res["errors"] == ["공유 설정 누락 또는 url 없음: inventory/services/rustfs"]


def test_json_encoded_string_lists_are_accepted():
    assert _resolve(backup_extra_paths='["/data"]')["backup_paths"] == MANDATORY + ["/data"]


# --------------------------------------------------------------------------
# agents_input.yml executed under ansible-playbook against a fake OpenBao
# --------------------------------------------------------------------------

GOOD_AGENTS = {"otel": {"docker_metrics": True, "extra_logs": ["/opt/app/*.log"]}}
BAD_EXCLUDE_AGENTS = {"backup": {"exclude_paths": ["/etc"]}}
NO_INGEST = {k: v for k, v in REQUIRED.items() if k != "ingest_token"}


def _host(fake, name, secrets=REQUIRED, agents=None):
    """Asset 문서(agents 절)와 에이전트 비밀을 가짜 서버에 올린다. 스키마 검사가 켜져 있어 모양이 틀리면 여기서 실패한다."""
    fake.set("inventory", "assets/" + name, dict({"description": "Fake host " + name}, **({"agents": agents} if agents else {})))
    if secrets is not None:
        fake.set("secrets", "assets/%s/agents" % name, secrets)


@pytest.fixture
def bao(fake_openbao):
    f = fake_openbao
    _host(f, "good", agents=GOOD_AGENTS)
    _host(f, "bare")
    _host(f, "badexclude", agents=BAD_EXCLUDE_AGENTS)
    _host(f, "missing", {k: v for k, v in REQUIRED.items() if k != "restic_password"})
    _host(f, "backuponly", NO_INGEST)
    _host(f, "notoken", NO_INGEST)
    _host(f, "nokv", None)
    _host(f, "denied")
    f.deny("secrets", "assets/denied/agents")
    # tcpcheck 대상 해석(inventory/assets/<ns>/endpoints): 주소·포트는 ssh Endpoint에서
    for name, address, port in (("svc-std", "192.0.2.10", 22), ("svc-odd", "192.0.2.11", 8487)):
        _host(f, name, None)
        f.set("inventory", "assets/%s/endpoints" % name, {"ssh": {"protocol": "ssh", "address": address, "port": port,
                                                                   "credential": "admin01"}})
    _host(f, "svc-noep", None)
    _host(f, "svc-denied", None)
    f.deny("inventory", "assets/svc-denied/endpoints")
    return f


@pytest.fixture
def openbao(bao):
    return bao.url


def _declared_pattern(mount, doc):
    """index.yml 패턴처럼 `+`가 경로 한 마디에 맞는 선언 패턴 가운데 이 문서를 덮는 것을 찾는다."""
    declared = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))["monitoring_openbao_required"]
    path = "%s/%s" % (mount, doc)
    return next((pat for pat in declared if re.fullmatch(pat.replace("+", "[^/]+"), path)), None)


def _assert_reads_are_declared(fake):
    """요청 기록 단언: 역할이 읽은 문서는 모두 monitoring_openbao_required 패턴 안에 있다."""
    undeclared = [(r.mount, r.doc) for r in fake.reads() if r.mount and _declared_pattern(r.mount, r.doc) is None]
    assert undeclared == [], "선언 밖 문서를 읽었다: %s" % undeclared


def _run_input_tasks(tmp_path, hosts, addr, check=False, extra_vars=None, token=APPROLE_TOKEN, extra_tasks=None,
                     with_backup_defaults=False, environment="production", backup_only_hosts=()):
    role_vars = {}
    for f in ("defaults", "vars"):
        role_vars.update(yaml.safe_load((ROLE / f / "main.yml").read_text(encoding="utf-8")))
    if environment is not None:
        role_vars["host_agents_environment"] = environment
    if with_backup_defaults:
        role_vars.update(yaml.safe_load((ROLE.parent / "backup" / "defaults" / "main.yml").read_text(encoding="utf-8")))
    tasks = [{"ansible.builtin.import_tasks": str(ROLE / "tasks" / "agents_input.yml")}]
    tasks.append({
        "name": "Dump result",
        "ansible.builtin.copy": {
            "content": "{{ {'inputs': host_agents_inputs, 'secrets': host_agents_secrets,"
                       " 'services': host_agents_services, 'attrs': host_agents_resource_attrs} | to_json }}",
            "dest": f"{tmp_path}/out-{{{{ inventory_hostname }}}}.json", "mode": "0600"},
        "check_mode": False,
    })
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "become": False,
        "vars": role_vars, "tasks": tasks + (extra_tasks or [])}]))
    inv = {"all": {"hosts": {h: {"_vault_token": token} for h in hosts},
                   "children": {"host_agents_backup_only": {"hosts": {h: {} for h in backup_only_hosts}}}}}
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")]
    if check:
        cmd.append("--check")
    for k, v in (extra_vars or {}).items():
        cmd += ["-e", json.dumps({k: v})]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR,
                         env=dict(os.environ, VAULT_ADDR=addr, ANSIBLE_NOCOLOR="1"))
    return res, {h: json.loads((tmp_path / f"out-{h}.json").read_text())
                 for h in hosts if (tmp_path / f"out-{h}.json").exists()}


@pytest.mark.parametrize("environment, ok", [(None, True), ("prod", False), ("production", True), ("staging", True)])
@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_environment_is_a_role_default_validated_before_any_change_in_both_modes(tmp_path, openbao, check, environment, ok):
    res, out = _run_input_tasks(tmp_path, ["bare"], openbao, check=check, environment=environment)
    assert (res.returncode == 0) is ok and (set(out) == {"bare"}) is ok
    if ok:
        assert out["bare"]["attrs"]["attributes"]["deployment.environment.name"] == (environment or "production")
    else:
        assert "bare: 리소스 속성 검증 실패" in res.stdout + res.stderr and "host_agents_environment" in res.stdout + res.stderr


def test_environment_is_never_read_from_openbao(tmp_path, bao, openbao):
    bao.set("secrets", "assets/bare/agents", dict(REQUIRED))
    res, out = _run_input_tasks(tmp_path, ["bare"], openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not [r for r in bao.reads() if "environment" in (r.doc or "")]


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_agents_resolution_under_ansible(tmp_path, bao, openbao, check):
    hosts = ["good", "bare", "badexclude", "missing"]
    res, out = _run_input_tasks(tmp_path, hosts, openbao, check=check)
    text = res.stdout + res.stderr
    assert set(out) == {"good", "bare"}                       # invalid hosts fail before any later task
    assert "badexclude: Host Agents 입력 검증 실패" in text and "agents.backup.exclude_paths" in text and "/etc" in text
    assert "inventory/assets/badexclude" in text
    assert "missing: OpenBao 조회 실패 또는 필수 키 누락" in text and "secrets/assets/+/agents.restic_password" in text
    assert res.returncode != 0
    assert out["good"]["secrets"] == REQUIRED
    assert out["good"]["services"] == {"openobserve": {"url": "https://o2.example.test", "org": "fake-org"},
                                       "rustfs": {"url": "https://s3.example.test", "region": "fake-region-1"}}
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
    _assert_reads_are_declared(bao)
    assert {r.namespace for r in bao.reads()} == {"infra"} and {r.mount for r in bao.reads()} <= {"inventory", "secrets"}


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_backup_only_host_does_not_need_the_otelcol_ingest_token(tmp_path, openbao, check):
    """Host Agents Backup Only 호스트는 ingest_token 없이 통과하고, 그룹 밖 호스트는 같은 비밀로 실패한다."""
    res, out = _run_input_tasks(tmp_path, ["backuponly", "notoken"], openbao, check=check,
                                backup_only_hosts=["backuponly"])
    text = res.stdout + res.stderr
    assert set(out) == {"backuponly"} and res.returncode != 0
    assert "notoken: Host Agents 입력 검증 실패" in text and "필수 키 누락: ingest_token" in text
    assert out["backuponly"]["secrets"] == NO_INGEST


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_openbao_error_fails_the_host_in_normal_and_check_mode(tmp_path, openbao, check):
    res, out = _run_input_tasks(tmp_path, ["denied"], openbao, check=check)
    text = res.stdout + res.stderr
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in text and "403" in text and "secrets/assets/denied/agents" in text


@pytest.mark.parametrize("check", [False, True], ids=["normal", "check"])
def test_unreachable_openbao_fails_the_host(tmp_path, check):
    res, out = _run_input_tasks(tmp_path, ["good"], "http://127.0.0.1:1", check=check)
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in res.stdout + res.stderr


def test_missing_agents_secret_document_fails_without_a_fallback(tmp_path, openbao):
    res, out = _run_input_tasks(tmp_path, ["nokv"], openbao)
    assert res.returncode != 0 and out == {}
    assert "secrets/assets/+/agents(문서 없음)" in res.stdout + res.stderr


def test_missing_vault_credentials_fail_instead_of_previewing_incomplete_config(tmp_path, openbao):
    res, out = _run_input_tasks(tmp_path, ["good"], openbao, token="", check=True)
    assert res.returncode != 0 and out == {}
    assert "OpenBao 조회 실패" in res.stdout + res.stderr


def test_missing_shared_service_document_fails_the_host(tmp_path, bao, openbao):
    bao.remove("inventory", "services/rustfs")
    res, out = _run_input_tasks(tmp_path, ["good"], openbao)
    assert res.returncode != 0 and out == {}
    assert "inventory/services/rustfs(문서 없음)" in res.stdout + res.stderr


def test_the_controller_ingest_document_is_only_required_where_the_inventory_event_runs(tmp_path, bao, openbao):
    bao.remove("secrets", "services/openobserve/ingest")
    res, out = _run_input_tasks(tmp_path, ["good"], openbao)
    assert res.returncode != 0 and "secrets/services/openobserve/ingest(문서 없음)" in res.stdout + res.stderr
    res, out = _run_input_tasks(tmp_path, ["good"], openbao, extra_vars={"backup_inventory_event_enabled": False})
    assert res.returncode == 0, res.stdout + res.stderr


def test_the_openbao_fixture_seam_answers_without_any_network(tmp_path, fake_openbao):
    docs = {"inventory/assets/good": {"description": "Fake host good"},
            "secrets/assets/good/agents": dict(REQUIRED),
            "inventory/services/openobserve": {"url": "https://o2.example.test"},
            "inventory/services/rustfs": {"url": "https://s3.example.test"},
            "secrets/services/openobserve/ingest": {"username": "fake-ingest", "password": "fake-pw-0014"}}
    res, out = _run_input_tasks(tmp_path, ["good"], "http://127.0.0.1:1", extra_vars={"openbao_fixture": docs})
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["good"]["secrets"] == REQUIRED and out["good"]["inputs"]["errors"] == []
    assert fake_openbao.requests == []


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
    assert "ready: 접속 계정" not in text and "access.admin_credentials" in text and "site.yml" in text
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


def test_home_log_dirs_expose_only_the_directories_of_logs_under_home():
    """otelcol은 ProtectHome 아래서 돈다. /home 아래 수집 경로는 그 디렉터리만 읽기 전용으로 노출한다."""
    res = _resolve(otel_extra_logs=[
        {"path": "/home/chakramax/log/maxsvr.log", "service": "a"}, {"path": "/home/chakramax/log/run_*.out", "service": "b"},
        "/opt/app/*.log", "/home/x.log", "/home/u/../etc/*.log"])
    assert res["errors"] == []
    assert res["otel_home_log_dirs"] == ["/home/chakramax/log"]
    assert _resolve()["otel_home_log_dirs"] == []


def test_switch_and_fortigate_syslog_paths_never_overlap_and_route_to_their_own_streams():
    """Spec #282: switch syslog stays on system_logs, firewall syslog goes to security_logs/fortigate-syslog.

    The firewall files live one directory deeper than the switch glob reaches, so no line is collected twice."""
    switch = {"path": "/var/log/remote/*/*.log", "stream": "system_logs", "service": "switch-syslog"}
    fw = {"path": "/var/log/remote/fortigate/*/*.log", "stream": "security_logs", "service": "fortigate-syslog"}
    res = _resolve(otel_extra_logs=[switch, fw])
    assert res["errors"] == []
    extra = {l["path"]: (l["stream"], l["service"]) for l in res["otel_logs"][len(STANDARD):]}
    assert extra == {switch["path"]: ("system_logs", "switch-syslog"), fw["path"]: ("security_logs", "fortigate-syslog")}
    # '*' does not cross '/', so the switch glob depth (2) cannot reach a firewall file (depth 3)
    assert switch["path"].count("/") < fw["path"].count("/")


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

def _render_config(tmp_path, _inventory=None, **over):
    vars_ = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    vars_.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8")))
    vars_.update({
        "inventory_hostname": "h1", "host_agents_os_type": "linux", "host_agents_os_description": "Rocky Linux 9",
        "host_agents_journald": False, "o2_endpoint": "https://o2.example:5080", "o2_org": "default",
        "host_agents_secrets": {"ingest_token": "s3cr3t-token"},
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
    inv = "localhost,"
    if _inventory:
        (tmp_path / "inv.yml").write_text(yaml.safe_dump(_inventory))
        inv = str(tmp_path / "inv.yml")
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(tmp_path / "vars.yml")],
        "tasks": [{"ansible.builtin.template": {"src": str(ROLE / "templates" / "otelcol-contrib.yaml.j2"),
                                                 "dest": str(tmp_path / "config.yaml")}},
                  {"ansible.builtin.template": {"src": str(ROLE / "templates" / "secrets.env.j2"),
                                                 "dest": str(tmp_path / "secrets.env")}}]}]))
    res = subprocess.run(["ansible-playbook", "-i", inv, str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    return yaml.safe_load((tmp_path / "config.yaml").read_text()), (tmp_path / "config.yaml").read_text()


def test_config_routes_logs_by_stream_to_otlphttp_with_stream_name(tmp_path):
    cfg, _ = _render_config(tmp_path)
    for stream in ("security_logs", "system_logs", "app_logs", "backup_logs", "host_status_logs"):
        exp = cfg["exporters"][f"otlphttp/{stream}"]
        assert exp["endpoint"] == "https://o2.example:5080/api/default"
        assert exp["headers"]["stream-name"] == stream
        assert exp["headers"]["Authorization"] == "Basic ${env:O2_BASIC_AUTH}"
        q = exp["sending_queue"]
        assert q["storage"] == "file_storage" and q["sizer"] == "bytes" and q["block_on_overflow"] is True
        assert exp["retry_on_failure"]["max_elapsed_time"] == 0
        assert cfg["service"]["pipelines"][f"logs/{stream}"]["exporters"] == [f"otlphttp/{stream}"]
    assert {c["pipelines"][0] for c in cfg["connectors"]["routing/logs"]["table"]} == {
        "logs/security_logs", "logs/system_logs", "logs/backup_logs", "logs/host_status_logs"}
    assert cfg["connectors"]["routing/logs"]["default_pipelines"] == ["logs/app_logs"]
    assert not any(k.startswith("otlp/") for k in cfg["exporters"])            # no legacy gRPC exporter


def test_config_filelog_checkpoints_and_start_at_end(tmp_path):
    cfg, _ = _render_config(tmp_path)
    for stream in ("security_logs", "system_logs", "app_logs"):
        rcv = cfg["receivers"][f"filelog/{stream}"]
        assert rcv["storage"] == "file_storage" and rcv["start_at"] == "end"
        assert rcv["attributes"]["log_type"] == stream
    assert cfg["extensions"]["file_storage"]["compaction"]["on_rebound"] is True
    # app_logs has no known format: only service.name is stamped (resource-level add), never parsed (ADR-0008).
    # Envelope Parsing of the standard sources is covered by test_envelope_parsing.py; no operator rewrites the body there either.
    ops = cfg["receivers"]["filelog/app_logs"]["operators"]
    assert {op["type"] for op in ops} == {"add"} and {op["field"] for op in ops} == {'resource["service.name"]'}


def test_config_stamps_service_name_per_log_file_group_keeping_receiver_ids(tmp_path):
    cfg, _ = _render_config(tmp_path)
    # the file_storage checkpoint key is the receiver id: it must stay one receiver per stream
    assert {k for k in cfg["receivers"] if k.startswith("filelog/")} == {
        "filelog/security_logs", "filelog/system_logs", "filelog/app_logs", "filelog/backup_logs",
        "filelog/host_status_logs"}
    ops = {op["value"]: op["if"] for op in cfg["receivers"]["filelog/security_logs"]["operators"]
           if op["type"] == "add" and op["field"] == 'resource["service.name"]'}
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


def test_config_host_status_logs_pipeline_parses_json_and_names_the_service_per_file(tmp_path):
    cfg, _ = _render_config(tmp_path)
    rcv = cfg["receivers"]["filelog/host_status_logs"]
    assert rcv["include"] == ["/var/log/host-agents/raid.jsonl", "/var/log/host-agents/time-sync.jsonl"]
    assert rcv["storage"] == "file_storage" and rcv["start_at"] == "end"
    assert rcv["attributes"]["log_type"] == "host_status_logs"
    op, *services = rcv["operators"]
    assert op["type"] == "json_parser" and op["parse_from"] == "body" and op["parse_to"] == "attributes"
    assert "preserve_to" not in op and op["timestamp"]["parse_from"] == "attributes.ts"
    assert services == [
        {"type": "add", "field": 'resource["service.name"]', "value": "raid",
         "if": 'attributes["log.file.path"] == "/var/log/host-agents/raid.jsonl"'},
        {"type": "add", "field": 'resource["service.name"]', "value": "timesync",
         "if": 'attributes["log.file.path"] == "/var/log/host-agents/time-sync.jsonl"'}]
    assert "filelog/host_status_logs" in cfg["service"]["pipelines"]["logs/in"]["receivers"]
    assert cfg["exporters"]["otlphttp/host_status_logs"]["headers"]["stream-name"] == "host_status_logs"


def test_config_metrics_pipeline_is_separate_droppable_and_60s(tmp_path):
    cfg, _ = _render_config(tmp_path)
    assert cfg["receivers"]["hostmetrics"]["collection_interval"] == "60s"
    assert set(cfg["receivers"]["hostmetrics"]["scrapers"]) == {
        "cpu", "memory", "load", "filesystem", "disk", "network", "paging", "processes", "system"}
    metrics = cfg["service"]["pipelines"]["metrics/host"]
    assert metrics["exporters"] == ["otlphttp/metrics"]
    assert metrics["processors"] == ["memory_limiter", "resource/host", "resource/hostmetrics", "batch"]
    mq = cfg["exporters"]["otlphttp/metrics"]["sending_queue"]
    assert mq["block_on_overflow"] is False and "storage" not in mq


def test_config_optional_receivers_are_off_by_default(tmp_path):
    cfg, _ = _render_config(tmp_path)
    assert {"journald", "docker_stats", "otlp"}.isdisjoint(cfg["receivers"])
    on, _ = _render_config(tmp_path, host_agents_journald=True,
                           host_agents_inputs={"otel_docker_metrics": True, "otel_app_telemetry": True, "otel_logs": [
                               {"path": "/var/log/secure", "stream": "security_logs", "service": "auth"}]})
    assert {"journald", "docker_stats", "otlp"} <= set(on["receivers"])
    pipes = on["service"]["pipelines"]
    assert pipes["metrics/docker"]["receivers"] == ["docker_stats"]
    assert "resource/docker" in pipes["metrics/docker"]["processors"]
    # app metrics arriving over OTLP keep the service.name their SDK set: no service.name processor on that pipeline
    assert pipes["metrics/otlp"]["receivers"] == ["otlp"]
    assert not {"resource/hostmetrics", "resource/docker"} & set(pipes["metrics/otlp"]["processors"])
    assert {"metrics/docker", "metrics/otlp", "traces/otlp"}.isdisjoint(cfg["service"]["pipelines"])


def test_app_telemetry_switch_opens_only_the_otlp_http_receiver_on_all_addresses(tmp_path):
    on, _ = _render_config(tmp_path, host_agents_inputs={"otel_docker_metrics": False, "otel_app_telemetry": True,
                                                         "otel_logs": []})
    protocols = on["receivers"]["otlp"]["protocols"]
    assert list(protocols) == ["http"]                                  # no gRPC
    assert protocols["http"]["endpoint"].startswith("0.0.0.0:")
    pipes = on["service"]["pipelines"]
    assert pipes["traces/otlp"]["receivers"] == ["otlp"]
    assert pipes["traces/otlp"]["processors"] == ["memory_limiter", "resource/host", "tail_sampling", "batch"]
    assert pipes["traces/otlp"]["exporters"] == ["otlphttp/app_traces"]
    assert pipes["metrics/otlp"]["processors"] == ["memory_limiter", "resource/host", "filter/app_metrics", "batch"]
    assert pipes["metrics/otlp"]["exporters"] == ["otlphttp/metrics"]
    exp = on["exporters"]["otlphttp/app_traces"]
    assert exp["headers"]["stream-name"] == "app_traces"
    assert exp["sending_queue"]["enabled"] is True and "storage" not in exp["sending_queue"]   # memory queue
    assert "otlp" not in pipes["logs/in"]["receivers"]                  # OTLP logs are never exported


def test_switch_off_renders_no_otlp_receiver_traces_pipeline_or_trace_exporter(tmp_path):
    off, text = _render_config(tmp_path, otel_otlp_enabled=True)    # the retired role variable has no effect
    assert "otlp" not in off["receivers"] and "otlp" not in off["service"]["pipelines"]["logs/in"]["receivers"]
    assert not [p for p in off["service"]["pipelines"] if p.startswith("traces")]
    assert "otlphttp/app_traces" not in off["exporters"] and "app_traces" not in text


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
    assert consts["host_agents_log_streams"] == ["security_logs", "system_logs", "app_logs", "backup_logs",
                                                "host_status_logs"]


def _rsyslog_rule_task():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    flat = []

    def walk(items):
        for t in items:
            flat.append(t)
            walk(t.get("block", []))
    walk(main)
    return next(t for t in flat if t.get("name", "").startswith("[MON-068]"))


def _run_rsyslog_rule_removal(tmp_path, existing, check=False):
    rule = tmp_path / "00-host-agents-containers.conf"
    if existing:
        rule.write_text("if ($!CONTAINER_NAME != \"\") then {\n    stop\n}\n")
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"otel_rsyslog_container_rule_path": str(rule), "enable_otelcol": True},
        "tasks": [_rsyslog_rule_task()],
        "handlers": [{"name": "Restart rsyslog", "ansible.builtin.debug": {"msg": "RESTART-RSYSLOG"}}]}]
    pb = tmp_path / "rule.yml"
    pb.write_text(yaml.safe_dump(play))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check"] if check else [])
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    return rule, res.stdout


def test_obsolete_rsyslog_container_rule_is_removed_with_a_restart(tmp_path):
    rule, out = _run_rsyslog_rule_removal(tmp_path, existing=True)
    assert not rule.exists() and "RESTART-RSYSLOG" in out


def test_hosts_without_the_obsolete_rule_see_no_change(tmp_path):
    rule, out = _run_rsyslog_rule_removal(tmp_path, existing=False)
    assert not rule.exists() and "changed=0" in out and "RESTART-RSYSLOG" not in out


def test_rsyslog_rule_removal_check_mode_changes_nothing(tmp_path):
    rule, out = _run_rsyslog_rule_removal(tmp_path, existing=True, check=True)
    assert rule.exists() and "changed=1" in out                                  # only reported, the file stays


def test_rsyslog_rule_removal_task_notifies_the_handler_and_is_check_safe():
    task = _rsyslog_rule_task()
    assert task["notify"] == "Restart rsyslog" and "check_mode" not in task
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    assert any(h["name"] == "Restart rsyslog" for h in handlers)


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
_O2_SERVICE = {"url": "https://o2.bao.invalid:5080", "org": "acme"}
_RUSTFS_SERVICE = {"url": "https://rfs.bao.invalid:9000", "region": "kr-1"}


def _effective(tmp_path, openbao, extra_vars=None, host="good"):
    dump = {"name": "Dump effective endpoints", "check_mode": False, "ansible.builtin.copy": {
        "content": "{{ {" + ", ".join("'%s': %s" % (k, k) for k in _EFFECTIVE_KEYS) + "} | to_json }}",
        "dest": f"{tmp_path}/eff.json", "mode": "0600"}}
    res, _ = _run_input_tasks(tmp_path, [host], openbao, extra_vars=extra_vars, extra_tasks=[dump],
                              with_backup_defaults=True)
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads((tmp_path / "eff.json").read_text())


def test_endpoints_come_from_the_service_documents_when_not_set_elsewhere(tmp_path, bao, openbao):
    bao.set("inventory", "services/openobserve", _O2_SERVICE)
    bao.set("inventory", "services/rustfs", _RUSTFS_SERVICE)
    eff = _effective(tmp_path, openbao)
    assert eff == {"o2_endpoint": "https://o2.bao.invalid:5080", "o2_org": "acme", "o2_ca_file": "",
                   "rustfs_endpoint": "https://rfs.bao.invalid:9000", "rustfs_bucket": "backup-prod-good",
                   "rustfs_region": "kr-1", "rustfs_ca_file": ""}


def test_extra_vars_win_over_openbao_endpoints(tmp_path, bao, openbao):
    bao.set("inventory", "services/openobserve", _O2_SERVICE)
    bao.set("inventory", "services/rustfs", _RUSTFS_SERVICE)
    eff = _effective(tmp_path, openbao, extra_vars={"o2_endpoint": "https://o2.extra.invalid:5080",
                                                    "rustfs_bucket": "extra-bucket"})
    assert eff["o2_endpoint"] == "https://o2.extra.invalid:5080" and eff["rustfs_bucket"] == "extra-bucket"
    assert eff["o2_org"] == "acme" and eff["rustfs_endpoint"] == "https://rfs.bao.invalid:9000"


def test_optional_service_keys_fall_back_to_the_role_defaults(tmp_path, bao, openbao):
    bao.set("inventory", "services/openobserve", {"url": "https://o2.bao.invalid:5080"})
    bao.set("inventory", "services/rustfs", {"url": "https://rfs.bao.invalid:9000"})
    eff = _effective(tmp_path, openbao)
    assert (eff["o2_org"], eff["rustfs_region"], eff["o2_ca_file"], eff["rustfs_ca_file"]) == ("default", "", "", "")


def test_bucket_follows_the_naming_rule_per_host(tmp_path, bao, openbao):
    assert _effective(tmp_path, openbao, host="good")["rustfs_bucket"] == "backup-prod-good"
    assert _effective(tmp_path, openbao, host="bare")["rustfs_bucket"] == "backup-prod-bare"


def test_private_ca_files_come_from_the_service_documents(tmp_path, bao, openbao):
    bao.set("inventory", "services/openobserve", dict(_O2_SERVICE, ca_file="/etc/pki/fake-o2-ca.pem"))
    bao.set("inventory", "services/rustfs", dict(_RUSTFS_SERVICE, ca_file="/etc/pki/fake-rustfs-ca.pem"))
    eff = _effective(tmp_path, openbao)
    assert (eff["o2_ca_file"], eff["rustfs_ca_file"]) == ("/etc/pki/fake-o2-ca.pem", "/etc/pki/fake-rustfs-ca.pem")


def test_a_host_bucket_in_the_asset_agents_clause_overrides_the_naming_rule(tmp_path, bao, openbao):
    """이름 규칙 밖 호스트(이전·개명 호스트)는 Asset 문서 agents.backup.bucket으로 버킷을 가리킨다."""
    _host(bao, "renamed", agents={"backup": {"bucket": "backup-prod-oldname"}})
    assert _effective(tmp_path, openbao, host="renamed")["rustfs_bucket"] == "backup-prod-oldname"
    assert _effective(tmp_path, openbao, host="good")["rustfs_bucket"] == "backup-prod-good"


def test_a_bucket_with_a_trailing_newline_is_not_a_valid_bucket_name():
    bad = host_agents_resolve_inputs({"backup": {"bucket": "good-bucket\n"}}, dict(REQUIRED), STANDARD, SECURITY, MANDATORY, "p")
    assert any("agents.backup.bucket" in e for e in bad["errors"]) and bad["backup_bucket"] == ""
    ok = host_agents_resolve_inputs({"backup": {"bucket": "good-bucket"}}, dict(REQUIRED), STANDARD, SECURITY, MANDATORY, "p")
    assert ok["backup_bucket"] == "good-bucket" and not any("bucket" in e for e in ok["errors"])


def test_extra_vars_still_win_over_the_asset_bucket(tmp_path, bao, openbao):
    _host(bao, "renamed", agents={"backup": {"bucket": "backup-prod-oldname"}})
    eff = _effective(tmp_path, openbao, host="renamed", extra_vars={"rustfs_bucket": "extra-bucket"})
    assert eff["rustfs_bucket"] == "extra-bucket"


def test_bucket_prefix_variable_changes_the_naming_rule(tmp_path, openbao):
    eff = _effective(tmp_path, openbao, extra_vars={"rustfs_bucket_prefix": "backup-stg"})
    assert eff["rustfs_bucket"] == "backup-stg-good"


def _run_mon020(tmp_path, hosts):
    tasks = yaml.safe_load((ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))[:2]
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "connection": "local", "tasks": tasks}]))
    (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"hosts": hosts}}))
    return subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)


def test_password_auth_exception_follows_the_endpoint_calculation_of_resolve_connection(tmp_path):
    exc = {"password_auth_exception": True}
    res = _run_mon020(tmp_path, {
        "optin": {"_is_already_provisioned": False, "_connection": exc},
        "optout": {"_is_already_provisioned": False, "_connection": {"password_auth_exception": False}},
        "noconn": {"_is_already_provisioned": False}})
    text = res.stdout + res.stderr
    assert "optin: 접속 계정" not in text
    assert "optout: 접속 계정으로 SSH 접속할 수 없는" in text and "noconn: 접속 계정으로 SSH 접속할 수 없는" in text
    assert "host_agents_allow_password_auth" not in text and "identity" in text


def test_password_auth_exception_leaves_an_audit_warning_only_where_it_applies(tmp_path):
    exc = {"password_auth_exception": True}
    res = _run_mon020(tmp_path, {
        "optin": {"_is_already_provisioned": False, "_connection": exc},
        "keyed": {"_is_already_provisioned": True, "_connection": exc}})
    text = res.stdout + res.stderr
    assert res.returncode == 0, text
    assert "PASSWORD-AUTH-EXCEPTION optin" in text and "PASSWORD-AUTH-EXCEPTION keyed" not in text


# --- 서버 도달성 tcp_check (Spec #184 / Ticket-6, ADR-0010) -------------------------------------------------------

def test_only_the_checker_host_gets_tcp_check_for_every_target_in_the_resolved_list(tmp_path):
    targets = ["192.0.2.1:22", "192.0.2.2:2222", "ns0003:22"]
    over = dict(otel_tcpcheck_targets=targets, inventory_hostname="localhost", host_agents_o2_health_checker="localhost")
    (tmp_path / "checker").mkdir()
    cfg, _ = _render_config(tmp_path / "checker", **over)
    rx = cfg["receivers"]["tcp_check"]
    assert rx["collection_interval"] == "60s"
    assert [t["endpoint"] for t in rx["targets"]] == targets
    pipe = cfg["service"]["pipelines"]["metrics/tcpcheck"]
    assert pipe["receivers"] == ["tcp_check"] and pipe["exporters"] == ["otlphttp/metrics"]
    (tmp_path / "other").mkdir()
    other, _ = _render_config(tmp_path / "other", **dict(over, host_agents_o2_health_checker="ns0266"))
    assert "tcp_check" not in other["receivers"] and "metrics/tcpcheck" not in other["service"]["pipelines"]


# --- tcpcheck 대상 해석: 실행 범위와 무관하게 OpenBao에서 읽는다 (Issue #203) --------------------------------------------

def test_tcpcheck_targets_come_from_the_ssh_endpoint_in_roster_order():
    f = host_agents_tcpcheck_targets
    docs = {"ns0001": {"ssh": {"protocol": "ssh", "address": "192.0.2.1", "port": 22}},
            "ns0002": {"ssh": {"protocol": "ssh", "address": "192.0.2.2", "port": 8487}, "telnet": {"address": "x", "port": 23}}}
    assert f(["ns0002", "ns0001"], docs) == ["192.0.2.2:8487", "192.0.2.1:22"]


def test_tcpcheck_targets_fail_naming_the_assets_without_an_ssh_endpoint_instead_of_guessing():
    from ansible.errors import AnsibleFilterError
    docs = {"ns0001": {"ssh": {"protocol": "ssh", "address": "192.0.2.1", "port": 22}}, "ns0002": {"https": {"address": "h", "port": 443}}}
    with pytest.raises(AnsibleFilterError) as err:
        host_agents_tcpcheck_targets(["ns0001", "ns0002", "ns0003"], docs)
    assert "ns0002" in str(err.value) and "ns0003" in str(err.value) and "ns0001" not in str(err.value)
    bad = {"ns0004": {"ssh": {"protocol": "ssh", "address": "192.0.2.4", "port": "ssh"}}}
    with pytest.raises(AnsibleFilterError, match="ns0004"):
        host_agents_tcpcheck_targets(["ns0004"], bad)


def _run_tcpcheck_tasks(tmp_path, addr, servers, checker="chk", excluded=(), inventory_hosts=None, token=APPROLE_TOKEN, others=(), excluded_group=None):
    role_vars = {}
    for f in ("defaults", "vars"):
        role_vars.update(yaml.safe_load((ROLE / f / "main.yml").read_text(encoding="utf-8")))
    role_vars.update({"host_agents_o2_health_checker": checker, "host_agents_tcpcheck_excluded": list(excluded)})
    tasks = [{"ansible.builtin.import_tasks": str(ROLE / "tasks" / "tcpcheck_targets.yml")},
             {"name": "Dump targets", "ansible.builtin.copy": {
                 "content": "{{ (otel_tcpcheck_targets | default(None)) | to_json }}",
                 "dest": f"{tmp_path}/targets-{{{{ inventory_hostname }}}}.json", "mode": "0600"}, "check_mode": False}]
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all:!servers", "gather_facts": False, "connection": "local", "become": False, "vars": role_vars, "tasks": tasks}]))
    hosts = {h: dict((inventory_hosts or {}).get(h, {})) for h in [checker, *others, *servers]}
    inv = {"all": {"hosts": {h: {"_vault_token": token, **v} for h, v in hosts.items()},
                   "children": {"servers": {"hosts": {h: {} for h in servers}}}}}
    if excluded_group is not None:   # Semaphore 인벤토리의 tcpcheck_excluded 그룹(host_agents_excluded와 같은 방식)
        inv["all"]["children"]["tcpcheck_excluded"] = {"hosts": {h: {} for h in excluded_group}}
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    res = subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR,
                         env=dict(os.environ, VAULT_ADDR=addr, ANSIBLE_NOCOLOR="1"))
    out = {h: json.loads((tmp_path / f"targets-{h}.json").read_text()) for h in hosts if (tmp_path / f"targets-{h}.json").exists()}
    return res, out


def test_checker_resolves_every_server_endpoint_from_openbao_regardless_of_the_run_scope(tmp_path, bao, openbao):
    # 인벤토리에는 포트가 없다(실제 값은 OpenBao에만 있다) — 부분 실행에서도 비표준 포트가 맞아야 한다
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-odd"])
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["chk"] == ["192.0.2.11:8487", "192.0.2.10:22"]     # 로스터는 호스트명 정렬(svc-odd, svc-std)
    _assert_reads_are_declared(bao)


def test_excluded_servers_are_not_probed(tmp_path, openbao):
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-odd"], excluded=["svc-odd"])
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["chk"] == ["192.0.2.10:22"]


def test_servers_in_the_tcpcheck_excluded_inventory_group_are_not_probed(tmp_path, openbao):
    # Semaphore 인벤토리는 DB에 저장된 static-yaml이라 저장소 group_vars가 아니라 인벤토리 그룹으로 제외한다 (Issue #205)
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-odd"], excluded_group=["svc-odd"])
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["chk"] == ["192.0.2.10:22"]


def test_group_and_variable_exclusions_are_combined(tmp_path, openbao):
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-odd", "svc-none"], excluded=["svc-odd"], excluded_group=["svc-std", "svc-none"])
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["chk"] == []


def test_a_non_checker_host_gets_no_targets(tmp_path, openbao):
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std"], others=["not-the-checker"])
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["chk"] == ["192.0.2.10:22"] and out["not-the-checker"] is None


def test_an_openbao_error_fails_the_checker_instead_of_silently_guessing_port_22(tmp_path, openbao):
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-denied"])
    text = res.stdout + res.stderr
    assert res.returncode != 0 and out == {}
    assert "svc-denied" in text and "403" in text


def test_a_server_without_an_ssh_endpoint_fails_the_checker_instead_of_guessing(tmp_path, openbao):
    res, out = _run_tcpcheck_tasks(tmp_path, openbao, ["svc-std", "svc-noep"])
    assert res.returncode != 0 and out == {}
    assert "svc-noep" in res.stdout + res.stderr


def test_the_declared_openbao_documents_are_known_to_index_yml_and_their_required_keys_exist_in_the_schema():
    """`monitoring_openbao_required` 선언과 스키마 대조: 패턴은 index.yml에 있고, 선언한 키는 스키마가 아는 키다."""
    sys.path.insert(0, str(ROOT_DIR / "scripts"))
    import openbao_validation as ov
    declared = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))["monitoring_openbao_required"]
    index = dict(ov.load_index(ov.DEFAULT_SCHEMA_DIR))
    assert set(declared) <= set(index)
    for pattern, keys in declared.items():
        schema = json.loads((Path(ov.DEFAULT_SCHEMA_DIR) / index[pattern]).read_text(encoding="utf-8"))
        assert set(keys) <= set(schema.get("properties", {})), pattern
        assert set(schema.get("required", [])) <= set(keys), pattern   # 스키마가 필수로 정한 키는 선언에도 있다
