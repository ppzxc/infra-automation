"""Host Audit Asset Inventory (ADR-0009, #120): probe -> record -> report model contract.

Observable behaviour only: given probe output the ``inventory`` record says what
the host has; given records and run metadata the report model says what the
report shows ('미지정', '선언 외', '장기 미사용', EOS). The probe script itself is
run with a local ``sh`` and, for the Raw Provisioning Path (CentOS 6/7, no
Python), inside ``centos:6``/``centos:7`` containers when those images are
already present locally (ADR-0006 Seam 3 legacy pattern: no CentOS VM in CI).
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_host_record, host_audit_report_model  # noqa: E402
from host_audit_inventory import (  # noqa: E402
    host_audit_asset_declaration, host_audit_inventory_record, host_audit_privileged_allowlist,
    inventory_section)
from host_audit_mail import host_audit_mail_summary  # noqa: E402

ROLE = ROOT_DIR / "roles" / "host_audit"
PROBE = ROLE / "files" / "inventory_probe.sh"
EOL_TABLE = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))["host_audit_eol_table"]
COLLECTED_AT = "2026-10-08T22:00:05Z"
NOW = 1791496805  # 2026-10-08T22:00:05Z

ROCKY9_INVENTORY = """banner
__HOST_AUDIT_INVENTORY_BEGIN__
now_epoch=1791496805
cpu_count=4
cpu_model=Intel(R) Xeon(R) Silver 4210R CPU @ 2.40GHz
mem_total_kb=16266740
dmi_sys_vendor=Dell Inc.
dmi_product_name=PowerEdge R640
dmi_product_serial=ABC1234
disk=/|xfs|52403200|10485760
disk=/data|xfs|1048576000|524288000
uptime_s=864000.12
timesync_tool=chrony
timesync_chrony_leap=Normal
pkg_manager=rpm
pkg=kernel-core|(none):5.14.0-570.el9|x86_64|1780000000
pkg=kernel-core|(none):5.14.0-503.el9|x86_64|1770000000
pkg=openssl-libs|1:3.2.2-6.el9|x86_64|1790000000
pkg=openssh-server|(none):8.7p1-45.el9|x86_64|1790000000
pkg=glibc|(none):2.34-168.el9|x86_64|1790000000
pkg=sudo|(none):1.9.5p2-10.el9|x86_64|1791000000
pkg=docker-ce|3:27.3.1-1.el9|x86_64|1785000000
pkg=zz-rare-package|(none):1.0-1|noarch|1700000000
listen_tcp=LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=900,fd=3))
listen_tcp=LISTEN 0      4096       127.0.0.1:8888      0.0.0.0:*    users:(("otelcol-contrib",pid=1200,fd=7))
listen_tcp=LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=900,fd=4))
listen_udp=UNCONN 0      0          127.0.0.1:323       0.0.0.0:*    users:(("chronyd",pid=700,fd=5))
passwd=root|0|0|/bin/bash
passwd=bin|1|1|/sbin/nologin
passwd=ppzxc|1000|1000|/bin/bash
passwd=deploy|1001|1001|/bin/bash
passwd=olduser|1002|1002|/bin/bash
passwd=ghost|1003|1003|/bin/bash
passwd=toor|0|0|/bin/sh
shadow=root|locked
shadow=bin|locked
shadow=ppzxc|set
shadow=deploy|set
shadow=olduser|locked
shadow=ghost|empty
shadow=toor|set
group=wheel|ppzxc,deploy
sudoers=/etc/sudoers|root    ALL=(ALL)       ALL
sudoers=/etc/sudoers|%wheel  ALL=(ALL)       ALL
sudoers=/etc/sudoers.d/90-ppzxc|ppzxc ALL=(ALL) NOPASSWD:ALL
sudoers=/etc/sudoers.d/91-ci|ci-runner ALL=(ALL) NOPASSWD: /usr/bin/systemctl
lastlog_available=1
lastlog=root                                       **Never logged in**
lastlog=bin                                        **Never logged in**
lastlog=ppzxc            pts/0    10.0.0.5         Thu Oct  8 21:58:01 +0900 2026
lastlog=deploy           pts/1    10.0.0.6         Mon Sep 28 10:00:00 +0900 2026
lastlog=olduser          pts/1    10.0.0.7         Mon Jan  5 10:00:00 +0900 2026
lastlog=ghost                                      **Never logged in**
lastlog=toor                                       **Never logged in**
recent_login=ppzxc
recent_login=deploy
agent_bin=otelcol-contrib
agent_bin=resticprofile
agent_bin=restic
agent_otelcol_active=active
agent_backup_timer_active=active
__HOST_AUDIT_INVENTORY_END__
"""

# CentOS 6: no ss in this shape -> netstat, rpm prints (none) epochs, no /etc/os-release, no timedatectl.
CENTOS6_INVENTORY = """__HOST_AUDIT_INVENTORY_BEGIN__
now_epoch=1791496805
cpu_count=2
cpu_model=Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz
mem_total_kb=3922944
disk=/|ext4|20511356|8123456
uptime_s=31536000.50
timesync_tool=ntpd
timesync_ntp_peer=0
pkg_manager=rpm
pkg=kernel|(none):2.6.32-754.el6|x86_64|1600000000
pkg=openssl|(none):1.0.1e-58.el6_10|x86_64|1600000000
pkg=openssh-server|(none):5.3p1-124.el6_10|x86_64|1600000000
netstat=tcp        0      0 0.0.0.0:22                  0.0.0.0:*                   LISTEN      1500/sshd
netstat=udp        0      0 0.0.0.0:123                 0.0.0.0:*                               1600/ntpd
passwd=root|0|0|/bin/bash
passwd=ppzxc|500|500|/bin/bash
shadow=root|set
shadow=ppzxc|set
group=wheel|ppzxc
lastlog_available=1
lastlog=root     pts/0    10.0.0.5         Mon Mar  2 10:00:00 +0900 2026
lastlog=ppzxc    pts/0    10.0.0.5         Thu Oct  8 21:00:00 +0900 2026
recent_login=ppzxc
agent_otelcol_active=inactive
__HOST_AUDIT_INVENTORY_END__
"""

ROCKY9_IDENTITY = """__HOST_AUDIT_BEGIN__
hostname=ns0331
fqdn=ns0331.nanoit.kr
account=ppzxc
kernel=5.14.0-570.el9.x86_64
arch=x86_64
os_release_ID="rocky"
os_release_VERSION_ID="9.6"
os_release_PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"
ip=10.0.0.32/24
__HOST_AUDIT_END__
"""

CENTOS6_IDENTITY = """__HOST_AUDIT_BEGIN__
hostname=ns0101
fqdn=ns0101
account=ppzxc
kernel=2.6.32-754.el6.x86_64
arch=x86_64
redhat_release=CentOS release 6.10 (Final)
ip=10.0.0.101
__HOST_AUDIT_END__
"""


def ok(stdout):
    return {"rc": 0, "stdout": stdout, "stderr": "", "changed": False}


def record(host, identity, inventory, asset=None, groups=("servers",)):
    rec = host_audit_host_record(ok(identity), host, {"fqdn": "", "ip": "", "environment": "production",
                                                      "groups": list(groups)}, COLLECTED_AT)
    rec["declared"]["asset"] = dict({"purpose": "", "department": "", "owner_role": "", "admin_role": "",
                                     "asset_importance": "", "privileged_allowlist": ["ppzxc"]}, **(asset or {}))
    rec["inventory"] = host_audit_inventory_record(ok(inventory)) if inventory is not None else None
    return rec


def meta(**overrides):
    m = {"run_id": "ha-20261008T220005Z", "run_kind": "scheduled", "started_at": COLLECTED_AT,
         "generated_at": COLLECTED_AT, "targets": [], "target_hosts": "", "archive": "-",
         "timezone": "Asia/Seoul", "eol_table": EOL_TABLE}
    m.update(overrides)
    return m


def host(model, name):
    return next(h for h in model["asset_inventory"]["hosts"] if h["host"] == name)


def account(section, name):
    return next(a for a in section["accounts"] if a["name"] == name)


# ----------------------------------------------------------------- probe -> record


def test_record_covers_every_inventory_area():
    inv = host_audit_inventory_record(ok(ROCKY9_INVENTORY))

    assert inv["status"] == "ok"
    assert set(inv) == {"status", "reason", "hardware", "operation", "packages", "ports", "accounts",
                        "host_agents"}
    assert inv["hardware"]["cpu_count"] == 4 and inv["hardware"]["dmi"]["serial"] == "ABC1234"
    assert inv["hardware"]["disks"][1] == {"mount": "/data", "fstype": "xfs", "size_kb": 1048576000,
                                           "used_kb": 524288000}
    assert inv["operation"]["boot_epoch"] == NOW - 864000
    assert inv["operation"]["timesync"] == {"tools": ["chrony"], "synced": True}
    assert inv["packages"]["count"] == 8 and inv["packages"]["last_update_epoch"] == 1791000000
    assert inv["packages"]["key"]["kernel"] == ["5.14.0-503.el9", "5.14.0-570.el9"]
    assert inv["packages"]["key"]["openssl"] == ["1:3.2.2-6.el9"]
    assert inv["packages"]["key"]["docker"] == ["3:27.3.1-1.el9"]
    assert {(p["proto"], p["address"], p["port"], p["process"]) for p in inv["ports"]} == {
        ("tcp", "0.0.0.0", 22, "sshd"), ("tcp", "::", 22, "sshd"),
        ("tcp", "127.0.0.1", 8888, "otelcol-contrib"), ("udp", "127.0.0.1", 323, "chronyd")}
    assert inv["host_agents"] == {"otelcol": {"installed": True, "active": True},
                                  "backup": {"installed": True, "scheduled": True}}


def test_privileged_users_come_from_uid0_groups_and_sudoers():
    accounts = host_audit_inventory_record(ok(ROCKY9_INVENTORY))["accounts"]
    priv = {p["name"]: p for p in accounts["privileged"]}

    assert set(priv) == {"root", "toor", "ppzxc", "deploy", "ci-runner"}
    assert priv["toor"]["via"] == ["uid 0"]
    assert priv["ppzxc"]["nopasswd"] is True
    assert "group wheel" in priv["deploy"]["via"] and priv["deploy"]["nopasswd"] is False
    assert priv["ci-runner"]["nopasswd"] is True


def test_password_hashes_never_reach_the_record():
    probe = PROBE.read_text(encoding="utf-8")
    # shadow is reduced to a status word on the host; the hash field is never printed.
    assert 'print "shadow=" $1 "|" s' in probe
    assert "$2" not in probe.split("/etc/shadow", 1)[1].split("\n", 3)[1].replace('$2 == ""', "").replace(
        "$2 ~ /^[!*]/", "")
    users = host_audit_inventory_record(ok(ROCKY9_INVENTORY))["accounts"]["users"]
    assert {u["name"]: u["password"] for u in users}["ghost"] == "empty"


def test_centos6_record_uses_netstat_and_rpm_without_epoch():
    inv = host_audit_inventory_record(ok(CENTOS6_INVENTORY))

    assert inv["status"] == "ok"
    assert {(p["proto"], p["port"], p["process"]) for p in inv["ports"]} == {("tcp", 22, "sshd"),
                                                                             ("udp", 123, "ntpd")}
    assert inv["packages"]["key"]["kernel"] == ["2.6.32-754.el6"]
    assert inv["operation"]["timesync"] == {"tools": ["ntpd"], "synced": False}
    assert inv["host_agents"]["otelcol"] == {"installed": False, "active": False}


def test_probe_without_markers_or_unreachable_is_not_a_crash():
    assert host_audit_inventory_record({"rc": 1, "stdout": "", "stderr": "sudo: a password is required"}) == {
        "status": "probe_failed", "reason": "sudo: a password is required"}
    assert host_audit_inventory_record({"unreachable": True, "msg": "timed out"})["status"] == "unreachable"


def test_probe_script_output_parses_on_this_machine():
    out = subprocess.run(["sh", str(PROBE)], capture_output=True, text=True, timeout=60, check=False)
    inv = host_audit_inventory_record(ok(out.stdout))

    assert inv["status"] == "ok", out.stderr
    assert inv["hardware"]["cpu_count"] > 0 and inv["hardware"]["mem_total_kb"] > 0
    assert inv["packages"]["count"] > 0
    assert any(u["name"] == "root" and u["uid"] == 0 for u in inv["accounts"]["users"])


def _image_present(image):
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode == 0


MANAGED_LISTING = (
    "for p in /etc /usr /var/lib/rpm /var/lib/dnf /var/lib/yum /var/lib/dpkg /var/lib/apt "
    "/var/cache/dnf /var/cache/yum /var/cache/apt /var/spool/cron; do [ -e $p ] && find $p -xdev "
    "-printf '%p|%y|%m|%U|%G|%s|%T@|%l\\n'; done | LC_ALL=C sort")


def _docker(*args, stdin=None):
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=180,
                          check=False)


@pytest.mark.parametrize("image", ["centos:6", "centos:7"])
def test_probe_runs_on_raw_provisioning_path_os(image):
    """Raw Provisioning Path hosts get the same probe through ``raw``; run it on the real userland as root
    and check that managed areas (incl. the rpm database files) keep their metadata."""
    if not _image_present(image):
        pytest.skip(f"{image} image not present locally (docker pull {image} to run)")
    cid = _docker("run", "-d", "--network", "none", image, "sleep", "300").stdout.strip()
    try:
        before = _docker("exec", cid, "/bin/sh", "-c", MANAGED_LISTING).stdout
        out = _docker("exec", "-i", cid, "/bin/sh", "-s", stdin=PROBE.read_text(encoding="utf-8"))
        after = _docker("exec", cid, "/bin/sh", "-c", MANAGED_LISTING).stdout
    finally:
        _docker("rm", "-f", cid)
    inv = host_audit_inventory_record(ok(out.stdout))

    assert before and before == after, sorted(set(before.splitlines()) ^ set(after.splitlines()))
    assert inv["status"] == "ok", out.stderr
    assert inv["packages"]["manager"] == "rpm" and inv["packages"]["count"] > 50
    assert inv["packages"]["key"]["glibc"], "rpm queryformat must work on this rpm version"
    assert inv["hardware"]["cpu_count"] > 0
    assert any(u["name"] == "root" and u["password"] in ("set", "locked", "empty")
               for u in inv["accounts"]["users"])
    assert inv["accounts"]["shadow_readable"] is True


# ----------------------------------------------------------------- report model


def test_unassigned_declarations_are_shown_as_unassigned():
    rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY, asset={"purpose": "웹 서비스"})
    model = host_audit_report_model([rec], meta())
    declared = {f["key"]: f for f in host(model, "ns0331")["declared"]}

    assert declared["purpose"] == {"key": "purpose", "label": "용도", "value": "웹 서비스", "state": "ok", "tag": ""}
    for key in ("department", "owner_role", "admin_role", "asset_importance"):
        assert declared[key]["value"] == "미지정" and declared[key]["state"] == "unassigned"
    assert declared["asset_importance"]["label"] == "자산중요도"
    assert model["asset_inventory"]["counts"]["unassigned_hosts"] == 1


# ------------------------------------------------- 선언 값은 OpenBao hosts/<host>에서 읽는다 (#492)

HOST_KV = {
    "description": "웹 서비스 [그룹자산A]", "isms_department": "인프라팀", "isms_owner_role": "인프라팀장",
    "isms_admin_role": "시스템 관리자", "isms_asset_importance": "H",
    "ssh_private_key": "-----BEGIN PRIVATE KEY-----zzz", "password": "s3cret-pw", "public_ip": "203.0.113.7",
    "admin_users": ["opuser"], "ansible_port": 2222, "isms_target": True,
}


def test_declaration_reads_exactly_the_five_keys_from_the_host_kv():
    decl = host_audit_asset_declaration(HOST_KV, True)

    assert decl == {"purpose": "웹 서비스 [그룹자산A]", "department": "인프라팀", "owner_role": "인프라팀장",
                    "admin_role": "시스템 관리자", "asset_importance": "H", "lookup": "ok"}


def test_declaration_never_carries_connection_values():
    text = json.dumps(host_audit_asset_declaration(HOST_KV, True), ensure_ascii=False)
    for secret in ("PRIVATE KEY", "s3cret-pw", "203.0.113.7", "opuser", "2222"):
        assert secret not in text


def test_declaration_keeps_the_ledger_text_unchanged_caps_only_blobs_and_drops_non_text_values():
    group_tail = "웹 서비스 [그룹자산A]"
    long_but_real = "가" * 200 + " " + group_tail
    decl = host_audit_asset_declaration({"description": long_but_real, "isms_owner_role": False,
                                         "isms_admin_role": ["x"], "isms_department": "{{ x }}"}, True)

    assert decl["purpose"] == long_but_real and decl["purpose"].endswith("[그룹자산A]")
    assert decl["department"] == "{{ x }}", "evidence is stored as the ledger copy has it"
    assert decl["owner_role"] == "" and decl["admin_role"] == ""
    assert decl["malformed"] == ["owner_role", "admin_role"]
    blob = host_audit_asset_declaration({"description": "x" * 5000}, True)["purpose"]
    assert len(blob) == 500 and blob.endswith("…")


def test_tag_colors_separate_unknown_values_from_data_errors():
    _m, failed = _decl_model(HOST_KV, lookup_ok=False)
    _m, unassigned = _decl_model({})
    _m, invalid = _decl_model(dict(HOST_KV, isms_asset_importance="높음"))
    _m, ok = _decl_model(HOST_KV)

    assert {f["tag"] for f in failed.values()} == {"na"} and {f["tag"] for f in unassigned.values()} == {"na"}
    assert invalid["asset_importance"]["tag"] == "crit" and invalid["purpose"]["tag"] == ""
    assert {f["tag"] for f in ok.values()} == {""}


def test_non_text_values_and_old_security_grade_records_show_as_invalid_not_unassigned():
    _m, declared = _decl_model(dict(HOST_KV, isms_owner_role=["x"], isms_department=True, isms_admin_role=123))
    assert declared["owner_role"]["state"] == "invalid" and declared["department"]["state"] == "invalid"
    assert declared["admin_role"]["state"] == "invalid" and declared["purpose"]["state"] == "ok"

    rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    rec["declared"]["asset"].pop("asset_importance")
    rec["declared"]["asset"]["security_grade"] = "2등급"
    old = {f["key"]: f for f in host(host_audit_report_model([rec], meta()), "ns0331")["declared"]}
    assert old["asset_importance"]["value"] == "잘못된 값 (2등급)"


def test_resolve_connection_still_sets_the_variables_host_audit_reads():
    text = (ROOT_DIR / "playbooks" / "common" / "resolve_connection.yml").read_text(encoding="utf-8")
    assert "register: _openbao_host_kv_resp\n" in text
    assert "_effective_host_resp:" in text and "_host_kv_dict:" in text


def test_invalid_importance_echoes_at_most_twenty_characters_of_the_original():
    _model, declared = _decl_model(dict(HOST_KV, isms_asset_importance="가" * 80))
    shown = declared["asset_importance"]["value"]

    assert shown.startswith("잘못된 값 (") and shown.endswith("…)") and len(shown) <= len("잘못된 값 ()") + 20


def _aud101_record(tmp_path, kv, status):
    """Run the real [AUD-101] task with ansible-playbook. The KV text arrives as parsed JSON data (like the
    OpenBao response), not as trusted playbook text, so any template syntax in it must stay plain text."""
    tasks = yaml.safe_load((ROLE / "tasks" / "inventory.yml").read_text(encoding="utf-8"))
    task = next(t for t in tasks if t["name"].startswith("[AUD-101]"))
    task["no_log"] = False
    (tmp_path / "kv.json").write_text(json.dumps({"kv": kv, "resp": {"status": status}}), encoding="utf-8")
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "tasks": [
        {"ansible.builtin.set_fact": {
            "_loaded": "{{ lookup('ansible.builtin.file', '%s') | from_json }}" % (tmp_path / "kv.json")}},
        {"ansible.builtin.set_fact": {"_host_kv_dict": "{{ _loaded.kv }}",
                                      "_effective_host_resp": "{{ _loaded.resp }}",
                                      "host_audit_record": {"status": "unreachable"},
                                      "_host_audit_inventory_probe": {"unreachable": True, "msg": "x"},
                                      "host_audit_privileged_extra": []}},
        task,
        {"ansible.builtin.copy": {"content": "{{ host_audit_record | to_json }}",
                                  "dest": str(tmp_path / "record.json"), "mode": "0600"}},
    ]}]
    (tmp_path / "play.yml").write_text(yaml.safe_dump(play, allow_unicode=True), encoding="utf-8")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "play.yml")], capture_output=True,
                         text=True, stdin=subprocess.DEVNULL, cwd=tmp_path, timeout=300,
                         env=dict(__import__("os").environ, ANSIBLE_NOCOLOR="1", ANSIBLE_BECOME="false",
                                  ANSIBLE_CONFIG=str(ROOT_DIR / "ansible.cfg"),
                                  ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins")))
    assert res.returncode == 0, res.stdout + res.stderr
    return json.loads((tmp_path / "record.json").read_text(encoding="utf-8"))["declared"]["asset"]


def test_aud_101_task_reads_the_five_keys_and_never_evaluates_template_text_from_the_kv(tmp_path):
    hostile = "{{ lookup('pipe', 'echo PWNED-' ~ 'X') }} [그룹자산A]"
    asset = _aud101_record(tmp_path, dict(HOST_KV, description=hostile), 200)

    assert asset["lookup"] == "ok" and asset["purpose"] == hostile
    assert asset["asset_importance"] == "H" and asset["privileged_allowlist"] == []
    assert "PWNED-X" not in json.dumps(asset) and "s3cret-pw" not in json.dumps(asset)


def test_aud_101_task_marks_a_non_200_host_kv_response_as_lookup_failed(tmp_path):
    for status in (404, 403, -1):
        sub = tmp_path / str(status)
        sub.mkdir()
        asset = _aud101_record(sub, HOST_KV, status)
        assert asset["lookup"] == "failed" and asset["purpose"] == ""


def test_declaration_with_failed_lookup_ignores_whatever_the_dict_holds():
    decl = host_audit_asset_declaration(HOST_KV, False)
    assert decl["lookup"] == "failed" and decl["purpose"] == "" and decl["asset_importance"] == ""
    assert host_audit_asset_declaration(None, True)["lookup"] == "ok"


def _decl_model(kv, lookup_ok=True):
    rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    rec["declared"]["asset"].update(host_audit_asset_declaration(kv, lookup_ok))
    model = host_audit_report_model([rec], meta())
    return model, {f["key"]: f for f in host(model, "ns0331")["declared"]}


def test_report_shows_the_five_declared_values_from_the_host_kv():
    model, declared = _decl_model(HOST_KV)

    assert [f["value"] for f in declared.values()] == ["웹 서비스 [그룹자산A]", "인프라팀", "인프라팀장",
                                                       "시스템 관리자", "H"]
    assert all(f["state"] == "ok" for f in declared.values())
    assert model["asset_inventory"]["counts"]["unassigned_hosts"] == 0
    assert model["asset_inventory"]["counts"]["lookup_failed_hosts"] == 0


def test_failed_lookup_shows_all_five_cells_as_lookup_failed_and_is_not_counted_as_unassigned():
    model, declared = _decl_model(HOST_KV, lookup_ok=False)

    assert [f["value"] for f in declared.values()] == ["조회 실패"] * 5
    assert {f["state"] for f in declared.values()} == {"lookup_failed"}
    counts = model["asset_inventory"]["counts"]
    assert counts["lookup_failed_hosts"] == 1 and counts["unassigned_hosts"] == 0


def test_empty_keys_are_unassigned_even_for_isms_target_false_hosts():
    kv = {"description": "", "isms_target": False, "isms_asset_importance": "L"}
    model, declared = _decl_model(kv)

    assert declared["purpose"]["value"] == "미지정" and declared["department"]["state"] == "unassigned"
    assert declared["asset_importance"]["value"] == "L"
    assert model["asset_inventory"]["counts"]["unassigned_hosts"] == 1


def test_asset_importance_outside_h_m_l_is_shown_as_invalid_with_the_original_value():
    for raw, shown in (("높음", "잘못된 값 (높음)"), ("h", "잘못된 값 (h)"), ("3", "잘못된 값 (3)")):
        _model, declared = _decl_model(dict(HOST_KV, isms_asset_importance=raw))
        assert declared["asset_importance"]["value"] == shown
        assert declared["asset_importance"]["state"] == "invalid"
    _model, declared = _decl_model(dict(HOST_KV, isms_asset_importance=" M "))
    assert declared["asset_importance"]["value"] == "M"


def test_nothing_but_the_five_keys_reaches_the_record_the_report_model_or_the_mail_summary():
    rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    rec["declared"]["asset"].update(host_audit_asset_declaration(HOST_KV, True))
    model = host_audit_report_model([rec], meta())
    summary = host_audit_mail_summary(model, {"sha256": "AB" * 32, "size": 1, "file_name": "r.html", "archive": "-"})

    for doc in (rec, model, summary):
        text = json.dumps(doc, ensure_ascii=False, default=str)
        for secret in ("PRIVATE KEY", "s3cret-pw", "203.0.113.7", "opuser", "isms_target"):
            assert secret not in text


def test_mail_summary_counts_unassigned_and_lookup_failed_hosts_separately():
    def summary(model):
        doc = host_audit_mail_summary(model, {"sha256": "AB" * 32, "size": 1, "file_name": "r.html", "archive": "-"})
        return next(line for line in doc["lines"] if line["section"] == "Asset Inventory")

    failed_model, _ = _decl_model(HOST_KV, lookup_ok=False)
    line = summary(failed_model)
    assert "선언 미지정 호스트 0" in line["text"] and "선언 조회 실패 호스트 1" in line["text"]
    assert line["level"] in ("warn", "crit")
    invalid_model, _ = _decl_model(dict(HOST_KV, isms_asset_importance="높음"))
    assert "선언 잘못된 값 호스트 1" in summary(invalid_model)["text"]
    unassigned_model, _ = _decl_model({})
    assert "선언 미지정 호스트 1" in summary(unassigned_model)["text"]
    assert "선언 조회 실패 호스트 0" in summary(unassigned_model)["text"]


def test_report_renders_asset_importance_and_lookup_failed_but_not_the_old_security_grade_label():
    jinja2 = __import__("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")))
    ok_rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    ok_rec["declared"]["asset"].update(host_audit_asset_declaration(HOST_KV, True))
    bad_rec = record("ns0101", CENTOS6_IDENTITY, CENTOS6_INVENTORY)
    bad_rec["declared"]["asset"].update(host_audit_asset_declaration({}, False))
    html = env.get_template("report.html.j2").render(
        host_audit_model=host_audit_report_model([ok_rec, bad_rec], meta()))

    assert "선언 조회 실패 호스트 1" in html
    assert "자산중요도" in html and "조회 실패" in html and "OpenBao" in html
    assert "보안등급" not in html


def test_removed_asset_variable_is_gone_from_the_repository():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT_DIR, capture_output=True, text=True, check=True)
    offenders = []
    for name in tracked.stdout.splitlines():
        path = ROOT_DIR / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if re.search(r"host_audit_" r"asset(?!_declaration)", text):
            offenders.append(name)
    assert offenders == []


def test_inventory_record_task_reads_the_host_kv_without_querying_openbao_again():
    tasks = yaml.safe_load((ROLE / "tasks" / "inventory.yml").read_text(encoding="utf-8"))
    record_task = next(t for t in tasks if t["name"].startswith("[AUD-101]"))
    text = json.dumps(record_task)

    assert "host_audit_asset_declaration" in text and "_host_kv_dict" in text
    assert "ansible.builtin.uri" not in json.dumps(tasks)


def test_privileged_users_outside_the_declared_allowlist_are_flagged():
    model = host_audit_report_model([record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)], meta())
    h = host(model, "ns0331")

    assert sorted(h["not_declared"]) == ["ci-runner", "deploy", "toor"]
    assert "선언 외" not in account(h, "ppzxc")["flags"]
    assert "선언 외" not in account(h, "root")["flags"], "root is always allowed"
    assert account(h, "ci-runner")["nopasswd"] is True


def test_accounts_unused_for_90_days_are_flagged_except_audit_account_and_root():
    model = host_audit_report_model([record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)], meta())
    h = host(model, "ns0331")

    assert sorted(h["inactive"]) == ["ghost", "olduser"], "uid 0 accounts are left to KISA root-login checks"
    assert account(h, "olduser")["inactive"] == "old"
    assert account(h, "ghost")["inactive"] == "never" and account(h, "ghost")["last_login"] == "기록 없음"
    assert "장기 미사용" not in account(h, "deploy")["flags"]
    assert "장기 미사용" not in account(h, "root")["flags"]
    assert "bin" not in [a["name"] for a in h["accounts"]], "non-login, non-privileged accounts are not listed"
    cover = model["asset_inventory"]["cover_note"]
    assert "90일" in cover and "ppzxc" in cover and "기준일 2026-10-08" in cover


def test_audit_account_is_excluded_even_when_never_logged_in():
    inventory = ROCKY9_INVENTORY.replace("recent_login=ppzxc\n", "")
    model = host_audit_report_model([record("ns0331", ROCKY9_IDENTITY, inventory)], meta())

    assert "ppzxc" not in host(model, "ns0331")["inactive"]


def test_missing_lastlog_makes_last_login_unavailable_instead_of_inactive():
    inventory = "\n".join(ln for ln in ROCKY9_INVENTORY.splitlines()
                          if not ln.startswith(("lastlog", "recent_login")))
    model = host_audit_report_model([record("ns0331", ROCKY9_IDENTITY, inventory)], meta())

    assert host(model, "ns0331")["inactive"] == []
    assert {"host": "ns0331", "item": "마지막 로그인", "label": "점검불가",
            "reason": "lastlog 명령 없음 — 장기 미사용 판정 불가"} in model["unavailable"]


def test_end_of_support_comes_from_the_static_table_and_raises_the_summary_band():
    recs = [record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY),
            record("ns0101", CENTOS6_IDENTITY, CENTOS6_INVENTORY)]
    model = host_audit_report_model(recs, meta())

    assert host(model, "ns0101")["eol"] == {"key": "centos-6", "date": "2020-11-30", "status": "eos",
                                            "label": "지원 종료(EOS)"}
    assert host(model, "ns0331")["eol"]["status"] == "supported"
    assert model["asset_inventory"]["eos"] == [{"host": "ns0101", "os": "CentOS release 6.10 (Final)",
                                                "date": "2020-11-30", "label": "지원 종료(EOS)"}]
    assert model["asset_inventory"]["eol_reviewed_on"] == "2026-10-08"


def test_end_of_life_soon_and_unknown_os():
    ubuntu = ROCKY9_IDENTITY.replace('"rocky"', '"ubuntu"').replace('"9.6"', '"22.04"')
    model = host_audit_report_model([record("ns0400", ubuntu, ROCKY9_INVENTORY)],
                                    meta(started_at="2027-01-15T00:00:00Z"))
    assert host(model, "ns0400")["eol"]["status"] == "soon"

    weird = ROCKY9_IDENTITY.replace('"rocky"', '"gentoo"')
    model = host_audit_report_model([record("ns0401", weird, ROCKY9_INVENTORY)], meta())
    assert host(model, "ns0401")["eol"]["status"] == "unknown"


def test_full_package_list_stays_out_of_the_report_model():
    rec = record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    model = host_audit_report_model([rec], meta())

    assert "zz-rare-package" in json.dumps(rec), "the per-host JSON keeps the full list"
    assert "zz-rare-package" not in json.dumps(model, ensure_ascii=False)
    assert host(model, "ns0331")["packages"]["count"] == 8


def test_inventory_collection_failure_is_reported_unavailable():
    rec = record("ns0331", ROCKY9_IDENTITY, None)
    rec["inventory"] = {"status": "probe_failed", "reason": "sudo: a password is required"}
    model = host_audit_report_model([rec], meta())

    assert {"host": "ns0331", "item": "Asset Inventory 상세", "label": "점검불가(수집 실패)",
            "reason": "sudo: a password is required"} in model["unavailable"]
    assert host(model, "ns0331")["collected"] is False


def test_host_agents_state_and_exclusion():
    stopped = ROCKY9_INVENTORY.replace("agent_otelcol_active=active", "agent_otelcol_active=failed")
    model = host_audit_report_model([record("ns0331", ROCKY9_IDENTITY, stopped),
                                     record("ns0333", ROCKY9_IDENTITY, CENTOS6_INVENTORY,
                                            groups=("servers", "host_agents_excluded"))], meta())

    assert host(model, "ns0331")["host_agents"] == "일부 이상"
    assert host(model, "ns0333")["host_agents"] == "제외(Host Agents Exclusion)"


def test_backup_only_host_is_normal_without_otelcol():
    """Host Agents Backup Only 호스트는 otelcol 없이 백업이 설치·예약돼 있으면 정상이다."""
    no_otel = ROCKY9_INVENTORY.replace("agent_otelcol_active=active", "agent_otelcol_active=inactive")
    no_otel = "\n".join(l for l in no_otel.splitlines() if l != "agent_bin=otelcol-contrib")
    groups = ("servers", "host_agents_backup_only")
    model = host_audit_report_model([record("ns0327", ROCKY9_IDENTITY, no_otel, groups=groups)], meta())
    assert host(model, "ns0327")["host_agents"] == "정상(백업 전용)"
    assert host(model, "ns0327")["host_agents_ok"] is True

    unscheduled = no_otel.replace("agent_backup_timer_active=active", "agent_backup_timer_active=inactive")
    model = host_audit_report_model([record("ns0327", ROCKY9_IDENTITY, unscheduled, groups=groups)], meta())
    assert host(model, "ns0327")["host_agents"] == "일부 이상"


def test_privileged_allowlist_from_declared_accounts():
    accounts = [{"name": "ppzxc", "tier": "admin"}, {"name": "op", "tier": "operator"},
                {"name": "ops2", "tier": "operator", "sudo": True}, {"name": "gone", "tier": "admin",
                                                                     "state": "absent"},
                {"name": "nosudo", "tier": "admin", "sudo": False}]
    assert host_audit_privileged_allowlist(accounts, ["admin"], ["backup-svc"]) == [
        "admin", "backup-svc", "ops2", "ppzxc"]


def test_report_renders_asset_inventory_and_appendix():
    jinja2 = __import__("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")))
    recs = [record("ns0331", ROCKY9_IDENTITY, ROCKY9_INVENTORY, asset={"purpose": "웹 서비스"}),
            record("ns0101", CENTOS6_IDENTITY, CENTOS6_INVENTORY)]
    html = env.get_template("report.html.j2").render(host_audit_model=host_audit_report_model(recs, meta()))

    for text in ("2.1 식별·선언", "2.2 상태", "2.3 계정 발견", "선언 외", "장기 미사용", "미지정",
                 "지원 종료(EOS) 운영 체제 1대", "부록 1. ns0101", "부록 2. ns0331", "PowerEdge R640",
                 "openssh", "8.7p1-45.el9", "NOPASSWD", "자산 기준"):
        assert text in html, text
    assert "zz-rare-package" not in html
    for external in ("http://", "https://", "<script", "<link", "@import", "url("):
        for part in (ROLE / "templates" / "sections").glob("*.j2"):
            assert external not in part.read_text(encoding="utf-8"), (part.name, external)


def test_inventory_task_is_read_only_raw_with_become():
    tasks = yaml.safe_load((ROLE / "tasks" / "inventory.yml").read_text(encoding="utf-8"))
    probe = next(t for t in tasks if "ansible.builtin.raw" in t)

    assert "read-only" in probe["name"]
    assert probe["become"] is True and probe["ignore_unreachable"] is True and probe["failed_when"] is False
    assert {k for t in tasks for k in t if k.startswith("ansible.builtin.")} == {"ansible.builtin.raw",
                                                                                 "ansible.builtin.set_fact"}


def test_inventory_section_tolerates_hosts_without_records():
    section = inventory_section([{"inventory_hostname": "ns0999", "status": "no_record"}], meta())
    assert section["hosts"][0]["collected"] is False and section["unavailable"] == []
