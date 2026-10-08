"""Host Audit Asset Inventory (ADR-0009, #120): probe -> record -> report model contract.

Observable behaviour only: given probe output the ``inventory`` record says what
the host has; given records and run metadata the report model says what the
report shows ('미지정', '선언 외', '장기 미사용', EOS). The probe script itself is
run with a local ``sh`` and, for the Raw Provisioning Path (CentOS 6/7, no
Python), inside ``centos:6``/``centos:7`` containers when those images are
already present locally (ADR-0006 Seam 3 legacy pattern: no CentOS VM in CI).
"""
import json
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
    host_audit_inventory_record, host_audit_privileged_allowlist, inventory_section)

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
hostname=ns0332
fqdn=ns0332.nanoit.kr
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
                                     "security_grade": "", "privileged_allowlist": ["ppzxc"]}, **(asset or {}))
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
    rec = record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY, asset={"purpose": "웹 서비스"})
    model = host_audit_report_model([rec], meta())
    declared = {f["key"]: f for f in host(model, "ns0332")["declared"]}

    assert declared["purpose"] == {"key": "purpose", "label": "용도", "value": "웹 서비스", "unassigned": False}
    for key in ("department", "owner_role", "admin_role", "security_grade"):
        assert declared[key]["value"] == "미지정" and declared[key]["unassigned"] is True
    assert model["asset_inventory"]["counts"]["unassigned_hosts"] == 1


def test_privileged_users_outside_the_declared_allowlist_are_flagged():
    model = host_audit_report_model([record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY)], meta())
    h = host(model, "ns0332")

    assert sorted(h["not_declared"]) == ["ci-runner", "deploy", "toor"]
    assert "선언 외" not in account(h, "ppzxc")["flags"]
    assert "선언 외" not in account(h, "root")["flags"], "root is always allowed"
    assert account(h, "ci-runner")["nopasswd"] is True


def test_accounts_unused_for_90_days_are_flagged_except_audit_account_and_root():
    model = host_audit_report_model([record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY)], meta())
    h = host(model, "ns0332")

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
    model = host_audit_report_model([record("ns0332", ROCKY9_IDENTITY, inventory)], meta())

    assert "ppzxc" not in host(model, "ns0332")["inactive"]


def test_missing_lastlog_makes_last_login_unavailable_instead_of_inactive():
    inventory = "\n".join(ln for ln in ROCKY9_INVENTORY.splitlines()
                          if not ln.startswith(("lastlog", "recent_login")))
    model = host_audit_report_model([record("ns0332", ROCKY9_IDENTITY, inventory)], meta())

    assert host(model, "ns0332")["inactive"] == []
    assert {"host": "ns0332", "item": "마지막 로그인", "label": "점검불가",
            "reason": "lastlog 명령 없음 — 장기 미사용 판정 불가"} in model["unavailable"]


def test_end_of_support_comes_from_the_static_table_and_raises_the_summary_band():
    recs = [record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY),
            record("ns0101", CENTOS6_IDENTITY, CENTOS6_INVENTORY)]
    model = host_audit_report_model(recs, meta())

    assert host(model, "ns0101")["eol"] == {"key": "centos-6", "date": "2020-11-30", "status": "eos",
                                            "label": "지원 종료(EOS)"}
    assert host(model, "ns0332")["eol"]["status"] == "supported"
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
    rec = record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY)
    model = host_audit_report_model([rec], meta())

    assert "zz-rare-package" in json.dumps(rec), "the per-host JSON keeps the full list"
    assert "zz-rare-package" not in json.dumps(model, ensure_ascii=False)
    assert host(model, "ns0332")["packages"]["count"] == 8


def test_inventory_collection_failure_is_reported_unavailable():
    rec = record("ns0332", ROCKY9_IDENTITY, None)
    rec["inventory"] = {"status": "probe_failed", "reason": "sudo: a password is required"}
    model = host_audit_report_model([rec], meta())

    assert {"host": "ns0332", "item": "Asset Inventory 상세", "label": "점검불가(수집 실패)",
            "reason": "sudo: a password is required"} in model["unavailable"]
    assert host(model, "ns0332")["collected"] is False


def test_host_agents_state_and_exclusion():
    stopped = ROCKY9_INVENTORY.replace("agent_otelcol_active=active", "agent_otelcol_active=failed")
    model = host_audit_report_model([record("ns0332", ROCKY9_IDENTITY, stopped),
                                     record("ns0333", ROCKY9_IDENTITY, CENTOS6_INVENTORY,
                                            groups=("servers", "host_agents_excluded"))], meta())

    assert host(model, "ns0332")["host_agents"] == "일부 이상"
    assert host(model, "ns0333")["host_agents"] == "제외(Host Agents Exclusion)"


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
    recs = [record("ns0332", ROCKY9_IDENTITY, ROCKY9_INVENTORY, asset={"purpose": "웹 서비스"}),
            record("ns0101", CENTOS6_IDENTITY, CENTOS6_INVENTORY)]
    html = env.get_template("report.html.j2").render(host_audit_model=host_audit_report_model(recs, meta()))

    for text in ("2.1 식별·선언", "2.2 상태", "2.3 계정 발견", "선언 외", "장기 미사용", "미지정",
                 "지원 종료(EOS) 운영 체제 1대", "부록 1. ns0101", "부록 2. ns0332", "PowerEdge R640",
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
