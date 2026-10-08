"""Host Audit (ADR-0009, #119): per-host record and report model contract.

Only observable behaviour is asserted: given a registered raw probe result the
record says what was collected (or why not); given records and run metadata
the report model says what the report shows. The probe script itself is run
with a local ``sh`` so its output format is checked against the parser.
"""
import subprocess
import sys
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_host_record, host_audit_report_model  # noqa: E402

PROBE_SCRIPT = ROOT_DIR / "roles" / "host_audit" / "files" / "identity_probe.sh"
COLLECTED_AT = "2026-10-08T22:00:05Z"

ROCKY9_STDOUT = """Welcome banner line
__HOST_AUDIT_BEGIN__
hostname=ns0332
fqdn=ns0332.nanoit.kr
account=ppzxc
kernel=5.14.0-570.el9.x86_64
arch=x86_64
os_release_NAME="Rocky Linux"
os_release_ID="rocky"
os_release_VERSION_ID="9.6"
os_release_PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"
redhat_release=Rocky Linux release 9.6 (Blue Onyx)
ip=127.0.0.1/8
ip=10.0.0.32/24
ip=::1/128
ip=fe80::1/64
ip=2001:db8::32/64
__HOST_AUDIT_END__
"""

CENTOS6_STDOUT = """__HOST_AUDIT_BEGIN__
hostname=ns0101
fqdn=ns0101
account=ppzxc
kernel=2.6.32-754.el6.x86_64
arch=x86_64
redhat_release=CentOS release 6.10 (Final)
ip=10.0.0.101 192.168.10.5
__HOST_AUDIT_END__
"""

DECLARED = {"fqdn": "ns0332.nanoit.kr", "ip": "10.0.0.32", "environment": "production",
            "groups": ["servers"]}


def ok_probe(stdout):
    return {"rc": 0, "stdout": stdout, "stderr": "", "changed": False}


# ----------------------------------------------------------------- per-host record


def test_record_from_modern_host_keeps_identity_and_os():
    rec = host_audit_host_record(ok_probe(ROCKY9_STDOUT), "ns0332", DECLARED, COLLECTED_AT)

    assert rec["schema_version"] == 2
    assert rec["status"] == "ok" and rec["reason"] == ""
    assert rec["collected_at"] == COLLECTED_AT
    assert rec["declared"] == DECLARED
    assert rec["identity"] == {"hostname": "ns0332", "fqdn": "ns0332.nanoit.kr",
                               "ips": ["10.0.0.32", "2001:db8::32"], "account": "ppzxc"}
    assert rec["os"]["id"] == "rocky"
    assert rec["os"]["version_id"] == "9.6"
    assert rec["os"]["name"] == "Rocky Linux 9.6 (Blue Onyx)"
    assert rec["os"]["kernel"] == "5.14.0-570.el9.x86_64"


def test_record_from_centos6_without_os_release_uses_redhat_release():
    rec = host_audit_host_record(ok_probe(CENTOS6_STDOUT), "ns0101", {}, COLLECTED_AT)

    assert rec["status"] == "ok"
    assert rec["os"]["name"] == "CentOS release 6.10 (Final)"
    assert rec["identity"]["ips"] == ["10.0.0.101", "192.168.10.5"]
    assert rec["declared"] == {"fqdn": "", "ip": "", "environment": "", "groups": []}


def test_unreachable_host_is_recorded_not_dropped():
    probe = {"unreachable": True, "msg": "Failed to connect to the host via ssh: timed out\nmore",
             "changed": False}
    rec = host_audit_host_record(probe, "ns0266", DECLARED, COLLECTED_AT)

    assert rec["status"] == "unreachable"
    assert "timed out" in rec["reason"] and "\n" not in rec["reason"]
    assert rec["identity"] is None and rec["os"] is None


def test_probe_without_markers_is_a_collection_failure():
    rec = host_audit_host_record({"rc": 127, "stdout": "", "stderr": "sh: not found"},
                                 "ns0400", DECLARED, COLLECTED_AT)

    assert rec["status"] == "probe_failed"
    assert rec["reason"] == "sh: not found"


def test_probe_script_output_parses_on_this_machine():
    out = subprocess.run(["sh", str(PROBE_SCRIPT)], capture_output=True, text=True, check=True)
    rec = host_audit_host_record(ok_probe(out.stdout), "local", {}, COLLECTED_AT)

    assert rec["status"] == "ok"
    assert rec["identity"]["hostname"]
    assert rec["os"]["kernel"] and rec["os"]["arch"]
    assert rec["os"]["name"], "os-release or redhat-release must yield an OS name"


# ----------------------------------------------------------------- report model


def run_meta(**overrides):
    meta = {"run_id": "ha-20261008T220005Z", "run_kind": "scheduled",
            "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:03:40Z",
            "targets": ["ns0332", "ns0266", "ns0101"], "target_hosts": "",
            "archive": "/tmp/host_audit/ha-20261008T220005Z (러너 로컬)"}
    meta.update(overrides)
    return meta


def records():
    return [
        host_audit_host_record(ok_probe(ROCKY9_STDOUT), "ns0332", DECLARED, COLLECTED_AT),
        host_audit_host_record({"unreachable": True, "msg": "ssh: connect timed out"},
                               "ns0266", DECLARED, COLLECTED_AT),
    ]


def test_model_cover_carries_isms_2_11_2_fields_in_kst():
    model = host_audit_report_model(records(), run_meta())
    cover = model["cover"]

    assert cover["run_kind"] == "정기"
    assert cover["started_at"] == "2026-10-09 07:00 (KST)"
    assert cover["generated_at"] == "2026-10-09 07:03 (KST)"
    assert cover["scope"].startswith("servers · loadbalancers · overseer — 3대")
    assert "cisco_switches" in cover["out_of_scope"]
    assert cover["method"] and cover["contents"] and cover["baseline"]
    assert cover["accounts"] == "ppzxc"
    assert cover["archive"].startswith("/tmp/host_audit/")


def test_model_reports_every_target_including_unreachable_and_unrecorded():
    model = host_audit_report_model(records(), run_meta())

    assert model["summary"] == {"hosts_total": 3, "hosts_inspected": 1, "hosts_unavailable": 2}
    labels = {u["host"]: u["label"] for u in model["unavailable"]}
    assert labels == {"ns0266": "점검불가(접속 실패)", "ns0101": "점검불가(접속 준비 실패)"}
    assert [row["host"] for row in model["inventory"]] == ["ns0101", "ns0266", "ns0332"]


def test_model_inventory_row_for_inspected_host():
    model = host_audit_report_model(records(), run_meta())
    row = next(r for r in model["inventory"] if r["host"] == "ns0332")

    assert row["fqdn"] == "ns0332.nanoit.kr"
    assert row["ips"] == "10.0.0.32, 2001:db8::32"
    assert row["environment"] == "production" and not row["environment_unassigned"]
    assert row["os"] == "Rocky Linux 9.6 (Blue Onyx)"
    assert row["status_label"] == "점검 완료" and row["inspected"]


def test_model_falls_back_to_declared_values_and_marks_unassigned_environment():
    unreachable = host_audit_host_record({"unreachable": True, "msg": "x"}, "lb-01",
                                         {"fqdn": "lb-01.idc", "ip": "10.0.1.40"}, COLLECTED_AT)
    row = host_audit_report_model([unreachable], run_meta(targets=["lb-01"]))["inventory"][0]

    assert row["fqdn"] == "lb-01.idc" and row["ips"] == "10.0.1.40"
    assert row["environment"] == "미지정" and row["environment_unassigned"]
    assert row["os"] == "-"


def test_model_flags_fqdn_that_differs_from_inventory():
    rec = host_audit_host_record(ok_probe(ROCKY9_STDOUT), "ns0332",
                                 dict(DECLARED, fqdn="old.nanoit.kr"), COLLECTED_AT)
    row = host_audit_report_model([rec], run_meta(targets=["ns0332"]))["inventory"][0]

    assert row["fqdn"] == "ns0332.nanoit.kr (인벤토리: old.nanoit.kr)"


def test_model_names_requested_subset_and_on_demand_kind():
    model = host_audit_report_model([], run_meta(run_kind="on_demand", targets=[],
                                                 target_hosts="ns0266"))

    assert model["cover"]["run_kind"] == "수시"
    assert "target_hosts: ns0266" in model["cover"]["scope"]
    assert model["summary"]["hosts_total"] == 0 and model["unavailable"] == []


# ----------------------------------------------------------------- template / wiring


def test_report_template_is_print_ready_and_self_contained():
    tpl = (ROOT_DIR / "roles" / "host_audit" / "templates" / "report.html.j2").read_text(encoding="utf-8")

    assert "@page { size: A4" in tpl
    assert "break-before: page" in tpl
    assert "table-header-group" in tpl
    assert "Malgun Gothic" in tpl and "Noto Sans CJK KR" in tpl
    for external in ("http://", "https://", "<script", "<link", "@import", "url("):
        assert external not in tpl, f"report must not load external resources ({external})"


def test_report_template_renders_the_model():
    jinja2 = __import__("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROOT_DIR / "roles" / "host_audit" / "templates")))
    model = host_audit_report_model(records(), run_meta())
    html = env.get_template("report.html.j2").render(host_audit_model=model)

    for text in ("Host Audit 점검 보고서", "점검일시", "점검대상", "점검방법", "점검내용", "비교 기준",
                 "점검 계정", "원본 보관", "점검불가(접속 실패)", "Asset Inventory",
                 "검토 및 결재", "정보보호 책임자", "ns0332.nanoit.kr"):
        assert text in html


def test_collection_targets_follow_spec_and_raw_probe_is_read_only():
    play_file = ROOT_DIR / "playbooks" / "host_audit.yml"
    plays = yaml.safe_load(play_file.read_text(encoding="utf-8"))
    defaults = yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    tasks_dir = ROOT_DIR / "roles" / "host_audit" / "tasks"
    tasks = []
    for t in yaml.safe_load((tasks_dir / "main.yml").read_text(encoding="utf-8")):
        included = t.get("ansible.builtin.include_tasks")
        tasks += yaml.safe_load((tasks_dir / included).read_text(encoding="utf-8")) if included else [t]

    assert defaults["host_audit_scope_pattern"] == "servers:loadbalancers:overseer"
    assert defaults["host_audit_run_kind"] == "on_demand"
    collect = next(p for p in plays if p.get("hosts") == "host_audit_targets")
    assert collect["gather_facts"] is False, "CentOS 6/7 have no usable Python; collection is raw-only"
    target_modules = {k for t in tasks for k in t if k.startswith("ansible.builtin.")}
    # Section checks live in their own task files included from main.yml; they obey the same rule.
    for inc in [t["ansible.builtin.include_tasks"] for t in tasks if "ansible.builtin.include_tasks" in t]:
        tasks = tasks + yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "tasks" / inc).read_text(encoding="utf-8"))
    tasks = [t for t in tasks if "ansible.builtin.include_tasks" not in t]
    remote = [t for t in tasks if t.get("delegate_to") != "localhost"]
    assert all("ansible.builtin.raw" in t or "ansible.builtin.set_fact" in t for t in remote), target_modules
    probe = next(t for t in tasks if "ansible.builtin.raw" in t)
    assert probe["ignore_unreachable"] is True and probe["failed_when"] is False
