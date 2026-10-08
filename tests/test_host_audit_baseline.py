"""Host Audit storage and Audit Baseline (ADR-0009 §5, #125).

Observable behaviour only: the S3 request signer is checked against AWS's published
Signature V4 examples, the Audit Baseline statuses through the report model the
template draws, and the storage settings through the files the operator applies.
No network: the RustFS end-to-end run is described in docs/host_audit.md §11.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_baseline import (  # noqa: E402
    EMPTY_SHA256, FIRST, NEW, PERSIST, RECUR, REMOVED, RESOLVED, UNKNOWN,
    host_audit_baseline_compare, host_audit_baseline_pick, host_audit_baseline_section,
    host_audit_findings_index, host_audit_json_loads, host_audit_pointer_keys,
    host_audit_s3_list, host_audit_s3_request, host_audit_storage_prefix, sigv4_authorization,
)

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
STORAGE_DIR = ROLE_DIR / "files" / "storage"
AWS_AK, AWS_SK = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
RUN = {"run_id": "ha-20261101T000000Z", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z"}


# ------------------------------------------------------------------------------
# S3 requests (RustFS) — AWS Signature V4
# ------------------------------------------------------------------------------
def test_signature_matches_the_aws_list_objects_example():
    auth = sigv4_authorization("GET", "examplebucket.s3.amazonaws.com", "/", {"max-keys": "2", "prefix": "J"}, {},
                               EMPTY_SHA256, AWS_AK, AWS_SK, "us-east-1", "20130524T000000Z")
    assert auth.endswith("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in auth


def test_signature_matches_the_aws_get_object_example_with_an_extra_signed_header():
    auth = sigv4_authorization("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {"Range": "bytes=0-9"},
                               EMPTY_SHA256, AWS_AK, AWS_SK, "us-east-1", "20130524T000000Z")
    assert auth.endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_s3_request_is_path_style_and_signs_the_payload_hash():
    storage = {"endpoint": "https://rustfs.example:9000/", "bucket": "host-audit",
               "access_key": "ak", "secret_key": "sk"}
    now = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
    req = host_audit_s3_request(storage, "PUT", "2026-10/ha-1/hosts/ns 0332.json", None, "ab" * 32, now=now)
    assert req["url"] == "https://rustfs.example:9000/host-audit/2026-10/ha-1/hosts/ns%200332.json"
    assert req["headers"]["x-amz-content-sha256"] == "ab" * 32
    assert req["headers"]["x-amz-date"] == "20261008T000000Z"
    assert "Credential=ak/20261008/us-east-1/s3/aws4_request" in req["headers"]["Authorization"]
    assert "sk" not in json.dumps(req["headers"]).replace("Credential=ak", ""), "secret key must never be sent"

    listing = host_audit_s3_request(storage, "GET", "", {"list-type": "2", "prefix": "baseline/"}, now=now)
    assert listing["url"] == "https://rustfs.example:9000/host-audit?list-type=2&prefix=baseline%2F"
    assert listing["headers"]["x-amz-content-sha256"] == EMPTY_SHA256


def test_default_port_is_left_out_of_the_signed_host():
    storage = {"endpoint": "https://rustfs.example:443", "bucket": "b", "access_key": "ak", "secret_key": "sk"}
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    signed = host_audit_s3_request(storage, "GET", "k", now=now)["headers"]["Authorization"]
    plain = host_audit_s3_request(dict(storage, endpoint="https://rustfs.example"), "GET", "k", now=now)
    assert signed == plain["headers"]["Authorization"]


def test_list_response_is_parsed_with_its_namespace():
    xml = ('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
           '<Name>host-audit</Name><IsTruncated>false</IsTruncated>'
           '<Contents><Key>baseline/ha-1.json</Key><LastModified>2026-10-01T00:00:05.120Z</LastModified></Contents>'
           '<Contents><Key>baseline/ha-2.json</Key><LastModified>2026-11-01T00:00:05Z</LastModified></Contents>'
           '</ListBucketResult>')
    out = host_audit_s3_list(xml)
    assert [k["key"] for k in out["keys"]] == ["baseline/ha-1.json", "baseline/ha-2.json"]
    assert out["truncated"] is False


def test_storage_prefix_uses_the_report_time_zone_month():
    # 2026-09-30 16:00 UTC is 2026-10-01 01:00 KST — the October folder.
    run = {"run_id": "ha-x", "started_at": "2026-09-30T16:00:00Z"}
    assert host_audit_storage_prefix(run, "Asia/Seoul") == "2026-10/ha-x/"


def test_pointer_keys_keep_only_pointers_within_the_window():
    listing = {"keys": [
        {"key": "baseline/old.json", "last_modified": "2025-09-01T00:00:00Z"},
        {"key": "baseline/recent.json", "last_modified": "2026-10-01T00:00:00Z"},
        {"key": "2026-10/ha-1/report.html", "last_modified": "2026-10-01T00:00:00Z"},
    ]}
    assert host_audit_pointer_keys(listing, RUN["started_at"]) == ["baseline/recent.json"]


def test_damaged_json_object_reads_as_none():
    assert host_audit_json_loads("{not json") is None
    assert host_audit_json_loads("") is None
    assert host_audit_json_loads('{"a": 1}') == {"a": 1}


# ------------------------------------------------------------------------------
# Audit Baseline selection and statuses
# ------------------------------------------------------------------------------
def pointer(run_id, started_at, kind="scheduled", resolved=()):
    return {"run_id": run_id, "run_kind": kind, "started_at": started_at,
            "findings_key": "x/%s/findings.json" % run_id, "resolved": list(resolved)}


def test_baseline_is_the_latest_earlier_scheduled_run_never_an_on_demand_one():
    pointers = [
        pointer("ha-sep", "2026-09-01T00:00:00Z"),
        pointer("ha-oct", "2026-10-01T00:00:00Z"),
        pointer("ha-oct-adhoc", "2026-10-20T00:00:00Z", kind="on_demand"),
        pointer("ha-dec", "2026-12-01T00:00:00Z"),          # later than this run
        pointer(RUN["run_id"], RUN["started_at"]),            # this run itself
    ]
    assert host_audit_baseline_pick(pointers, RUN)["run_id"] == "ha-oct"
    assert host_audit_baseline_pick([pointer("a", "2026-10-02T00:00:00Z", kind="on_demand")], RUN) is None
    assert host_audit_baseline_pick([], RUN) is None


def index(**sections):
    return {name: {"hosts": hosts, "findings": [{"host": h, "id": i, "label": i} for h, i in items]}
            for name, (hosts, items) in sections.items()}


def stored(run_id, started_at, **sections):
    return {"run_id": run_id, "run_kind": "scheduled", "started_at": started_at,
            "sections": {name: {"hosts": hosts, "ids": {h: [i for hh, i in items if hh == h] for h in hosts}}
                         for name, (hosts, items) in sections.items()}}


def test_statuses_new_persisting_recurring_resolved_and_unknown():
    baseline = stored("ha-oct", "2026-10-01T00:00:00Z",
                      config_vulnerability=(["a", "b"], [("a", "U-01"), ("a", "U-02"), ("b", "U-05")]))
    pointers = [pointer("ha-mar", "2026-03-01T00:00:00Z", resolved=["config_vulnerability|a|U-03"])]
    current = index(config_vulnerability=(["a"], [("a", "U-01"), ("a", "U-03"), ("a", "U-04")]))
    out = host_audit_baseline_compare(current, baseline, pointers, RUN)

    assert out["status"]["config_vulnerability|a|U-01"] == PERSIST
    assert out["status"]["config_vulnerability|a|U-03"] == RECUR   # resolved by a scheduled run 8 months ago
    assert out["status"]["config_vulnerability|a|U-04"] == NEW
    assert out["resolved"] == ["config_vulnerability|a|U-02"]      # host a inspected, finding gone
    assert out["unknown"] == ["config_vulnerability|b|U-05"]       # host b not inspected this run


def test_recurrence_window_is_twelve_months_and_on_demand_resolutions_do_not_count():
    current = index(package_vulnerability=(["a"], [("a", "CVE-1|openssl"), ("a", "CVE-2|bash")]))
    baseline = stored("ha-oct", "2026-10-01T00:00:00Z", package_vulnerability=(["a"], []))
    pointers = [
        pointer("ha-2025-10", "2025-10-15T00:00:00Z", resolved=["package_vulnerability|a|CVE-1|openssl"]),  # >12 months
        pointer("ha-adhoc", "2026-06-01T00:00:00Z", kind="on_demand",
                resolved=["package_vulnerability|a|CVE-2|bash"]),
    ]
    out = host_audit_baseline_compare(current, baseline, pointers, RUN)
    assert out["status"]["package_vulnerability|a|CVE-1|openssl"] == NEW
    assert out["status"]["package_vulnerability|a|CVE-2|bash"] == NEW

    pointers[0]["started_at"] = "2025-11-15T00:00:00Z"   # inside the 12 months before 2026-11-01
    out = host_audit_baseline_compare(current, baseline, pointers, RUN)
    assert out["status"]["package_vulnerability|a|CVE-1|openssl"] == RECUR


def test_without_a_baseline_every_finding_is_first_run_and_nothing_is_resolved():
    current = index(config_vulnerability=(["a"], [("a", "U-01")]),
                    asset_inventory=(["a"], [("a", "account:alice")]))
    out = host_audit_baseline_compare(current, None, [], RUN)
    assert out["status"] == {"config_vulnerability|a|U-01": FIRST}
    assert out["resolved"] == [] and out["asset_changes"] == []


def test_asset_inventory_changes_are_new_or_removed_and_a_new_host_is_not_a_pile_of_changes():
    baseline = stored("ha-oct", "2026-10-01T00:00:00Z",
                      asset_inventory=(["a"], [("a", "account:alice"), ("a", "port:tcp/22")]))
    current = index(asset_inventory=(["a", "z"], [("a", "account:alice"), ("a", "account:mallory"),
                                                  ("a", "privileged:mallory"), ("z", "account:zed")]))
    out = host_audit_baseline_compare(current, baseline, [], RUN)
    changes = {c["key"]: c["change"] for c in out["asset_changes"]}
    assert changes == {"asset_inventory|a|account:mallory": NEW,
                       "asset_inventory|a|privileged:mallory": NEW,
                       "asset_inventory|a|port:tcp/22": REMOVED}
    assert out["status"] == {}, "inventory items are changes, not findings"


# ------------------------------------------------------------------------------
# Report model: badges, cover, stored document
# ------------------------------------------------------------------------------
def section_model():
    """A model as the three section builders leave it (only the parts the baseline reads)."""
    return {
        "cover": {"baseline": ""},
        "asset_inventory": {"hosts": [
            {"host": "a", "collected": True, "accounts": [{"name": "alice", "privilege": "group wheel"}],
             "ports": [{"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}]},
            {"host": "down", "collected": False},
        ]},
        "config_vulnerability": {
            "appendix": {"a": [{"code": "KISA-2026:U-01", "title": "root", "verdict": "취약"},
                               {"code": "KISA-2026:U-07", "title": "manual", "verdict": "점검불가(수동)"},
                               {"code": "KISA-2026:U-04", "title": "shadow", "verdict": "양호"}]},
            "findings": [{"code": "KISA-2026:U-01", "verdict": "취약", "hosts": [{"host": "a", "evidence": "", "note": ""}]}],
        },
        "package_vulnerability": {"status": "ok", "details": [
            {"host": "a", "id": "CVE-1|openssl", "cve": "CVE-1", "package": "openssl"}]},
    }


PACKAGE_RESULTS = [{"host": "a", "status": "ok", "findings": [
    {"id": "CVE-1|openssl", "cve": "CVE-1", "package": "openssl"},
    {"id": "CVE-9|zlib", "cve": "CVE-9", "package": "zlib"}]}]


def test_findings_index_reads_every_section_and_skips_manual_items_and_uninspected_hosts():
    idx = host_audit_findings_index(section_model(), PACKAGE_RESULTS)
    assert [f["id"] for f in idx["config_vulnerability"]["findings"]] == ["KISA-2026:U-01"]
    assert sorted(f["id"] for f in idx["package_vulnerability"]["findings"]) == ["CVE-1|openssl", "CVE-9|zlib"]
    assert idx["asset_inventory"]["hosts"] == ["a"]
    assert sorted(f["id"] for f in idx["asset_inventory"]["findings"]) == [
        "account:alice", "port:tcp/22", "privileged:alice"]


def test_a_new_section_takes_part_through_baseline_findings():
    model = dict(section_model(), configuration_drift={"baseline_findings": {
        "hosts": ["a"], "findings": [{"host": "a", "id": "DOC-011", "label": "daemon.json"}]}})
    idx = host_audit_findings_index(model, PACKAGE_RESULTS)
    assert idx["configuration_drift"]["findings"][0]["id"] == "DOC-011"


def test_section_marks_rows_other_sections_draw_and_builds_the_stored_document():
    baseline = stored("ha-oct", "2026-10-01T00:00:00Z",
                      config_vulnerability=(["a"], [("a", "KISA-2026:U-01"), ("a", "KISA-2026:U-02")]),
                      package_vulnerability=(["a"], [("a", "CVE-9|zlib")]),
                      asset_inventory=(["a"], [("a", "account:alice")]))
    history = {"state": "ok", "baseline": baseline, "pointers": []}
    model = host_audit_baseline_section(section_model(), history, dict(RUN, package_results=PACKAGE_RESULTS))

    host_badge = model["config_vulnerability"]["findings"][0]["hosts"][0]["baseline"]
    assert host_badge["status"] == PERSIST
    assert model["package_vulnerability"]["details"][0]["baseline"]["status"] == NEW
    assert "ha-oct" in model["cover"]["baseline"]
    b = model["baseline"]
    assert b["compared"] and b["baseline_run_id"] == "ha-oct"
    assert [r["item"] for r in b["resolved"]] == ["KISA-2026:U-02 비밀번호 관리정책 설정"]
    assert {(r["kind"], r["item"], r["change"]) for r in b["asset_changes"]} == {
        ("listening 포트", "tcp/22", NEW), ("특수권한자", "alice", NEW)}

    doc = b["document"]
    assert doc["run_kind"] == "scheduled" and doc["baseline_run_id"] == "ha-oct"
    assert doc["resolved"] == ["config_vulnerability|a|KISA-2026:U-02"]
    assert doc["sections"]["package_vulnerability"]["ids"]["a"] == ["CVE-1|openssl", "CVE-9|zlib"]
    assert b["pointer"]["resolved"] == doc["resolved"]


def test_on_demand_run_is_compared_but_records_no_resolutions():
    baseline = stored("ha-oct", "2026-10-01T00:00:00Z", config_vulnerability=(["a"], [("a", "KISA-2026:U-02")]))
    meta = dict(RUN, run_kind="on_demand", package_results=PACKAGE_RESULTS)
    model = host_audit_baseline_section(section_model(), {"state": "ok", "baseline": baseline, "pointers": []}, meta)
    assert [r["status"] for r in model["baseline"]["resolved"]] == [RESOLVED]
    assert model["baseline"]["document"]["resolved"] == [], "an on-demand run never marks the 재발 history"


def test_lookup_failure_and_disabled_storage_leave_findings_unmarked():
    failed = host_audit_baseline_section(section_model(), {"state": "failed", "reason": "status=403"}, RUN)
    assert failed["baseline"]["failed"] and "조회 실패" in failed["cover"]["baseline"] and "403" in failed["cover"]["baseline"]
    assert "baseline" not in failed["config_vulnerability"]["findings"][0]["hosts"][0]
    disabled = host_audit_baseline_section(section_model(), None, RUN)
    assert disabled["baseline"]["state"] == "disabled" and not disabled["baseline"]["failed"]


def test_first_scheduled_run_says_so_on_the_cover():
    model = host_audit_baseline_section(section_model(), {"state": "ok", "baseline": None, "pointers": []},
                                        dict(RUN, package_results=PACKAGE_RESULTS))
    assert "첫 정기 실행" in model["cover"]["baseline"]
    assert model["config_vulnerability"]["findings"][0]["hosts"][0]["baseline"]["status"] == FIRST


def test_report_model_and_template_carry_the_baseline_and_storage_path():
    jinja2 = __import__("jinja2")
    records = [{"inventory_hostname": "ns0332", "status": "ok", "reason": "", "collected_at": "2026-11-01T00:00:01Z",
                "declared": {"fqdn": "", "ip": "", "environment": "prod", "groups": ["servers"]},
                "identity": {"hostname": "ns0332", "fqdn": "ns0332.example", "ips": [], "account": "audit"},
                "os": {"id": "rocky", "version_id": "9.4", "name": "Rocky Linux 9.4", "kernel": "", "arch": ""}}]
    meta = dict(RUN, generated_at="2026-11-01T00:05:00Z", targets=["ns0332"], timezone="Asia/Seoul",
                archive="RustFS host-audit/2026-11/ha-20261101T000000Z/ (3년 보관)",
                baseline_history={"state": "ok", "baseline": None, "pointers": []})
    model = host_audit_report_model(records, meta)
    assert model["baseline"]["document"]["run_id"] == RUN["run_id"]
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    html = env.get_template("report.html.j2").render(host_audit_model=model)
    assert "Audit Baseline 대비 변경" in html
    assert "RustFS host-audit/2026-11/ha-20261101T000000Z/" in html
    assert "첫 정기 실행" in html


# ------------------------------------------------------------------------------
# Storage settings the operator applies, and the playbook wiring
# ------------------------------------------------------------------------------
def test_dedicated_key_policy_grants_put_get_list_only_on_the_host_audit_bucket():
    policy = json.loads((STORAGE_DIR / "host-audit-putget-policy.json").read_text(encoding="utf-8"))
    actions = sorted(a for s in policy["Statement"] for a in s["Action"])
    assert actions == ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
    resources = {r for s in policy["Statement"] for r in s["Resource"]}
    assert resources == {"arn:aws:s3:::host-audit", "arn:aws:s3:::host-audit/*"}
    assert all(s["Effect"] == "Allow" for s in policy["Statement"])


def test_bucket_keeps_objects_three_years():
    lifecycle = json.loads((STORAGE_DIR / "host-audit-lifecycle.json").read_text(encoding="utf-8"))
    (rule,) = lifecycle["Rules"]
    assert rule["Status"] == "Enabled" and rule["Expiration"]["Days"] == 1095
    lock = json.loads((STORAGE_DIR / "host-audit-object-lock.json").read_text(encoding="utf-8"))
    assert lock["Rule"]["DefaultRetention"] == {"Mode": "GOVERNANCE", "Days": 1095}


def _tasks(name):
    return yaml.safe_load((ROLE_DIR / "tasks" / name).read_text(encoding="utf-8"))


def test_storage_never_uses_backup_or_maintenance_keys():
    for name in ("storage_credentials.yml", "storage_lookup.yml", "storage_upload.yml", "storage_result.yml"):
        text = (ROLE_DIR / "tasks" / name).read_text(encoding="utf-8")
        for forbidden in ("maintenance_access_key", "maintenance_secret_key", "backup_access_key", "rustfs_access_key"):
            assert forbidden not in text


def test_pointer_is_uploaded_only_for_a_scheduled_run_after_every_upload_succeeded():
    upload = _tasks("storage_upload.yml")
    pointer_task = next(t for t in upload if "[AUD-515]" in t["name"])
    when = " ".join(pointer_task["when"])
    assert "run_kind == 'scheduled'" in when
    assert "reject('equalto', 200)" in when
    assert all("ansible.builtin.assert" not in t for t in upload), "storage_upload.yml must not fail the run before the mail (#126)"
    final = _tasks("storage_result.yml")[-1]
    assert "ansible.builtin.assert" in final and "[AUD-516]" in final["name"]
    assert "host_audit_baseline_history.state != 'failed'" in final["ansible.builtin.assert"]["that"]


def test_report_builds_the_model_between_lookup_and_upload_and_secrets_stay_hidden():
    report = _tasks("report.yml")
    names = [t.get("name", "") for t in report]
    lookup = next(i for i, t in enumerate(report) if t.get("ansible.builtin.include_tasks") == "storage_lookup.yml")
    build = next(i for i, n in enumerate(names) if "[AUD-021]" in n)
    upload = next(i for i, t in enumerate(report) if t.get("ansible.builtin.include_tasks") == "storage_upload.yml")
    result = next(i for i, t in enumerate(report) if t.get("ansible.builtin.include_tasks") == "storage_result.yml")
    assert lookup < build < upload < result
    for name in ("storage_credentials.yml", "storage_lookup.yml", "storage_upload.yml"):
        for task in _tasks(name):
            if "ansible.builtin.uri" in task or "[AUD-502]" in task.get("name", ""):
                assert task.get("no_log") is True, task["name"]
