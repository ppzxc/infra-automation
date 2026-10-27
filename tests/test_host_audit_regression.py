"""Host Audit Security Regression: judgement, report section, Audit Baseline, alert (Spec #364 / Ticket-10, #377).

필터만 읽는 테스트(ADR-0013, ansible 불필요). 프로브 자체는 tests/test_host_audit_regression_probe.py가 본다.
백업 정책 판정은 서버를 읽지 않고 저장소 정책 JSON과 읽기 전용 수집기(scripts/collect-rustfs-policy.py)의 출력 형식으로 시험한다.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_baseline import host_audit_kisa_alert, host_audit_regression_worsened  # noqa: E402
from host_audit_regression import (  # noqa: E402
    BEGIN, END, ITEMS, host_audit_regression_backup, host_audit_regression_env,
    host_audit_regression_result, host_audit_regression_section)

POLICY = (ROOT_DIR / "roles" / "backup" / "files" / "host-key-policy.json").read_text(encoding="utf-8")
EXPECT_ALL = {
    "mgmt_web_ports": [3000], "mgmt_wildcard_allowed": [22, 443], "mgmt_removed_ports": [9000],
    "recv_syslog_conf": ["/etc/a.conf"], "recv_trap_conf": ["/etc/b.conf"], "ssh_restricted": True,
    "det_journald": True, "det_fail2ban": True, "det_fail2ban_no_firewall": True, "det_auditd": True,
    "det_audit_secret": True, "det_log_agent": True, "sec_roots": ["/opt"], "sec_files": ["/opt/k"],
    "sec_env_files": ["/opt/e.env"],
}
HOST_ITEMS = [c for c, m in ITEMS.items() if m["area"] != "백업 정책"]


def _collector():
    spec = importlib.util.spec_from_file_location("collect_rustfs_policy", ROOT_DIR / "scripts" / "collect-rustfs-policy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _snapshot(policies):
    """수집기가 만드는 service-accounts 구간 형식. policies: {계정 이름: 정책 dict}."""
    mod = _collector()
    out = ["## service-accounts"]
    for i, (name, pol) in enumerate(sorted(policies.items())):
        out.append("%012x name=%s parent=svc status=on implied=false expiration=None" % (i, name))
        out.extend("    " + line for line in mod._statements(pol))
    return "\n".join(out) + "\n"


def _policy_for(bucket, mutate=None):
    pol = json.loads(POLICY.replace("${BUCKET}", bucket))
    if mutate:
        mutate(pol)
    return pol


def _probe(lines):
    return {"stdout": "noise\n%s\n%s\n%s\n" % (BEGIN, "\n".join(lines), END)}


def _results(part):
    return {r["code"]: r["verdict"] for r in part["results"]}


# --- 프로브 출력 -> 판정 --------------------------------------------------------------------
def test_every_declared_item_gets_the_probe_verdict_and_undeclared_ones_are_not_applicable():
    expect = {"ssh_restricted": True}
    part = host_audit_regression_result(_probe(["EXP-SSH-1|PASS", "EXP-SSH-2|FAIL", "EXP-SSH-3|UNK"]), expect)
    got = _results(part)
    assert got["EXP-SSH-1"] == "통과" and got["EXP-SSH-2"] == "실패" and got["EXP-SSH-3"] == "점검불가"
    assert got["EXP-SSH-4"] == "점검불가"  # 선언했는데 프로브가 말하지 않음 -> 통과로 세지 않는다
    assert got["EXP-MGMT-1"] == "해당없음" and got["EXP-SEC-3"] == "해당없음"
    assert sorted(got) == sorted(HOST_ITEMS)


def test_optional_items_are_not_declared_by_the_category_flag_alone():
    got = _results(host_audit_regression_result(_probe(["EXP-DET-2|PASS"]), {"det_fail2ban": True}))
    assert got["EXP-DET-2"] == "통과" and got["EXP-DET-3"] == "해당없음" and got["EXP-DET-4"] == "해당없음"


def test_probe_without_markers_or_unreachable_is_a_failed_collection_not_a_pass():
    for probe in ({"stdout": "nothing"}, {"unreachable": True, "msg": "ssh: no route"}, {"skipped": True}):
        part = host_audit_regression_result(probe, EXPECT_ALL)
        assert part["status"] == "probe_failed" and part["results"] == []


def test_unknown_raw_lines_are_ignored():
    got = _results(host_audit_regression_result(_probe(["EXP-NOPE-1|PASS", "garbage"]), EXPECT_ALL))
    assert set(got.values()) == {"점검불가"}


def test_result_never_carries_values():
    part = host_audit_regression_result(_probe(["EXP-SSH-1|PASS"]), EXPECT_ALL)
    text = json.dumps(part)
    assert set(part) == {"status", "reason", "results"}
    assert all(set(r) == {"code", "verdict"} for r in part["results"])
    assert not re.search(r"\d+\.\d+\.\d+\.\d+|:\d{2,5}|/etc/", text)


# --- 프로브 환경 ----------------------------------------------------------------------------
def test_env_passes_safe_tokens_and_drops_shell_metacharacters():
    env = host_audit_regression_env({"mgmt_web_ports": [3000, "8080; rm -rf /", "$(id)"], "ssh_restricted": True,
                                     "recv_syslog_conf": "/etc/a.conf /etc/b.conf"})
    assert env["HA_MGMT_WEB_PORTS"] == "3000"
    assert env["HA_SSH"] == "1" and env["HA_DET_JOURNALD"] == ""
    assert env["HA_RECV_SYSLOG_CONF"] == "/etc/a.conf /etc/b.conf"


def test_env_with_nothing_declared_is_all_empty():
    assert set(host_audit_regression_env({}).values()) == {""}


# --- 백업 정책 (#373) -----------------------------------------------------------------------
def _backup(policies, **kw):
    return {r["code"]: r["verdict"] for r in host_audit_regression_backup(POLICY, _snapshot(policies), **kw)}


def test_backup_healthy_snapshot_passes_every_item():
    got = _backup({"backup-prod-a": _policy_for("bucket-a"), "backup-prod-b": _policy_for("bucket-b")})
    assert got == {"EXP-BAK-1": "통과", "EXP-BAK-2": "통과", "EXP-BAK-3": "통과"}


def test_backup_repo_policy_widened_fails_bak1():
    wide = json.loads(POLICY)
    wide["Statement"][1]["Action"].append("s3:DeleteObject")
    got = {r["code"]: r["verdict"] for r in host_audit_regression_backup(json.dumps(wide), "")}
    assert got["EXP-BAK-1"] == "실패"
    star = json.loads(POLICY)
    star["Statement"][0]["Action"] = ["s3:*"]
    assert {r["code"]: r["verdict"] for r in host_audit_regression_backup(json.dumps(star), "")}["EXP-BAK-1"] == "실패"


def test_backup_host_key_that_can_delete_everything_fails_shape_but_not_bucket_scope():
    def widen(pol):
        pol["Statement"][2]["Resource"] = ["arn:aws:s3:::bucket-b/*"]
    got = _backup({"backup-prod-a": _policy_for("bucket-a"), "backup-prod-b": _policy_for("bucket-b", widen)})
    assert got["EXP-BAK-2"] == "실패" and got["EXP-BAK-3"] == "통과"


def test_backup_host_key_reaching_another_bucket_or_all_buckets_fails_bak3():
    def other(pol):
        pol["Statement"][1]["Resource"] = ["arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-z/*"]
    assert _backup({"backup-prod-a": _policy_for("bucket-a", other)})["EXP-BAK-3"] == "실패"

    def everything(pol):
        pol["Statement"][1]["Resource"] = ["arn:aws:s3:::*"]
    assert _backup({"backup-prod-a": _policy_for("bucket-a", everything)})["EXP-BAK-3"] == "실패"


def test_backup_account_without_a_policy_fails():
    snap = "## service-accounts\n000000000001 name=backup-prod-a parent=svc status=on implied=true expiration=None\n"
    got = {r["code"]: r["verdict"] for r in host_audit_regression_backup(POLICY, snap)}
    assert got["EXP-BAK-2"] == "실패" and got["EXP-BAK-3"] == "실패"


def test_backup_without_snapshot_or_matching_accounts_is_not_a_pass():
    for snap in ("", _snapshot({"other-account": _policy_for("x")})):
        got = {r["code"]: r["verdict"] for r in host_audit_regression_backup(POLICY, snap)}
        assert got["EXP-BAK-1"] == "통과" and got["EXP-BAK-2"] == got["EXP-BAK-3"] == "점검불가"
    assert {r["verdict"] for r in host_audit_regression_backup("", "")} == {"점검불가"}


# --- 보고서 섹션과 Audit Baseline ------------------------------------------------------------
def _record(host, verdicts, status="ok"):
    part = {"status": "ok", "reason": "", "results": [{"code": c, "verdict": v} for c, v in verdicts.items()]}
    return {"inventory_hostname": host, "status": status, "security_regression": part}


def _model(records, backup=None):
    meta = {"run_id": "ha-2", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z", "targets": [r["inventory_hostname"] for r in records],
            "regression_backup": backup}
    return host_audit_report_model(records, meta)


def test_section_absent_when_nothing_was_judged():
    assert "security_regression" not in host_audit_report_model([{"inventory_hostname": "h1", "status": "ok"}], {"targets": ["h1"]})


def test_section_counts_findings_and_failed_collections():
    recs = [_record("h1", {"EXP-SSH-1": "통과", "EXP-SSH-2": "실패", "EXP-DET-1": "점검불가"}),
            {"inventory_hostname": "h2", "status": "ok", "security_regression": {"status": "probe_failed", "reason": "표식 없음", "results": []}}]
    sec = _model(recs, backup=[{"code": "EXP-BAK-1", "verdict": "실패"}])["security_regression"]
    assert sec["failed_total"] == 2 and sec["unknown_total"] == 1
    ids = {(f["host"], f["id"]) for f in sec["baseline_findings"]["findings"]}
    assert ids == {("h1", "EXP-SSH-2"), ("backup-storage", "EXP-BAK-1")}
    assert sorted(sec["baseline_findings"]["hosts"]) == ["backup-storage", "h1"]  # 수집에 실패한 h2는 비교 대상이 아니다
    model = _model(recs)
    assert any(u["host"] == "h2" and u["item"] == "Security Regression" for u in model["unavailable"])


def test_failed_items_are_findings_of_the_audit_baseline_document():
    model = _model([_record("h1", {"EXP-SSH-2": "실패", "EXP-SSH-1": "통과"})])
    doc = model["baseline"]["document"]["sections"]["security_regression"]
    assert doc == {"hosts": ["h1"], "ids": {"h1": ["EXP-SSH-2"]}}


def _baseline(hosts, ids):
    return {"run_id": "ha-1", "sections": {"security_regression": {"hosts": hosts, "ids": ids}}}


def test_worsened_is_per_item_and_only_for_hosts_the_baseline_inspected():
    model = _model([_record("h1", {"EXP-SSH-2": "실패", "EXP-DET-1": "실패"}), _record("h3", {"EXP-SSH-2": "실패"})])
    worse = host_audit_regression_worsened(model, _baseline(["h1"], {"h1": ["EXP-DET-1"]}))
    assert [(w["host"], w["id"]) for w in worse] == [("h1", "EXP-SSH-2")]
    assert host_audit_regression_worsened(model, None) == []
    assert host_audit_regression_worsened(model, _baseline([], {})) == []


def test_alert_includes_regression_items_and_carries_no_address_or_secret():
    model = _model([_record("h1", {"EXP-SSH-2": "실패"})], backup=[{"code": "EXP-BAK-3", "verdict": "실패"}])
    base = _baseline(["h1", "backup-storage"], {})
    plan = host_audit_kisa_alert(model, {"run_id": "ha-2", "run_kind": "scheduled"}, {"state": "ok", "baseline": base})
    assert plan["send"] and plan["count"] == 2 and plan["hosts"] == 2
    assert "• h1: EXP-SSH-2" in plan["text"] and "• backup-storage: EXP-BAK-3" in plan["text"]
    assert "보안 퇴행" in plan["text"] and len(plan["text"]) <= 5000
    assert not re.search(r"\d+\.\d+\.\d+\.\d+|https?://|@|:\d{2,5}", plan["text"].replace("ha-2", ""))


def test_alert_not_sent_for_on_demand_or_when_nothing_got_worse():
    model = _model([_record("h1", {"EXP-SSH-2": "실패"})])
    base = _baseline(["h1"], {"h1": ["EXP-SSH-2"]})  # 지난달에도 실패 -> 지속, 악화 아님
    assert host_audit_kisa_alert(model, {"run_kind": "scheduled"}, {"state": "ok", "baseline": base})["send"] is False
    assert host_audit_kisa_alert(model, {"run_kind": "on_demand"}, {"state": "ok", "baseline": _baseline(["h1"], {})})["send"] is False


def test_the_report_model_json_has_no_infra_detail():
    model = _model([_record("h1", {c: "통과" for c in HOST_ITEMS})], backup=[{"code": "EXP-BAK-1", "verdict": "통과"}])
    text = json.dumps(model["security_regression"], ensure_ascii=False)
    assert not re.search(r"\d+\.\d+\.\d+\.\d+|:\d{2,5}\b", text)
