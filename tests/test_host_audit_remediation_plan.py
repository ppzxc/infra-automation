"""Host Audit Remediation Plan rows (Spec #488 / Ticket-6, #494): the pure row filter.

Direct filter tests (ADR-0013): the report model of a few synthetic hosts goes in, header, rows and footer come out.
"""
import copy
import inspect
import sys
from collections.abc import Mapping
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

import host_audit_remediation_plan as plan_module  # noqa: E402
from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import ITEMS, REMEDIATION_SOURCE, host_audit_kisa_result  # noqa: E402
from host_audit_remediation_plan import (  # noqa: E402
    HEADERS, NO_FINDINGS, NO_RESULT, host_audit_remediation_file_name, host_audit_remediation_plan,
    host_audit_remediation_plans)

TODAY = "2026-10-09"
ALL = list(range(1, 68))
COL = {name: i for i, name in enumerate(HEADERS)}


def _exception(code, **kw):
    entry = {"code": "KISA-2026:" + code, "reason": "R-reason", "risk": "R-risk", "mitigation": "R-mitig",
             "approver": "R-approver", "approved_on": "2026-09-01", "expires_on": "2027-09-01"}
    entry.update(kw)
    return entry


def _record(host, overrides, os_id="rocky", admin="관리자-직책", register=()):
    lines = ["U-%02d|%s|ev-%02d" % (i, overrides.get(i, "GOOD"), i) for i in ALL]
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n",
             "stderr": ""}
    asset = {"admin_role": admin, "lookup": "ok"}
    if admin is None:
        asset = {"lookup": "failed"}
    return {"inventory_hostname": host, "status": "ok", "reason": "", "schema_version": 2,
            "declared": {"groups": ["servers"], "asset": asset}, "identity": {"account": "root"},
            "os": {"id": os_id, "name": "OS"},
            "config_vulnerability": host_audit_kisa_result(probe, list(register), host, ["servers"], TODAY)}


def _model(records, register=(), history=None):
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": [r["inventory_hostname"] for r in records], "kisa_exceptions": list(register)}
    if history is not None:
        meta["baseline_history"] = history
    return host_audit_report_model(records, meta)


def _rows(plan, code):
    title = ITEMS[code]["title"]
    return [r for r in plan["rows"] if r[COL["통제내용"]] == "%s %s" % (code, title)]


def test_rows_are_only_non_good_items_one_row_each():
    reg = [_exception("U-04")]
    model = _model([_record("h1", {1: "VULN", 2: "MANUAL", 3: "NA", 4: "VULN"}, register=reg)], reg)
    plan = host_audit_remediation_plan(model, "h1")
    assert plan["headers"] == HEADERS
    codes = sorted(r[COL["통제내용"]][:4] for r in plan["rows"])
    assert codes == ["U-01", "U-02", "U-04"]  # 양호 and 해당없음 are not rows; 예외(승인) is
    assert all(r[COL["자산명"]] == "h1" for r in plan["rows"])


def test_a_host_without_findings_has_one_line():
    plan = host_audit_remediation_plan(_model([_record("h1", {})]), "h1")
    assert len(plan["rows"]) == 1
    assert plan["rows"][0][COL["통제내용"]] == NO_FINDINGS == "양호 외 항목 없음"
    assert plan["rows"][0][COL["자산명"]] == "h1"


def test_a_host_without_check_results_is_not_called_clean():
    rec = _record("h1", {})
    rec["config_vulnerability"] = {"status": "failed", "reason": "x", "results": []}
    plan = host_audit_remediation_plan(_model([rec]), "h1")
    assert [r[COL["통제내용"]] for r in plan["rows"]] == [NO_RESULT]
    assert NO_RESULT != NO_FINDINGS


def test_steps_follow_the_host_family_else_summary():
    model = _model([_record("el", {2: "VULN", 1: "VULN"}, os_id="rocky"),
                    _record("de", {2: "VULN", 1: "VULN"}, os_id="ubuntu"),
                    _record("xx", {2: "VULN", 1: "VULN"}, os_id="")])
    steps = ITEMS["U-02"]["remediation"]["steps"]
    assert "rhel" in steps and "debian" in steps  # U-02 differs by family
    assert "steps" not in ITEMS["U-01"]["remediation"]  # U-01 has only the summary

    def cell(host, code):
        return _rows(host_audit_remediation_plan(model, host), code)[0][COL["조치방법"]]

    assert cell("el", "U-02") == steps["rhel"].strip()
    assert cell("de", "U-02") == steps["debian"].strip()
    assert cell("xx", "U-02") == ITEMS["U-02"]["remediation"]["summary"]  # unknown family -> summary
    assert cell("el", "U-01") == ITEMS["U-01"]["remediation"]["summary"]


def test_a_family_without_steps_falls_back_to_the_summary(monkeypatch):
    """No shipped item has steps for only one family, so the catalog seen by the filter is patched for this case."""
    patched = dict(ITEMS)
    meta = dict(ITEMS["U-02"])
    meta["remediation"] = {"summary": meta["remediation"]["summary"], "steps": {"rhel": "only rhel steps\n"}}
    patched["U-02"] = meta
    monkeypatch.setattr(plan_module, "ITEMS", patched)
    model = _model([_record("de", {2: "VULN"}, os_id="debian"), _record("el", {2: "VULN"}, os_id="rocky")])
    de = _rows(host_audit_remediation_plan(model, "de"), "U-02")[0]
    el = _rows(host_audit_remediation_plan(model, "el"), "U-02")[0]
    assert de[COL["조치방법"]] == meta["remediation"]["summary"]
    assert el[COL["조치방법"]] == "only rhel steps"


def test_owner_cell_is_the_asset_inventory_administrator_role_as_shown():
    ok = host_audit_remediation_plan(_model([_record("h1", {1: "VULN"})]), "h1")
    assert ok["rows"][0][COL["담당자"]] == "관리자-직책"
    failed = host_audit_remediation_plan(_model([_record("h2", {1: "VULN"}, admin=None)]), "h2")
    assert failed["rows"][0][COL["담당자"]] == "조회 실패"
    empty = host_audit_remediation_plan(_model([_record("h3", {1: "VULN"}, admin="")]), "h3")
    assert empty["rows"][0][COL["담당자"]] == "미지정"
    clean = host_audit_remediation_plan(_model([_record("h4", {}, admin="")]), "h4")
    assert clean["rows"][0][COL["담당자"]] == "미지정"


def test_a_host_the_asset_inventory_does_not_know_is_lookup_failed_not_unassigned():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"})]))
    model["asset_inventory"]["hosts"] = []
    assert host_audit_remediation_plan(model, "h1")["rows"][0][COL["담당자"]] == "조회 실패"


def test_a_host_that_was_never_reached_is_lookup_failed_not_unassigned():
    model = host_audit_report_model([], {"run_id": "ha-1", "targets": ["ns1"], "started_at": "2026-10-08T22:00:05Z"})
    plan = host_audit_remediation_plan(model, "ns1")
    assert plan["rows"][0][COL["담당자"]] == "조회 실패"
    assert plan["rows"][0][COL["통제내용"]] == NO_RESULT


def test_an_item_the_catalog_lacks_is_named_as_such():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"})]))
    model["config_vulnerability"]["findings"][0]["code"] = "KISA-2026:U-99"
    row = host_audit_remediation_plan(model, "h1")["rows"][0]
    assert row[COL["통제내용"]] == "U-99 (카탈로그에 없는 항목)"


def test_one_odd_host_does_not_stop_the_plans_of_the_others():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"}), _record("h2", {1: "VULN"})]))
    model["config_vulnerability"]["findings"][0]["hosts"][0].pop("evidence")  # h1's entry is broken
    plans = {p["host"]: p for p in host_audit_remediation_plans(model)}
    assert plans["h1"]["rows"][0][COL["통제내용"]] == "이행계획서 생성 실패 (KeyError: 'evidence')"
    assert plans["h1"]["error"] == "KeyError: 'evidence'" and "error" not in plans["h2"]
    assert plans["h1"]["rows"][0][COL["담당자"]] == "관리자-직책"  # the owner is still the known role
    assert plans["h2"]["rows"][0][COL["통제내용"]].startswith("U-01 ")


def test_a_broken_asset_inventory_entry_still_gives_every_host_a_plan():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"}), _record("h2", {1: "VULN"})]))
    model["asset_inventory"]["hosts"].insert(0, "not a dict")  # breaks the owner lookup for every host
    plans = {p["host"]: p for p in host_audit_remediation_plans(model)}
    assert set(plans) == {"h1", "h2"}
    assert plans["h1"]["rows"][0][COL["담당자"]] == "조회 실패"
    assert plans["h1"]["rows"][0][COL["통제내용"]].startswith("이행계획서 생성 실패 (AttributeError")


def test_a_register_view_with_missing_keys_only_blanks_the_remark():
    reg = [_exception("U-01")]
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"}, register=reg)], reg))
    exc = model["config_vulnerability"]["findings"][0]["hosts"][0]["exception"]
    exc.pop("reason")
    exc.pop("approver")
    assert "사유: - / 위험: R-risk" in host_audit_remediation_plan(model, "h1")["rows"][0][COL["비고"]]


def test_columns_carry_catalog_and_derived_values():
    plan = host_audit_remediation_plan(_model([_record("h1", {1: "VULN", 12: "MANUAL"})]), "h1")
    u01 = _rows(plan, "U-01")[0]
    meta = ITEMS["U-01"]
    assert u01[COL["그룹"]] == meta["category"]
    assert u01[COL["점검방법"]] == meta["check"]
    assert u01[COL["취약점현황"]] == "취약: ev-01"
    assert u01[COL["위험도"]] == 3 and u01[COL["우선순위"]] == 1 and u01[COL["시급성"]] == "단기"
    assert u01[COL["영향도"]] == meta["remediation_impact"]["level"]
    assert u01[COL["환경성"]] == meta["remediation_effort"]["level"]
    u12 = _rows(plan, "U-12")[0]
    assert u12[COL["취약점현황"]] == "점검불가(수동): ev-12"
    assert u12[COL["위험도"]] == 1 and u12[COL["우선순위"]] == 3 and u12[COL["시급성"]] == "장기"


def test_status_cell_has_the_note_the_html_appendix_shows():
    reg = [_exception("U-01")]
    plan = host_audit_remediation_plan(_model([_record("h1", {1: "VULN"}, register=reg)], reg), "h1")
    assert _rows(plan, "U-01")[0][COL["취약점현황"]] == "예외(승인): ev-01\n예외 승인 (만료 2027-09-01)"


def test_human_columns_are_blank():
    plan = host_audit_remediation_plan(_model([_record("h1", {1: "VULN"})]), "h1")
    row = plan["rows"][0]
    assert row[COL["이행과제"]] == "" and row[COL["이행 결과"]] == ""


def test_rows_are_sorted_by_priority_then_impact_then_effort():
    ids = {1: "VULN", 2: "VULN", 12: "VULN", 28: "VULN", 40: "VULN", 55: "VULN"}
    plan = host_audit_remediation_plan(_model([_record("h1", ids)]), "h1")
    keys = [(r[COL["우선순위"]], r[COL["영향도"]], r[COL["환경성"]]) for r in plan["rows"]]
    assert keys == sorted(keys) and len(keys) == 6


def _remarks(verdicts, register=(), history=None):
    model = _model([_record("h1", verdicts, register=register)], register, history)
    plan = host_audit_remediation_plan(model, "h1")
    return {r[COL["통제내용"]][:4]: r[COL["비고"]] for r in plan["rows"]}


def test_remark_of_an_approved_exception():
    reg = [_exception("U-01")]
    assert _remarks({1: "VULN"}, reg)["U-01"] == (
        "예외(승인) — 사유: R-reason / 위험: R-risk / 보완: R-mitig / 승인: R-approver 2026-09-01 / 만료: 2027-09-01")


def test_remark_of_an_expired_exception_and_a_pending_one():
    expired = [_exception("U-01", expires_on="2026-09-30")]
    assert _remarks({1: "VULN"}, expired)["U-01"] == "예외 만료(2026-09-30)"
    pending = [_exception("U-01", approver="", approved_on="")]
    assert _remarks({1: "VULN"}, pending)["U-01"] == "예외 승인 대기"


def test_remark_is_blank_without_exception_or_baseline():
    assert _remarks({1: "VULN"})["U-01"] == ""


def _history():
    return {"state": "ok", "pointers": [], "baseline": {
        "run_id": "ha-0", "started_at": "2026-09-08T22:00:00Z",
        "sections": {"config_vulnerability": {"hosts": ["h1"], "ids": {"h1": ["KISA-2026:U-01"]}}}}}


def test_baseline_state_prefixes_the_remark():
    reg = [_exception("U-02")]
    remarks = _remarks({1: "VULN", 2: "VULN", 12: "MANUAL"}, reg, _history())
    assert remarks["U-01"] == "[지속]"
    assert remarks["U-02"].startswith("[신규] 예외(승인) — 사유: ")
    assert remarks["U-12"] == ""  # 점검불가(수동) never gets a Baseline state


def test_recurrence_prefix_is_passed_through():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"})], history=_history()))
    model["config_vulnerability"]["findings"][0]["hosts"][0]["baseline"] = {"status": "재발", "class": "crit"}
    plan = host_audit_remediation_plan(model, "h1")
    assert plan["rows"][0][COL["비고"]] == "[재발]"


def test_manual_row_gets_no_prefix_even_if_the_model_carries_a_state():
    model = copy.deepcopy(_model([_record("h1", {12: "MANUAL"})]))
    model["config_vulnerability"]["findings"][0]["hosts"][0]["baseline"] = {"status": "신규", "class": "crit"}
    assert host_audit_remediation_plan(model, "h1")["rows"][0][COL["비고"]] == ""


def test_first_run_without_a_baseline_has_no_prefix():
    history = {"state": "ok", "pointers": [], "baseline": None}
    assert _remarks({1: "VULN"}, history=history)["U-01"] == ""


def test_footer_has_the_source_sentence_and_run_id():
    plan = host_audit_remediation_plan(_model([_record("h1", {1: "VULN"})]), "h1")
    assert plan["footer"] == [REMEDIATION_SOURCE, "실행 ID: ha-1"]


def test_an_unknown_catalog_code_gives_blank_level_cells_not_none():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"})]))
    finding = model["config_vulnerability"]["findings"][0]
    finding.update(code="KISA-2026:U-99", risk=None, priority=None, urgency=None, impact_level=None,
                   effort_level=None, remediation_summary="")
    row = host_audit_remediation_plan(model, "h1")["rows"][0]
    assert all(cell is not None for cell in row)
    assert [row[COL[k]] for k in ("위험도", "시급성", "영향도", "환경성", "우선순위", "점검방법")] == [""] * 6


def test_only_the_three_baseline_states_prefix_the_remark():
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"})]))
    host = model["config_vulnerability"]["findings"][0]["hosts"][0]
    for state in ("확인 불가", "삭제", "해소", "첫 실행"):
        host["baseline"] = {"status": state, "class": "na"}
        assert host_audit_remediation_plan(model, "h1")["rows"][0][COL["비고"]] == "", state


def test_a_missing_exception_date_is_shown_as_a_dash_like_the_register_table():
    reg = [_exception("U-01", approved_on="not-a-date")]  # pending: no valid approval date
    assert _remarks({1: "VULN"}, reg)["U-01"] == "예외 승인 대기"
    model = copy.deepcopy(_model([_record("h1", {1: "VULN"}, register=[_exception("U-01")])], [_exception("U-01")]))
    exc = model["config_vulnerability"]["findings"][0]["hosts"][0]["exception"]
    exc["approved_on"] = ""
    assert "승인: R-approver - / 만료" in host_audit_remediation_plan(model, "h1")["rows"][0][COL["비고"]]


def test_plans_of_every_host_come_with_their_file_names():
    model = _model([_record("h1", {1: "VULN"}), _record("h2", {})])
    plans = host_audit_remediation_plans(model)
    assert [(p["host"], p["file_name"]) for p in plans] == [
        ("h1", "host-audit-ha-1-h1.xlsx"), ("h2", "host-audit-ha-1-h2.xlsx")]
    assert plans[0]["rows"] == host_audit_remediation_plan(model, "h1")["rows"]


def test_file_name_is_ascii_and_safe():
    assert host_audit_remediation_file_name("ha-1", "ns0331") == "host-audit-ha-1-ns0331.xlsx"
    import hashlib
    suffix = hashlib.sha256("../a b/한".encode()).hexdigest()[:8]
    assert host_audit_remediation_file_name("ha-1", "../a b/한") == "host-audit-ha-1-.._a_b__-%s.xlsx" % suffix
    assert host_audit_remediation_file_name("r", "ns1 ") != host_audit_remediation_file_name("r", "ns1_")
    assert "/" not in host_audit_remediation_file_name("r", "a/b")
    long_name = host_audit_remediation_file_name("r", "h" * 300)
    assert len(long_name) < 200 and long_name != host_audit_remediation_file_name("r", "h" * 301)
    assert host_audit_remediation_file_name("r", "a\ud800").startswith("host-audit-r-a_-")  # a lone surrogate cannot break it


def test_os_families_are_the_step_families_of_the_catalog():
    from host_audit import OS_FAMILIES
    from host_audit_kisa import STEP_FAMILIES
    assert set(OS_FAMILIES.values()) <= set(STEP_FAMILIES)


def test_the_report_model_names_the_os_family():
    assert _model([_record("h1", {}, os_id="ubuntu")])["inventory"][0]["os_family"] == "debian"
    assert _model([_record("h1", {}, os_id="rhel-family")])["inventory"][0]["os_family"] == "rhel"
    assert _model([_record("h1", {}, os_id="")])["inventory"][0]["os_family"] == ""


# ------------------------------------------------------------------ cell source rule

_CONNECTORS = ["예외(승인) — 사유: ", " — 사유: ", " / 위험: ", " / 보완: ", " / 승인: ", " / 만료: ", "예외 만료(", "예외(", "예외 승인 대기",
               "취약", "점검불가(수동)", "예외(승인)", "실행 ID: ", ": ", "\n", "[", "]", ")", " / ", " — ", " "]


def _strings(value, out):
    if isinstance(value, Mapping):
        for k, v in value.items():
            _strings(k, out)
            _strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _strings(v, out)
    elif isinstance(value, str) and value:
        out.update((value, value.strip()))
        out.update(line.strip() for line in value.splitlines() if line.strip())
    return out


def _strip(cell, groups):
    for texts in groups:
        for text in sorted(texts, key=len, reverse=True):
            cell = cell.replace(text, "\0")
    return cell.replace("\0", "")


def _residue(cell, known):
    """What is left of a cell after taking out known values and the fixed connector words (either order, since a
    connector such as '예외 만료(' may overlap a short known value such as '만료')."""
    return min(_strip(cell, (known, _CONNECTORS)), _strip(cell, (_CONNECTORS, known)), key=len)


def test_every_string_cell_is_made_of_values_the_model_or_the_catalog_already_has():
    reg = [_exception("U-01"), _exception("U-04", expires_on="2026-09-30"), _exception("U-05", approver="")]
    records = [_record("h1", {1: "VULN", 2: "MANUAL", 4: "VULN", 5: "VULN", 12: "VULN"}, register=reg),
               _record("h2", {2: "VULN"}, os_id="ubuntu", admin="")]
    model = _model(records, reg, _history())
    known = _strings(model, set()) | _strings(ITEMS, set())
    known |= {REMEDIATION_SOURCE, NO_FINDINGS, NO_RESULT} | set(HEADERS)
    checked = 0
    for host in ("h1", "h2"):
        plan = host_audit_remediation_plan(model, host)
        for row in plan["rows"] + [[line] for line in plan["footer"]]:
            for cell in row:
                if isinstance(cell, str):
                    assert _residue(cell, known) == "", cell
                    checked += 1
    assert checked > 40


def test_the_filter_reads_nothing_beyond_the_model_and_the_catalog():
    source = inspect.getsource(plan_module)
    assert "open(" not in source and "lookup(" not in source and "environ" not in source


def test_zip_name_is_ascii_and_follows_the_xlsx_naming_rule():
    from host_audit_remediation_plan import host_audit_remediation_zip_name
    assert host_audit_remediation_zip_name("ha-20261031T220000Z") == "host-audit-ha-20261031T220000Z-xlsx.zip"
    odd = host_audit_remediation_zip_name("월간 점검/1")
    assert odd.isascii() and odd.endswith("-xlsx.zip") and "/" not in odd and " " not in odd
    assert odd != host_audit_remediation_zip_name("월간 점검/2")


# ------------------------------------------------------------------------------
# Total workbook: the rows of every host in one sheet (follow-up of #488)
# ------------------------------------------------------------------------------
def host_audit_remediation_total(model):
    from host_audit_remediation_plan import host_audit_remediation_files
    files = host_audit_remediation_files(model)
    return next((p for p in files.values() if p['zip_member'] == 'total.xlsx'), {})


def _total_model():
    return _model([_record("h2", {1: "VULN", 2: "VULN"}), _record("h1", {1: "VULN", 12: "VULN"}, admin="직책-A"),
                   _record("h3", {})])


def test_the_total_has_the_rows_of_every_host_with_the_same_columns():
    model = _total_model()
    total = host_audit_remediation_total(model)
    assert total["headers"] == HEADERS and total["sheet"] == host_audit_remediation_plan(model, "h1")["sheet"]
    per_host = [r for h in ("h1", "h2") for r in host_audit_remediation_plan(model, h)["rows"]]
    assert sorted(total["rows"], key=repr) == sorted(per_host, key=repr)
    assert {r[COL["자산명"]] for r in total["rows"]} == {"h1", "h2"}  # h3 is clean: no line of its own
    assert {r[COL["담당자"]] for r in total["rows"] if r[COL["자산명"]] == "h1"} == {"직책-A"}


def test_the_total_is_sorted_by_priority_impact_effort_then_host_then_code():
    model = _model([_record("h2", {1: "VULN", 2: "VULN", 12: "VULN"}), _record("h1", {1: "VULN", 2: "VULN", 28: "VULN"})])
    rows = host_audit_remediation_total(model)["rows"]
    keys = [(r[COL["우선순위"]], r[COL["영향도"]], r[COL["환경성"]], r[COL["자산명"]], r[COL["통제내용"]]) for r in rows]
    assert keys == sorted(keys) and len(keys) == 6
    same = [r for r in rows if r[COL["통제내용"]].startswith("U-01 ")]
    assert [r[COL["자산명"]] for r in same] == ["h1", "h2"]  # equal level: host name order


def test_a_total_without_any_non_good_item_is_one_line():
    total = host_audit_remediation_total(_model([_record("h1", {}), _record("h2", {})]))
    assert total["rows"] == [[""] * 3 + [NO_FINDINGS] + [""] * (len(HEADERS) - 4)]


def test_a_host_without_check_results_keeps_its_line_in_the_total():
    model = _model([_record("h1", {1: "VULN"}), _record("h2", {})], )
    model["config_vulnerability"]["appendix"].pop("h2")
    rows = host_audit_remediation_total(model)["rows"]
    assert [r[COL["자산명"]] for r in rows if r[COL["통제내용"]] == NO_RESULT] == ["h2"]
    assert rows[-1][COL["통제내용"]] == NO_RESULT  # no data sorts after the items


def test_the_total_has_the_footer_and_its_own_file_name_and_member():
    model = _total_model()
    total = host_audit_remediation_total(model)
    assert total["footer"] == host_audit_remediation_plan(model, "h1")["footer"]
    assert total["file_name"] == "host-audit-ha-1-total.xlsx" and total["zip_member"] == "total.xlsx"


def test_a_run_without_hosts_has_no_total():
    assert host_audit_remediation_total(_model([])) == {}


def test_a_host_that_breaks_its_plan_still_has_its_line_in_the_total(monkeypatch):
    model = _model([_record("h1", {1: "VULN"}), _record("h2", {1: "VULN"})])
    real = plan_module._host_findings

    def boom(model, host):
        if host == "h2":
            raise ValueError("odd record")
        return real(model, host)

    monkeypatch.setattr(plan_module, "_host_findings", boom)
    rows = host_audit_remediation_total(model)["rows"]
    assert [r[COL["자산명"]] for r in rows] == ["h1", "h2"]
    assert rows[1][COL["통제내용"]].startswith(plan_module.PLAN_FAILED)


def test_a_run_without_hosts_has_no_files():
    from host_audit_remediation_plan import host_audit_remediation_files
    assert host_audit_remediation_files(_model([])) == {}


def test_the_total_has_a_label_that_is_not_a_host_name():
    total = host_audit_remediation_total(_total_model())
    assert total["label"] == "합계 xlsx" and total["kind"] == "total"


def test_each_plan_names_its_zip_member_under_hosts():
    model = _total_model()
    plans = host_audit_remediation_plans(model)
    assert [p["zip_member"] for p in plans] == ["hosts/h1.xlsx", "hosts/h2.xlsx", "hosts/h3.xlsx"]
    assert [p["label"] for p in plans] == ["h1", "h2", "h3"]


def test_a_host_named_total_does_not_take_the_name_of_the_total():
    from host_audit_remediation_plan import host_audit_remediation_files
    model = _model([_record("total", {1: "VULN"}), _record("h1", {})])
    by_file = host_audit_remediation_files(model)
    assert len(by_file) == 3 and "host-audit-ha-1-total.xlsx" in by_file
    assert by_file["host-audit-ha-1-total.xlsx"]["zip_member"] == "total.xlsx"


def test_a_host_listed_twice_has_one_file_and_is_not_counted_twice_in_the_total():
    from host_audit_remediation_plan import host_audit_remediation_files
    model = _model([_record("h1", {1: "VULN"}), _record("h2", {})])
    once = host_audit_remediation_total(model)["rows"]
    model["hosts"] = ["h1", "h1", "h2"]
    files = host_audit_remediation_files(model)
    assert len(files) == 3 and host_audit_remediation_total(model)["rows"] == once


def test_a_host_named_total_in_another_case_does_not_take_the_name_of_the_total_either():
    from host_audit_remediation_plan import host_audit_remediation_files
    model = _model([_record("TOTAL", {1: "VULN"})])
    names = sorted(host_audit_remediation_files(model))
    assert len(names) == 2 and "host-audit-ha-1-TOTAL.xlsx" not in names


def test_zip_members_map_every_file_to_its_folder_name():
    from host_audit_remediation_plan import host_audit_remediation_files, host_audit_remediation_zip_members
    model = _total_model()
    by_file = host_audit_remediation_files(model)
    assert host_audit_remediation_zip_members(by_file) == {
        "host-audit-ha-1-total.xlsx": "total.xlsx", "host-audit-ha-1-h1.xlsx": "hosts/h1.xlsx",
        "host-audit-ha-1-h2.xlsx": "hosts/h2.xlsx", "host-audit-ha-1-h3.xlsx": "hosts/h3.xlsx"}


def test_every_string_cell_of_the_total_is_made_of_values_the_model_or_the_catalog_already_has():
    reg = [_exception("U-01")]
    model = _model([_record("h1", {1: "VULN", 2: "MANUAL"}, register=reg), _record("h2", {2: "VULN"}, admin="")],
                   reg, _history())
    known = _strings(model, set()) | _strings(ITEMS, set()) | {REMEDIATION_SOURCE, NO_FINDINGS, NO_RESULT} | set(HEADERS)
    total = host_audit_remediation_total(model)
    checked = 0
    for row in total["rows"] + [[line] for line in total["footer"]]:
        for cell in row:
            if isinstance(cell, str):
                assert _residue(cell, known) == "", cell
                checked += 1
    assert checked > 10


def test_the_total_puts_the_verdict_after_the_levels_and_before_the_host():
    reg = [_exception("U-01")]
    model = _model([_record("h1", {1: "MANUAL"}), _record("h2", {1: "VULN"}), _record("h3", {1: "VULN"}, register=reg)],
                   reg)
    rows = host_audit_remediation_total(model)["rows"]
    same = [r for r in rows if r[COL["통제내용"]].startswith("U-01 ")]
    order = [(r[COL["자산명"]], r[COL["취약점현황"]].split(":")[0]) for r in same]
    assert order == [("h2", "취약"), ("h1", "점검불가(수동)"), ("h3", "예외(승인)")]
    assert len({(r[COL["우선순위"]], r[COL["영향도"]], r[COL["환경성"]]) for r in same}) == 1  # only the verdict differs


def test_a_host_sheet_keeps_its_own_order_and_the_total_changes_nothing_in_it():
    model = _model([_record("h1", {1: "MANUAL", 2: "VULN"})])
    before = host_audit_remediation_plan(model, "h1")["rows"]
    host_audit_remediation_total(model)
    assert host_audit_remediation_plan(model, "h1")["rows"] == before
