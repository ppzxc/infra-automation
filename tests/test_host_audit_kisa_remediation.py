"""Host Audit remediation data (Spec #488 / Ticket-2, #490): catalog completeness, derived values, report column.

Pure filter tests for the derived values and the ordering (ADR-0013: many direct filter tests, few integrations);
the HTML assertions render the report template once per module and read the visible text.
"""
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
FILTER_DIR = ROOT_DIR / "filter_plugins"
sys.path.insert(0, str(FILTER_DIR))

import host_audit_kisa as kisa  # noqa: E402
from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import ITEMS, host_audit_kisa_result  # noqa: E402

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
CODES = ["U-%02d" % i for i in range(1, 68)]
TODAY = "2026-10-09"
SOURCE_SENTENCE = ("조치방법은 KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」를 "
                   "바탕으로 요약함")

# Items whose "조치 시 영향" the 2026 guide describes individually instead of "영향 없음" (U-05 and U-50 are
# conditional "영향 없음" and stay 1). Counted from the guide, independent of the catalog.
INDIVIDUALLY_DESCRIBED = {"U-02", "U-03", "U-04", "U-06", "U-10", "U-12", "U-19", "U-23", "U-28", "U-41", "U-45",
                          "U-49", "U-56", "U-57", "U-66"}


# ---------------------------------------------------------------- catalog completeness (all 67)


def _catalog():
    return yaml.safe_load((FILTER_DIR / "host_audit_kisa_items.yml").read_text(encoding="utf-8"))


def test_every_item_has_the_remediation_fields():
    data = _catalog()
    assert sorted(data) == CODES
    for code, meta in data.items():
        for field in ("check", "purpose", "threat"):
            assert isinstance(meta.get(field), str) and meta[field].strip() == meta[field] != "", (code, field)
        assert isinstance(meta["remediation"]["summary"], str) and meta["remediation"]["summary"].strip(), code
        for field in ("remediation_impact", "remediation_effort"):
            level = meta[field]["level"]
            assert type(level) is int and level in (1, 2, 3), (code, field)
            assert isinstance(meta[field]["reason"], str) and meta[field]["reason"].strip(), (code, field)
        page = meta["guide_page"]
        assert type(page) is int and 7 <= page <= 171, code  # Unix server chapter of the 2026 guide


def test_steps_only_use_rhel_and_debian_keys_with_text():
    stepped = 0
    for code, meta in _catalog().items():
        steps = meta["remediation"].get("steps")
        if steps is None:
            continue
        stepped += 1
        assert steps and set(steps) <= {"rhel", "debian"}, code
        assert all(isinstance(v, str) and v.strip() for v in steps.values()), code
    split = {"U-02", "U-03", "U-13", "U-60", "U-61"}  # the guide gives these separate Redhat/Debian cases
    assert split <= {c for c, m in _catalog().items() if m["remediation"].get("steps")}
    assert stepped >= len(split)


def test_remediation_impact_follows_the_guide_split():
    """52 items the guide calls no-impact are level 1; the 15 individually described are level 2 or 3."""
    levels = {c: ITEMS[c]["remediation_impact"]["level"] for c in CODES}
    assert {c for c, lv in levels.items() if lv != 1} == {c for c in INDIVIDUALLY_DESCRIBED if levels[c] != 1}
    assert all(levels[c] in (2, 3) for c in INDIVIDUALLY_DESCRIBED)
    assert sum(1 for lv in levels.values() if lv == 1) == 52
    assert {1, 2, 3} <= {ITEMS[c]["remediation_effort"]["level"] for c in CODES}  # effort uses the whole scale


def test_find_commands_in_summaries_keep_their_shell_escapes():
    """A summary is pasted into a shell: find's parentheses and -exec terminator must stay escaped."""
    assert r"\( -nouser -o -nogroup \)" in ITEMS["U-15"]["remediation"]["summary"]
    assert r"\( -perm -04000 -o -perm -02000 \)" in ITEMS["U-23"]["remediation"]["summary"]
    assert r"-exec ls -l {} \;" in ITEMS["U-26"]["remediation"]["summary"]


def test_catalog_text_has_no_infrastructure_details():
    """Public repo: no addresses, host management numbers, or e-mail in the catalog text."""
    text = (FILTER_DIR / "host_audit_kisa_items.yml").read_text(encoding="utf-8")
    text = re.sub(r"(?m)^  cis: .*$", "", text)  # CIS rule numbers (5.3.3.2.2) look like dotted quads
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert not re.search(r"\bns\d{4}\b", text)
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text)


def test_catalog_is_deeply_read_only():
    with pytest.raises(TypeError):
        ITEMS["U-01"]["remediation"]["summary"] = "x"
    with pytest.raises(TypeError):
        ITEMS["U-01"]["remediation_impact"]["level"] = 3
    assert isinstance(ITEMS["U-02"]["remediation"]["steps"], kisa.MappingProxyType)


# ---------------------------------------------------------------- loader validation of the new fields


FULL = {
    "title": "t", "severity": "상", "category": "계정 관리", "criteria": "c", "cis": "",
    "check": "k", "purpose": "p", "threat": "h", "guide_page": 12,
    "remediation": {"summary": "s"},
    "remediation_impact": {"level": 1, "reason": "r"},
    "remediation_effort": {"level": 2, "reason": "r"},
}


def _load(tmp_path, **override):
    item = {k: v for k, v in dict(FULL, **override).items() if v is not None}
    path = tmp_path / "items.yml"
    path.write_text(yaml.safe_dump({"U-01": item}, allow_unicode=True), encoding="utf-8")
    return kisa._load_items(str(path))


def test_loader_accepts_a_complete_item(tmp_path):
    assert _load(tmp_path)["U-01"]["remediation_effort"]["level"] == 2


@pytest.mark.parametrize("field,value,match", [
    ("check", None, "check"),
    ("purpose", " ", "purpose"),
    ("threat", None, "threat"),
    ("guide_page", None, "guide_page"),
    ("guide_page", "12", "guide_page"),
    ("guide_page", True, "guide_page"),
    ("guide_page", 0, "guide_page"),
    ("remediation", None, "remediation"),
    ("remediation", {"summary": " "}, "summary"),
    ("remediation", {"summary": "s", "steps": {"suse": "x"}}, "steps"),
    ("remediation", {"summary": "s", "steps": {"rhel": ""}}, "steps"),
    ("remediation", {"summary": "s", "extra": 1}, "remediation"),
    ("remediation", {"summary": " s"}, "remediation"),
    ("remediation", {"summary": "s\n"}, "remediation"),
    ("remediation", {"summary": "한" * 301}, "summary"),
    ("remediation", {"summary": "s", "steps": {"rhel": "\nx"}}, "steps"),
    ("remediation_impact", {"level": 1, "reason": "r "}, "remediation_impact"),
    ("remediation_impact", {"level": 4, "reason": "r"}, "remediation_impact"),
    ("remediation_impact", {"level": 0, "reason": "r"}, "remediation_impact"),
    ("remediation_impact", {"level": True, "reason": "r"}, "remediation_impact"),
    ("remediation_impact", {"level": "2", "reason": "r"}, "remediation_impact"),
    ("remediation_effort", {"level": 1}, "remediation_effort"),
    ("remediation_effort", {"level": 1, "reason": ""}, "remediation_effort"),
])
def test_loader_rejects_a_malformed_remediation_field(tmp_path, field, value, match):
    with pytest.raises(RuntimeError, match=r"U-01.*" + match):
        _load(tmp_path, **{field: value})


# ---------------------------------------------------------------- derived values (pure filter functions)


@pytest.mark.parametrize("severity,risk,priority,urgency", [("상", 3, 1, "단기"), ("중", 2, 2, "중기"), ("하", 1, 3, "장기")])
def test_risk_priority_and_urgency_derive_from_severity(severity, risk, priority, urgency):
    assert kisa.risk_level(severity) == risk
    assert kisa.priority_of(severity) == priority
    assert kisa.urgency_of(severity) == urgency


def test_derived_values_are_not_stored_in_the_catalog():
    assert all(not ({"risk", "priority", "urgency"} & set(meta)) for meta in ITEMS.values())


def _fake(code, severity, impact, effort):
    return {"title": code, "severity": severity, "category": "계정 관리", "criteria": "c", "cis": "",
            "remediation": {"summary": "s"}, "remediation_impact": {"level": impact, "reason": "r"}, "remediation_effort": {"level": effort, "reason": "r"}}


def test_findings_sort_by_priority_then_impact_then_effort():
    items = {"U-01": _fake("U-01", "하", 1, 1),   # priority 3
             "U-02": _fake("U-02", "상", 3, 1),   # priority 1, impact 3
             "U-03": _fake("U-03", "상", 1, 3),   # priority 1, impact 1, effort 3
             "U-04": _fake("U-04", "상", 1, 1),   # priority 1, impact 1, effort 1
             "U-05": _fake("U-05", "중", 1, 1)}   # priority 2
    findings = [{"code": "KISA-2026:" + c, "verdict": "취약"} for c in ("U-01", "U-02", "U-03", "U-04", "U-05")]
    ordered = [f["code"][-4:] for f in kisa.order_findings(findings, items)]
    assert ordered == ["U-04", "U-03", "U-02", "U-05", "U-01"]


def test_findings_with_the_same_levels_keep_verdict_then_code_order():
    items = {"U-01": _fake("U-01", "상", 1, 1), "U-02": _fake("U-02", "상", 1, 1)}
    findings = [{"code": "KISA-2026:U-02", "verdict": "취약"}, {"code": "KISA-2026:U-01", "verdict": "예외(승인)"},
                {"code": "KISA-2026:U-01", "verdict": "취약"}]
    ordered = [(f["code"][-4:], f["verdict"]) for f in kisa.order_findings(findings, items)]
    assert ordered == [("U-01", "취약"), ("U-02", "취약"), ("U-01", "예외(승인)")]


# ---------------------------------------------------------------- report model, table and appendix


def _record(host, lines):
    rec = {"inventory_hostname": host, "status": "ok", "reason": "", "declared": {"groups": ["servers"]},
           "identity": {"account": "root"}, "os": {"name": "Rocky Linux 9.6"}}
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n",
             "stderr": ""}
    rec["config_vulnerability"] = host_audit_kisa_result(probe, [], host, ["servers"], TODAY)
    return rec


@pytest.fixture(scope="module")
def model():
    lines = ["U-%02d|GOOD|ok-evidence-%02d" % (i, i) for i in range(1, 68) if i not in (1, 2, 12, 28)]
    lines += ["U-01|VULN|permit-root", "U-02|VULN|max-days", "U-12|MANUAL|no-tmout", "U-28|VULN|open"]
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": ["ns0001"], "kisa_exceptions": []}
    return host_audit_report_model([_record("ns0001", lines)], meta)


@pytest.fixture(scope="module")
def html(model):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    return env.get_template("report.html.j2").render(host_audit_model=model)


def test_findings_carry_remediation_and_derived_values_in_priority_order(model):
    findings = model["config_vulnerability"]["findings"]
    assert [f["code"][-4:] for f in findings] == ["U-01", "U-02", "U-28", "U-12"]  # 상 impact1, 상 impact2, 상 impact3, 하
    u01 = findings[0]
    assert u01["remediation_summary"] == ITEMS["U-01"]["remediation"]["summary"]
    assert (u01["risk"], u01["priority"], u01["urgency"]) == (3, 1, "단기")
    assert u01["impact_level"] == ITEMS["U-01"]["remediation_impact"]["level"]
    assert u01["effort_level"] == ITEMS["U-01"]["remediation_effort"]["level"]
    u12 = findings[-1]
    assert (u12["risk"], u12["priority"], u12["urgency"]) == (1, 3, "장기")


def test_per_host_appendix_rows_carry_no_remediation_data(model):
    rows = model["config_vulnerability"]["appendix"]["ns0001"]
    assert len(rows) == 67
    for row in rows:
        assert set(row) == {"code", "title", "severity", "category", "criteria", "cis", "verdict", "verdict_class",
                            "evidence", "note"}


def _between(html, start, end):
    first = html.index(start)
    return html[first:html.index(end, first)]


def test_body_table_shows_impact_column_and_remediation_line(html, model):
    table = _between(html, "<h3>양호 외 항목</h3>", "<h3>예외 레지스터</h3>")
    heads = re.findall(r"<th>(.*?)</th>", table)
    assert heads[:5] == ["판정", "항목", "중요도", "조치 영향도", "판단 기준"]
    u01 = ITEMS["U-01"]
    assert "조치: " + u01["remediation"]["summary"] in table
    assert 'class="impact"' in table
    first_row = table.split("<tr>")[2]  # first data row is the highest priority finding
    assert "KISA-2026:U-01" in first_row
    cells = re.findall(r"<td[^>]*>(.*?)</td>", first_row, re.S)
    assert cells[3].strip() == str(u01["remediation_impact"]["level"])


def test_report_states_the_guide_source_sentence_at_the_bottom(html):
    assert html.count(SOURCE_SENTENCE) == 1
    assert html.index(SOURCE_SENTENCE) > html.index("검토 및 결재")


def test_source_sentence_is_stated_even_without_findings():
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    lines = ["U-%02d|GOOD|ok" % i for i in range(1, 68)]
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": ["ns0001"], "kisa_exceptions": []}
    page = env.get_template("report.html.j2").render(
        host_audit_model=host_audit_report_model([_record("ns0001", lines)], meta))
    assert "양호 외 항목 없음" in page and SOURCE_SENTENCE in page


def test_unknown_item_code_gets_empty_remediation_instead_of_failing():
    view = kisa.remediation_view("KISA-2026:U-99")
    assert view["remediation_summary"] == "" and view["priority"] == ""
    assert kisa.remediation_view("KISA-2026:U-01")["priority"] == 1


def test_per_host_appendix_html_has_no_remediation_text(html):
    appendix = html[html.index("부록 1. ns0001"):]
    for code in ("U-01", "U-02", "U-28"):
        assert ITEMS[code]["remediation"]["summary"] not in appendix
    assert "조치: " not in appendix
    assert "조치 영향도" not in appendix


# ---------------------------------------------------------------- per-host JSON stays as it was


def test_per_host_config_vulnerability_json_shape_is_unchanged():
    part = _record("ns0001", ["U-01|VULN|x"])["config_vulnerability"]
    assert set(part) == {"edition", "status", "reason", "results"}
    assert set(part["results"][0]) == {"code", "result", "verdict", "evidence", "exception"}


def test_finding_of_an_unknown_code_renders_without_an_empty_remediation_line(model):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    cv = dict(model["config_vulnerability"])
    stray = dict(cv["findings"][0], code="KISA-2026:U-99", **kisa.remediation_view("KISA-2026:U-99"))
    page = env.get_template("report.html.j2").render(
        host_audit_model=dict(model, config_vulnerability=dict(cv, findings=cv["findings"] + [stray])))
    row = page[page.index("KISA-2026:U-99"):]
    row = row[:row.index("</tr>")]
    assert "조치: " not in row and '<td class="impact">-</td>' in row


def test_report_without_the_source_key_has_no_stray_sentence_line(model):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    cv = {k: v for k, v in model["config_vulnerability"].items() if k != "remediation_source"}
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    assert '<p class="small mute">.</p>' not in page and SOURCE_SENTENCE not in page
