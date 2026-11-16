"""Host Audit item-level remediation appendix `부록 N+1. 조치 안내` (Spec #488 / Ticket-3, #491).

Shared rendering test (ADR-0013): the model is built and the report rendered once per module, and the assertions
read the visible HTML. Steps and verdict host lists are checked on blocks of the rendered page, not on internals.
"""
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import ITEMS, host_audit_kisa_result  # noqa: E402

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
TODAY = "2026-10-09"
ALL = range(1, 68)
FINDING_CODES = {"U-01", "U-02", "U-12", "U-28"}


def _lines(overrides):
    base = {"U-%02d" % i: "GOOD|ok-%02d" % i for i in ALL}
    base.update(overrides)
    return ["%s|%s" % (code, value) for code, value in sorted(base.items())]


def _record(host, overrides, register=()):
    probe = {"rc": 0, "stderr": "",
             "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(_lines(overrides)) + "\n__HOST_AUDIT_KISA_END__\n"}
    return {"inventory_hostname": host, "status": "ok", "reason": "", "declared": {"groups": ["servers"]},
            "identity": {"account": "root"}, "os": {"name": "Rocky Linux 9.6"},
            "config_vulnerability": host_audit_kisa_result(probe, list(register), host, ["servers"], TODAY)}


def _model(records):
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": [r["inventory_hostname"] for r in records], "kisa_exceptions": []}
    return host_audit_report_model(records, meta)


def _approved_u28():
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    return [dict(defaults["host_audit_kisa_exceptions"][0], approver="정보보호 책임자",
                 approved_on="2026-10-01", expires_on="2027-09-30")]


@pytest.fixture(scope="module")
def env():
    jinja2 = pytest.importorskip("jinja2")
    return jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))


@pytest.fixture(scope="module")
def model():
    """Three hosts. U-28 has all three verdicts (취약 / 점검불가(수동) / 예외(승인)), U-02 is 취약 on two hosts."""
    return _model([
        _record("ns0001", {"U-01": "VULN|permit-root", "U-02": "VULN|max-days", "U-28": "VULN|open"}),
        _record("ns0002", {"U-02": "VULN|max-days", "U-12": "MANUAL|no-tmout", "U-28": "MANUAL|docker"}),
        _record("ns0003", {"U-28": "MANUAL|docker"}, register=_approved_u28()),
    ])


@pytest.fixture(scope="module")
def html(model, env):
    return env.get_template("report.html.j2").render(host_audit_model=model)


def _head(html):
    """All CSS of the page (the shared sheet plus the `<style>` of each section)."""
    return "\n".join(re.findall(r"<style>(.*?)</style>", html, re.S))


def _blocks(html):
    """The remediation blocks of the appendix as ``{code: html}`` in page order."""
    start = html.index("조치 안내</h2>")
    end = html.index("검토 및 결재</h2>")
    parts = re.split(r'(?=<section class="rg-block)', html[start:end])[1:]
    return {re.search(r'data-code="[^"]*?(U-\d+)"', p).group(1): p for p in parts}


def _visible(fragment):
    """Visible text: tags become spaces, runs of whitespace one space, and no space is left before `:` or `,`."""
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment)).strip()
    return re.sub(r" ([:,])", r"\1", text)


def _body_codes(html):
    table = html[html.index("<h3>양호 외 항목</h3>"):html.index("<h3>예외 레지스터</h3>")]
    codes = []
    for row in table.split("<tr>")[2:]:
        code = re.search(r"U-\d+", row).group(0)
        if code not in codes:
            codes.append(code)
    return codes


# ------------------------------------------------------------------ position and numbering


def test_appendix_comes_after_the_per_host_appendices_and_before_the_sign_off(html):
    last_host = html.index("부록 3. ns0003")
    guide = html.index("부록 4. 조치 안내")
    assert last_host < guide < html.index("검토 및 결재</h2>")
    assert html.count("조치 안내</h2>") == 1


def test_appendix_number_follows_the_number_of_host_appendices(env, model):
    one = dict(model, hosts=model["hosts"][:1])
    page = env.get_template("report.html.j2").render(host_audit_model=one)
    assert "부록 1. ns0001" in page and "부록 2. 조치 안내" in page


def test_appendix_starts_on_a_new_page(html):
    assert re.search(r'<h2 class="pb[^"]*">부록 4\. 조치 안내', html)


# ------------------------------------------------------------------ block set and order


def test_blocks_are_the_body_table_items_in_the_body_table_order(html):
    assert list(_blocks(html)) == _body_codes(html)
    assert set(_body_codes(html)) == FINDING_CODES


def test_blocks_must_not_split_across_pages(html):
    assert re.search(r"\.rg-block\s*\{[^}]*break-inside:\s*avoid", _head(html))


# ------------------------------------------------------------------ per-verdict host lists


def test_block_head_lists_hosts_per_verdict(html):
    blocks = _blocks(html)
    assert "취약: ns0001 · 점검불가(수동): ns0002 · 예외(승인): ns0003" in _visible(blocks["U-28"])
    assert "취약: ns0001, ns0002" in _visible(blocks["U-02"])


def test_verdicts_without_hosts_are_left_out_of_the_head(html):
    blocks = _blocks(html)
    text = _visible(blocks["U-02"])
    assert "점검불가(수동):" not in text and "예외(승인):" not in text
    assert "취약:" not in _visible(blocks["U-12"])
    assert "점검불가(수동): ns0002" in _visible(blocks["U-12"])


def test_host_evidence_is_not_repeated_in_the_blocks(html):
    for block in _blocks(html).values():
        assert "max-days" not in block and "permit-root" not in block and "no-tmout" not in block


# ------------------------------------------------------------------ block content


def test_block_carries_purpose_threat_criteria_check_summary_levels_and_page(html):
    for code, block in _blocks(html).items():
        item, text = ITEMS[code], _visible(block)
        assert code in text and item["title"] in text
        for field in ("purpose", "threat", "criteria", "check"):
            assert item[field] in text, (code, field)
        assert item["remediation"]["summary"] in text
        for kind in ("remediation_impact", "remediation_effort"):
            assert item[kind]["reason"] in text
        assert "가이드 p.%d" % item["guide_page"] in text


def test_block_without_family_steps_has_only_the_summary(html):
    assert not ITEMS["U-01"]["remediation"].get("steps")
    block = _blocks(html)["U-01"]
    assert "RHEL 계열" not in block and "Debian 계열" not in block
    assert "rg-steps" not in block


def test_block_with_family_steps_shows_every_family_with_its_name(html):
    steps = ITEMS["U-02"]["remediation"]["steps"]
    assert set(steps) == {"rhel", "debian"}
    text = _visible(_blocks(html)["U-02"])
    assert text.index("RHEL 계열") < text.index("Debian 계열")
    for family in steps.values():
        for line in family.strip().splitlines():
            assert " ".join(line.split()) in text


def test_heading_and_intro_keep_with_the_first_block(html):
    assert re.search(r"\.rg-head\s*\{[^}]*break-after:\s*avoid", _head(html))
    assert re.search(r'<h2 class="pb rg-head">부록 4\. 조치 안내', html)


def test_a_family_without_text_is_dropped_from_the_steps(monkeypatch):
    import host_audit_kisa as kisa
    item = {k: v for k, v in ITEMS["U-02"].items()}
    item["remediation"] = {"summary": "s", "steps": {"rhel": None, "debian": "  "}}
    monkeypatch.setattr(kisa, "ITEMS", {**ITEMS, "U-02": item})
    assert kisa._build_remediation_guide([_stray("KISA-2026:U-02")])[0]["steps"] == []


def test_steps_keep_their_line_breaks(html):
    assert re.search(r"\.rg-steps\s*\{[^}]*white-space:\s*pre-wrap", _head(html))
    assert 'class="rg-steps"' in _blocks(html)["U-02"]


def test_catalog_text_is_escaped(env, model):
    cv = dict(model["config_vulnerability"])
    cv["remediation_guide"] = [dict(cv["remediation_guide"][0], purpose="<script>x</script>")]
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page


# ------------------------------------------------------------------ no targets


def test_run_without_findings_says_there_are_no_targets(env):
    page = env.get_template("report.html.j2").render(host_audit_model=_model([_record("ns0001", {})]))
    block = page[page.index("부록 2. 조치 안내"):page.index("검토 및 결재</h2>")]
    assert "조치 안내 대상 없음" in block and '<section class="rg-block' not in block


def test_report_without_the_config_vulnerability_section_has_no_guide_appendix(env, model):
    bare = {k: v for k, v in model.items() if k != "config_vulnerability"}
    page = env.get_template("report.html.j2").render(host_audit_model=bare)
    assert "조치 안내</h2>" not in page


def test_finding_of_a_code_the_catalog_lacks_still_gets_a_block(env, model):
    cv = dict(model["config_vulnerability"])
    stray = dict(cv["findings"][0], code="KISA-2026:U-99", title="U-99 unknown", hosts=[{"host": "ns0009"}])
    findings = cv["findings"] + [stray]
    import host_audit_kisa as kisa
    cv["remediation_guide"] = kisa._build_remediation_guide(findings)
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    block = _blocks(page)["U-99"]
    assert "ns0009" in block and "가이드 p." not in block and "None" not in block
    assert "조치 안내 대상 없음" not in page


def test_only_unknown_code_findings_do_not_show_the_no_targets_notice():
    import host_audit_kisa as kisa
    stray = {"code": "KISA-2026:U-99", "title": "t", "severity": "상", "criteria": "c", "verdict": "취약",
             "verdict_class": "crit", "hosts": [{"host": "ns0009"}]}
    assert [b["code"] for b in kisa._build_remediation_guide([stray])] == ["KISA-2026:U-99"]


def test_verdicts_of_one_item_stay_in_one_block_even_when_not_adjacent():
    import host_audit_kisa as kisa
    def f(code, verdict, host):
        return {"code": "KISA-2026:" + code, "title": code, "severity": "상", "criteria": "", "verdict": verdict,
                "verdict_class": "x", "hosts": [{"host": host}]}
    blocks = kisa._build_remediation_guide([f("U-01", "취약", "a"), f("U-02", "취약", "b"), f("U-01", "예외(승인)", "c")])
    assert [b["code"] for b in blocks] == ["KISA-2026:U-01", "KISA-2026:U-02"]
    assert [v["verdict"] for v in blocks[0]["verdict_hosts"]] == ["취약", "예외(승인)"]


def test_block_heading_shows_the_same_full_code_as_the_body_table(html):
    body = html[:html.index("조치 안내</h2>")]
    for code, block in _blocks(html).items():
        assert "KISA-2026:" + code in _visible(block) and "KISA-2026:" + code in body


def _stray(code):
    return {"code": code, "title": "t", "severity": "상", "criteria": "c", "verdict": "취약",
            "verdict_class": "crit", "hosts": [{"host": "ns0009"}]}


def test_unknown_code_block_leaves_out_labels_without_text(env, model):
    import host_audit_kisa as kisa
    cv = dict(model["config_vulnerability"], remediation_guide=kisa._build_remediation_guide([_stray("KISA-2026:U-99")]))
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    text = _visible(_blocks(page)["U-99"])
    for label in ("점검 목적", "보안 위협", "점검방법", "조치방법"):
        assert label not in text
    assert "판단 기준" in text and "조치 영향도 -" in text


def test_editions_with_the_same_short_code_stay_separate_blocks():
    import host_audit_kisa as kisa
    blocks = kisa._build_remediation_guide([_stray("KISA-2026:U-01"), _stray("OTHER-2025:U-01")])
    assert [b["code"] for b in blocks] == ["KISA-2026:U-01", "OTHER-2025:U-01"]


def test_block_resolves_the_catalog_like_the_body_table_does():
    import host_audit_kisa as kisa
    # the body table strips the edition and uses the catalog entry, so the appendix block must agree with it
    for code in ("KISA-2026:U-01", "U-01", "OTHER-2025:U-01"):
        block = kisa._build_remediation_guide([_stray(code)])[0]
        assert block["purpose"] == ITEMS["U-01"]["purpose"] and block["code"] == code


def test_run_where_no_host_was_checked_does_not_claim_a_clean_result(env, model):
    cv = dict(model["config_vulnerability"], findings=[], remediation_guide=[], hosts_checked=0)
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    block = page[page.index("조치 안내</h2>"):page.index("검토 및 결재</h2>")]
    assert "조치 안내 대상 없음" not in block and "만들지 못했다" in block


def test_unknown_code_heading_has_no_dangling_severity_label(env, model):
    import host_audit_kisa as kisa
    stray = dict(_stray("KISA-2026:U-99"), severity="")
    cv = dict(model["config_vulnerability"], remediation_guide=kisa._build_remediation_guide([stray]))
    page = env.get_template("report.html.j2").render(host_audit_model=dict(model, config_vulnerability=cv))
    assert "중요도" not in _visible(_blocks(page)["U-99"])


def test_steps_are_shown_even_when_the_summary_is_empty(env, model):
    cv = dict(model["config_vulnerability"])
    block = dict(cv["remediation_guide"][0], summary="", steps=[{"family": "RHEL 계열", "text": "step-text-x"}])
    page = env.get_template("report.html.j2").render(
        host_audit_model=dict(model, config_vulnerability=dict(cv, remediation_guide=[block])))
    assert "step-text-x" in page and "조치방법" in page
