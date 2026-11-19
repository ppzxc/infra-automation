"""Host Audit 보고서의 스위치 부분 (Spec #568 / Ticket-5, #587).

공유 렌더링 시험(AGENTS.md 5절): session 범위 fixture `rendered`가 합성 기록(서버 둘, 스위치 L2·L3·접속 실패·수집 실패·기록 없음)으로
보고서 모델과 HTML을 한 번 만들고, 아래 시험은 그 결과를 읽기만 한다. 서버만 있는 같은 입력의 렌더링(`rendered_servers_only`)은
스위치 기록이 서버 출력을 바꾸지 않는지 대조한다. 장비 주소·모델·실제 결과는 쓰지 않는다(합성 값만).
"""
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

import host_audit_switch as hs  # noqa: E402
from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import GOOD, MANUAL, NOT_APPLICABLE, VERDICTS, VULNERABLE, host_audit_kisa_result  # noqa: E402

TODAY = "2026-11-19"
VERSION = "Cisco IOS Software, C0000 Software (C0000-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"
L2_CONFIG = """\
version 15.0
hostname swtest
enable password plain-synthetic
!
line vty 0 4
 transport input telnet ssh
 login
!
end
"""
L3_CONFIG = L2_CONFIG + "ip routing\n"
EXCEPTION_ENTRY = {"code": "KISA-2026:N-03", "hosts": ["ns9101"], "reason": "합성 사유", "risk": "합성 위험",
                   "mitigation": "합성 보완", "approver": "책임자", "approved_on": "2026-11-01", "expires_on": "2027-11-01"}
SERVER_EXCEPTION = dict(EXCEPTION_ENTRY, code="KISA-2026:U-02", hosts=["ns9001"])

pytestmark = pytest.mark.xdist_group("host-audit-switch-report")


def _switch_record(host, config, status="ok", register=()):
    if status == "unreachable":
        probe = {"unreachable": True}
    elif status == "probe_failed":
        probe = {"rc": 2}  # reached, but the output is not a configuration
    else:
        probe = {"rc": 0, "stdout": json.dumps({"running_config": config, "version": VERSION})}
    return hs.host_audit_switch_record(probe, host, {"environment": "production", "groups": ["cisco_switches"]},
                                       "2026-11-19T00:00:00Z", "ssh", list(register), TODAY)


def _server_record(host, vulnerable):
    lines = ["U-%02d|%s|synthetic-evidence" % (i, "VULN" if i in vulnerable else "GOOD") for i in range(1, 68)]
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n",
             "stderr": ""}
    return {"inventory_hostname": host, "status": "ok", "reason": "", "declared": {"groups": ["servers"]},
            "identity": {"account": "root"}, "os": {"id": "rocky", "name": "Rocky"},
            "config_vulnerability": host_audit_kisa_result(probe, [SERVER_EXCEPTION], host, ["servers"], TODAY)}


def _meta(**extra):
    meta = {"run_id": "ha-test", "run_kind": "scheduled", "started_at": "2026-11-19T00:00:00Z",
            "generated_at": "2026-11-19T00:05:00Z", "targets": ["ns9001", "ns9002"], "archive": "synthetic",
            "kisa_exceptions": [SERVER_EXCEPTION, EXCEPTION_ENTRY]}
    meta.update(extra)
    return meta


def _render(model):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    return env.get_template("report.html.j2").render(host_audit_model=model)


SERVERS = [_server_record("ns9001", {2}), _server_record("ns9002", {1})]
SWITCHES = [_switch_record("ns9101", L2_CONFIG, register=[EXCEPTION_ENTRY]), _switch_record("ns9102", L3_CONFIG),
            _switch_record("ns9103", "", "unreachable"), _switch_record("ns9104", "", "probe_failed")]
SWITCH_TARGETS = ["ns9101", "ns9102", "ns9103", "ns9104", "ns9105"]  # ns9105 has no record (its task failed)


@pytest.fixture(scope="session")
def rendered():
    model = host_audit_report_model(SERVERS, _meta(switch_records=SWITCHES, switch_targets=SWITCH_TARGETS))
    return {"model": model, "html": _render(model)}


@pytest.fixture(scope="session")
def rendered_servers_only():
    model = host_audit_report_model(SERVERS, _meta())
    return {"model": model, "html": _render(model)}


def _slice(html, start, end=None):
    i = html.index(start)
    j = html.index(end, i + len(start)) if end else len(html)
    return html[i:j]


def _until_next_h2(html, start):
    """The part from ``start`` up to the next section heading, without that section's trailing style block."""
    i = html.index(start)
    j = html.index("<h2", i + len(start)) if "<h2" in html[i + len(start):] else len(html)
    return re.sub(r"<style>.*?</style>\s*$", "", html[i:j], flags=re.S).rstrip()


def _switch_html(html):
    """The switch section and the switch appendices (the server appendices sit between them)."""
    return _until_next_h2(html, "스위치 설정 취약점 점검") + html[html.index("스위치</span></h2>"):]


# ------------------------------------------------------------------ (1) 스위치 소제목과 항목별·호스트별 결과


def test_report_has_switch_subheading_with_item_and_host_results(rendered):
    html = rendered["html"]
    assert "스위치 설정 취약점 점검" in html
    sw = _switch_html(html)
    assert "KISA-2026:N-01" in sw
    # 항목별 요약 표는 레지스트리의 항목마다 한 행이고 항목 수는 코드에 박혀 있지 않다
    rows = rendered["model"]["switch_vulnerability"]["summary"]
    assert [r["code"] for r in rows] == ["KISA-2026:%s" % c for c in sorted(hs.CHECKS)]
    # 호스트별 부록: 스위치마다 한 절, 항목별 판정과 증적
    assert "ns9101" in sw and "ns9102" in sw
    appendix = rendered["model"]["switch_vulnerability"]["appendix"]
    assert set(appendix) == {"ns9101", "ns9102"}
    assert {it["verdict"] for it in appendix["ns9101"]} <= set(VERDICTS)
    assert any(it["verdict"] == VULNERABLE for it in appendix["ns9101"])


def test_exception_register_of_a_switch_item_applies_and_is_listed_in_the_switch_part(rendered):
    cv = rendered["model"]["switch_vulnerability"]
    n03 = next(it for it in cv["appendix"]["ns9101"] if it["code"] == "KISA-2026:N-03")
    assert n03["verdict"] == "예외(승인)"
    assert [r["code"] for r in cv["register"]] == ["KISA-2026:N-03"]
    assert cv["register"][0]["applied"] == 1


def test_remediation_guide_is_per_item_with_ios_command_and_without_long_copy(rendered):
    guide = rendered["model"]["switch_vulnerability"]["remediation_guide"]
    assert guide, "취약 항목이 있으니 조치 안내가 있다"
    for block in guide:
        assert block["code"].startswith("KISA-2026:N-")
        assert block["summary"], "%s: 조치 방법 요약이 비어 있다" % block["code"]
        assert len(block["summary"]) <= 400, "%s: 원문 장문 복사 금지 — 짧게 요약" % block["code"]
    n03 = next(b for b in guide if b["code"] == "KISA-2026:N-03")
    assert "enable secret" in n03["summary"]
    html = _switch_html(rendered["html"])
    assert "조치 안내" in html and 'data-code="KISA-2026:N-03"' in html


# ------------------------------------------------------------------ (2) 점검불가 장비


def test_unavailable_switches_are_in_the_report_as_not_inspected(rendered):
    sw = rendered["model"]["switch_vulnerability"]
    rows = {r["host"]: r for r in sw["rows"]}
    assert rows["ns9103"]["inspected"] is False and "접속 실패" in rows["ns9103"]["status_label"]
    assert rows["ns9104"]["inspected"] is False and "수집 실패" in rows["ns9104"]["status_label"]
    assert rows["ns9105"]["inspected"] is False and "접속 준비 실패" in rows["ns9105"]["status_label"]
    html = _switch_html(rendered["html"])
    for host in ("ns9103", "ns9104", "ns9105"):
        assert host in html
    # 요약의 점검불가 표(호스트·항목)에도 나온다
    unavailable = {(u["host"], u["item"]) for u in rendered["model"]["unavailable"]}
    assert {("ns9103", "스위치 전체 점검"), ("ns9104", "스위치 전체 점검"), ("ns9105", "스위치 전체 점검")} <= unavailable
    groups = [t["host"] for g in rendered["model"]["unavailable_groups"] for t in g["targets"]]
    assert {"ns9103", "ns9104", "ns9105"} <= set(groups)


# ------------------------------------------------------------------ (3) 요약 호스트 수는 장비 종류별


def test_summary_counts_hosts_by_device_type(rendered):
    summary = rendered["model"]["summary"]
    assert (summary["hosts_total"], summary["hosts_inspected"], summary["hosts_unavailable"]) == (2, 2, 0)  # 서버
    assert summary["switch"] == {"hosts_total": 5, "hosts_inspected": 2, "hosts_unavailable": 3}
    top = _slice(rendered["html"], "<h2>1. 요약</h2>", "용어 풀이")
    assert "서버" in top and "스위치" in top


def test_summary_without_switches_has_no_switch_counts(rendered_servers_only):
    assert "switch" not in rendered_servers_only["model"]["summary"]
    assert "스위치" not in rendered_servers_only["html"]


# ------------------------------------------------------------------ (4) 서버 출력 불변


def test_server_model_is_unchanged_by_switch_records(rendered, rendered_servers_only):
    with_sw, without = rendered["model"], rendered_servers_only["model"]
    for key in ("inventory", "hosts", "asset_inventory", "config_vulnerability", "package_vulnerability"):
        assert with_sw[key] == without[key], key
    assert {k: v for k, v in with_sw["summary"].items() if k != "switch"} == without["summary"]


def test_server_part_of_the_html_is_unchanged_by_switch_records(rendered, rendered_servers_only):
    html, base = rendered["html"], rendered_servers_only["html"]
    # 서버 4절(항목 표·양호 외·예외 레지스터), 서버 호스트별 부록, 서버 조치 안내 부록은 스위치 입력이 있어도 같은 HTML이다
    for start in ("4. 설정 취약점 점검", "부록 1. ns9001", "부록 2. ns9002", "부록 3. 조치 안내"):
        assert _until_next_h2(html, start) == _until_next_h2(base, start), start


def test_server_register_table_has_no_switch_entries(rendered):
    cv = rendered["model"]["config_vulnerability"]
    assert [r["code"] for r in cv["register"]] == ["KISA-2026:U-02"]


# ------------------------------------------------------------------ (5) N 항목과 U 항목 비혼합


def test_switch_and_server_item_codes_are_not_mixed(rendered):
    html, model = rendered["html"], rendered["model"]
    marker = "스위치 설정 취약점 점검"
    server_part = html[:html.index(marker)] + _until_next_h2(html, "부록 1. ns9001") + _until_next_h2(html, "부록 3. 조치 안내")
    assert not re.search(r"KISA-2026:N-\d\d", server_part)
    switch_codes = {c for s in model["switch_vulnerability"]["summary"] for c in [s["code"]]}
    assert all(":N-" in c for c in switch_codes)
    cv = model["config_vulnerability"]
    assert not any(":N-" in s["code"] for s in cv["summary"])
    assert not any(":N-" in f["code"] for f in cv["findings"])
    assert not any(":N-" in b["code"] for b in cv["remediation_guide"])
    # 스위치 쪽 항목별 부록(조치 안내)에도 U 항목은 없다
    sw = model["switch_vulnerability"]
    assert not any(":U-" in s["code"] for s in sw["summary"])
    assert not any(":U-" in f["code"] for f in sw["findings"])
    assert not any(":U-" in b["code"] for b in sw["remediation_guide"])
    switch_html = _switch_html(html)
    assert not re.search(r"KISA-2026:U-\d\d", switch_html)


# ------------------------------------------------------------------ 보고서 표지·범위 문구


def test_cover_no_longer_says_switches_are_out_of_scope(rendered, rendered_servers_only):
    cover = rendered["model"]["cover"]
    assert "cisco_switches" not in cover["out_of_scope"] and "네트워크 장비" not in cover["out_of_scope"]
    assert cover["out_of_scope"] != rendered_servers_only["model"]["cover"]["out_of_scope"]
    assert "cisco_switches" in cover["switch_scope"]
    assert any("스위치" in c for c in cover["contents"])


# ------------------------------------------------------------------ 조치 요약 데이터와 레지스트리


def test_every_registered_switch_item_has_report_text_for_all_38_codes():
    items = yaml.safe_load((ROOT_DIR / "filter_plugins" / "host_audit_switch_items.yml").read_text(encoding="utf-8"))
    assert set(hs.CHECKS) <= set(items), "레지스트리의 항목에 보고서 설명이 없다"
    assert set(items) == {"N-%02d" % i for i in range(1, 39)}
    for code, meta in items.items():
        assert meta["criteria"].strip() and meta["remediation"].strip(), code
        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", meta["remediation"]), code  # 장비 주소 없음


def test_switch_part_is_not_rendered_without_switch_input(rendered_servers_only):
    assert "switch_vulnerability" not in rendered_servers_only["model"]
    assert "스위치 설정 취약점 점검" not in rendered_servers_only["html"]


# ------------------------------------------------------------------ 배선(report.yml)


def _flat(tasks):
    for t in tasks:
        yield t
        yield from _flat(t.get("block", []))


def test_report_tasks_read_switch_records_and_pass_them_into_the_model():
    tasks = list(_flat(yaml.safe_load((ROLE_DIR / "tasks" / "report.yml").read_text(encoding="utf-8"))))
    read = next(t for t in tasks if "[AUD-027]" in t.get("name", ""))
    assert "_host_audit_switch_records" in read["ansible.builtin.set_fact"]
    build = next(t for t in tasks if "[AUD-021]" in t.get("name", ""))
    meta = build["vars"]["_meta"]
    assert meta["switch_records"] == "{{ _host_audit_switch_records | default([]) }}"
    assert "host_audit_switch_targets" in meta["switch_targets"]
