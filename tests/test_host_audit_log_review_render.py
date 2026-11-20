"""Log Review Report A4 HTML 공유 렌더링 (Spec #544 / Ticket-3 #558, ADR-0013 두 층 정책).

보고서 모델 하나를 세션에 한 번 그리고(`rendered`) 그 HTML을 읽기만 한다. 템플릿은 Jinja 내장 필터만 쓰므로
ansible-playbook 없이 jinja2로 직접 그린다(커밋 훅의 빠른 테스트에 든다). 판정은 모델 필터 테스트가 본다.
"""
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import jinja2
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT_DIR / "roles" / "host_audit" / "templates"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_log_review import host_audit_log_review_model, host_audit_log_review_period  # noqa: E402

pytestmark = pytest.mark.xdist_group("log-review-render")

STARTED = "2026-10-31T22:00:05Z"
OCT = ["2026-10-%02d" % d for d in range(1, 32)]


@pytest.fixture(scope="session")
def model():
    hits = [{"name": "ns0001", "day": d, "records": 3} for d in OCT]
    results = {"collection_hosts_daily": {"ok": True, "hits": hits, "error": ""},
               "collection_switch_daily": {"ok": True, "hits": [], "error": ""},
               "collection_fortigate_daily": {"ok": False, "hits": [], "error": "HTTP 503"}}
    meta = {"run_id": "ha-20261031T220000Z", "run_kind": "scheduled", "started_at": STARTED,
            "generated_at": "2026-10-31T22:10:00Z", "timezone": "Asia/Seoul",
            "period": host_audit_log_review_period(STARTED, "Asia/Seoul"),
            "settings": {"collection_targets": {"hosts": ["ns0001", "ns0002"], "devices": ["ns0900"]},
                         # 장비 관리자 로그인 몫(#562): 파싱 설정이 없는 스위치는 항목마다 '점검 불가(파싱 없음)'
                         "devices": {"fortigate": [], "switch": ["ns0900"], "parsing": {}}},
            "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/log_review/x.html (3년 보관)"}
    return host_audit_log_review_model(results, meta)


@pytest.fixture(scope="session")
def rendered(model):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=False, undefined=jinja2.StrictUndefined)
    return env.get_template("log_review.html.j2").render(host_audit_log_review_model=model)


class _Cells(HTMLParser):
    """class 속성별 셀 텍스트와 data-* 속성이 붙은 요소를 모은다."""

    def __init__(self):
        super().__init__()
        self.stack, self.cells, self.items = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "data-part" in a:
            self.items.append(("item", a["data-part"], int(a["data-no"])))
        if a.get("class", "").startswith("policy-item"):
            self.items.append(("item", "2", int(a["data-no"])))
        if a.get("class", "").startswith("approval"):
            self.items.append(("approval", "", 0))
        self.stack.append([tag, a.get("class", ""), ""])

    def handle_data(self, data):
        if self.stack:
            self.stack[-1][2] += data

    def handle_endtag(self, tag):
        while self.stack:
            t, cls, text = self.stack.pop()
            if cls:
                self.cells.append((cls, text.strip()))
            if t == tag:
                break


@pytest.fixture(scope="session")
def parsed(rendered):
    p = _Cells()
    p.feed(rendered)
    return p


def test_the_report_is_self_contained_a4_without_external_resources(rendered):
    assert "@page { size: A4" in rendered
    assert not re.search(r'(src|href)\s*=\s*["\']?(https?:)?//', rendered)
    assert "<script" not in rendered


def test_the_19_and_9_items_come_in_form_order_then_part3_then_the_approval_last(parsed, model):
    order = parsed.items
    part1 = [no for kind, part, no in order if part == "1"]
    part2 = [no for kind, part, no in order if part == "2"]
    part3 = [no for kind, part, no in order if part == "3"]
    assert part1 == list(range(1, 20)) and part2 == list(range(1, 10)) and part3 == [i["no"] for i in model["part3"]]
    kinds = [(k, p) for k, p, _ in order]
    assert kinds.index(("item", "2")) > max(i for i, x in enumerate(kinds) if x == ("item", "1"))
    assert kinds.index(("item", "3")) > max(i for i, x in enumerate(kinds) if x == ("item", "2"))
    assert kinds[-1] == ("approval", "")


def test_every_item_title_is_printed(rendered, model):
    for item in model["part1"] + model["part2"] + model["part3"]:
        assert "%s" % item["title"].replace("&", "&amp;") in rendered


def test_the_verdict_remarks_and_action_cells_are_empty_everywhere(parsed):
    for cls in ("final-verdict", "remarks", "action"):
        cells = [text for c, text in parsed.cells if cls in c.split()]
        assert len(cells) == 19 + 9 + 6 and set(cells) == {""}, cls


def test_the_last_page_has_three_empty_signature_boxes_with_a_date_row(rendered, parsed):
    approval = rendered[rendered.index('<section class="approval'):]
    assert approval.index("정보보호책임자(CISO)") > approval.index("정보보호관리자") > approval.index("점검자")
    assert "일자" in approval
    names = [t for c, t in parsed.cells if c == "sign-name"]
    assert names and names[0] == ""
    assert 'class="approval pb' in rendered  # 마지막 쪽(앞에서 쪽을 나눈다)


def test_the_period_status_reasons_and_criteria_are_printed(rendered):
    assert "2026-10-01 00:00 ~ 2026-10-31 24:00 (KST)" in rendered
    assert "점검 불가(애플리케이션 접속기록·업무 기록 미수집)" in rendered
    assert "점검 불가(파싱 없음)" in rendered  # 장비 관리자 로그인 몫(#562)
    assert "장비 관리자 로그인 — 스위치" in rendered
    assert "조회 실패(장비 로그 HTTP 503)" in rendered  # 조회 실패는 숨기지 않는다
    assert "하루 이상 빈 날이 있으면" in rendered  # 수집 공백의 판정 기준
    assert "ns0002" in rendered and "점검 기간 내내 로그 없음" in rendered


def test_header_lists_the_criteria_of_judged_items(model):
    """머리에 이번 자동 점검에 쓴 기준을 모아 찍는다(#571). 공유 모델에는 판정된 항목이 없으니 접속 위치 판정이 있는 모델을 따로 그린다."""
    results = {"source_logins": {"ok": True, "hits": [], "error": ""},
               "source_login_minutes": {"ok": True, "hits": [], "error": ""}}
    meta = {"run_id": "r", "run_kind": "scheduled", "started_at": STARTED, "generated_at": "2026-10-31T22:10:00Z",
            "timezone": "Asia/Seoul", "period": host_audit_log_review_period(STARTED, "Asia/Seoul"),
            "settings": {"sources": {"reference": {"normal_sources": [{"address": "203.0.113.10", "name": "사무실"}]}}}}
    judged = host_audit_log_review_model(results, meta)
    assert judged["criteria"]
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=False, undefined=jinja2.StrictUndefined)
    html = env.get_template("log_review.html.j2").render(host_audit_log_review_model=judged)
    head = html.split("1부 로그 검토 항목")[0]
    assert "이번 자동 점검에 쓴 기준" in head
    assert judged["criteria"][0]["criterion"] in head
    assert "이번 자동 점검에 쓴 기준" not in env.get_template("log_review.html.j2").render(host_audit_log_review_model=model)


def test_the_first_page_is_a_dashboard_with_status_cards_and_the_part3_state_before_part1(rendered, model):
    head = rendered.split("1부 로그 검토 (19개 항목)")[0]
    assert head.count('class="card st-') == 5
    for c in model["counts"]:
        assert ">%s</span>" % c["label"] in head
    assert "확인이 필요한 항목" in head and "3부 로그 관리 상태" in head and "점검하지 못한 항목" in head
    for item in model["part3"]:
        assert item["title"].replace("&", "&amp;") in head


def test_the_footnote_says_what_the_item_numbers_are_and_names_no_internal_document_number(rendered):
    assert "회사 '로그·보안정책 검토결과 대장' 양식의 항목 번호" in rendered
    assert "KISA 2026 취약점 점검 기준" in rendered
    assert "AK-0" not in rendered
