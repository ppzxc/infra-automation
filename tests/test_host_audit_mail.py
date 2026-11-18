"""Host Audit mail delivery (ADR-0009 §6, #126).

Observable behaviour only: the summary built from a real report model, the body the
template draws from it (what Gmail/Outlook keep: tables and inline styles), how
recipients are read and kept out of every text, the resend location of an archived
run, and the order in which the playbook keeps, mails and judges. No network: the
end-to-end runs against mailpit and RustFS are described in docs/host_audit.md §13.
"""
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import host_audit_kisa_result  # noqa: E402
from host_audit_mail import (  # noqa: E402
    REDACTED, host_audit_mail_attachment_name, host_audit_mail_outcome, host_audit_mail_recipients,
    host_audit_mail_redact, host_audit_mail_resend_prefix, host_audit_mail_resend_summary,
    host_audit_mail_sender, host_audit_mail_summary,
)

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
SHA = "a" * 64
ADDRS = ["sec-team@example.kr", "Infra.Lead@Example.kr"]


def _kisa_stdout(lines):
    return {"rc": 0, "stderr": "",
            "stdout": "banner\n__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n"}


def _record(host, status="ok"):
    rec = {"inventory_hostname": host, "status": status, "reason": "" if status == "ok" else "connection refused",
           "collected_at": "2026-10-31T22:00:01Z",
           "declared": {"fqdn": "", "ip": "", "environment": "prod", "groups": ["servers"]},
           "identity": {"hostname": host, "fqdn": host + ".example", "ips": [], "account": "audit"},
           "os": {"id": "rocky", "version_id": "9.6", "name": "Rocky Linux 9.6", "kernel": "", "arch": ""}}
    if status == "ok":
        rec["config_vulnerability"] = host_audit_kisa_result(
            _kisa_stdout(["U-01|VULN|PermitRootLogin yes", "U-02|GOOD|ok"]), [], host, ["servers"], "2026-11-01")
    else:
        rec["identity"] = rec["os"] = None
    return rec


def _model(**meta_overrides):
    meta = {"run_id": "ha-20261031T220000Z", "run_kind": "scheduled", "started_at": "2026-10-31T22:00:00Z",
            "generated_at": "2026-10-31T22:05:00Z", "targets": ["ns0001", "ns0002"], "timezone": "Asia/Seoul",
            "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/ (3년 보관)"}
    meta.update(meta_overrides)
    return host_audit_report_model([_record("ns0001"), _record("ns0002", "unreachable")], meta)


ZIP_SHA = "c" * 64
ZIP_NAME = "host-audit-ha-20261031T220000Z-xlsx.zip"


def _xlsx_zip(**override):
    zip_info = {"sha256": ZIP_SHA.upper(), "size": 4321, "file_name": ZIP_NAME,
                "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/xlsx/" + ZIP_NAME + " (3년 보관)"}
    zip_info.update(override)
    return zip_info


def _summary(model=None, xlsx_zip=None):
    args = [model or _model(), {
        "sha256": SHA.upper(), "size": 1234, "file_name": host_audit_mail_attachment_name("ha-20261031T220000Z"),
        "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/report.html (3년 보관)"}]
    return host_audit_mail_summary(*args, **({"xlsx_zip": xlsx_zip} if xlsx_zip is not None else {}))


def _render(doc):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    return env.get_template("mail_body.html.j2").render(host_audit_mail_doc=doc)


# ------------------------------------------------------------------------------
# Recipients and redaction
# ------------------------------------------------------------------------------
def test_recipients_accept_a_list_or_a_separated_string_and_drop_duplicates():
    assert host_audit_mail_recipients("a@x.kr, b@x.kr;c@x.kr\nA@X.kr") == {
        "addresses": ["a@x.kr", "b@x.kr", "c@x.kr"], "invalid": 0}
    assert host_audit_mail_recipients(["a@x.kr", "b@x.kr, a@x.kr", None]) == {
        "addresses": ["a@x.kr", "b@x.kr"], "invalid": 0}
    assert host_audit_mail_recipients(None) == {"addresses": [], "invalid": 0}
    assert host_audit_mail_recipients("") == {"addresses": [], "invalid": 0}


def test_invalid_recipients_are_only_counted_never_echoed():
    out = host_audit_mail_recipients(["ok@x.kr", "no-at-sign", "two@@x.kr", "<bad>@x.kr", "nodot@localhost"])
    assert out == {"addresses": ["ok@x.kr"], "invalid": 4}
    assert "no-at-sign" not in json.dumps(out)


def test_redaction_hides_every_address_in_an_smtp_error():
    msg = "Failed to send mail to 'sec-team@example.kr, infra.lead@example.kr': (550, b'5.7.1 <other@corp.kr> denied')"
    out = host_audit_mail_redact(msg, ADDRS)
    assert "@" not in out
    assert out.count(REDACTED) == 3
    assert "550" in out and "denied" in out


def test_outcome_treats_refused_recipients_as_failure_and_redacts_errors():
    assert host_audit_mail_outcome({"changed": False, "msg": "Mail sent successfully", "result": {}}, ADDRS) == {
        "sent": True, "error": ""}
    partial = host_audit_mail_outcome({"msg": "Failed to send mail to at least one recipient",
                                       "result": {"sec-team@example.kr": [550, "no such user"]}}, ADDRS)
    assert partial["sent"] is False and "@" not in partial["error"] and "550" in partial["error"]
    failed = host_audit_mail_outcome({"failed": True, "msg": "Unable to Connect smtp:587 for sec-team@example.kr"}, ADDRS)
    assert failed["sent"] is False and "@" not in failed["error"]
    assert host_audit_mail_outcome({"skipped": True}, ADDRS) == {"sent": False, "error": ""}
    # failed_when: false rewrites 'failed' to false — rc and the missing success message still tell
    reshaped = host_audit_mail_outcome({"failed": False, "rc": 1, "msg": "Unable to Connect smtp:587"}, ADDRS)
    assert reshaped["sent"] is False and "Unable to Connect" in reshaped["error"]
    assert host_audit_mail_outcome({"changed": False}, ADDRS)["sent"] is False


def test_outcome_of_one_send_per_recipient_fails_when_any_recipient_failed():
    ok = {"msg": "Mail sent successfully", "result": {}}
    refused = {"failed": False, "rc": 1, "msg": "Failed to send mail to 'infra.lead@example.kr': (550, b'no')"}
    assert host_audit_mail_outcome({"results": [ok, ok]}, ADDRS) == {"sent": True, "error": ""}
    out = host_audit_mail_outcome({"results": [ok, refused]}, ADDRS)
    assert out["sent"] is False and out["error"].startswith("수신자 2명 중 1명 실패") and "@" not in out["error"]
    assert host_audit_mail_outcome({"results": []}, ADDRS)["sent"] is False


# ------------------------------------------------------------------------------
# Summary and body
# ------------------------------------------------------------------------------
def test_attachment_name_is_ascii():
    name = host_audit_mail_attachment_name("ha-20261031T220000Z")
    assert name == "host-audit-ha-20261031T220000Z.html"
    assert host_audit_mail_attachment_name("월간 점검/1").isascii()


def test_summary_counts_come_from_the_report_model_and_carry_no_address():
    doc = _summary()
    assert doc["run_id"] == "ha-20261031T220000Z"
    assert doc["hosts"] == {"total": 2, "inspected": 1, "unavailable": 1}
    assert doc["report"] == {"file_name": "host-audit-ha-20261031T220000Z.html", "sha256": SHA, "size": 1234,
                             "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/report.html (3년 보관)"}
    cv = next(line for line in doc["lines"] if line["section"] == "Configuration Vulnerability")
    assert "취약 1" in cv["text"] and cv["level"] == "crit"
    unavailable = next(line for line in doc["lines"] if line["section"] == "점검불가")
    assert unavailable["level"] == "warn"
    assert doc["subject"].startswith("[Host Audit] 정기 점검 보고서 2026-11-01")
    assert "취약 1" in doc["subject"] and "긴급/높음 -" in doc["subject"]
    assert "@" not in json.dumps(doc, ensure_ascii=False)


def test_summary_includes_package_drift_and_baseline_lines_when_present():
    model = _model()
    model["package_vulnerability"] = {"status": "ok", "total": 9, "db_label": "2026-10-31 갱신",
                                      "totals": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 3},
                                      "classes": {"update": 3}, "class_rows": [{"key": "update", "label": "업데이트 가능", "count": 3}]}
    model["configuration_drift"] = {"rows": [{"host": "ns0001"}], "hosts_with_drift": 1,
                                    "subruns": [{"key": "agents", "label": "Host Agents Config", "status": "error"}]}
    model["baseline"] = {"compared": True, "baseline_run_id": "ha-20260930T220000Z", "statuses": ["신규", "재발", "지속"],
                         "count_rows": [{"counts": [1, 0, 2]}, {"counts": [0, 1, 0]}]}
    doc = _summary(model)
    texts = {line["section"]: line["text"] for line in doc["lines"]}
    assert texts["Package Vulnerability"].startswith("긴급 1 · 높음 2")
    assert "하위 실행 점검불가: Host Agents Config" in texts["Configuration Drift"]
    assert texts["Audit Baseline"] == "기준 ha-20260930T220000Z — 신규 1 · 재발 1 · 지속 2"
    assert "긴급/높음 3" in doc["subject"]


def test_unavailable_package_section_is_shown_as_such():
    model = _model()
    model["package_vulnerability"] = {"status": "unavailable", "reason": "DB 9일 경과"}
    texts = {line["section"]: line for line in _summary(model)["lines"]}
    assert texts["Package Vulnerability"]["text"] == "점검불가 — DB 9일 경과"


def test_body_is_tables_and_inline_styles_only_and_shows_hash_and_archive():
    html = _render(_summary())
    assert "<table" in html and 'style="' in html
    for banned in ("<style", "<img", "<svg", "data:", "@media", "@font-face", "<script", "class="):
        assert banned not in html.lower(), banned
    assert SHA in html
    assert "RustFS host-audit/2026-11/ha-20261031T220000Z/report.html" in html
    assert "host-audit-ha-20261031T220000Z.html" in html
    assert len(html.encode("utf-8")) < 50 * 1024  # Gmail clips long bodies; the summary stays small


def test_summary_carries_the_xlsx_zip_sha256_lowercased_and_the_body_shows_it():
    doc = _summary(xlsx_zip=_xlsx_zip())
    assert doc["xlsx_zip"] == {"file_name": ZIP_NAME, "sha256": ZIP_SHA, "size": 4321,
                               "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/xlsx/" + ZIP_NAME + " (3년 보관)"}
    assert doc["report"]["sha256"] == SHA  # the report hash stays where it was
    html = _render(doc)
    assert ZIP_SHA in html and ZIP_NAME in html and SHA in html
    assert len(html.encode("utf-8")) < 50 * 1024
    assert "@" not in json.dumps(doc, ensure_ascii=False)


def test_summary_without_an_xlsx_zip_has_no_zip_line():
    doc = _summary()
    assert "xlsx_zip" not in doc
    assert ZIP_NAME not in _render(doc)


LR_SHA = "d" * 64
LR_NAME = "host-audit-ha-20261031T220000Z-log-review.html"


def _log_review(**override):
    info = {"sha256": LR_SHA.upper(), "size": 999, "file_name": LR_NAME, "period": "2026-10",
            "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/log_review/" + LR_NAME + " (3년 보관)"}
    info.update(override)
    return info


def test_summary_carries_the_log_review_report_as_a_third_record_and_the_body_shows_its_hash():
    """Spec #544 / Ticket-3 (#558): 세 번째 첨부. 해시는 메일 본문·헤더와 보관 경로에 함께 남는다."""
    doc = host_audit_mail_summary(_model(), _summary()["report"], _xlsx_zip(), _log_review())
    assert doc["log_review"] == {"file_name": LR_NAME, "sha256": LR_SHA, "size": 999, "period": "2026-10",
                                 "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/log_review/" + LR_NAME + " (3년 보관)"}
    html = _render(doc)
    assert LR_SHA in html and LR_NAME in html and "log_review/" + LR_NAME in html and "2026-10" in html
    assert ZIP_SHA in html and SHA in html
    # 보고서를 만들지 않은 실행과 해시 없는 기록은 첨부 기록이 없다
    assert "log_review" not in _summary(xlsx_zip=_xlsx_zip())
    assert "log_review" not in host_audit_mail_summary(_model(), _summary()["report"], None, _log_review(sha256=""))
    assert LR_NAME not in _render(_summary())


def test_resend_keeps_the_archived_log_review_record_and_points_it_at_the_archive():
    kept = host_audit_mail_summary(_model(), _summary()["report"], None, _log_review())
    doc = host_audit_mail_resend_summary(kept, kept["run_id"], "RustFS b/x/report.html", SHA,
                                         log_review_archive="RustFS b/x/log_review/" + LR_NAME)
    assert doc["log_review"]["sha256"] == LR_SHA and doc["log_review"]["file_name"] == LR_NAME
    assert doc["log_review"]["archive"] == "RustFS b/x/log_review/" + LR_NAME
    assert kept["log_review"]["archive"].startswith("RustFS host-audit/")  # the kept summary is not mutated
    assert "log_review" not in host_audit_mail_resend_summary(dict(kept, log_review={}), kept["run_id"], "a", SHA)
    assert "log_review" not in host_audit_mail_resend_summary(None, kept["run_id"], "a", SHA)  # 최소 요약엔 기록이 없다


def test_body_escapes_model_text():
    doc = _summary()
    doc["lines"].append({"section": "<b>x</b>", "text": "<script>alert(1)</script>", "level": "crit"})
    html = _render(doc)
    assert "<script>alert" not in html and "&lt;script&gt;" in html


# ------------------------------------------------------------------------------
# Resend
# ------------------------------------------------------------------------------
def test_resend_prefix_uses_the_report_time_zone_month_of_the_default_run_id():
    # 2026-10-31 22:00 UTC is 2026-11-01 07:00 KST — kept under 2026-11/ (#125)
    assert host_audit_mail_resend_prefix("ha-20261031T220000Z") == "2026-11/ha-20261031T220000Z/"
    assert host_audit_mail_resend_prefix("ha-20261015T000000Z") == "2026-10/ha-20261015T000000Z/"
    assert host_audit_mail_resend_prefix("my-run", "2026-09") == "2026-09/my-run/"


@pytest.mark.parametrize("run_id,month", [("", ""), ("../etc", ""), ("my-run", ""), ("my-run", "2026-13")])
def test_resend_prefix_rejects_unsafe_or_unlocatable_ids(run_id, month):
    with pytest.raises(Exception):
        host_audit_mail_resend_prefix(run_id, month)


def test_resend_keeps_the_archived_zip_record_and_points_it_at_the_archive():
    kept = _summary(xlsx_zip=_xlsx_zip())
    doc = host_audit_mail_resend_summary(kept, kept["run_id"], "RustFS host-audit/2026-11/x/report.html", SHA,
                                         xlsx_archive="RustFS host-audit/2026-11/x/xlsx/" + ZIP_NAME)
    assert doc["xlsx_zip"]["sha256"] == ZIP_SHA and doc["xlsx_zip"]["file_name"] == ZIP_NAME
    assert doc["xlsx_zip"]["archive"] == "RustFS host-audit/2026-11/x/xlsx/" + ZIP_NAME
    assert kept["xlsx_zip"]["archive"].startswith("RustFS host-audit/2026-11/ha-")  # the kept summary is not mutated
    empty = dict(kept, xlsx_zip={})
    assert "xlsx_zip" not in host_audit_mail_resend_summary(empty, kept["run_id"], "RustFS b/x/report.html", SHA)
    old = host_audit_mail_resend_summary(_summary(), "ha-1", "RustFS b/x/report.html", SHA)
    assert "xlsx_zip" not in old  # a run kept before the zip existed resends the report only


def test_resend_keeps_the_archived_summary_and_marks_it():
    kept = _summary()
    doc = host_audit_mail_resend_summary(kept, kept["run_id"], "RustFS host-audit/2026-11/x/report.html", SHA)
    tampered = host_audit_mail_resend_summary(dict(kept, report=dict(kept["report"], file_name="../x")), kept["run_id"], "a", SHA)
    assert tampered["report"]["file_name"] == "host-audit-ha-20261031T220000Z.html"  # never a path from the bucket
    assert doc["subject"] == "[재발송] " + kept["subject"]
    assert doc["resent"] is True and doc["report"]["sha256"] == SHA and doc["lines"] == kept["lines"]
    assert "(재발송)" in _render(doc)
    fallback = host_audit_mail_resend_summary(None, "ha-1", "RustFS b/2026-11/ha-1/report.html", "B" * 64, 10)
    assert fallback["report"]["sha256"] == "b" * 64 and fallback["report"]["file_name"] == "host-audit-ha-1.html"
    assert "(재발송)" in _render(fallback)


# ------------------------------------------------------------------------------
# Playbook wiring
# ------------------------------------------------------------------------------
def _tasks(name):
    return yaml.safe_load((ROLE_DIR / "tasks" / name).read_text(encoding="utf-8"))


def _flatten(tasks):
    for t in tasks:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _flatten(t.get(key) or [])


def test_report_keeps_then_mails_then_judges_storage_then_mail():
    report = list(_flatten(_tasks("report.yml")))
    includes = [t.get("ansible.builtin.include_tasks") for t in report]
    names = [t.get("name", "") for t in report]
    summary_saved = next(i for i, n in enumerate(names) if "[AUD-613]" in n)
    upload, mail = includes.index("storage_upload.yml"), includes.index("mail.yml")
    storage_result, mail_result = includes.index("storage_result.yml"), includes.index("mail_result.yml")
    assert summary_saved < upload < mail < storage_result < mail_result
    archive_ok = next(t for t in report if "[AUD-614]" in t.get("name", ""))
    text = json.dumps(archive_ok)
    assert "reject('equalto', 200)" in text and "_host_audit_storage_problem" in text


def test_every_task_touching_addresses_is_no_log():
    for name in ("mail.yml", "resend.yml"):
        for task in _flatten(_tasks(name)):
            text = json.dumps(task)
            touches = any(k in text for k in ("_host_audit_mail_rcpt", "mail_recipients", "mail_sender",
                                              "_host_audit_mail_config", "_req.headers"))
            if touches and "[AUD-608]" not in task.get("name", "") and "block" not in task:
                assert task.get("no_log") is True, task.get("name")
    outcome = next(t for t in _tasks("mail.yml") if "[AUD-608]" in t.get("name", ""))
    assert outcome.get("no_log") is True
    shown = next(t for t in _tasks("mail.yml") if "[AUD-609]" in t.get("name", ""))
    assert "_host_audit_mail_rcpt" not in json.dumps(shown) and "mail_recipients" not in json.dumps(shown)


def test_send_uses_the_relay_defaults_and_attaches_the_ascii_report_and_the_xlsx_zip():
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["host_audit_mail_host"] == "smtp-relay.gmail.com"
    assert defaults["host_audit_mail_port"] == 587
    assert defaults["host_audit_mail_secure"] == "starttls"
    # 수신자·발신자·표시 이름은 OpenBao 문서에서만 읽는다(실행 변수 대체 없음, #528)
    assert not {"host_audit_mail_to", "host_audit_mail_from", "host_audit_mail_from_name"} & set(defaults)
    assert "host_audit_mail_cc" not in defaults
    send = next(t for t in _flatten(_tasks("mail.yml")) if "community.general.mail" in t)
    args = send["community.general.mail"]
    # the attachments are the report and, when the summary records one, the xlsx zip (integration: test_host_audit_xlsx_zip_report.py)
    assert args["subtype"] == "html" and "_host_audit_mail_copied" in args["attach"]
    assert "username" not in args and "password" not in args  # relay with IP authentication
    # one SMTP transaction per recipient: a partial refusal would make the module warn() the
    # refused address, and warnings are printed even under no_log; recipients do not see each other
    assert args["to"] == ["{{ item }}"] and "cc" not in args and "bcc" not in args
    assert send["loop"] == "{{ _host_audit_mail_rcpt.to }}"
    # ignore_errors would print the module error (with addresses) despite no_log
    assert send["no_log"] is True and send["failed_when"] is False and "ignore_errors" not in send


def test_mail_is_not_sent_in_check_mode_or_without_a_kept_archive():
    plan = next(t for t in _tasks("mail.yml") if "[AUD-600]" in t.get("name", ""))
    skip = plan["vars"]["_skip"]
    assert "ansible_check_mode" in skip and "_host_audit_archive_ok" in skip and "host_audit_mail_enabled" in skip


def test_resend_checks_the_hash_against_the_archived_summary_before_sending():
    resend = list(_flatten(_tasks("resend.yml")))  # the download, check and mail sit in one block (cleanup in always)
    names = [t.get("name", "") for t in resend]
    check = names.index(next(n for n in names if "[AUD-626]" in n))
    mail = next(i for i, t in enumerate(resend) if t.get("ansible.builtin.include_tasks") == "mail.yml")
    assert check < mail
    assert "_host_audit_resend_stat.stat.checksum" in json.dumps(resend[check])
    playbook = yaml.safe_load((ROOT_DIR / "playbooks" / "host_audit_resend.yml").read_text(encoding="utf-8"))
    assert [p["hosts"] for p in playbook] == ["localhost"]


def test_no_address_is_committed_in_the_role():
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    for path in list((ROLE_DIR / "defaults").glob("*.yml")) + list((ROLE_DIR / "tasks").glob("mail*.yml")):
        assert not pattern.search(path.read_text(encoding="utf-8")), path


# ------------------------------------------------------------------------------
# '점검불가' means one thing everywhere in one mail (#488 follow-up)
# ------------------------------------------------------------------------------
def _model_with_not_applicable():
    model = _model()
    model["unavailable"] = list(model["unavailable"]) + [
        {"host": "ns0003", "item": "Configuration Drift — 프로비저닝", "label": "점검불가(점검 중 오류)", "reason": "x"}]
    model["configuration_drift"] = {"rows": [], "hosts_with_drift": 0, "subruns": [],
                                    "not_applicable_note": "raw 태스크가 --check에서 스킵됨 (Raw Provisioning Path, 점검불가 아님)",
                                    "not_applicable": [{"host": "ns0100", "reason": "raw"}, {"host": "ns0101", "reason": "raw"}]}
    return model


def test_subject_and_body_line_use_the_same_unavailable_count_and_not_applicable_is_its_own_line():
    doc = _summary(_model_with_not_applicable())
    line = next(l for l in doc["lines"] if l["section"] == "점검불가")
    assert line["text"] == "2건 (호스트·항목)"
    assert doc["subject"].endswith("점검불가 2")
    na = next(l for l in doc["lines"] if l["section"] == "Configuration Drift 비대상")
    assert na["text"].startswith("2대") and "--check에서 스킵" in na["text"]
    assert na["level"] == "na"


def test_no_not_applicable_line_without_hosts():
    doc = _summary()
    assert not any(l["section"] == "Configuration Drift 비대상" for l in doc["lines"])


def test_mail_body_labels_host_card_and_item_count_differently():
    html = _render(_summary(_model_with_not_applicable()))
    assert "점검불가 호스트 (수집 단계)" in html
    assert re.search(r">\s*2건 \(호스트·항목\)\s*<", html)
    assert re.search(r">\s*2대 — raw 태스크가 --check에서 스킵됨", html)
    assert "Configuration Drift 비대상" in html


# --- 발신자 표시 이름 -----------------------------------------------------------------------------------

def test_sender_without_a_name_is_the_bare_address():
    assert host_audit_mail_sender("noreply@example.kr", "") == "noreply@example.kr"
    assert host_audit_mail_sender("noreply@example.kr", None) == "noreply@example.kr"
    assert host_audit_mail_sender("noreply@example.kr") == "noreply@example.kr"


def test_sender_name_is_rfc2047_encoded_and_keeps_the_address_apart():
    from email.header import decode_header, make_header
    from email.utils import parseaddr

    header = host_audit_mail_sender("noreply@example.kr", "서버 감사")
    assert header.isascii()  # the From: header carries no raw non-ASCII bytes
    phrase, addr = parseaddr(header)
    assert addr == "noreply@example.kr"  # the envelope sender the module takes from parseaddr
    assert str(make_header(decode_header(phrase))) == "서버 감사"


@pytest.mark.parametrize("name", ["a\r\nBcc: x@example.kr", "x\ny", "서버 <evil@example.kr>", 'a"b', "x@example.kr", "  "])
def test_unsafe_or_blank_sender_name_is_dropped_not_sent(name):
    assert host_audit_mail_sender("noreply@example.kr", name) == "noreply@example.kr"


def test_the_name_comes_from_the_config_document_only_and_the_header_is_sent():
    resolve = next(t for t in _tasks("mail.yml") if "[AUD-603]" in t.get("name", ""))
    text = json.dumps(resolve)
    assert "mail_sender_display_name" in text and "host_audit_mail_from_name" not in text
    assert resolve.get("no_log") is True
    send = next(t for t in _flatten(_tasks("mail.yml")) if "community.general.mail" in t)
    assert "from_header" in send["community.general.mail"]["sender"]
    outcome = next(t for t in _tasks("mail.yml") if "[AUD-608]" in t.get("name", ""))
    assert "from_header" not in json.dumps(outcome)  # the judged value never carries the header form


def test_comma_in_a_sender_name_is_quoted_not_dropped():
    from email.utils import parseaddr

    header = host_audit_mail_sender("noreply@example.kr", "Audit, Server")
    phrase, addr = parseaddr(header)
    assert (phrase, addr) == ("Audit, Server", "noreply@example.kr")


def test_the_sender_name_is_redacted_from_the_mail_outcome():
    outcome = next(t for t in _tasks("mail.yml") if "[AUD-608]" in t.get("name", ""))
    assert "sender_name" in json.dumps(outcome)
    assert host_audit_mail_redact("From: Audit Name <a@example.kr> rejected", ["a@example.kr", "Audit Name"]) \
        .count("Audit Name") == 0


def test_a_too_long_name_and_an_empty_address_never_make_a_malformed_from():
    assert host_audit_mail_sender("noreply@example.kr", "가" * 16) == "noreply@example.kr"
    assert all(len(w) <= 75 for w in host_audit_mail_sender("noreply@example.kr", "가" * 15).split()[:-1])
    assert host_audit_mail_sender("noreply@example.kr", "a" * 65) == "noreply@example.kr"
    assert host_audit_mail_sender("noreply@example.kr", "a" * 64) != "noreply@example.kr"
    assert host_audit_mail_sender("", "서버 감사") == ""
