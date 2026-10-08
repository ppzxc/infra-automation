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
    host_audit_mail_summary,
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


def _summary(model=None):
    return host_audit_mail_summary(model or _model(), {
        "sha256": SHA.upper(), "size": 1234, "file_name": host_audit_mail_attachment_name("ha-20261031T220000Z"),
        "archive": "RustFS host-audit/2026-11/ha-20261031T220000Z/report.html (3년 보관)"})


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


def test_resend_keeps_the_archived_summary_and_marks_it():
    kept = _summary()
    doc = host_audit_mail_resend_summary(kept, kept["run_id"], "RustFS host-audit/2026-11/x/report.html", SHA)
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
    report = _tasks("report.yml")
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
            touches = any(k in text for k in ("_host_audit_mail_rcpt", "host_audit_mail_to", "mail_to",
                                              "mail_from", "_host_audit_mail_kv", "X-Vault-Token", "_req.headers"))
            if touches and "[AUD-608]" not in task.get("name", "") and "block" not in task:
                assert task.get("no_log") is True, task.get("name")
    outcome = next(t for t in _tasks("mail.yml") if "[AUD-608]" in t.get("name", ""))
    assert outcome.get("no_log") is True
    shown = next(t for t in _tasks("mail.yml") if "[AUD-609]" in t.get("name", ""))
    assert "_host_audit_mail_rcpt" not in json.dumps(shown) and "mail_to" not in json.dumps(shown)


def test_send_uses_the_relay_defaults_and_attaches_one_ascii_html():
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["host_audit_mail_host"] == "smtp-relay.gmail.com"
    assert defaults["host_audit_mail_port"] == 587
    assert defaults["host_audit_mail_secure"] == "starttls"
    assert defaults["host_audit_mail_to"] == [] and defaults["host_audit_mail_from"] == ""
    assert "host_audit_mail_cc" not in defaults
    send = next(t for t in _flatten(_tasks("mail.yml")) if "community.general.mail" in t)
    args = send["community.general.mail"]
    assert args["subtype"] == "html" and len(args["attach"]) == 1
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
    resend = _tasks("resend.yml")
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
