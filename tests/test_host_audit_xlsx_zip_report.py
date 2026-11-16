"""Host Audit report stage: the xlsx zip is built (AUD-026), hashed into the mail summary (AUD-615), kept, attached
to the report mail as the second attachment (AUD-605/606) and checked and sent again by the resend (AUD-629/633).
(Spec #488 / Ticket-7, #495)

Few integration tests (ADR-0013): the real tasks of report.yml, mail.yml and resend.yml run with ansible-playbook
against a throw-away SMTP server and a throw-away S3-style HTTP server on 127.0.0.1 (no real network, no secrets).
"""
import email
import hashlib
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import zipfile
from email import policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
TASKS = ROOT_DIR / "roles" / "host_audit" / "tasks"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import host_audit_kisa_result  # noqa: E402
from host_audit_mail import host_audit_mail_summary  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")

RUN_ID = "ha-20261031T220000Z"
ZIP_NAME = "host-audit-%s-xlsx.zip" % RUN_ID
PREFIX = "2026-11/%s/" % RUN_ID
BUCKET = "host-audit"


def _tasks(name):
    return yaml.safe_load((TASKS / name).read_text(encoding="utf-8"))


def _flat(tasks):
    for task in tasks:
        yield task
        yield from _flat(task.get("block", []))


def _by_name(file, *needles):
    """The tasks of a file whose name contains one of the needles, in file order."""
    return [t for t in _flat(_tasks(file)) if any(n in t.get("name", "") for n in needles)]


def _record(host, vulnerable):
    lines = ["U-%02d|%s|ev" % (i, "VULN" if i in vulnerable else "GOOD") for i in range(1, 68)]
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n",
             "stderr": ""}
    return {"inventory_hostname": host, "status": "ok", "reason": "", "declared": {"groups": ["servers"]},
            "identity": {"account": "root"}, "os": {"id": "rocky", "name": "Rocky"},
            "config_vulnerability": host_audit_kisa_result(probe, [], host, ["servers"], "2026-10-31")}


def _model():
    meta = {"run_id": RUN_ID, "started_at": "2026-10-31T22:00:05Z", "generated_at": "2026-10-31T22:01:00Z",
            "run_kind": "scheduled", "targets": ["h1", "h2"], "timezone": "Asia/Seoul", "kisa_exceptions": []}
    return host_audit_report_model([_record("h1", {1, 2}), _record("h2", set())], meta)


def _ansible(tmp_path, play, extra_vars=None, name="pb"):
    pb = tmp_path / (name + ".yml")
    pb.write_text(yaml.safe_dump([play], allow_unicode=True))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)]
    if extra_vars:
        ev = tmp_path / (name + "-vars.json")
        ev.write_text(json.dumps(extra_vars))
        cmd += ["-e", "@%s" % ev]
    env = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json",
               ANSIBLE_LIBRARY=str(ROOT_DIR / "roles" / "host_audit" / "library"),
               ANSIBLE_MODULE_UTILS=str(ROOT_DIR / "roles" / "host_audit" / "module_utils"),
               ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"),
               ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"))
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300,
                          env=env)


def _text(res):
    """Everything the json callback printed, with non-ASCII kept readable (the callback escapes it)."""
    try:
        return json.dumps(json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0], ensure_ascii=False)
    except ValueError:
        return res.stdout + res.stderr


# ------------------------------------------------------------------------------
# Throw-away servers
# ------------------------------------------------------------------------------
class _Smtp(socketserver.StreamRequestHandler):
    def _say(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self._say("220 test")
        data = None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            word = line[:4].upper()
            if data is not None:
                if line in (b".\r\n", b".\n"):
                    self.server.messages.append(b"".join(data))
                    data = None
                    self._say("250 ok")
                else:
                    data.append(line[1:] if line.startswith(b"..") else line)
            elif word in (b"EHLO", b"HELO"):
                self._say("250 test")
            elif word == b"DATA":
                data = []
                self._say("354 go")
            elif word == b"QUIT":
                self._say("221 bye")
                return
            else:  # MAIL / RCPT / RSET / NOOP
                self._say("250 ok")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Smtp)
        self.messages = []


@pytest.fixture
def smtp():
    server = _Server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def bucket():
    objects = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            key = self.path.split("?")[0].lstrip("/")
            body = objects.get(key)
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Length", str(len(body or b"")))
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    objects["endpoint"] = "http://127.0.0.1:%d" % server.server_address[1]
    yield objects
    server.shutdown()
    server.server_close()


def _attachments(raw):
    msg = email.message_from_bytes(raw, policy=policy.default)
    return {part.get_filename(): part.get_payload(decode=True) for part in msg.iter_attachments()}, msg


def _mail_vars(smtp):
    return {"host_audit_mail_to": ["a@example.test"], "host_audit_mail_from": "b@example.test",
            "host_audit_mail_host": "127.0.0.1", "host_audit_mail_port": smtp.server_address[1],
            "host_audit_mail_secure": "never"}


# ------------------------------------------------------------------------------
# Report stage: xlsx -> zip -> hash in the summary -> kept
# ------------------------------------------------------------------------------
def _role_vars():
    """The role's own zip name/path/archive variables (vars/main.yml), so the test plays the real definitions."""
    role_vars = yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "vars" / "main.yml").read_text(encoding="utf-8"))
    return {k: v for k, v in role_vars.items() if k.startswith("_host_audit_xlsx_zip_")}


def _report_stage(tmp_path, out, model=None, break_xlsx=False):
    out.mkdir(parents=True, exist_ok=True)
    if break_xlsx:  # xlsx/ is read-only: no writer can create a file in it, so every xlsx write fails
        (out / "xlsx").mkdir(mode=0o500)
    model_file = tmp_path / "model.json"
    model_file.write_text(json.dumps(model or _model(), ensure_ascii=False))
    (out / "report.html").write_text("<html>report</html>")
    names = ("Build the Remediation Plan of every host", "[AUD-025]",
             "Collect the hosts whose Remediation Plan xlsx could not be written", "[AUD-026]",
             "Remove a leftover xlsx zip", "Reset the xlsx zip failure mark", "Remember that the xlsx zip", "Remove the xlsx zip when packing", "Summarize the Remediation Plan xlsx", "[AUD-615]", "[AUD-611]", "[AUD-612]", "[AUD-613]")
    block = next(t for t in _tasks("report.yml") if "always" in t)["block"]
    tasks = [t for t in block if any(n in t.get("name", "") for n in names)]
    assert len(tasks) == len(names), [t.get("name") for t in tasks]
    tasks += _by_name("storage_upload.yml", "[AUD-512]", "[AUD-513]")
    load = {"ansible.builtin.set_fact": {"host_audit_model": "{{ lookup('ansible.builtin.file', '%s') | from_json }}"
                                         % model_file}}
    show = {"ansible.builtin.debug": {"msg": "{{ _host_audit_keep_stats.results | map(attribute='stat', default={}) | list }}"}}
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
            "vars": dict(_role_vars(), host_audit_run={"run_id": RUN_ID, "run_kind": "scheduled", "output_dir": str(out),
                                                       "timezone": "Asia/Seoul"},
                         _host_audit_storage_active=True, _host_audit_storage_problem="",
                         _host_audit_storage_prefix=PREFIX, _host_audit_storage_target={"bucket": BUCKET},
                         host_audit_storage_bucket=BUCKET),
            "tasks": [load] + tasks + [show]}
    res = _ansible(tmp_path, play)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    plays = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    return {s["path"][len(str(out)) + 1:]: s["checksum"] for s in plays[-1]["hosts"]["localhost"]["msg"]}


def test_the_zip_is_built_deterministically_hashed_into_the_summary_and_kept(tmp_path):
    out = tmp_path / "run"
    stats = _report_stage(tmp_path, out)
    zip_path = out / "xlsx" / ZIP_NAME
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as z:
        assert z.namelist() == ["host-audit-%s-h1.xlsx" % RUN_ID, "host-audit-%s-h2.xlsx" % RUN_ID]
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    assert stats["xlsx/" + ZIP_NAME] == digest  # kept with its own SHA-256, like every other file
    assert {"xlsx/host-audit-%s-h1.xlsx" % RUN_ID, "xlsx/host-audit-%s-h2.xlsx" % RUN_ID} <= set(stats)
    summary = json.loads((out / "mail_summary.json").read_text())
    assert summary["xlsx_zip"]["sha256"] == digest and summary["xlsx_zip"]["file_name"] == ZIP_NAME
    assert summary["xlsx_zip"]["size"] == zip_path.stat().st_size
    assert summary["xlsx_zip"]["archive"].endswith(PREFIX + "xlsx/" + ZIP_NAME + " (3년 보관)")
    assert summary["report"]["sha256"] == hashlib.sha256(b"<html>report</html>").hexdigest()
    # the same input gives the same bytes: a second run of the whole stage changes nothing
    assert _report_stage(tmp_path / "again", tmp_path / "again" / "run")["xlsx/" + ZIP_NAME] == digest


def test_a_stale_xlsx_of_an_earlier_run_with_the_same_id_is_not_packed(tmp_path):
    out = tmp_path / "run"
    (out / "xlsx").mkdir(parents=True)
    (out / "xlsx" / ("host-audit-%s-gone.xlsx" % RUN_ID)).write_bytes(b"stale plan of a host not audited now")
    _report_stage(tmp_path, out)
    with zipfile.ZipFile(out / "xlsx" / ZIP_NAME) as z:
        assert z.namelist() == ["host-audit-%s-h1.xlsx" % RUN_ID, "host-audit-%s-h2.xlsx" % RUN_ID]


def test_a_stale_zip_of_an_earlier_attempt_is_not_hashed_mailed_or_kept_when_this_attempt_builds_none(tmp_path):
    out = tmp_path / "run"
    (out / "xlsx").mkdir(parents=True)
    (out / "xlsx" / ZIP_NAME).write_bytes(b"PK-old-attempt")
    # a run without hosts builds no zip (AUD-026 is skipped), so only the removal can keep the old file out
    meta = {"run_id": RUN_ID, "started_at": "2026-10-31T22:00:05Z", "generated_at": "2026-10-31T22:01:00Z",
            "run_kind": "scheduled", "targets": [], "timezone": "Asia/Seoul", "kisa_exceptions": []}
    stats = _report_stage(tmp_path, out, host_audit_report_model([], meta))
    assert "xlsx/" + ZIP_NAME not in stats and not (out / "xlsx" / ZIP_NAME).exists()
    assert "xlsx_zip" not in json.loads((out / "mail_summary.json").read_text())


def test_a_run_without_hosts_builds_no_zip_and_still_goes_on(tmp_path):
    out = tmp_path / "run"
    meta = {"run_id": RUN_ID, "started_at": "2026-10-31T22:00:05Z", "generated_at": "2026-10-31T22:01:00Z",
            "run_kind": "scheduled", "targets": [], "timezone": "Asia/Seoul", "kisa_exceptions": []}
    stats = _report_stage(tmp_path, out, host_audit_report_model([], meta))
    assert "xlsx/" + ZIP_NAME not in stats and not (out / "xlsx").exists()
    assert "xlsx_zip" not in json.loads((out / "mail_summary.json").read_text())


def test_when_an_xlsx_could_not_be_written_no_incomplete_zip_is_hashed_mailed_or_kept(tmp_path):
    """A zip of some hosts must not pass for the whole deliverable; the final judgement names the failure (AUD-025)."""
    if os.geteuid() == 0:
        pytest.skip("root can write into a read-only directory")
    out = tmp_path / "run"
    try:
        stats = _report_stage(tmp_path, out, break_xlsx=True)
    finally:
        (out / "xlsx").chmod(0o700)  # let pytest remove the directory
    assert not [k for k in stats if k.endswith(".zip")]
    summary = json.loads((out / "mail_summary.json").read_text())
    assert "xlsx_zip" not in summary and summary["report"]["sha256"]  # the report mail still goes out


def test_the_zip_exists_before_the_mail_and_before_the_cleanup_so_a_storage_off_run_loses_nothing():
    """#494's transitional gap: with storage off a successful mail removed the run directory before the zip was attached.
    The zip is built and hashed in the block that the always: cleanup follows, before the summary, upload and mail."""
    block = next(t for t in _tasks("report.yml") if "always" in t)
    names = [t.get("name", "") for t in block["block"]]

    def at(needle):
        return next(i for i, n in enumerate(names) if needle in n)

    zip_at, hash_at, summary_at = at("[AUD-026]"), at("[AUD-615]"), at("[AUD-612]")
    assert at("[AUD-025]") < zip_at < hash_at < summary_at < at("Keep the originals") < at("Mail the report")
    assert any("cleanup.yml" in json.dumps(t) for t in block["always"])


# ------------------------------------------------------------------------------
# Mail: two attachments
# ------------------------------------------------------------------------------
def _send_play(tmp_path, smtp, doc, report, zip_path):
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
            "vars": dict(_mail_vars(smtp), host_audit_mail_doc=doc, _host_audit_archive_ok=True,
                         _host_audit_mail_report_path=str(report),
                         _host_audit_mail_xlsx_path=str(zip_path) if zip_path else ""),
            "tasks": [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "mail"}}]}
    return _ansible(tmp_path, play)


def _summary_doc(report_bytes, zip_bytes):
    zip_info = {"sha256": hashlib.sha256(zip_bytes).hexdigest(), "size": len(zip_bytes), "file_name": ZIP_NAME,
                "archive": "RustFS %s/%sxlsx/%s (3년 보관)" % (BUCKET, PREFIX, ZIP_NAME)} if zip_bytes else None
    return host_audit_mail_summary(_model(), {
        "sha256": hashlib.sha256(report_bytes).hexdigest(), "size": len(report_bytes),
        "file_name": "host-audit-%s.html" % RUN_ID, "archive": "RustFS %s/%sreport.html (3년 보관)" % (BUCKET, PREFIX)},
        **({"xlsx_zip": zip_info} if zip_info else {}))


def test_the_mail_has_the_report_and_the_xlsx_zip_and_the_body_shows_the_zip_hash(tmp_path, smtp):
    report, zip_bytes = tmp_path / "report.html", b"PK-zip-bytes"
    report.write_bytes(b"<html>report</html>")
    (tmp_path / "x.zip").write_bytes(zip_bytes)
    res = _send_play(tmp_path, smtp, _summary_doc(report.read_bytes(), zip_bytes), report, tmp_path / "x.zip")
    assert res.returncode == 0, res.stdout[-3000:]
    assert len(smtp.messages) == 1
    files, msg = _attachments(smtp.messages[0])
    assert files == {"host-audit-%s.html" % RUN_ID: b"<html>report</html>", ZIP_NAME: zip_bytes}
    body = msg.get_body(preferencelist=("html",)).get_content()
    assert hashlib.sha256(zip_bytes).hexdigest() in body and hashlib.sha256(b"<html>report</html>").hexdigest() in body


def test_a_summary_that_names_a_zip_but_gets_no_zip_path_sends_nothing(tmp_path, smtp):
    """The body would announce an attachment the mail does not carry."""
    report = tmp_path / "report.html"
    report.write_bytes(b"<html>report</html>")
    _send_play(tmp_path, smtp, _summary_doc(report.read_bytes(), b"PK-zip-bytes"), report, None)
    assert smtp.messages == []


def test_a_missing_attachment_file_is_a_mail_problem_not_an_aborted_play(tmp_path, smtp):
    """The mail tasks record the problem so the later judgements (AUD-516, AUD-610, KISA alert) still run."""
    report = tmp_path / "report.html"
    report.write_bytes(b"<html>report</html>")
    res = _send_play(tmp_path, smtp, _summary_doc(report.read_bytes(), b"PK-zip"), report, tmp_path / "gone.zip")
    assert res.returncode == 0, res.stdout[-3000:]  # mail.yml itself does not fail the run
    assert smtp.messages == []
    assert "첨부할 파일이 없음" in _text(res)


def test_a_summary_without_a_zip_still_sends_the_report_alone(tmp_path, smtp):
    report = tmp_path / "report.html"
    report.write_bytes(b"<html>report</html>")
    res = _send_play(tmp_path, smtp, _summary_doc(report.read_bytes(), None), report, None)
    assert res.returncode == 0, res.stdout[-3000:]
    assert list(_attachments(smtp.messages[0])[0]) == ["host-audit-%s.html" % RUN_ID]


# ------------------------------------------------------------------------------
# Resend: the archived zip is fetched and checked before anything is sent
# ------------------------------------------------------------------------------
REPORT = b"<html>report</html>"
ZIP = b"PK-archived-zip"


def _resend(tmp_path, smtp, bucket, summary_zip=ZIP, served_zip=ZIP, summary_doc=None, no_summary=False):
    """Serve a kept run and run the real resend.yml; ``summary_zip`` is the zip the summary recorded, ``served_zip``
    the zip the bucket returns now (None: missing)."""
    bucket[BUCKET + "/" + PREFIX + "report.html"] = REPORT
    if not no_summary:
        bucket[BUCKET + "/" + PREFIX + "mail_summary.json"] = json.dumps(
            summary_doc or _summary_doc(REPORT, summary_zip)).encode()
    if served_zip is not None:
        bucket[BUCKET + "/" + PREFIX + "xlsx/" + ZIP_NAME] = served_zip
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
            "tasks": [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "resend"}}]}
    extra = dict(_mail_vars(smtp), host_audit_resend_run_id=RUN_ID, host_audit_output_root=str(tmp_path / "out"),
                 host_audit_storage={"endpoint": bucket["endpoint"], "bucket": BUCKET, "access_key": "k",
                                     "secret_key": "s", "region": "us-east-1"},
                 host_audit_storage_validate_certs=False)
    return _ansible(tmp_path, play, extra)


def test_resend_sends_both_when_the_archived_zip_matches_the_recorded_hash(tmp_path, smtp, bucket):
    res = _resend(tmp_path, smtp, bucket)
    assert res.returncode == 0, res.stdout[-3000:]
    files, msg = _attachments(smtp.messages[0])
    assert files == {"host-audit-%s.html" % RUN_ID: REPORT, ZIP_NAME: ZIP}
    assert msg["Subject"].startswith("[재발송]")
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())  # the downloads are removed


def test_resend_stops_without_sending_when_the_zip_hash_differs(tmp_path, smtp, bucket):
    res = _resend(tmp_path, smtp, bucket, served_zip=b"PK-tampered")  # AUD-633
    assert res.returncode != 0 and smtp.messages == []
    assert "받은 xlsx zip의 SHA-256" in _text(res)
    assert not list((tmp_path / "out").iterdir())  # a stopped resend leaves no downloaded file on the runner


def test_resend_stops_without_sending_when_the_recorded_zip_is_missing_from_the_bucket(tmp_path, smtp, bucket):
    res = _resend(tmp_path, smtp, bucket, served_zip=None)  # AUD-629 gets a 404, AUD-633 stops
    assert res.returncode != 0 and smtp.messages == []
    assert "보관된 xlsx zip을 받지 못함" in _text(res)


def test_resend_stops_on_a_malformed_zip_record_of_the_archived_summary(tmp_path, smtp, bucket):
    doc = _summary_doc(REPORT, ZIP)
    doc["xlsx_zip"] = "not-an-object"
    res = _resend(tmp_path, smtp, bucket, summary_doc=doc)
    assert res.returncode != 0 and smtp.messages == []
    assert "형식이 맞지 않음" in _text(res)


def test_resend_stops_when_the_recorded_zip_name_is_not_the_one_the_run_id_gives(tmp_path, smtp, bucket):
    doc = _summary_doc(REPORT, ZIP)
    doc["xlsx_zip"]["file_name"] = "../evil.zip"
    res = _resend(tmp_path, smtp, bucket, summary_doc=doc)
    assert res.returncode != 0 and smtp.messages == []
    assert "실행 ID에서 정한 이름" in _text(res)


def test_resend_without_a_kept_summary_sends_the_report_alone_and_says_the_zip_was_not_resent(tmp_path, smtp, bucket):
    res = _resend(tmp_path, smtp, bucket, no_summary=True)
    assert res.returncode == 0, res.stdout[-3000:]
    assert list(_attachments(smtp.messages[0])[0]) == ["host-audit-%s.html" % RUN_ID]
    assert "zip은 보내지 않고 보고서만" in _text(res)


def test_resend_of_a_run_kept_before_the_zip_existed_sends_the_report_alone(tmp_path, smtp, bucket):
    res = _resend(tmp_path, smtp, bucket, summary_zip=None, served_zip=None)
    assert res.returncode == 0, res.stdout[-3000:]
    assert list(_attachments(smtp.messages[0])[0]) == ["host-audit-%s.html" % RUN_ID]
