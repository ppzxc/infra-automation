"""Log Review Report 서명본 등록 템플릿과 다음 달 보고서의 확인 (Spec #544 / Ticket-9 #564, ADR-0015).

통합 테스트(소수, ADR-0013): 실제 playbooks/host_audit_log_review_sign.yml을 가짜 S3(127.0.0.1, 받은 요청을 모두 기록)에 돌린다.
잠금 버킷이라 잘못 올리면 지울 수 없으므로, 검증에 걸리는 입력은 PUT이 하나도 없어야 한다. 성공하면 PDF → 등록 기록 순서로
올리고 접수 파일을 지우며, 그 기록을 다음 달 정기 실행의 log_review.yml이 '전월 서명본: 있음'으로 읽는다.
비밀·실주소는 없다(openbao_fixture 우회, example 값).
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
BUCKET = "host-audit"
PREV_ID = "ha-20261031T220000Z"
PREV_STARTED = "2026-10-31T22:00:05Z"
PREFIX = "2026-11/%s/" % PREV_ID
PDF = b"%PDF-1.7\n% signed scan fixture\n" + bytes(range(256)) * 8 + b"\n%%EOF\n"
SECRET = "s3cr3t-fixture-key"

needs_ansible = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")


class _S3:
    """경로 방식 S3 흉내: GET은 저장된 객체(없으면 404), PUT은 x-amz-content-sha256과 본문 해시가 같을 때만 200."""

    def __init__(self):
        self.objects, self.requests, self.errors, self.put_errors = {}, [], {}, {}
        s3 = self

        class Handler(BaseHTTPRequestHandler):
            def _key(self):
                path = self.path.split("?", 1)[0]
                return path[len("/%s/" % BUCKET):] if path.startswith("/%s/" % BUCKET) else path.lstrip("/")

            def _send(self, status, body=b""):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                key = self._key()
                s3.requests.append(("GET", key))
                if key in s3.errors:
                    self._send(s3.errors[key], b"<Error/>")
                    return
                body = s3.objects.get(key)
                self._send(200 if body is not None else 404, body or b"")

            def do_HEAD(self):
                key = self._key()
                s3.requests.append(("HEAD", key))
                body = s3.objects.get(key)
                self.send_response(200 if body is not None else 404)
                self.send_header("Content-Length", str(len(body or b"")))
                if body is not None:
                    self.send_header("ETag", '"%s"' % hashlib.md5(body).hexdigest())
                self.end_headers()

            def do_PUT(self):
                key = self._key()
                if key in s3.put_errors:
                    s3.requests.append(("PUT", key))
                    self._send(s3.put_errors[key], b"<Error/>")
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                s3.requests.append(("PUT", key))
                if hashlib.sha256(body).hexdigest() != self.headers.get("x-amz-content-sha256"):
                    self._send(400, b"XAmzContentSHA256Mismatch")
                    return
                s3.objects[key] = body
                s3.content_types[key] = self.headers.get("Content-Type", "")
                self._send(200)

            def log_message(self, *args):
                pass

        self.content_types = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def puts(self):
        return [k for m, k in self.requests if m == "PUT"]


@pytest.fixture
def s3():
    server = _S3()
    server.objects["baseline/%s.json" % PREV_ID] = json.dumps(
        {"run_id": PREV_ID, "run_kind": "scheduled", "started_at": PREV_STARTED, "findings_key": PREFIX + "findings.json"}).encode()
    server.objects[PREFIX + "mail_summary.json"] = json.dumps(
        {"schema_version": 1, "log_review": {"file_name": "host-audit-%s-log-review.html" % PREV_ID,
                                             "sha256": "c" * 64, "size": 10, "period": "2026-10"}}).encode()
    yield server
    server.server.shutdown()
    server.server.server_close()


def _env():
    return dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json",
                ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"), ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"))


def _fixture(endpoint):
    return {"inventory/services/rustfs": {"url": endpoint},
            "secrets/services/rustfs/audit_reports": {"access_key": "example-access", "secret_key": SECRET}}


def _sign(tmp_path, s3, sha256, run_id=PREV_ID):
    ev = {"openbao_fixture": _fixture(s3.url), "host_audit_signed_run_id": run_id, "host_audit_signed_sha256": sha256,
          "host_audit_signed_intake_dir": str(tmp_path / "intake")}
    evf = tmp_path / "sign-vars.json"
    evf.write_text(json.dumps(ev))
    return subprocess.run(["ansible-playbook", "-i", "localhost,", str(ROOT_DIR / "playbooks" / "host_audit_log_review_sign.yml"),
                           "-e", "@%s" % evf], capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR,
                          timeout=300, env=_env())


def _said(res):
    """json 콜백 출력(한글은 \\u 이스케이프)을 읽을 수 있는 글로 바꾼다."""
    doc = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]
    return json.dumps(doc, ensure_ascii=False)


def _intake(tmp_path, data=PDF, name=PREV_ID + ".pdf"):
    intake = tmp_path / "intake"
    intake.mkdir(mode=0o700, exist_ok=True)
    path = intake / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _next_month_report(tmp_path, s3):
    """다음 달(12월 1일 07:00 KST) 정기 실행의 log_review.yml을 같은 가짜 버킷으로 돌려 보고서 HTML을 돌려준다."""
    run_id, out = "ha-20261130T220000Z", tmp_path / "run"
    out.mkdir(exist_ok=True)
    play = {"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
            "tasks": [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "log_review"}}]}
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([play], allow_unicode=True))
    ev = {"openbao_fixture": {},  # OpenObserve 문서 없음: 조회 항목은 '조회 실패'이고 서명본 확인만 본다
          "host_audit_run": {"run_id": run_id, "run_kind": "scheduled", "started_at": "2026-11-30T22:00:05Z",
                             "output_dir": str(out), "timezone": "Asia/Seoul", "target_hosts": ""},
          "host_audit_log_review_collect_hosts": [], "host_audit_log_review_devices": [],
          "host_audit_storage_enabled": True, "_host_audit_storage_problem": "",
          "_host_audit_storage_target": {"endpoint": s3.url, "bucket": BUCKET, "access_key": "example-access",
                                         "secret_key": SECRET, "region": "us-east-1"},
          "host_audit_baseline_history": {"state": "ok", "reason": "", "pointers": [
              {"run_id": PREV_ID, "run_kind": "scheduled", "started_at": PREV_STARTED}]}}
    evf = tmp_path / "lr-vars.json"
    evf.write_text(json.dumps(ev))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb), "-e", "@%s" % evf], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=_env())
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    assert SECRET not in res.stdout + res.stderr
    return (out / "log_review" / ("host-audit-%s-log-review.html" % run_id)).read_text(encoding="utf-8")


@needs_ansible
def test_a_verified_copy_is_kept_with_its_record_and_next_months_report_says_it_is_there(tmp_path, s3):
    path = _intake(tmp_path)
    sha = hashlib.sha256(PDF).hexdigest()
    res = _sign(tmp_path, s3, sha.upper())
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    pdf_key = PREFIX + "signed/host-audit-%s-log-review-signed.pdf" % PREV_ID
    record_key = PREFIX + "signed/registration.json"
    assert s3.puts() == [pdf_key, record_key]  # PDF가 먼저, 등록 완료 표시인 기록이 나중
    assert s3.objects[pdf_key] == PDF and s3.content_types[pdf_key] == "application/pdf"
    record = json.loads(s3.objects[record_key])
    assert record["sha256"] == sha and record["size"] == len(PDF) and record["file_key"] == pdf_key
    assert record["run_id"] == PREV_ID and record["review_month"] == "2026-10"
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", record["registered_at"])
    assert not path.exists()  # 둘 다 올라간 뒤에만 접수 파일을 지운다
    assert SECRET not in res.stdout + res.stderr

    approval = _next_month_report(tmp_path, s3).split('<section class="approval', 1)[1]
    assert "전월 서명본: 있음(" in approval and sha in approval

    # 같은 실행에 다시 등록하면 덮어쓰지 않고 멈춘다(잠금 버킷)
    _intake(tmp_path)
    again = _sign(tmp_path, s3, sha)
    assert again.returncode != 0 and "이미 등록된 서명본이 있음" in _said(again)
    assert s3.puts() == [pdf_key, record_key]


@needs_ansible
def test_a_rerun_after_a_failed_record_does_not_upload_the_same_pdf_again(tmp_path, s3):
    """PDF만 올라가고 기록이 실패한 뒤 같은 입력으로 다시 돌려도 잠긴 사본이 늘지 않는다(#572)."""
    sha = hashlib.sha256(PDF).hexdigest()
    pdf_key = PREFIX + "signed/host-audit-%s-log-review-signed.pdf" % PREV_ID
    record_key = PREFIX + "signed/registration.json"
    path = _intake(tmp_path)
    s3.put_errors[record_key] = 503
    first = _sign(tmp_path, s3, sha)
    assert first.returncode != 0 and "등록 기록 업로드 status=503" in _said(first)
    assert s3.puts() == [pdf_key, record_key] and path.exists()  # PDF는 올라갔고 접수 파일은 그대로

    s3.put_errors.clear()
    second = _sign(tmp_path, s3, sha)
    assert second.returncode == 0, second.stdout[-3000:] + second.stderr[-2000:]
    assert s3.puts() == [pdf_key, record_key, record_key]  # PDF는 한 번만, 기록만 다시
    assert json.loads(s3.objects[record_key])["sha256"] == sha and not path.exists()


@needs_ansible
def test_a_different_pdf_under_the_same_key_is_still_uploaded(tmp_path, s3):
    """같은 키에 다른 바이트가 있으면 건너뛰지 않는다(건너뛰기는 같은 바이트일 때만)."""
    pdf_key = PREFIX + "signed/host-audit-%s-log-review-signed.pdf" % PREV_ID
    s3.objects[pdf_key] = b"%PDF-1.7\nan older upload\n"
    _intake(tmp_path)
    res = _sign(tmp_path, s3, hashlib.sha256(PDF).hexdigest())
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    assert s3.puts()[0] == pdf_key and s3.objects[pdf_key] == PDF


@needs_ansible
def test_an_unexpected_storage_answer_is_a_query_failure_in_the_report_not_a_failed_monthly_run(tmp_path, s3):
    s3.errors[PREFIX + "signed/registration.json"] = 502
    html = _next_month_report(tmp_path, s3)  # 실행은 성공해야 한다(메일이 나간다)
    assert "조회 실패(서명본 기록 HTTP 502)" in html
    assert "전월 서명본: 확인 실패" in html.split('<section class="approval', 1)[1]


@needs_ansible
@pytest.mark.parametrize("case",["wrong_hash", "not_pdf", "symlink", "unknown_run", "no_report"])
def test_a_copy_that_fails_any_check_uploads_nothing_and_stays_in_the_intake(tmp_path, s3, case):
    sha = hashlib.sha256(PDF).hexdigest()
    run_id, needle = PREV_ID, ""
    if case == "wrong_hash":
        path, sha, needle = _intake(tmp_path), "0" * 64, "SHA-256 불일치"
    elif case == "not_pdf":
        data = b"PK\x03\x04 not a pdf"
        path, sha, needle = _intake(tmp_path, data), hashlib.sha256(b"PK\x03\x04 not a pdf").hexdigest(), "PDF 파일이 아님"
    elif case == "symlink":
        real = _intake(tmp_path, name="elsewhere.pdf")
        path = tmp_path / "intake" / (PREV_ID + ".pdf")
        path.symlink_to(real)
        needle = "심볼릭 링크"
    elif case == "unknown_run":  # 형식은 맞지만 정기 실행 기록이 없는 실행 ID(오타)
        run_id = "ha-20261031T220001Z"
        path, needle = _intake(tmp_path, name=run_id + ".pdf"), "정기 실행 기록(baseline/%s.json)이 없음" % run_id
    else:  # 보고서를 보내지 않은 실행
        s3.objects[PREFIX + "mail_summary.json"] = json.dumps({"schema_version": 1}).encode()
        path, needle = _intake(tmp_path), "Log Review Report를 보내지 않았음"
    res = _sign(tmp_path, s3, sha, run_id)
    assert res.returncode != 0
    assert needle in _said(res), _said(res)[-3000:]
    assert s3.puts() == []
    assert path.exists() or path.is_symlink()
    assert SECRET not in res.stdout + res.stderr


def test_the_default_intake_folder_is_not_swept_by_the_old_run_cleanup():
    """오래된 실행 디렉터리 정리(AUD-006)는 run_id 규칙에 맞는 이름만 지운다. 접수 폴더 이름은 그 규칙에 맞지 않아야 한다."""
    defaults = yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    name = re.search(r"/(\w+)'\s*,\s*true\)", defaults["host_audit_signed_intake_dir"]).group(1)
    prepare = (ROOT_DIR / "roles" / "host_audit" / "tasks" / "prepare.yml").read_text(encoding="utf-8")
    assert "[A-Za-z0-9][A-Za-z0-9._-]*" in prepare
    assert not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name), name
