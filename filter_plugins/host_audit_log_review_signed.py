"""Log Review Report 서명본: 등록 검증과 전월 서명본 확인 (Spec #544 / Ticket-9 #564, ADR-0015 §4).

서명 스캔본(PDF)은 보고서를 만든 실행의 보관 경로 ``<YYYY-MM>/<run_id>/signed/``에 올린다(Host Audit 버킷, 같은 GOVERNANCE 3년 잠금).
- ``signed/host-audit-<run_id>-log-review-signed.pdf``: 서명본 그대로(바이트를 바꾸지 않는다).
- ``signed/registration.json``: 등록 기록(SHA-256·크기·등록 일시). **등록 완료 표시**이고 다음 달 보고서가 이것만 읽는다.

등록(``playbooks/host_audit_log_review_sign.yml``, tasks/log_review_sign.yml): Semaphore는 파일 업로드를 받지 못하므로(#556) 운영자가
러너의 접수 폴더에 ``<run_id>.pdf``를 두고 템플릿에는 실행 ID와 SHA-256만 준다. 버킷 키에는 Delete가 없고 잠금이 걸려 있어 잘못 올리면
지울 수 없으므로, 아래 검증을 **모두 통과해야만** 올린다: 입력 형식(``..._request``), 파일(``..._file_problems``: 일반 파일·크기·
``%PDF-`` 머리·해시 일치), 버킷(``..._target``: 정기 실행 포인터가 있고, 그 실행이 Log Review Report를 보냈고, 아직 등록 기록이 없음).

전월 서명본(3부 7번, ``JUDGES``): '전월 서명본'은 직전 정기 실행(Audit Baseline과 같은 고르기, ``host_audit_baseline_pick``)의 ``signed/``다.
tasks/log_review_signed.yml이 그 등록 기록을 GET하고 ``host_audit_log_review_signed_lookup``으로 판정 입력을 만들어
AUD-804 ``settings['previous_signed_copy']``로 넘긴다.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import AUTO, VERDICT_CHECK, VERDICT_OK, failed, result, unavailable  # noqa: E402
from host_audit_baseline import host_audit_baseline_pick, host_audit_storage_prefix  # noqa: E402

try:
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - pytest without ansible
    AnsibleFilterError = ValueError

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

ITEM = 'part3.previous_signed_copy'
SETTING = 'previous_signed_copy'
SCHEMA_VERSION = 1
RECORD_NAME = 'registration.json'
PDF_MAGIC = '%PDF-'
REPORT_TIMEZONE = 'Asia/Seoul'

_SAFE_RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')  # host_audit_mail._SAFE_RUN_ID와 같다
_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_STAMP = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$')

METHOD = ('직전 정기 실행(Audit Baseline 포인터로 고름)의 보관 경로 signed/registration.json(서명본 등록 기록)을 읽어 '
          '등록 일시와 SHA-256을 적는다')
CRITERION = '직전 정기 실행의 서명본이 등록돼 있으면 "있음", 없으면 "없음"(확인 필요)'
COLUMNS = ['직전 정기 실행', '시작', '서명본', '등록 일시', 'SHA-256', '크기(바이트)']


# ------------------------------------------------------------------ 공통

def _tz(tz_name):
    if ZoneInfo is None:  # pragma: no cover
        return timezone(timedelta(hours=9))
    return ZoneInfo(tz_name or REPORT_TIMEZONE)


def _parse(iso):
    m = _STAMP.match(str(iso or '').strip())
    return datetime(*[int(x) for x in m.groups()], tzinfo=timezone.utc) if m else None


def _local(iso, tz_name, fmt='%Y-%m-%d %H:%M'):
    dt = _parse(iso)
    return dt.astimezone(_tz(tz_name)).strftime(fmt) if dt else str(iso or '')


def _tz_label(tz_name):
    return 'KST' if (tz_name or REPORT_TIMEZONE) == REPORT_TIMEZONE else tz_name


def _status_text(what, status):
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = -1
    if status == -1:
        return '%s 연결 불가·시간 초과' % what
    return '%s HTTP %d' % (what, status)


def _json(response):
    try:
        doc = json.loads((response or {}).get('content') or '')
    except (TypeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def host_audit_log_review_signed_keys(run, tz_name=REPORT_TIMEZONE):
    """실행(``run_id``·``started_at``)의 서명본 위치: ``prefix``·``pdf_key``·``record_key``·``pdf_name``."""
    run = run or {}
    prefix = host_audit_storage_prefix(run, tz_name)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', str(run.get('run_id') or 'report')).strip('-.') or 'report'
    pdf_name = 'host-audit-%s-log-review-signed.pdf' % safe
    return {'prefix': prefix, 'pdf_name': pdf_name, 'pdf_key': prefix + 'signed/' + pdf_name,
            'record_key': prefix + 'signed/' + RECORD_NAME}


def _valid_record(doc, run_id):
    return (isinstance(doc, dict) and doc.get('run_id') == run_id and _SHA256.match(str(doc.get('sha256') or ''))
            and _parse(doc.get('registered_at')) is not None and str(doc.get('file_key') or ''))


# ------------------------------------------------------------------ 전월 서명본 확인 (보고서)

def host_audit_log_review_signed_lookup(history, run, response, tz_name=REPORT_TIMEZONE):
    """전월 서명본 판정 입력 ``{'state', 'reason', 'run_id', 'started_at', 'month', 'record'}``.

    ``history``: Audit Baseline 조회(``host_audit_baseline_history``, ``state`` ok/failed/disabled와 ``pointers``).
    ``response``: 직전 정기 실행의 ``signed/registration.json`` GET 결과(``status``·``content``), 부르지 않았으면 None.
    state: ``ok``(record가 None이면 없음), ``no_previous``(직전 정기 실행 없음), ``failed``, ``disabled``.
    """
    history = history or {}
    state = history.get('state') or 'disabled'
    if state == 'disabled':
        return {'state': 'disabled', 'reason': history.get('reason') or '보관 비활성'}
    if state != 'ok':
        return {'state': 'failed', 'reason': history.get('reason') or 'Audit Baseline 포인터 조회 실패'}
    pick = host_audit_baseline_pick(history.get('pointers') or [], run or {})
    if pick is None:
        return {'state': 'no_previous', 'reason': '전월 정기 실행 없음'}
    out = {'state': 'ok', 'reason': '', 'run_id': pick.get('run_id', ''), 'started_at': pick.get('started_at', ''),
           'month': _local(pick.get('started_at'), tz_name, '%Y-%m'), 'record': None}
    if response is None or (response or {}).get('skipped'):
        return dict(out, state='failed', reason='서명본 기록을 조회하지 않음')
    status = response.get('status', -1)
    if status == 404:
        return out
    if status != 200:
        return dict(out, state='failed', reason=_status_text('서명본 기록', status))
    doc = _json(response)
    if not _valid_record(doc, out['run_id']):
        return dict(out, state='failed', reason='서명본 기록 형식 오류')
    out['record'] = {k: doc.get(k) for k in ('file_key', 'sha256', 'size', 'registered_at', 'review_month')}
    return out


def judge_previous_signed_copy(ctx):
    signed = ctx['settings'].get(SETTING)
    tz_name = ctx['period'].get('timezone') or REPORT_TIMEZONE
    tz_label = _tz_label(tz_name)

    def _with(out, summary):
        out.update(summary='전월 서명본: ' + summary, method=METHOD, criterion=CRITERION)
        return out

    if not isinstance(signed, dict):
        return _with(unavailable('전월 서명본 확인 안 함'), '확인 안 함')
    state = signed.get('state')
    if state == 'no_previous':
        return _with(unavailable('전월 정기 실행 없음'), '전월 정기 실행 없음')
    if state == 'disabled':
        return _with(unavailable(signed.get('reason') or '보관 비활성'), '확인 안 함')
    if state != 'ok':
        return _with(failed(signed.get('reason') or '조회 실패'), '확인 실패')
    run_id, record = signed.get('run_id', ''), signed.get('record')
    expected = ctx['period'].get('month', '')
    off_month = bool(expected) and signed.get('month') != expected
    note = (' · 직전 정기 실행이 %s 실행이 아님(%s)' % (expected, run_id)) if off_month else ''
    started = '%s %s' % (_local(signed.get('started_at'), tz_name), tz_label)
    if record:
        when = '%s %s' % (_local(record.get('registered_at'), tz_name), tz_label)
        rows = [[run_id, started, record.get('file_key', ''), when, record.get('sha256', ''), record.get('size', '')]]
        out = result(AUTO, VERDICT_CHECK if off_month else VERDICT_OK, columns=COLUMNS, rows=rows)
        return _with(out, '있음(%s · SHA-256 %s)%s' % (when, record.get('sha256', ''), note))
    rows = [[run_id, started, '(등록 기록 없음)', '', '', '']]
    out = result(AUTO, VERDICT_CHECK, columns=COLUMNS, rows=rows)
    return _with(out, '없음(직전 정기 실행 %s의 signed/에 등록 기록 없음)%s' % (run_id, note))


JUDGES = {ITEM: judge_previous_signed_copy}


# ------------------------------------------------------------------ 등록 (Semaphore 템플릿)

def host_audit_log_review_signed_request(run_id, sha256, intake_dir):
    """등록 입력 검증. 틀리면 AnsibleFilterError(아무것도 읽거나 올리기 전에 멈춘다).

    반환: ``run_id``·``sha256``(소문자)·``src``(접수 폴더의 ``<run_id>.pdf``)·``pointer_key``(``baseline/<run_id>.json``).
    """
    run_id = str(run_id or '').strip()
    if not _SAFE_RUN_ID.match(run_id):
        raise AnsibleFilterError('서명본을 등록할 실행 ID가 비었거나 형식이 맞지 않음(영문·숫자·._- 만 허용): %r' % run_id)
    digest = str(sha256 or '').strip().lower()
    if not _SHA256.match(digest):
        raise AnsibleFilterError('서명본 SHA-256은 16진수 64자여야 함(sha256sum 출력의 앞부분): %r' % (sha256,))
    intake = str(intake_dir or '').rstrip('/')
    if not intake.startswith('/'):
        raise AnsibleFilterError('서명본 접수 폴더(host_audit_signed_intake_dir)는 절대 경로여야 함: %r' % (intake_dir,))
    return {'run_id': run_id, 'sha256': digest, 'src': '%s/%s.pdf' % (intake, run_id),
            'pointer_key': 'baseline/%s.json' % run_id}


def host_audit_log_review_signed_file_problems(stat, head, sha256, max_bytes):
    """접수 폴더의 파일 검증. 문제 문장 목록(빈 목록 = 통과). ``stat``: ``ansible.builtin.stat``(follow 없이, sha256)."""
    stat = stat or {}
    if not stat.get('exists'):
        return ['서명본 파일이 접수 폴더에 없음']
    if stat.get('islnk'):
        return ['서명본 파일이 심볼릭 링크임(일반 파일만 받는다)']
    if not stat.get('isreg'):
        return ['서명본 파일이 일반 파일이 아님']
    problems = []
    size = int(stat.get('size') or 0)
    if size <= 0:
        problems.append('서명본 파일이 비어 있음')
    elif size > int(max_bytes):
        problems.append('서명본 파일 크기 %d바이트가 상한 %d바이트를 넘음' % (size, int(max_bytes)))
    actual = str(stat.get('checksum') or '').lower()
    if actual != str(sha256 or '').lower():
        problems.append('SHA-256 불일치(입력 %s…, 파일 %s…): 다른 파일이거나 입력 오타' % (str(sha256)[:12], actual[:12]))
    if not str(head or '').startswith(PDF_MAGIC):
        problems.append('PDF 파일이 아님(파일 머리에 %s 없음)' % PDF_MAGIC)
    return problems


def host_audit_log_review_signed_target(request, pointer, summary=None, record=None, tz_name=REPORT_TIMEZONE):
    """버킷 쪽 검증: ``{'problems', 'prefix', 'pdf_key', 'record_key', 'pdf_name', 'started_at', 'review_month'}``.

    ``pointer``: ``baseline/<run_id>.json`` GET(정기 실행이고 보관이 끝났다는 증거, 보관 경로의 월도 여기서 정한다).
    ``summary``: ``<prefix>mail_summary.json`` GET(그 실행이 Log Review Report를 보냈는지). ``record``: ``signed/registration.json`` GET(404여야 함).
    응답이 None이면(앞 단계가 실패해 부르지 않음) 그 단계 문제는 앞 단계 문장 하나로 대신한다.
    """
    request = request or {}
    run_id = request.get('run_id', '')
    out = {'problems': [], 'prefix': '', 'pdf_key': '', 'record_key': '', 'pdf_name': '', 'started_at': '', 'review_month': ''}
    pointer = pointer or {}
    status = pointer.get('status', -1)
    if status == 404:
        out['problems'].append('정기 실행 기록(baseline/%s.json)이 없음: 실행 ID 오타, 수시 실행, 보관을 마치지 못한 실행은 등록하지 않는다'
                               % run_id)
        return out
    if status != 200:
        out['problems'].append(_status_text('정기 실행 기록', status))
        return out
    doc = _json(pointer)
    if not doc or doc.get('run_id') != run_id or doc.get('run_kind') != 'scheduled' or _parse(doc.get('started_at')) is None:
        out['problems'].append('정기 실행 기록(baseline/%s.json)의 형식이 맞지 않음' % run_id)
        return out
    out['started_at'] = doc['started_at']
    out.update(host_audit_log_review_signed_keys({'run_id': run_id, 'started_at': doc['started_at']}, tz_name))
    if summary is None:
        out['problems'].append('메일 요약을 조회하지 않음')
        return out
    if summary.get('status') != 200:
        out['problems'].append(_status_text('메일 요약(mail_summary.json)', summary.get('status', -1)))
    else:
        lr = (_json(summary) or {}).get('log_review')
        if not isinstance(lr, dict) or not lr.get('sha256'):
            out['problems'].append('이 실행은 Log Review Report를 보내지 않았음(메일 요약에 기록 없음)')
        else:
            out['review_month'] = str(lr.get('period') or '')
    if record is None:
        out['problems'].append('서명본 등록 기록을 조회하지 않음')
    elif record.get('status') == 200:
        prev = _json(record) or {}
        out['problems'].append('이미 등록된 서명본이 있음(등록 일시 %s %s, SHA-256 %s…): 잠금 버킷이라 덮어쓰지 않는다'
                               % (_local(prev.get('registered_at'), tz_name), _tz_label(tz_name),
                                  str(prev.get('sha256') or '')[:12]))
    elif record.get('status') != 404:
        out['problems'].append(_status_text('서명본 등록 기록', record.get('status', -1)))
    return out


def host_audit_log_review_signed_already_kept(head, md5, size):
    """같은 바이트의 서명본 PDF가 그 키에 이미 올라가 있는가(#572). 있으면 다시 올리지 않는다.

    ``head``: 키에 대한 HEAD 응답(``status``, 헤더 ``etag``·``content_length``). 200이고 크기와 ETag(큰따옴표 제외, 단일 PUT은 본문 MD5)가
    접수 파일의 ``size``·``md5``와 모두 같을 때만 참이다. 응답이 이상하거나 ETag를 못 받으면 거짓이라 그대로 올린다
    (건너뛰기는 최적화일 뿐, 틀리게 건너뛰면 기록이 없는 채 끝나므로 확실할 때만).
    """
    head = head or {}
    if head.get('status') != 200 or not md5:
        return False
    etag = str(head.get('etag') or '').strip().strip('"').lower()
    try:
        length = int(head.get('content_length'))
    except (TypeError, ValueError):
        return False
    return bool(etag) and etag == str(md5).strip().lower() and length == int(size or -1)


def host_audit_log_review_signed_record(request, target, size, registered_at):
    """``signed/registration.json`` 내용. 서명본 PDF가 올라간 뒤에만 쓴다(등록 완료 표시)."""
    return {'schema_version': SCHEMA_VERSION, 'run_id': request['run_id'], 'review_month': target.get('review_month', ''),
            'file_key': target['pdf_key'], 'sha256': request['sha256'], 'size': int(size or 0),
            'registered_at': str(registered_at)}


class FilterModule(object):
    """판정 모듈(JUDGES, 등록은 host_audit_log_review._JUDGE_MODULES)이자 서명본 조회·등록 필터."""

    def filters(self):
        return {
            'host_audit_log_review_signed_keys': host_audit_log_review_signed_keys,
            'host_audit_log_review_signed_lookup': host_audit_log_review_signed_lookup,
            'host_audit_log_review_signed_request': host_audit_log_review_signed_request,
            'host_audit_log_review_signed_file_problems': host_audit_log_review_signed_file_problems,
            'host_audit_log_review_signed_target': host_audit_log_review_signed_target,
            'host_audit_log_review_signed_record': host_audit_log_review_signed_record,
            'host_audit_log_review_signed_already_kept': host_audit_log_review_signed_already_kept,
        }
