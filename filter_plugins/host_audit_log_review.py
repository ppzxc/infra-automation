"""Log Review Report 보고서 모델 (Spec #544 / Ticket-3 #558, ADR-0015).

Host Audit 정기 실행이 전월 한 달(KST 달력 월)의 OpenObserve 조회 결과로 Log Review Report 초안을 만든다.
판정은 모두 이 필터(와 판정 모듈)에 있고, 태스크(roles/host_audit/tasks/log_review.yml)는 조회 결과를 그대로 넘기기만 한다.
템플릿(log_review.html.j2)은 모델을 그리기만 한다.

구조(후속 티켓이 항목 단위로 덧붙이는 자리):
- 항목 정의(1부 19·2부 9·3부)는 ``host_audit_log_review_items.py``의 표다.
- 판정은 묶음별 모듈(``host_audit_log_review_<묶음>.py``)의 ``JUDGES = {항목 key: 함수}``이고, 그 판정이 쓰는 OpenObserve
  조회는 같은 모듈의 ``QUERIES = {항목 key: [{'name', 'sql', 'size'}]}``다. 모듈을 만들면 아래 ``_JUDGE_MODULES``에 한 줄 더한다.
- 판정 함수는 ``judge(ctx)``이고 ``host_audit_log_review_items.result(...)``로 만든 dict를 돌려준다. ``ctx``: ``period``, ``results``({조회 이름:
  {'ok', 'hits', 'error'}}), ``settings``(기준 설정), ``collection_gap``(3부 수집 공백 이름 집합, 1부가 공백과 연결할 때 쓴다).
- 조회는 OpenObserve ``POST /api/<org>/_search`` 하나뿐이다(조회 전용 계정, 서버는 조회 전용을 강제하지 못한다: #556).

항목 상태(ADR-0015 §4·#544): ``auto``(자동 판정: 이상 없음/확인 필요), ``partial``(일부 자동), ``manual``(사람 대조),
``unavailable``(점검 불가, 사유), ``failed``(조회 실패). 최종 판정·소견·조치 칸은 언제나 비어 있다(사람이 쓴다).
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import (  # noqa: E402
    AUTO, FAILED, MANUAL, PART1, PART2, PART3, PARTIAL, STATUS_LABELS, UNAVAILABLE, result as _result,
)
import host_audit_log_review_collection as _collection  # noqa: E402
import host_audit_log_review_accounts as _accounts  # noqa: E402
import host_audit_log_review_status as _status  # noqa: E402

try:
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - pytest without ansible
    AnsibleFilterError = ValueError

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

SCHEMA_VERSION = 1
REPORT_TIMEZONE = 'Asia/Seoul'
TITLE = 'Log Review Report (로그·보안정책 검토 결과)'

# 판정 모듈. 후속 티켓은 모듈 하나를 만들고 여기에 한 줄을 더한다(같은 파일의 다른 줄을 건드리지 않는다).
_JUDGE_MODULES = (
    _collection,
    _accounts,
    _status,
)

APPROVERS = ('점검자', '정보보호관리자', '정보보호책임자(CISO)')

_STAMP = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$')


def _tz(tz_name):
    if ZoneInfo is None:  # pragma: no cover
        return timezone(timedelta(hours=9))
    return ZoneInfo(tz_name or REPORT_TIMEZONE)


def _offset(dt):
    total = int(dt.utcoffset().total_seconds() // 60)
    sign = '+' if total >= 0 else '-'
    return '%s%02d:%02d' % (sign, abs(total) // 60, abs(total) % 60)


def host_audit_log_review_period(started_at, tz_name=REPORT_TIMEZONE):
    """점검 기간: 실행 시작 시각(UTC ISO)이 속한 보고서 시간대 월의 전월 1일 00:00 ~ 말일 24:00.

    끝은 포함하지 않는다(다음 달 1일 00:00 미만). ``start_us``·``end_us``는 OpenObserve ``_search``의 마이크로초,
    ``utc_offset``은 ``date_format``의 세 번째 인자(시간대 이름을 쓰지 않는다)다.
    """
    m = _STAMP.match(str(started_at or '').strip())
    if not m:
        raise AnsibleFilterError('Log Review 점검 기간: 실행 시작 시각 형식이 맞지 않음(UTC ISO, ...Z): %r' % (started_at,))
    tz = _tz(tz_name)
    started = datetime(*[int(x) for x in m.groups()], tzinfo=timezone.utc).astimezone(tz)
    end = datetime(started.year, started.month, 1, tzinfo=tz)
    prev = end - timedelta(days=1)
    start = datetime(prev.year, prev.month, 1, tzinfo=tz)
    days = [(start + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(prev.day)]
    label_tz = 'KST' if (tz_name or REPORT_TIMEZONE) == 'Asia/Seoul' else (tz_name or REPORT_TIMEZONE)
    return {
        'month': start.strftime('%Y-%m'),
        'start': start.strftime('%Y-%m-%d 00:00'),
        'end': prev.strftime('%Y-%m-%d 24:00'),
        'label': '%s ~ %s (%s)' % (start.strftime('%Y-%m-%d 00:00'), prev.strftime('%Y-%m-%d 24:00'), label_tz),
        'start_us': int(start.timestamp()) * 1000000,
        'end_us': int(end.timestamp()) * 1000000,
        'utc_offset': _offset(start),
        'timezone': tz_name or REPORT_TIMEZONE,
        'days': days,
    }


def host_audit_log_review_file_name(run_id):
    """메일 세 번째 첨부·보관 파일의 ASCII 이름: ``host-audit-<run_id>-log-review.html``."""
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', str(run_id or 'report')).strip('-.') or 'report'
    return 'host-audit-%s-log-review.html' % safe


def _registry(name):
    merged = {}
    for module in _JUDGE_MODULES:
        for key, value in (getattr(module, name, None) or {}).items():
            if key in merged:
                raise AnsibleFilterError('Log Review 항목 %s의 %s가 두 모듈에 있음' % (key, name))
            merged[key] = value
    return merged


def host_audit_log_review_queries(period):
    """이번 점검 기간에 부를 OpenObserve 조회 목록 ``[{'name', 'size', 'body'}]``.

    ``body``는 ``POST /api/<org>/_search``의 본문 그대로다. SQL의 ``{offset}``은 기간의 UTC 오프셋(+09:00)으로 바뀐다.
    """
    period = period or {}
    out, seen = [], set()
    registry = _registry('QUERIES')
    for key in sorted(registry):
        for spec in registry[key]:
            if spec['name'] in seen:
                raise AnsibleFilterError('Log Review 조회 이름 중복: %s' % spec['name'])
            seen.add(spec['name'])
            size = int(spec.get('size') or 1000)
            out.append({'name': spec['name'], 'size': size, 'body': {'query': {
                'sql': spec['sql'].replace('{offset}', period.get('utc_offset', '+09:00')),
                'start_time': int(period.get('start_us') or 0),
                'end_time': int(period.get('end_us') or 0),
                'from': 0,
                'size': size,
            }}})
    return out


def _http_error(result):
    status = result.get('status', -1)
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = -1
    if status == -1:
        return '연결 불가·시간 초과'
    if status in (401, 403):
        return 'HTTP %d(인증·권한)' % status
    return 'HTTP %d' % status


def host_audit_log_review_results(uri_results, problem=''):
    """``ansible.builtin.uri`` 반복 결과를 ``{조회 이름: {'ok', 'hits', 'error'}}``로 바꾼다.

    ``problem``이 있으면(자격증명·주소 문서를 못 읽음) 모든 조회가 그 사유로 실패다. 원인 문구에는 주소·계정·응답 본문을
    넣지 않는다(상태 코드만). 결과 행 수가 요청한 ``size``에 닿으면 잘렸을 수 있어 실패로 본다(잘린 결과로 공백을 만들지 않는다).
    """
    if isinstance(uri_results, dict):
        uri_results = uri_results.get('results') or []
    out = {}
    for r in uri_results or []:
        if not isinstance(r, dict):
            continue
        item = r.get('item') or {}
        name = item.get('name')
        if not name:
            continue
        if problem:
            out[name] = {'ok': False, 'hits': [], 'error': str(problem)}
            continue
        if r.get('skipped'):
            out[name] = {'ok': False, 'hits': [], 'error': '조회하지 않음'}
            continue
        body = r.get('json')
        if r.get('status') != 200 or not isinstance(body, dict) or not isinstance(body.get('hits'), list):
            out[name] = {'ok': False, 'hits': [], 'error': _http_error(r) if r.get('status') != 200 else '응답 형식 오류'}
            continue
        hits = [h for h in body['hits'] if isinstance(h, dict)]
        size = int(item.get('size') or 0)
        if size and len(hits) >= size:
            out[name] = {'ok': False, 'hits': [], 'error': '결과가 조회 한도(%d행)에 닿음' % size}
            continue
        out[name] = {'ok': True, 'hits': hits, 'error': ''}
    return out


def _status_label(status, reason):
    label = STATUS_LABELS.get(status, status)
    if status in (UNAVAILABLE, FAILED) and reason:
        return '%s(%s)' % (label, reason)
    return label


def _evaluate(definition, part, judges, ctx, errors):
    judge = judges.get(definition['key'])
    if judge is None:
        res = _result(definition['default_status'], reason=definition['default_reason'])
    else:
        try:
            res = judge(ctx)
        except Exception as exc:  # 한 항목의 판정 오류가 보고서 전체를 막지 않는다. 실행은 끝에서 실패로 끝난다(AUD-806).
            errors.append('%s: %s' % (definition['key'], type(exc).__name__))
            res = _result(FAILED, reason='판정 오류 %s' % type(exc).__name__)
    if res['status'] not in STATUS_LABELS:
        errors.append('%s: 알 수 없는 상태 %r' % (definition['key'], res['status']))
        res = _result(FAILED, reason='판정 오류(상태 값)')
    item = {
        'part': part, 'no': definition['no'], 'key': definition['key'], 'title': definition['title'],
        'method': definition['method'], 'criterion': definition['criterion'],
        'status_label': _status_label(res['status'], res['reason']),
        # 사람이 쓰는 칸(ADR-0015 §4). 모델은 언제나 비워 둔다.
        'final_verdict': '', 'remarks': '', 'action': '',
    }
    item.update((k, v) for k, v in res.items() if k not in ('method', 'criterion'))
    for key in ('method', 'criterion'):  # 판정이 이번에 쓴 방법·기준(임곗값)을 주면 표 문구 대신 찍힌다
        if res.get(key):
            item[key] = res[key]
    return item


def _local(iso, tz_name):
    m = _STAMP.match(str(iso or '').strip())
    if not m:
        return str(iso or '')
    dt = datetime(*[int(x) for x in m.groups()], tzinfo=timezone.utc).astimezone(_tz(tz_name))
    return dt.strftime('%Y-%m-%d %H:%M')


def host_audit_log_review_model(results, meta):
    """Log Review Report 모델: 머리·1부(19)·2부(9)·3부·결재란.

    ``results``: ``host_audit_log_review_results``의 출력. ``meta``: ``run_id``, ``run_kind``, ``started_at``·``generated_at``
    (UTC ISO), ``timezone``, ``period``(``host_audit_log_review_period``), ``settings``(기준 설정: ``collection_targets``
    ``{'hosts': [...], 'devices': [...]}`` 등), ``archive``(보관 위치 문구).
    """
    meta = meta or {}
    tz_name = meta.get('timezone') or REPORT_TIMEZONE
    period = meta.get('period') or host_audit_log_review_period(meta.get('started_at'), tz_name)
    settings = meta.get('settings') or {}
    judges = _registry('JUDGES')
    ctx = {'period': period, 'results': results or {}, 'settings': settings, 'collection_gap': set()}
    errors = []
    # 3부를 먼저 계산한다: 1부 판정이 수집 공백 호스트를 연결해 '이상 없음'으로 단정하지 않게 한다(#544 이야기 21).
    part3 = [_evaluate(d, 3, judges, ctx, errors) for d in PART3]
    part1 = [_evaluate(d, 1, judges, ctx, errors) for d in PART1]
    part2 = [_evaluate(d, 2, judges, ctx, errors) for d in PART2]
    counts = dict((s, 0) for s in STATUS_LABELS)
    for item in part1 + part2 + part3:
        counts[item['status']] += 1
    targets = settings.get('collection_targets') or {}
    return {
        'schema_version': SCHEMA_VERSION,
        'title': TITLE,
        'run_id': meta.get('run_id', ''),
        'run_kind': meta.get('run_kind', ''),
        'started_at': _local(meta.get('started_at'), tz_name),
        'generated_at': _local(meta.get('generated_at'), tz_name),
        'period': period,
        'scope': '호스트 %d대 · 장비 %d대 (OpenObserve에 수집되는 서버·네트워크·보안 장비·서비스 로그)' % (
            len(targets.get('hosts') or []), len(targets.get('devices') or [])),
        'source': 'OpenObserve(조회 전용 계정, POST _search만 호출. 서버가 조회 전용을 강제하지는 않는다)',
        'archive': meta.get('archive', ''),
        'status_legend': [{'key': s, 'label': STATUS_LABELS[s]} for s in (AUTO, PARTIAL, MANUAL, UNAVAILABLE, FAILED)],
        'counts': [{'key': s, 'label': STATUS_LABELS[s], 'count': counts[s]} for s in (AUTO, PARTIAL, MANUAL, UNAVAILABLE, FAILED)],
        'part1': part1,
        'part2': part2,
        'part3': part3,
        'approvals': [{'role': r, 'name': '', 'signature': '', 'date': ''} for r in APPROVERS],
        'errors': errors,
    }


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_log_review_period': host_audit_log_review_period,
            'host_audit_log_review_file_name': host_audit_log_review_file_name,
            'host_audit_log_review_queries': host_audit_log_review_queries,
            'host_audit_log_review_results': host_audit_log_review_results,
            'host_audit_log_review_model': host_audit_log_review_model,
        }
