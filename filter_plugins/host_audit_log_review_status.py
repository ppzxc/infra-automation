"""Log Review Report 3부 로그 관리 상태 나머지 (Spec #544 / Ticket-8 #563, ADR-0015).

보존 기간·시각 동기·전월 백업 결과·알림 이력·GitHub 감사 로그 수집 상태. 조회는 점검 기간 안의 OpenObserve ``_search``뿐이다.
- 시각 동기: ``host_status_logs``의 ``kind='time_sync'`` 판독(Host Agents 시각 동기 수집기, 5분 주기)을 수집 로스터 호스트와 대조한다.
  판독이 없는 호스트(수집기 미배포 등)와 도구가 없는 호스트(``no_tool``)는 '확인 불가'다(ADR-0015 Consequences, #544 이야기 23).
- 백업: ``backup_logs``(``host`` 필드)의 ``job='backup'`` 성공 일자와 실패 건수, 유지보수·무결성 검사(``job<>'backup'``) 실패.
  대상은 백업 누락 알림(``infra-backup-missing``)과 같은 수집 로스터다.
- GitHub: 조직 웹훅 수신 이벤트(``service_name='github-audit'``)는 참고 건수이고, 수집 상태는 전달 점검 작업의 하트비트
  (``service_name='github-webhook-watch'``, ``record_type='heartbeat'``)로 본다. 조직 웹훅에는 로그인 이벤트가 없다.
- 보존·알림 이력: 서버의 스트림 보존 설정과 알림 발생 이력은 ``_search``로 읽을 수 없다(이 역할은 다른 경로를 부르지 않는다, #556).
  보존은 저장소가 선언한 로그 종류별 보존 일수(기준 설정 ``log_management.retention_days``)를 기준과 대조하는 '일부 자동'이고,
  알림 이력은 '사람 대조'다.
기준 설정은 ``settings['log_management']``(tasks/log_review.yml AUD-804, role 기본값 ``host_audit_log_review_log_management``)다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import (  # noqa: E402
    AUTO, MANUAL, PARTIAL, VERDICT_CHECK, VERDICT_OK, failed, result, unavailable,
)
from host_audit_log_review_collection import _ranges  # noqa: E402  같은 날짜 범위 표기(10-03~10-05)

TIME_SYNC = 'part3.time_sync'
TIME_SYNC_QUERY = 'status_time_sync'
BACKUP = 'part3.backup'
BACKUP_DAILY = 'status_backup_daily'
BACKUP_OTHERS = 'status_backup_other_failures'
GITHUB = 'part3.github_audit'
GITHUB_HEARTBEATS = 'status_github_heartbeats'
GITHUB_EVENTS = 'status_github_events'
_SIZE = 20000

DEFAULT_MAX_OFFSET_MS = 1000

UNVERIFIABLE = '확인 불가'


def _settings(ctx):
    return ctx['settings'].get('log_management') or {}


def _hosts(ctx):
    return sorted({str(h) for h in ((ctx['settings'].get('collection_targets') or {}).get('hosts') or [])})


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _unverifiable(name, ctx, why=''):
    if name in ctx['collection_gap']:
        return '%s(수집 공백)' % UNVERIFIABLE
    return '%s(%s)' % (UNVERIFIABLE, why) if why else UNVERIFIABLE


# ------------------------------------------------------------------ 시각 동기

TIME_SYNC_METHOD = ('OpenObserve host_status_logs의 시각 동기 판독(kind=time_sync, 5분 주기)을 호스트별로 집계해 '
                    '수집 로스터 호스트와 대조')
TIME_SYNC_COLUMNS = ['호스트', '판독', '동기', '미동기·오류', '최대 오차(ms)', '상태']


def judge_time_sync(ctx):
    hosts = _hosts(ctx)
    if not hosts:
        return unavailable('수집 대상 목록 없음')
    r = ctx['results'].get(TIME_SYNC_QUERY) or {'ok': False, 'error': '조회하지 않음'}
    if not r['ok']:
        return failed(r['error'])
    limit = _int(_settings(ctx).get('time_sync_max_offset_ms')) or DEFAULT_MAX_OFFSET_MS
    seen = {}
    for h in r['hits']:
        name = str(h.get('name') or '').strip()
        if not name:
            continue
        s = seen.setdefault(name, {'readings': 0, 'synced': 0, 'bad': 0, 'no_tool': 0, 'offset': None})
        n = _int(h.get('readings'))
        status = str(h.get('sync_status') or '')
        s['readings'] += n
        if status == 'synced':
            s['synced'] += n
        elif status == 'no_tool':
            s['no_tool'] += n
        else:
            s['bad'] += n
        try:  # 문자열·소수로 와도 오차를 0으로 읽지 않는다(_int는 실패를 0으로 바꾼다)
            off = abs(float(h.get('max_offset_ms')))
        except (TypeError, ValueError):
            off = None
        if off is not None:
            off = int(round(off))
            s['offset'] = off if s['offset'] is None else max(s['offset'], off)
    rows, unknown, check = [], 0, 0
    for name in hosts:
        s = seen.get(name)
        if not s or not s['readings']:
            state = _unverifiable(name, ctx, '판독 없음')
            rows.append([name, 0, 0, 0, '-', state])
            unknown += 1
            continue
        if s['no_tool'] and not s['synced'] and not s['bad']:
            state = _unverifiable(name, ctx, '동기 도구 없음')
            unknown += 1
        elif s['bad'] or s['no_tool'] or (s['offset'] is not None and s['offset'] > limit):
            state = VERDICT_CHECK
            check += 1
        else:
            state = VERDICT_OK
        rows.append([name, s['readings'], s['synced'], s['bad'] + s['no_tool'],
                     '-' if s['offset'] is None else s['offset'], state])
    status = PARTIAL if unknown else AUTO
    verdict = VERDICT_CHECK if (check or unknown) else VERDICT_OK
    summary = '대상 호스트 %d대 중 확인 필요 %d · 확인 불가 %d' % (len(hosts), check, unknown)
    return result(status, verdict, summary=summary, columns=TIME_SYNC_COLUMNS, rows=rows, method=TIME_SYNC_METHOD,
                  criterion='미동기·도구 없음·오류 판독이 있거나 오차 절댓값이 %dms를 넘으면 "확인 필요", '
                            '판독이 없는 호스트는 "확인 불가"' % limit)


# ------------------------------------------------------------------ 전월 백업 결과

BACKUP_METHOD = ('OpenObserve backup_logs의 job=backup 결과를 호스트(host)·KST 일자별로 집계해 수집 로스터 호스트와 대조하고, '
                 '유지보수·무결성 검사(job≠backup) 실패를 함께 센다')
BACKUP_CRITERION = '실패가 있거나, 성공한 백업이 없는 날이 있거나(누락), 유지보수·무결성 검사 실패가 있으면 "확인 필요"'
BACKUP_COLUMNS = ['대상', '성공 일수', '실패', '빈 날짜', '상태']


def _success(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('true', '1')


def judge_backup(ctx):
    hosts = _hosts(ctx)
    if not hosts:
        return unavailable('수집 대상 목록 없음')
    results = ctx['results']
    daily = results.get(BACKUP_DAILY) or {'ok': False, 'error': '조회하지 않음'}
    others = results.get(BACKUP_OTHERS) or {'ok': False, 'error': '조회하지 않음'}
    if not daily['ok']:
        return failed(daily['error'])
    all_days = ctx['period']['days']
    ok_days, failures = {}, {}
    for h in daily['hits']:
        name, day, runs = str(h.get('name') or '').strip(), str(h.get('day') or '').strip(), _int(h.get('runs'))
        if not name or not day or runs <= 0:
            continue
        if _success(h.get('success')):
            ok_days.setdefault(name, set()).add(day)
        else:
            failures[name] = failures.get(name, 0) + runs
    rows, check = [], 0
    for name in hosts:
        days, failed_runs = ok_days.get(name, set()), failures.get(name, 0)
        missing = [d for d in all_days if d not in days]
        if not days:
            state = '성공 없음(수집 공백)' if name in ctx['collection_gap'] else '성공 없음'
            gaps = '전체'
        else:
            gaps = _ranges(missing) if missing else ''
            notes = (['실패 %d회' % failed_runs] if failed_runs else []) + (['누락 %d일' % len(missing)] if missing else [])
            state = ', '.join(notes) or VERDICT_OK
        if state != VERDICT_OK:
            check += 1
        rows.append([name, len(days), failed_runs, gaps, state])
    other_rows = []
    if others['ok']:
        for h in others['hits']:
            n = _int(h.get('failures'))
            if n > 0:
                label = '%s/%s' % (h.get('job') or '-', h.get('command') or '-')
                other_rows.append([label, '-', n, '', '실패 %d회' % n])
        check += len(other_rows)
    summary = '대상 호스트 %d대 중 확인 필요 %d (유지보수·무결성 검사 실패 %d종)' % (
        len(hosts), check - len(other_rows), len(other_rows))
    verdict = VERDICT_CHECK if check else VERDICT_OK
    if not others['ok']:
        out = failed('유지보수·무결성 검사 결과 %s' % others['error'])
        out.update(summary=summary + ' (조회한 부분만)', columns=BACKUP_COLUMNS, rows=rows,
                   method=BACKUP_METHOD, criterion=BACKUP_CRITERION)
        return out
    return result(AUTO, verdict, summary=summary, columns=BACKUP_COLUMNS, rows=rows + sorted(other_rows),
                  method=BACKUP_METHOD, criterion=BACKUP_CRITERION)


# ------------------------------------------------------------------ GitHub 감사 로그 수집 상태

GITHUB_METHOD = ('OpenObserve security_logs의 GitHub 조직 웹훅 전달 점검 하트비트(service_name=github-webhook-watch)를 KST 일자별로 '
                 '보고, 수신 이벤트(service_name=github-audit) 건수를 참고로 센다. 조직 웹훅에는 로그인 이벤트가 없어 로그인은 이 항목이 '
                 '보지 않는다(월간 감사 로그 내보내기로 보완)')
GITHUB_CRITERION = ('전달 점검 기록이 없는 날, 점검 오류, 훅 상태 이상(missing·inactive·events_mismatch·unknown), '
                    '재전송 기간을 넘기거나 복구되지 않은 실패 전달이 있으면 "확인 필요". 조직 이벤트가 없는 것은 이상이 아니다')
GITHUB_COLUMNS = ['구분', '날짜', '건수']


def _days_where(hits, pred, value):
    days, total = set(), 0
    for h in hits:
        if pred(h):
            days.add(str(h.get('day')))
            total = value(h, total)
    return days, total


def judge_github_audit(ctx):
    results, all_days = ctx['results'], ctx['period']['days']
    beats = results.get(GITHUB_HEARTBEATS) or {'ok': False, 'error': '조회하지 않음'}
    events = results.get(GITHUB_EVENTS) or {'ok': False, 'error': '조회하지 않음'}
    if not beats['ok']:
        return failed('전달 점검 기록 %s' % beats['error'])
    hits = [h for h in beats['hits'] if str(h.get('day') or '').strip() and _int(h.get('checks')) > 0]
    checks = sum(_int(h.get('checks')) for h in hits)
    seen = {str(h['day']) for h in hits}
    rows = []
    missing = [d for d in all_days if d not in seen]
    if missing:
        rows.append(['전달 점검 기록 없는 날', '전체' if not seen else _ranges(missing), len(missing)])

    def add(label, pred, value):
        days, total = _days_where(hits, pred, value)
        if days:
            rows.append([label, _ranges(days), total])

    count = lambda h, t: t + _int(h.get('checks'))  # noqa: E731
    add('점검 오류(result=error)', lambda h: str(h.get('result')) != 'ok', count)
    for status in sorted({str(h.get('hook_status')) for h in hits} - {'ok'}):
        if status != 'unknown':  # unknown은 API 호출 실패(result=error)와 같은 줄이다
            add('훅 상태 %s' % status, lambda h, s=status: str(h.get('hook_status')) == s, count)
    add('재전송 기간을 넘긴 실패 전달(최대)', lambda h: _int(h.get('expired')) > 0,
        lambda h, t: max(t, _int(h.get('expired'))))
    add('복구되지 않은 실패 전달(최대)', lambda h: _int(h.get('failed')) > 0, lambda h, t: max(t, _int(h.get('failed'))))
    received = sum(_int(h.get('records')) for h in events['hits']) if events['ok'] else None
    summary = '전달 점검 %d회(%d일) · 수신 이벤트 %s' % (
        checks, len(seen), ('%d건' % received) if received is not None else '조회 실패')
    if not events['ok']:
        out = failed('수신 이벤트 %s' % events['error'])
        out.update(summary=summary, columns=GITHUB_COLUMNS if rows else [], rows=rows,
                   method=GITHUB_METHOD, criterion=GITHUB_CRITERION)
        return out
    return result(AUTO, VERDICT_CHECK if rows else VERDICT_OK, summary=summary, columns=GITHUB_COLUMNS if rows else [],
                  rows=rows, method=GITHUB_METHOD, criterion=GITHUB_CRITERION)


# ------------------------------------------------------------------ 보존 기간

STANDARD_DAYS = 365           # 로그 1년(ISMS 2.9.4, 회사 로그 보관 정책)
PERSONAL_INFO_DAYS = 730      # 개인정보처리시스템 접속기록 2년(개인정보의 안전성 확보조치 기준)
RETENTION_COLUMNS = ['로그 종류(스트림)', '보존(일)', '기준(일)', '상태']
RETENTION_METHOD = ('저장소가 선언한 로그 종류별 OpenObserve 보존 일수(ADR-0006 스트림 표, role 기본값)를 기준과 대조. '
                    '서버의 실제 보존 설정은 조회 전용 경로(POST _search)로 읽을 수 없어 점검자가 OpenObserve 화면'
                    '(스트림 상세의 Data Retention, 비어 있으면 서버 전역 값)에서 같은지 확인한다')


def judge_retention(ctx):
    settings = _settings(ctx)
    declared = settings.get('retention_days') or {}
    if not declared:
        return unavailable('보존 기간 설정 없음')
    pii = bool(settings.get('personal_info_system'))
    standard = PERSONAL_INFO_DAYS if pii else STANDARD_DAYS
    rows, short = [], 0
    for stream in sorted(declared):
        days = _int(declared[stream])
        ok = days >= standard
        short += 0 if ok else 1
        rows.append([str(stream), days, standard, VERDICT_OK if ok else '기준 미달'])
    basis = '개인정보처리시스템 포함, 접속기록 2년' if pii else '개인정보처리시스템 없음, 1년'
    summary = ('로그 종류 %d개 중 기준 미달 %d (기준 %s). 서버 설정은 _search로 읽지 못해 점검자가 대조한다'
               % (len(rows), short, basis))
    return result(PARTIAL, VERDICT_CHECK if short else VERDICT_OK, summary=summary, columns=RETENTION_COLUMNS,
                  rows=rows, method=RETENTION_METHOD,
                  criterion='로그 종류마다 보존 %d일 이상(개인정보처리시스템 접속기록은 %d일 이상)'
                            % (STANDARD_DAYS, PERSONAL_INFO_DAYS))


# ------------------------------------------------------------------ 알림 이력

def judge_alert_history(ctx):
    return result(
        MANUAL,
        summary='알림 발생 이력은 OpenObserve 알림 기능에 있고 로그 스트림이 아니라서 조회 전용 경로(POST _search)로 읽을 수 없다',
        method='점검자가 OpenObserve 알림 화면의 이력에서 점검 기간의 발생을 알림 이름별로 센다. 같은 알림이 같은 대상에서 '
               '반복되면 원인이 풀렸는지, 조치 없이 닫힌 알림은 사유를 기록한다(docs/runbooks/alerts.md)',
        criterion='반복 발생·조치 없이 닫힌 알림이 있으면 소견에 사유를 적는다')


QUERIES = {
    GITHUB: [
        {'name': GITHUB_HEARTBEATS, 'size': 2000,
         'sql': "SELECT date_format(_timestamp, '%Y-%m-%d', '{offset}') AS day, result, hook_status, count(*) AS checks, "
                "max(expired_count) AS expired, max(failed_count) AS failed FROM \"security_logs\" "
                "WHERE service_name = 'github-webhook-watch' AND record_type = 'heartbeat' GROUP BY day, result, hook_status"},
        {'name': GITHUB_EVENTS, 'size': 10,
         'sql': "SELECT count(*) AS records FROM \"security_logs\" WHERE service_name = 'github-audit'"},
    ],
    BACKUP: [
        {'name': BACKUP_DAILY, 'size': _SIZE,
         'sql': "SELECT host AS name, date_format(_timestamp, '%Y-%m-%d', '{offset}') AS day, success, count(*) AS runs "
                "FROM \"backup_logs\" WHERE job = 'backup' GROUP BY name, day, success"},
        {'name': BACKUP_OTHERS, 'size': 1000,
         'sql': "SELECT job, command, count(*) AS failures FROM \"backup_logs\" "
                "WHERE job <> 'backup' AND success = false GROUP BY job, command"},
    ],
    TIME_SYNC: [
        {'name': TIME_SYNC_QUERY, 'size': _SIZE,
         'sql': "SELECT host_name AS name, sync_status, count(*) AS readings, max(abs(offset_ms)) AS max_offset_ms "
                "FROM \"host_status_logs\" WHERE kind = 'time_sync' GROUP BY name, sync_status"},
    ],
}

JUDGES = {
    'part3.retention': judge_retention,
    'part3.alert_history': judge_alert_history,
    GITHUB: judge_github_audit,
    BACKUP: judge_backup,
    TIME_SYNC: judge_time_sync,
}


class FilterModule(object):
    """판정 모듈(필터 없음). 등록은 host_audit_log_review._JUDGE_MODULES가 한다."""

    def filters(self):
        return {}
