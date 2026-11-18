"""Log Review Report 1부 계정·시간 항목 1·2·3·4·5번 (Spec #544 / Ticket-4 #559, ADR-0015).

서버 sshd·sudo·su 기록(``security_logs``, ``security_semantics`` VRL이 붙인 ``event_action``·``event_outcome``·``user_name``)과
auditd 계정 관리 기록으로 판정한다. 조회는 모두 OpenObserve에서 집계해서 받는다(원시 이벤트를 받으면 자동화 로그인·sudo만으로
조회 한도에 닿는다). 시각은 수신 시각 ``_timestamp``의 KST(점검 기간의 UTC 오프셋)다.

기준 설정 ``settings['accounts']``(tasks/log_review.yml AUD-804):
- ``hosts``: ``{인벤토리 호스트명: {'declared', 'bootstrap', 'agents_only', 'inventory_accounts'}}``
  (``host_audit_log_review_account_hosts``가 만든다). 목록에 없는 호스트는 '허용 계정 목록 없음'으로 드러난다.
- ``business_hours``(``{'start': 8, 'end': 20}``, 정시), ``holidays``(``{연도: ['YYYY-MM-DD', ...]}``),
  ``failure_threshold``·``failure_window_minutes``.
``settings['personal_info_systems']``(호스트 이름 목록)가 있으면 개인정보처리시스템 행을 따로 표시하고, 없으면 '미지정'이다.
이 값의 원본은 로그 검토 작업 설정 문서(#560)다.
수집 공백 호스트(3부, ``ctx['collection_gap']``)는 '이상 없음'으로 단정하지 않는다: 행을 붙이고 판정을 '확인 필요'로 둔다.
"""

import os
import sys
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import (  # noqa: E402
    AUTO, MANUAL, PARTIAL, VERDICT_CHECK, VERDICT_OK, failed, result,
)
import host_audit_log_review_collection as _collection  # noqa: E402

ITEM_UNAUTHORIZED = 'part1.unauthorized_account'
ITEM_FAILURES = 'part1.login_failures'
ITEM_OFF_HOURS_LOGIN = 'part1.off_hours_login'
ITEM_OFF_HOURS_PRIVILEGE = 'part1.off_hours_privilege'
ITEM_ABSENTEE = 'part1.absentee_login'

SUCCESS_HOURLY = 'accounts_ssh_success_hourly'
FAILURE_MINUTELY = 'accounts_ssh_failure_minutely'
INVALID_USER = 'accounts_ssh_invalid_user'
PRIVILEGE_HOURLY = 'accounts_privilege_hourly'
ACCOUNT_CHANGE_HOURLY = 'accounts_account_change_hourly'

# 결과 행 수 한도. 닿으면 잘린 결과라 조회 실패다(host_audit_log_review_results).
_SIZE = 50000
_FAILURE_SIZE = 100000
# 보고서 표에 싣는 행 수 한도(A4 인쇄). 넘으면 요약에 남은 수를 적는다.
MAX_ROWS = 200

_HOUR = "date_format(_timestamp, '%Y-%m-%d %H', '{offset}')"
_MINUTE = "date_format(_timestamp, '%Y-%m-%d %H:%M', '{offset}')"
_ACCOUNT_TYPES = ('ADD_USER', 'DEL_USER', 'ADD_GROUP', 'DEL_GROUP', 'USER_MGMT', 'GRP_MGMT', 'USER_CHAUTHTOK',
                  'GRP_CHAUTHTOK', 'CHUSER_ID', 'CHGRP_ID', 'ACCT_LOCK', 'ACCT_UNLOCK')

_SUCCESS_QUERY = {
    'name': SUCCESS_HOURLY, 'size': _SIZE,
    'sql': "SELECT host_name AS host, user_name AS user, " + _HOUR + " AS hour, count(*) AS logins "
           "FROM \"security_logs\" WHERE event_action = 'ssh_login' AND event_outcome = 'success' "
           "GROUP BY host, user, hour"}
_INVALID_QUERY = {
    'name': INVALID_USER, 'size': 5000,
    # "Invalid user" 줄만 센다: 같은 시도의 "Failed password for invalid user" 줄(event_outcome failure)과 이중 집계하지 않는다.
    'sql': "SELECT host_name AS host, count(*) AS attempts, count(DISTINCT user_name) AS users, "
           "count(DISTINCT source_address) AS sources FROM \"security_logs\" "
           "WHERE event_action = 'ssh_login' AND event_reason = 'invalid user' AND event_outcome IS NULL GROUP BY host"}
_FAILURE_QUERY = {
    'name': FAILURE_MINUTELY, 'size': _FAILURE_SIZE,
    'sql': "SELECT host_name AS host, user_name AS user, " + _MINUTE + " AS minute, count(*) AS failures "
           "FROM \"security_logs\" WHERE event_action = 'ssh_login' AND event_outcome = 'failure' "
           "AND (event_reason IS NULL OR event_reason <> 'invalid user') GROUP BY host, user, minute"}
_PRIVILEGE_QUERY = {
    'name': PRIVILEGE_HOURLY, 'size': _SIZE,
    'sql': "SELECT host_name AS host, user_name AS user, event_action AS action, " + _HOUR + " AS hour, count(*) AS runs, "
           "sum(CASE WHEN process_command_line LIKE '%BECOME-SUCCESS-%' THEN 1 ELSE 0 END) AS automation "
           "FROM \"security_logs\" WHERE event_action IN ('sudo', 'su') AND event_outcome = 'success' "
           "GROUP BY host, user, action, hour"}
_ACCOUNT_CHANGE_QUERY = {
    'name': ACCOUNT_CHANGE_HOURLY, 'size': _SIZE,
    'sql': "SELECT host_name AS host, regexp_replace(body, '^type=([A-Z_]+) .*$', '\\1') AS kind, "
           "CASE WHEN body LIKE '%AUID=\"%' THEN substr(regexp_replace(body, '^.*AUID=\"([^\"]*)\".*$', '\\1'), 1, 40) "
           "ELSE '' END AS actor, " + _HOUR + " AS hour, count(*) AS changes FROM \"security_logs\" "
           "WHERE service_name = 'audit' AND (" + ' OR '.join("body LIKE 'type=%s %%'" % t for t in _ACCOUNT_TYPES) + ") "
           "GROUP BY host, kind, actor, hour"}

QUERIES = {
    ITEM_UNAUTHORIZED: [_SUCCESS_QUERY, _INVALID_QUERY],
    ITEM_FAILURES: [_FAILURE_QUERY],
    ITEM_OFF_HOURS_PRIVILEGE: [_PRIVILEGE_QUERY, _ACCOUNT_CHANGE_QUERY],
}

PII_YES, PII_NO, PII_UNSET = '예', '아니오', '미지정'
NOTE_GAP = '수집 공백 호스트(로그 없음·끊김): 이 호스트는 판정하지 못함'
NOTE_NO_LIST = '허용 계정 목록 없음(점검 대상 밖이거나 계정 정보를 얻지 못함)'


# ------------------------------------------------------------------ 입력

def _query(ctx, name):
    return ctx['results'].get(name) or {'ok': False, 'hits': [], 'error': '조회하지 않음'}


def _int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _text(value):
    return str(value if value is not None else '').strip()


def _account_settings(ctx):
    return ctx['settings'].get('accounts') or {}


def _pii(ctx):
    """개인정보처리시스템 호스트 집합. 설정이 없으면 None('미지정')."""
    value = ctx['settings'].get('personal_info_systems')
    if value is None:
        return None
    return set(_text(h) for h in value if _text(h))


def _pii_cell(pii, host):
    if pii is None:
        return PII_UNSET
    return PII_YES if host in pii else PII_NO


# ------------------------------------------------------------------ 수집 공백·개인정보처리시스템 연결

def _coverage(ctx):
    """(공백 호스트 목록, 공백을 확인하지 못한 사유). 1부 판정은 이 둘을 결과에 붙인다."""
    hosts = [_text(h) for h in ((ctx['settings'].get('collection_targets') or {}).get('hosts') or [])]
    gap = sorted(set(hosts) & set(ctx['collection_gap']))
    status = ctx['results'].get(_collection.HOSTS_DAILY)
    unknown = ''
    if hosts and not (status or {}).get('ok'):
        unknown = '수집 공백을 확인하지 못함(%s)' % ((status or {}).get('error') or '조회하지 않음')
    return gap, unknown


def _finish(ctx, status, findings, summary, columns, rows, method, criterion, notes=()):
    """판정 결과에 수집 공백 호스트와 개인정보처리시스템 표시를 붙인다.

    ``rows``의 첫 칸은 호스트다. 끝에 '개인정보처리시스템'·'비고' 칸을 더한다. 공백 호스트는 발견 행이 없어도 행으로 남고,
    공백이 있거나 확인하지 못했으면 자동 판정은 '이상 없음'이 될 수 없다(일부 자동, 확인 필요).
    """
    pii = _pii(ctx)
    gap, unknown = _coverage(ctx)
    gap_set = set(gap)
    out_rows, seen_hosts = [], set()
    for row, note in rows:
        host = row[0]
        seen_hosts.add(host)
        extra = [n for n in (note, NOTE_GAP if host in gap_set else '') if n]
        out_rows.append(list(row) + [_pii_cell(pii, host), '; '.join(extra)])
    for host in gap:
        if host not in seen_hosts:
            out_rows.append([host] + ['-'] * (len(columns) - 1) + [_pii_cell(pii, host), NOTE_GAP])
    parts = [summary] + [n for n in notes if n]
    if gap:
        parts.append('수집 공백 호스트 %d대(%s)는 로그가 없어 판정하지 못함' % (len(gap), ', '.join(gap)))
    if unknown:
        parts.append(unknown)
    if pii is None:
        parts.append('개인정보처리시스템 표시: 미지정')
    else:
        hit = sorted(set(r[0] for r in out_rows) & pii)
        parts.append('개인정보처리시스템 해당 행 %d(호스트 %s)' % (
            sum(1 for r in out_rows if r[0] in pii), ', '.join(hit) or '없음'))
    if len(out_rows) > MAX_ROWS:
        parts.append('표는 앞 %d행만 싣는다(전체 %d행)' % (MAX_ROWS, len(out_rows)))
        out_rows = out_rows[:MAX_ROWS]
    if status == AUTO and (gap or unknown):
        status = PARTIAL
    verdict = ''
    if status in (AUTO, PARTIAL):
        verdict = VERDICT_CHECK if (findings or gap or unknown) else VERDICT_OK
    cols = list(columns) + ['개인정보처리시스템', '비고']
    return result(status, verdict, summary=' · '.join(p for p in parts if p),
                  columns=cols if out_rows else [], rows=out_rows, method=method, criterion=criterion)


# ------------------------------------------------------------------ 허용 계정

def _allowed(entry):
    """호스트 한 대의 허용 계정 집합. 알 수 없으면 None."""
    if not isinstance(entry, dict):
        return None
    if entry.get('agents_only'):
        inventory = entry.get('inventory_accounts')
        if inventory is None:
            return None
        names = set(_text(n) for n in inventory)
    else:
        names = set(_text(n) for n in (entry.get('declared') or []))
        names.add(_text(entry.get('bootstrap')))
    names.add('root')
    names.discard('')
    return names


def host_audit_log_review_account_hosts(sources, asset_inventory_hosts=None):
    """1번 허용 계정 입력을 만든다(tasks/log_review.yml AUD-804).

    ``sources``: ``{호스트: {'accounts': provisioning 계정 선언(dict 목록, state absent 제외), 'admin_users': [...],
    'bootstrap': bootstrap 계정 이름, 'agents_only': bool}}``. ``asset_inventory_hosts``: 보고서 모델의
    ``asset_inventory.hosts``(수집한 호스트만 계정 목록이 있다). 비밀이 없는 이름만 남긴다.
    """
    inventory = {}
    for h in asset_inventory_hosts or []:
        if isinstance(h, dict) and h.get('collected'):
            inventory[_text(h.get('host'))] = sorted(set(_text(a.get('name')) for a in h.get('accounts') or []
                                                         if isinstance(a, dict) and _text(a.get('name'))))
    out = {}
    for host, src in (sources or {}).items():
        src = src or {}
        declared = set(_text(n) for n in (src.get('admin_users') or []))
        for account in src.get('accounts') or []:
            if isinstance(account, dict) and account.get('state', 'present') != 'absent':
                declared.add(_text(account.get('name')))
            elif isinstance(account, str):
                declared.add(_text(account))
        declared.discard('')
        out[_text(host)] = {'declared': sorted(declared), 'bootstrap': _text(src.get('bootstrap')),
                            'agents_only': bool(src.get('agents_only')),
                            'inventory_accounts': inventory.get(_text(host))}
    return out


ALLOWED_RULE = ('허용 계정: provisioning 선언 사용자·bootstrap 사용자·root(에이전트만 설치된 호스트는 Asset Inventory 계정과 root). '
                '존재하지 않는 계정 시도(invalid user)는 1번과 별도 통계')


def judge_unauthorized(ctx):
    method = ('OpenObserve security_logs의 SSH 로그인 성공(event_action=ssh_login, event_outcome=success)을 '
              '호스트·계정별로 세어 호스트별 허용 계정 목록과 대조')
    criterion = '허용 계정 목록 밖 계정의 로그인 성공이 1건 이상이면 확인 필요. ' + ALLOWED_RULE
    success = _query(ctx, SUCCESS_HOURLY)
    if not success['ok']:
        out = failed(success['error'])
        out.update(method=method, criterion=criterion)
        return out
    hosts = _account_settings(ctx).get('hosts') or {}
    counts = {}
    for h in success['hits']:
        key = (_text(h.get('host')), _text(h.get('user')))
        if key[0] and key[1]:
            counts[key] = counts.get(key, 0) + _int(h.get('logins'))
    rows = []
    for (host, user), n in sorted(counts.items()):
        allowed = _allowed(hosts.get(host))
        if allowed is None:
            rows.append(([host, user, n], NOTE_NO_LIST))
        elif user not in allowed:
            rows.append(([host, user, n], ''))
    invalid = _query(ctx, INVALID_USER)
    if invalid['ok']:
        per_host = [h for h in invalid['hits'] if _int(h.get('attempts')) > 0]
        stat = '존재하지 않는 계정 시도 %d건(호스트 %d대, 1번 판정과 별도 통계)' % (
            sum(_int(h.get('attempts')) for h in per_host), len(per_host))
    else:
        stat = '존재하지 않는 계정 시도 통계: 조회 실패(%s)' % invalid['error']
    summary = '로그인 성공 계정 %d개(호스트·계정 조합) 중 허용 목록 밖 %d' % (len(counts), len(rows))
    return _finish(ctx, AUTO, rows, summary, ['호스트', '계정', '로그인 수'], rows, method, criterion, notes=[stat])


def _minute(text):
    try:
        return datetime.strptime(_text(text), '%Y-%m-%d %H:%M')
    except ValueError:
        return None


def _worst_window(points, window):
    """분 단위 (시각, 건수) 목록에서 ``window``분 구간(시작 분 포함, 시작+window분 미만)의 최대 합과 그 시작 시각."""
    points = sorted(points)
    best, start, j, total = 0, None, 0, 0
    for i, (t, n) in enumerate(points):
        while j < len(points) and points[j][0] - t < timedelta(minutes=window):
            total += points[j][1]
            j += 1
        if total > best:
            best, start = total, t
        total -= n
    return best, start


def judge_login_failures(ctx):
    cfg = _account_settings(ctx)
    threshold = _int(cfg.get('failure_threshold')) or 5
    window = _int(cfg.get('failure_window_minutes')) or 10
    method = ('OpenObserve security_logs의 SSH 로그인 실패(event_outcome=failure, 존재하지 않는 계정 시도 제외)를 '
              '호스트·계정·분(KST)별로 세어 %d분 구간의 최대 실패 수를 계산' % window)
    criterion = '같은 계정·같은 호스트에서 %d분 안에 %d회 이상 실패하면 확인 필요(분 단위 집계)' % (window, threshold)
    res = _query(ctx, FAILURE_MINUTELY)
    if not res['ok']:
        out = failed(res['error'])
        out.update(method=method, criterion=criterion)
        return out
    series = {}
    for h in res['hits']:
        key, t, n = (_text(h.get('host')), _text(h.get('user'))), _minute(h.get('minute')), _int(h.get('failures'))
        if key[0] and key[1] and t is not None and n > 0:
            series.setdefault(key, []).append((t, n))
    rows = []
    for (host, user), points in sorted(series.items()):
        worst, start = _worst_window(points, window)
        if worst >= threshold:
            rows.append(([host, user, worst, start.strftime('%Y-%m-%d %H:%M'), sum(n for _t, n in points)], ''))
    summary = '실패가 있는 호스트·계정 %d개 중 기준 이상 %d' % (len(series), len(rows))
    columns = ['호스트', '계정', '%d분 내 최대 실패' % window, '처음 시각(KST)', '전월 실패 합계']
    return _finish(ctx, AUTO, rows, summary, columns, rows, method, criterion)


# ------------------------------------------------------------------ 업무시간

class _Calendar(object):
    """업무시간 판정: 평일 start~end시(정시, 끝 미포함) KST, 주말·연도별 공휴일 목록."""

    def __init__(self, ctx):
        cfg = _account_settings(ctx)
        hours = cfg.get('business_hours') or {}
        self.start = _int(hours.get('start')) if hours.get('start') is not None else 8
        self.end = _int(hours.get('end')) if hours.get('end') is not None else 20
        self.year = _text(ctx['period'].get('month'))[:4]
        listed = None
        for key, days in (cfg.get('holidays') or {}).items():
            if _text(key) == self.year:  # YAML 키가 숫자(2026)든 문자열('2026')이든 같은 해다
                listed = set(_text(d) for d in (days or []))
        self.holidays = listed  # None = 그 해 목록 없음(빈 목록과 다르다)

    def kind(self, day, hour):
        """'주말'·'공휴일'·'야간' 또는 업무시간이면 ''."""
        try:
            weekday = date.fromisoformat(day).weekday()
        except ValueError:
            return ''
        if weekday >= 5:
            return '주말'
        if self.holidays and day in self.holidays:
            return '공휴일'
        if hour < self.start or hour >= self.end:
            return '야간'
        return ''

    def criterion(self, what):
        if self.holidays is None:
            hol = '%s년 공휴일 목록 없음(공휴일은 판정에 반영되지 않음, role 기본값 host_audit_log_review_holidays에 추가)' % self.year
        else:
            hol = '%s년 공휴일 %d일' % (self.year, len(self.holidays))
        return '업무시간 평일 %02d:00~%02d:00 KST 밖, 주말, 공휴일의 %s이 있으면 확인 필요(시 단위 집계). %s' % (
            self.start, self.end, what, hol)

    def status(self):
        return AUTO if self.holidays is not None else PARTIAL


def _hour(text):
    text = _text(text)
    try:
        return text[:10], int(text[11:13])
    except ValueError:
        return None


def _when(stamps, limit=6):
    stamps = sorted(stamps)
    shown = ', '.join('%s시' % s for s in stamps[:limit])
    return shown + (' 외 %d' % (len(stamps) - limit) if len(stamps) > limit else '')


def judge_off_hours_login(ctx):
    cal = _Calendar(ctx)
    method = 'OpenObserve security_logs의 SSH 로그인 성공을 호스트·계정·시(KST)별로 세어 업무시간 밖 시각만 추림'
    criterion = cal.criterion('SSH 로그인 성공')
    res = _query(ctx, SUCCESS_HOURLY)
    if not res['ok']:
        out = failed(res['error'])
        out.update(method=method, criterion=criterion)
        return out
    found = {}
    for h in res['hits']:
        host, user, at, n = _text(h.get('host')), _text(h.get('user')), _hour(h.get('hour')), _int(h.get('logins'))
        if not (host and user and at and n > 0):
            continue
        kind = cal.kind(*at)
        if kind:
            entry = found.setdefault((host, user), {'kinds': set(), 'count': 0, 'stamps': []})
            entry['kinds'].add(kind)
            entry['count'] += n
            entry['stamps'].append('%s %02d' % at)
    rows = [([host, user, '·'.join(k for k in ('주말', '공휴일', '야간') if k in e['kinds']), e['count'], _when(e['stamps'])], '')
            for (host, user), e in sorted(found.items())]
    summary = '업무시간 외 로그인 %d건(호스트·계정 %d개)' % (sum(e['count'] for e in found.values()), len(found))
    columns = ['호스트', '계정', '구분', '접속 수', '일시(KST)']
    return _finish(ctx, cal.status(), rows, summary, columns, rows, method, criterion)


def judge_off_hours_privilege(ctx):
    cal = _Calendar(ctx)
    method = ('OpenObserve security_logs의 sudo·su 성공(event_action, 실행 계정 user_name)과 auditd 계정 관리 기록'
              '(ADD_USER·USER_MGMT·USER_CHAUTHTOK 등, 실행 계정 AUID)을 호스트·계정·시(KST)별로 세어 업무시간 밖만 추림. '
              'Ansible become(BECOME-SUCCESS 명령)은 자동화 건수로 따로 센다')
    criterion = cal.criterion('sudo·su 실행 또는 계정·권한 변경') + '. 자동화(Ansible) 건만 있는 행은 확인 필요로 세지 않는다'
    privilege, changes = _query(ctx, PRIVILEGE_HOURLY), _query(ctx, ACCOUNT_CHANGE_HOURLY)
    bad = [r for r in (privilege, changes) if not r['ok']]
    if bad:
        out = failed(bad[0]['error'])
        out.update(method=method, criterion=criterion)
        return out
    events = [(h.get('host'), h.get('user'), _text(h.get('action')), h.get('hour'), _int(h.get('runs')), _int(h.get('automation')))
              for h in privilege['hits']]
    events += [(h.get('host'), h.get('actor') or '알 수 없음', '계정 변경 %s' % _text(h.get('kind')), h.get('hour'),
                _int(h.get('changes')), 0) for h in changes['hits']]
    found = {}
    for host, user, kind_name, hour, n, automation in events:
        host, user, at = _text(host), _text(user), _hour(hour)
        if not (host and user and kind_name and at and n > 0):
            continue
        kind = cal.kind(*at)
        if kind:
            e = found.setdefault((host, user, kind_name), {'kinds': set(), 'count': 0, 'automation': 0, 'stamps': []})
            e['kinds'].add(kind)
            e['count'] += n
            e['automation'] += min(automation, n)
            e['stamps'].append('%s %02d' % at)
    rows, findings = [], []
    for (host, user, kind_name), e in sorted(found.items()):
        row = ([host, user, kind_name, '·'.join(k for k in ('주말', '공휴일', '야간') if k in e['kinds']), e['count'],
                e['automation'], _when(e['stamps'])], '')
        rows.append(row)
        if e['count'] > e['automation']:
            findings.append(row)
    summary = '업무시간 외 권한 사용·변경 %d건(자동화 %d건), 행 %d' % (
        sum(e['count'] for e in found.values()), sum(e['automation'] for e in found.values()), len(rows))
    columns = ['호스트', '계정', '종류', '구분', '건수', '자동화(Ansible)', '일시(KST)']
    return _finish(ctx, cal.status(), findings, summary, columns, rows, method, criterion)


def judge_absentee_login(ctx):
    method = ('OpenObserve security_logs의 SSH 로그인 성공을 계정별 접속일(KST)·호스트로 정리. '
              '휴직자·휴가자 명단은 수집하지 않으므로 점검자가 명단과 대조한다')
    criterion = '계정별 접속일이 휴직·휴가 기간과 겹치면 확인 필요(사람 대조)'
    res = _query(ctx, SUCCESS_HOURLY)
    if not res['ok']:
        out = failed(res['error'])
        out.update(method=method, criterion=criterion)
        return out
    per_user = {}
    for h in res['hits']:
        host, user, at = _text(h.get('host')), _text(h.get('user')), _hour(h.get('hour'))
        if host and user and at and _int(h.get('logins')) > 0:
            e = per_user.setdefault(user, {'days': set(), 'hosts': set()})
            e['days'].add(at[0])
            e['hosts'].add(host)
    pii = _pii(ctx)
    rows = []
    for user, e in sorted(per_user.items()):
        mark = PII_UNSET if pii is None else (PII_YES if e['hosts'] & pii else PII_NO)
        rows.append([user, len(e['days']), ', '.join(d[5:] for d in sorted(e['days'])), ', '.join(sorted(e['hosts'])), mark])
    gap, unknown = _coverage(ctx)
    parts = ['로그인 계정 %d개' % len(per_user)]
    if gap:
        parts.append('수집 공백 호스트 %d대(%s)는 접속일이 빠졌을 수 있음' % (len(gap), ', '.join(gap)))
    if unknown:
        parts.append(unknown)
    if pii is None:
        parts.append('개인정보처리시스템 표시: 미지정')
    if len(rows) > MAX_ROWS:
        parts.append('표는 앞 %d행만 싣는다(전체 %d행)' % (MAX_ROWS, len(rows)))
        rows = rows[:MAX_ROWS]
    columns = ['계정', '접속일 수', '접속일', '호스트', '개인정보처리시스템 접속']
    return result(MANUAL, summary=' · '.join(parts), columns=columns if rows else [], rows=rows,
                  method=method, criterion=criterion)


JUDGES = {
    ITEM_UNAUTHORIZED: judge_unauthorized,
    ITEM_FAILURES: judge_login_failures,
    ITEM_OFF_HOURS_LOGIN: judge_off_hours_login,
    ITEM_OFF_HOURS_PRIVILEGE: judge_off_hours_privilege,
    ITEM_ABSENTEE: judge_absentee_login,
}


class FilterModule(object):
    """판정 모듈. 등록은 host_audit_log_review._JUDGE_MODULES가 한다. 허용 계정 입력 필터 하나를 낸다."""

    def filters(self):
        return {'host_audit_log_review_account_hosts': host_audit_log_review_account_hosts}
