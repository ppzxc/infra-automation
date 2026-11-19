"""Log Review Report 1부 13번과 장비 관리자 로그인 적용 (Spec #544 / Ticket-7 #562, ADR-0015).

13번(명령 집중): 서버 sudo 성공(``security_logs``의 ``event_action='sudo'``·``event_outcome='success'``)을 계정·호스트·분(KST)별로
세어 같은 계정(호스트 무관)의 ``window_minutes``분 구간 최대 실행 수를 잰다. Ansible ``become``(명령에 ``BECOME-SUCCESS-``)은
조회에서 뺀다(매 실행이 기준을 넘는다). 기준은 ``ctx['settings']['command_burst']``(role 기본값 2분·30회).

장비 관리자 로그인(1·2·3·4·7·12번): 서버 판정은 accounts·sources 모듈이 그대로 하고, 이 모듈은 ``EXTENDS``로 그 결과에 장비 종류별
몫(``sections``)을 덧붙인다. 기준은 ``ctx['settings']['devices']``(tasks/log_review.yml AUD-804):
- ``fortigate``·``switch``: 종류별 대상 장비 관리번호(로그의 ``device_id``).
- ``parsing``: ``{종류: {항목 key: 'auto'|'partial'}}``(role 기본값 ``host_audit_log_review_device_parsing``). 없는 칸과 이 모듈에
  판정이 없는 칸은 '점검 불가(파싱 없음)'이다.
- ``admin_accounts``: ``[{'device': 장비 관리번호, 'accounts': [관리자 계정]}]``(OpenBao ``inventory/config/log_review``의 ``device_admin_accounts``). 없으면
  1번의 모든 로그인 계정이 '장비 관리자 허용 목록 없음'으로 나온다.
업무시간·공휴일·2번 기준은 ``settings['accounts']``, 정상 출발지·12번 기준은 ``settings['sources']``를 서버와 같이 쓴다.
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import (  # noqa: E402
    AUTO, FAILED, PARTIAL, STATUS_LABELS, UNAVAILABLE, VERDICT_CHECK, VERDICT_OK, failed, result,
)
from host_audit_log_review_common import gap_label, to_int as _int  # noqa: E402
import host_audit_log_review_accounts as _accounts  # noqa: E402
import host_audit_log_review_sources as _sources  # noqa: E402
import host_audit_log_review_collection as _collection  # noqa: E402

COMMAND_BURST = 'part1.command_burst'
SUDO_MINUTELY = 'command_burst_sudo_minutely'
FORTIGATE, SWITCH = 'fortigate', 'switch'
FORTIGATE_LOGINS = 'device_fortigate_logins'
FORTIGATE_CHANGES = 'device_fortigate_changes'
SWITCH_FAILURES = 'device_switch_login_failures'
SWITCH_CHANGES = 'device_switch_config_changes'
MAX_ROWS = _accounts.MAX_ROWS
_COLLECTION = {FORTIGATE: _collection.FORTIGATE_DAILY, SWITCH: _collection.SWITCH_DAILY}

_MINUTE = "date_format(_timestamp, '%Y-%m-%d %H:%M', '{offset}')"
_LIMIT = ('sudo 명령만 본다: sudo 없이 root 셸 안에서 실행한 명령, su 뒤의 명령, root 직접 로그인의 명령, Ansible become(자동화)은 '
          '세지 않는다')


def _text(value):
    return str(value if value is not None else '').strip()


def _minute(text):
    try:
        return datetime.strptime(_text(text), '%Y-%m-%d %H:%M')
    except ValueError:
        return None


def _query(ctx, name):
    return ctx['results'].get(name) or {'ok': False, 'hits': [], 'error': '조회하지 않음'}


def _burst_settings(ctx):
    cfg = ctx['settings'].get('command_burst') or {}
    return _int(cfg.get('threshold')) or 30, _int(cfg.get('window_minutes')) or 2


def judge_command_burst(ctx):
    threshold, window = _burst_settings(ctx)
    method = ('OpenObserve security_logs의 sudo 성공(event_action=sudo, event_outcome=success, Ansible become 제외)을 '
              '계정·호스트·분(KST)별로 세어 같은 계정(호스트 무관)의 %d분 구간 최대 실행 수를 계산' % window)
    criterion = '같은 계정이 %d분 안에 sudo를 %d회 이상 실행하면 확인 필요(분 단위 집계). %s' % (window, threshold, _LIMIT)
    res = _query(ctx, SUDO_MINUTELY)
    if not res['ok']:
        out = failed(res['error'])
        out.update(method=method, criterion=criterion)
        return out
    per_minute, hosts, totals = {}, {}, {}
    for h in res['hits']:
        user, host, t, n = _text(h.get('user')), _text(h.get('host')), _minute(h.get('minute')), _int(h.get('runs'))
        if not (user and t is not None and n > 0):
            continue
        per_minute.setdefault(user, {})
        per_minute[user][t] = per_minute[user].get(t, 0) + n
        hosts.setdefault(user, set()).add(host)
        totals[user] = totals.get(user, 0) + n
    rows = []
    for user in sorted(per_minute):
        worst, start = _accounts._worst_window(list(per_minute[user].items()), window)
        if worst >= threshold:
            rows.append([user, worst, start.strftime('%Y-%m-%d %H:%M'), ', '.join(sorted(h for h in hosts[user] if h)),
                         totals[user]])
    gap, unknown = _accounts._coverage(ctx)
    parts = ['sudo를 실행한 계정 %d개 중 기준 이상 %d' % (len(per_minute), len(rows))]
    if gap:
        parts.append('%s는 그 날짜를 점검하지 못함' % gap_label(gap))
    if unknown:
        parts.append(unknown)
    status = PARTIAL if (gap or unknown) else AUTO
    verdict = VERDICT_CHECK if (rows or gap or unknown) else VERDICT_OK
    columns = ['계정', '%d분 내 최대 sudo' % window, '처음 시각(KST)', '호스트', '전월 sudo 합계']
    return result(status, verdict, summary=' · '.join(parts), columns=columns if rows else [], rows=rows,
                  method=method, criterion=criterion)


# ------------------------------------------------------------------ 장비 관리자 로그인(1·2·3·4·7·12번)

KIND_TITLES = {FORTIGATE: 'FortiGate', SWITCH: '스위치'}
NO_PARSING = '파싱 없음'
NOTE_NO_ADMIN_LIST = '장비 관리자 허용 목록 없음'


def _device_settings(ctx):
    cfg = ctx['settings'].get('devices')
    return cfg if isinstance(cfg, dict) else None


def _section(kind, status, verdict='', reason='', summary='', columns=None, rows=None):
    label = STATUS_LABELS.get(status, status)
    if status in (UNAVAILABLE, FAILED) and reason:
        label = '%s(%s)' % (label, reason)
    rows = [list(r) for r in (rows or [])]
    return {'kind': kind, 'title': '장비 관리자 로그인 — %s' % KIND_TITLES[kind], 'status': status, 'status_label': label,
            'verdict': verdict if status in (AUTO, PARTIAL) else '', 'summary': summary,
            'columns': list(columns or []) if rows else [], 'rows': rows}


def _finish(ctx, kind, devices, status, findings, summary, columns, rows, unknown=0):
    """장비 몫의 판정: 수집 공백 장비와 결과를 알 수 없는 로그인이 있으면 '이상 없음'으로 단정하지 않는다(일부 자동, 확인 필요)."""
    gap = sorted(set(devices) & set(ctx['collection_gap']))
    parts = [summary]
    if unknown:
        parts.append('결과를 알 수 없는 로그인 %d건(성공·실패가 구조화되지 않음)은 판정 밖' % unknown)
    if gap:
        parts.append('수집 공백 장비 %d대(%s)는 로그가 없어 판정 밖' % (len(gap), ', '.join(gap)))
    collected = ctx['results'].get(_COLLECTION[kind]) or {}
    blind = not collected.get('ok')  # 수집 공백 조회가 실패하면 공백 장비를 모른다: 로그가 없어 '이상 없음'이 될 수 있다
    if blind:
        parts.append('수집 공백을 확인하지 못함(%s)' % (collected.get('error') or '조회하지 않음'))
    if status == AUTO and (gap or unknown or blind):
        status = PARTIAL
    verdict = VERDICT_CHECK if (findings or gap or unknown or blind) else VERDICT_OK
    if len(rows) > MAX_ROWS:
        parts.append('표는 앞 %d행만 싣는다(전체 %d행)' % (MAX_ROWS, len(rows)))
        rows = rows[:MAX_ROWS]
    return _section(kind, status, verdict, summary=' · '.join(p for p in parts if p), columns=columns, rows=rows)


def _logins(ctx, devices):
    """FortiGate 관리자 로그인 조회 결과 중 대상 장비의 행. (행 목록, 결과를 알 수 없는 로그인 수) 또는 조회 실패 결과."""
    res = _query(ctx, FORTIGATE_LOGINS)
    if not res['ok']:
        return None, res['error']
    wanted, rows, unknown = set(devices), [], 0
    for h in res['hits']:
        device, n = _text(h.get('device')), _int(h.get('logins'))
        if device not in wanted or n <= 0:
            continue
        outcome = _text(h.get('outcome'))
        if outcome not in ('success', 'failure'):
            unknown += n
            continue
        rows.append({'device': device, 'user': _text(h.get('user')), 'source': _text(h.get('source')),
                     'minute': _text(h.get('minute')), 'outcome': outcome, 'logins': n,
                     'first': _int(h.get('first_us')), 'last': max(_int(h.get('first_us')), _int(h.get('last_us')))})
    return (rows, unknown), ''


def _admin_accounts(ctx):
    """작업 설정 문서의 ``device_admin_accounts``(``[{'device', 'accounts'}]``)를 ``{장비: 계정 집합}``으로. 없거나 형식이 틀리면 빈 표."""
    out = {}
    value = (_device_settings(ctx) or {}).get('admin_accounts')
    for entry in value if isinstance(value, list) else []:
        if isinstance(entry, dict) and _text(entry.get('device')) and isinstance(entry.get('accounts'), list):
            out.setdefault(_text(entry['device']), set()).update(_text(a) for a in entry['accounts'] if _text(a))
    return out


def _fortigate_unauthorized(ctx, devices):
    data, error = _logins(ctx, devices)
    if data is None:
        return _section(FORTIGATE, FAILED, reason=error)
    rows_in, unknown = data
    admins = _admin_accounts(ctx)
    counts = {}
    for r in rows_in:
        if r['outcome'] == 'success' and r['user']:
            key = (r['device'], r['user'])
            counts[key] = counts.get(key, 0) + r['logins']
    rows = []
    for (device, user), n in sorted(counts.items()):
        allowed = admins.get(device)
        if allowed is None:
            rows.append([device, user, n, NOTE_NO_ADMIN_LIST])
        elif user not in allowed:
            rows.append([device, user, n, ''])
    summary = '관리자 로그인 성공 계정 %d개(장비·계정 조합) 중 허용 목록 밖 %d' % (len(counts), len(rows))
    return _finish(ctx, FORTIGATE, devices, AUTO, rows, summary, ['장비', '계정', '로그인 수', '비고'], rows, unknown)


def _fortigate_failures(ctx, devices):
    data, error = _logins(ctx, devices)
    if data is None:
        return _section(FORTIGATE, FAILED, reason=error)
    rows_in, unknown = data
    threshold, window = _failure_settings(ctx)
    series = {}
    for r in rows_in:
        t = _minute(r['minute'])
        if r['outcome'] == 'failure' and t is not None:
            series.setdefault((r['device'], r['user'] or '(계정 없음)'), []).append((t, r['logins']))
    rows = []
    for (device, user), points in sorted(series.items()):
        worst, start = _accounts._worst_window(points, window)
        if worst >= threshold:
            rows.append([device, user, worst, start.strftime('%Y-%m-%d %H:%M'), sum(n for _t, n in points)])
    summary = '로그인 실패가 있는 장비·계정 %d개 중 기준(%d분 %d회) 이상 %d' % (len(series), window, threshold, len(rows))
    columns = ['장비', '계정', '%d분 내 최대 실패' % window, '처음 시각(KST)', '전월 실패 합계']
    return _finish(ctx, FORTIGATE, devices, AUTO, rows, summary, columns, rows, unknown)


def _switch_failures(ctx, devices):
    res = _query(ctx, SWITCH_FAILURES)
    if not res['ok']:
        return _section(SWITCH, FAILED, reason=res['error'])
    threshold, window = _failure_settings(ctx)
    wanted, series = set(devices), {}
    for h in res['hits']:
        device, t, n = _text(h.get('device')), _minute(h.get('minute')), _int(h.get('failures'))
        if device in wanted and t is not None and n > 0:
            series.setdefault(device, []).append((t, n))
    rows = []
    for device, points in sorted(series.items()):
        worst, start = _accounts._worst_window(points, window)
        if worst >= threshold:
            rows.append([device, worst, start.strftime('%Y-%m-%d %H:%M'), sum(n for _t, n in points)])
    summary = ('로그인 실패(SEC_LOGIN-4-LOGIN_FAILED)가 있는 장비 %d대 중 기준(%d분 %d회) 이상 %d. 계정·출발지가 구조화되지 않아 '
               '장비 단위로만 센다' % (len(series), window, threshold, len(rows)))
    columns = ['장비', '%d분 내 최대 실패' % window, '처음 시각(KST)', '전월 실패 합계']
    return _finish(ctx, SWITCH, devices, PARTIAL, rows, summary, columns, rows)


def _kinds_label(kinds):
    return '·'.join(k for k in ('주말', '공휴일', '야간') if k in kinds)


def _fortigate_off_hours_login(ctx, devices):
    data, error = _logins(ctx, devices)
    if data is None:
        return _section(FORTIGATE, FAILED, reason=error)
    rows_in, unknown = data
    cal = _accounts._Calendar(ctx)
    found = {}
    for r in rows_in:
        at = _accounts._hour(r['minute'][:13])
        if r['outcome'] != 'success' or not at:
            continue
        kind = cal.kind(*at)
        if kind:
            e = found.setdefault((r['device'], r['user']), {'kinds': set(), 'count': 0, 'stamps': set()})
            e['kinds'].add(kind)
            e['count'] += r['logins']
            e['stamps'].add('%s %02d' % at)
    rows = [[device, user, _kinds_label(e['kinds']), e['count'], _accounts._when(e['stamps'])]
            for (device, user), e in sorted(found.items())]
    summary = '업무시간 외 관리자 로그인 %d건(장비·계정 %d개)' % (sum(e['count'] for e in found.values()), len(found))
    return _finish(ctx, FORTIGATE, devices, cal.status(), rows, summary, ['장비', '계정', '구분', '접속 수', '일시(KST)'], rows,
                   unknown)


CHANGE_ADMIN = '관리자 계정·권한 변경'
CHANGE_CONFIG = '설정 변경(참고)'
CHANGE_HA = 'HA 동기화(참고)'


def _fortigate_off_hours_privilege(ctx, devices):
    res = _query(ctx, FORTIGATE_CHANGES)
    if not res['ok']:
        return _section(FORTIGATE, FAILED, reason=res['error'])
    cal = _accounts._Calendar(ctx)
    wanted, found = set(devices), {}
    for h in res['hits']:
        device, at, n = _text(h.get('device')), _accounts._hour(h.get('hour')), _int(h.get('changes'))
        if device not in wanted or not at or n <= 0:
            continue
        kind = cal.kind(*at)
        if not kind:
            continue
        if _text(h.get('via')) == 'ha':
            change = CHANGE_HA
        else:
            change = CHANGE_ADMIN if _text(h.get('target')) == 'admin' else CHANGE_CONFIG
        e = found.setdefault((device, _text(h.get('user')), change), {'kinds': set(), 'count': 0, 'stamps': set()})
        e['kinds'].add(kind)
        e['count'] += n
        e['stamps'].add('%s %02d' % at)
    rows, findings = [], []
    for (device, user, change), e in sorted(found.items()):
        row = [device, user, change, _kinds_label(e['kinds']), e['count'], _accounts._when(e['stamps'])]
        rows.append(row)
        if change == CHANGE_ADMIN:
            findings.append(row)
    summary = ('업무시간 외 관리자 계정·권한 변경(cfgpath system.admin·system.accprofile) %d건, 그 밖의 설정 변경·HA 동기화는 '
               '참고 행' % sum(r[4] for r in findings))
    columns = ['장비', '계정', '종류', '구분', '건수', '일시(KST)']
    return _finish(ctx, FORTIGATE, devices, cal.status(), findings, summary, columns, rows)


def _switch_off_hours_privilege(ctx, devices):
    res = _query(ctx, SWITCH_CHANGES)
    if not res['ok']:
        return _section(SWITCH, FAILED, reason=res['error'])
    cal = _accounts._Calendar(ctx)
    wanted, found = set(devices), {}
    for h in res['hits']:
        device, at, n = _text(h.get('device')), _accounts._hour(h.get('hour')), _int(h.get('changes'))
        if device not in wanted or not at or n <= 0:
            continue
        kind = cal.kind(*at)
        if kind:
            e = found.setdefault(device, {'kinds': set(), 'count': 0, 'stamps': set()})
            e['kinds'].add(kind)
            e['count'] += n
            e['stamps'].add('%s %02d' % at)
    rows = [[device, '설정 변경(SYS-5-CONFIG_I)', _kinds_label(e['kinds']), e['count'], _accounts._when(e['stamps'])]
            for device, e in sorted(found.items())]
    summary = ('업무시간 외 설정 변경 %d건. 권한 변경과 다른 설정 변경을 구분하지 못하고 변경 주체(계정·주소)는 원문에만 있다'
               % sum(r[3] for r in rows))
    return _finish(ctx, SWITCH, devices, PARTIAL, rows, summary, ['장비', '종류', '구분', '건수', '일시(KST)'], rows)


def _fortigate_unauthorized_source(ctx, devices):
    ref = _sources._reference(ctx['settings'])
    if ref is None:
        return _section(FORTIGATE, FAILED, reason=_sources.REFERENCE_FAILURE)
    data, error = _logins(ctx, devices)
    if data is None:
        return _section(FORTIGATE, FAILED, reason=error)
    rows_in, unknown = data
    groups = {}
    for r in rows_in:
        if r['outcome'] != 'success' or _sources._normal_name(r['source'], ref)[0]:
            continue
        e = groups.setdefault((r['source'], r['device'], r['user']), {'count': 0, 'first': r['first'], 'last': r['last']})
        e['count'] += r['logins']
        e['first'], e['last'] = min(e['first'], r['first']), max(e['last'], r['last'])
    rows, findings = [], []
    for (source, device, user), e in sorted(groups.items()):
        managed = _sources._managed_host(source, ctx, ref)
        row = [source or '(출발지 없음)', device, user, e['count'], _sources._local(e['first'], ctx),
               _sources._local(e['last'], ctx), '관리 호스트 %s' % managed if managed else '']
        rows.append(row)
        if not managed:
            findings.append(row)
    summary = ('정상 출발지 목록 밖 관리자 로그인 %d묶음(관리 호스트 주소에서 온 %d묶음은 행에만 싣고 확인 필요로 세지 않음)'
               % (len(findings), len(rows) - len(findings)))
    columns = ['출발지', '장비', '계정', '건수', '처음', '마지막', '비고']
    return _finish(ctx, FORTIGATE, devices, AUTO, findings, summary, columns, rows, unknown)


def _fortigate_multi_source(ctx, devices):
    ref = _sources._reference(ctx['settings'])
    if ref is None:
        return _section(FORTIGATE, FAILED, reason=_sources.REFERENCE_FAILURE)
    data, error = _logins(ctx, devices)
    if data is None:
        return _section(FORTIGATE, FAILED, reason=error)
    rows_in, unknown = data
    cfg = ctx['settings'].get('sources') or {}
    window = _int(cfg.get('window_seconds')) or 120
    min_sources = _int(cfg.get('min_sources')) or 2
    accounts = {}
    for r in rows_in:
        if r['outcome'] == 'success':
            accounts.setdefault(r['user'], []).append({'source': r['source'], 'first': r['first'], 'last': r['last'],
                                                       'logins': r['logins']})
    rows = []
    for user in sorted(accounts):
        buckets = sorted(accounts[user], key=lambda x: (x['first'], x['last'], x['source']))
        for hit in _sources._hits_of_account(buckets, window * 1000000, min_sources):
            srcs = sorted(set(b['source'] for b in hit['buckets']))
            rows.append([user, _sources._local(hit['start'], ctx), _sources._local(hit['end'], ctx),
                         ', '.join(_sources._label(s, ctx, ref) for s in srcs), sum(b['logins'] for b in hit['buckets'])])
    summary = '같은 관리자 계정(장비 무관)이 %d초 안에 출발지 %d개 이상: %d건' % (window, min_sources, len(rows))
    return _finish(ctx, FORTIGATE, devices, AUTO, rows, summary, ['계정', '시작', '끝', '출발지', '건수'], rows, unknown)


def _failure_settings(ctx):
    cfg = ctx['settings'].get('accounts') or {}
    return _int(cfg.get('failure_threshold')) or 5, _int(cfg.get('failure_window_minutes')) or 10


# 항목 key -> {장비 종류: 판정}. 여기 없는 (종류, 항목)은 파싱 설정과 상관없이 '점검 불가(파싱 없음)'다.
DEVICE_JUDGES = {
    'part1.unauthorized_account': {FORTIGATE: _fortigate_unauthorized},
    'part1.login_failures': {FORTIGATE: _fortigate_failures, SWITCH: _switch_failures},
    'part1.off_hours_login': {FORTIGATE: _fortigate_off_hours_login},
    'part1.off_hours_privilege': {FORTIGATE: _fortigate_off_hours_privilege, SWITCH: _switch_off_hours_privilege},
    'part1.unauthorized_source': {FORTIGATE: _fortigate_unauthorized_source},
    'part1.multi_source_login': {FORTIGATE: _fortigate_multi_source},
}


def _device_sections(ctx, key):
    cfg = _device_settings(ctx)
    if cfg is None:
        return []
    parsing = cfg.get('parsing') or {}
    out = []
    for kind in (FORTIGATE, SWITCH):
        devices = [_text(d) for d in (cfg.get(kind) or []) if _text(d)]
        if not devices:
            continue
        judge = DEVICE_JUDGES[key].get(kind)
        if judge is None or (parsing.get(kind) or {}).get(key) not in (AUTO, PARTIAL):
            out.append(_section(kind, UNAVAILABLE, reason=NO_PARSING))
        else:
            out.append(judge(ctx, devices))
    return out


def extend_with_devices(key):
    """다른 모듈(1~4번 accounts, 7·12번 sources)이 판정한 서버 결과에 장비 관리자 로그인 몫을 덧붙인다.

    장비 몫 중 하나라도 자동 판정이 아니면(파싱 없음·일부 자동·조회 실패) 항목은 '일부 자동'이 되고, 장비 몫이 확인 필요이거나
    조회 실패면 항목 판정은 '확인 필요'다. 서버 결과가 조회 실패·점검 불가면 상태는 그대로 두고 장비 몫만 붙인다.
    """
    def extend(ctx, res):
        sections = _device_sections(ctx, key)
        res = dict(res)
        res['sections'] = sections
        if not sections:
            return res
        note = '장비 관리자 로그인: ' + ', '.join(
            '%s: %s%s' % (KIND_TITLES[s['kind']], s['status_label'], ' · %s' % s['verdict'] if s['verdict'] else '')
            for s in sections)
        res['summary'] = ' · '.join(p for p in (res.get('summary'), note) if p)
        if res['status'] in (AUTO, PARTIAL):
            if any(s['status'] != AUTO for s in sections):
                res['status'] = PARTIAL
            if any(s['verdict'] == VERDICT_CHECK or s['status'] == FAILED for s in sections):
                res['verdict'] = VERDICT_CHECK
        return res
    return extend


EXTENDS = dict((key, extend_with_devices(key)) for key in DEVICE_JUDGES)

# FortiGate 관리자 로그인 결과: VRL(fortigate_semantics)이 붙이는 event_outcome을 쓰고, 그 필드가 없는 기록(VRL 보완 전에 들어온
# 기록)은 원문 status 키로 가른다(OpenObserve Config의 방화벽 로그인 알림과 같은 원문 일치). 어느 쪽도 아니면 ''(결과 모름).
_STATUS = "(body LIKE '%% status=\"%s\"%%' OR body LIKE '%% status=%s %%')"
_OUTCOME = ("coalesce(event_outcome, CASE WHEN " + _STATUS % ('success', 'success') + " THEN 'success' WHEN "
            + _STATUS % ('failed', 'failed') + " THEN 'failure' ELSE '' END)")
_FGT = "FROM \"security_logs\" WHERE service_name = 'fortigate-syslog' AND fortigate_log_subtype = 'system' "
_HOUR = "date_format(_timestamp, '%Y-%m-%d %H', '{offset}')"

QUERIES = {
    COMMAND_BURST: [{
        'name': SUDO_MINUTELY, 'size': 50000,
        'sql': "SELECT host_name AS host, user_name AS user, " + _MINUTE + " AS minute, count(*) AS runs "
               "FROM \"security_logs\" WHERE event_action = 'sudo' AND event_outcome = 'success' "
               "AND coalesce(process_command_line, '') NOT LIKE '%BECOME-SUCCESS-%' GROUP BY host, user, minute"}],
    # 장비 몫의 조회. 키는 이 모듈 고유 키다(항목 key는 accounts·sources 모듈이 갖는다). 관리자 로그인은 한 달 수십~수백 건이라
    # (장비, 계정, 출발지, 분, 결과) 묶음 하나로 1·2·3·7·12번을 모두 판정한다.
    'devices.fortigate': [
        {'name': FORTIGATE_LOGINS, 'size': 50000,
         'sql': "SELECT coalesce(device_id, device_name) AS device, user_name AS user, source_address AS source, "
                + _MINUTE + " AS minute, " + _OUTCOME + " AS outcome, count(*) AS logins, min(_timestamp) AS first_us, "
                "max(_timestamp) AS last_us " + _FGT + "AND event_action = 'login' "
                "GROUP BY device, user, source, minute, outcome"},
        {'name': FORTIGATE_CHANGES, 'size': 20000,
         'sql': "SELECT coalesce(device_id, device_name) AS device, user_name AS user, " + _HOUR + " AS hour, "
                "CASE WHEN body LIKE '%cfgpath=\"system.admin%' OR body LIKE '%cfgpath=\"system.accprofile%' "
                "THEN 'admin' ELSE 'config' END AS target, "
                "CASE WHEN body LIKE '% ui=\"ha_daemon\"%' OR body LIKE '% ui=ha_daemon %' THEN 'ha' ELSE '' END AS via, "
                "count(*) AS changes " + _FGT + "AND event_action IN ('edit', 'add', 'delete') "
                "GROUP BY device, user, hour, target, via"},
    ],
    'devices.switch': [
        {'name': SWITCH_FAILURES, 'size': 20000,
         'sql': "SELECT coalesce(device_id, device_name) AS device, " + _MINUTE + " AS minute, count(*) AS failures "
                "FROM \"system_logs\" WHERE service_name = 'switch-syslog' AND event_name = 'SEC_LOGIN-4-LOGIN_FAILED' "
                "GROUP BY device, minute"},
        {'name': SWITCH_CHANGES, 'size': 20000,
         'sql': "SELECT coalesce(device_id, device_name) AS device, " + _HOUR + " AS hour, count(*) AS changes "
                "FROM \"system_logs\" WHERE service_name = 'switch-syslog' AND event_name = 'SYS-5-CONFIG_I' "
                "GROUP BY device, hour"},
    ],
}
JUDGES = {COMMAND_BURST: judge_command_burst}


class FilterModule(object):
    """판정 모듈(필터 없음). 등록은 host_audit_log_review._JUDGE_MODULES가 한다."""

    def filters(self):
        return {}
