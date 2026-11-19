"""Log Review Report 1부 출발지 항목 6·7·12번 (Spec #544 / Ticket-5 #560, ADR-0015).

서버 sshd 로그인 성공(``security_logs``의 ``event_action='ssh_login'``·``event_outcome='success'``, security_semantics.vrl)만 본다.
장비 관리자 로그인은 #562 몫이다.

기준은 ``ctx['settings']['sources']``(tasks/log_review.yml AUD-804가 만든다):
- ``reference``: OpenBao 로그 검토 작업 설정 문서(``inventory/config/log_review``). 없거나 읽지 못하면(``None``) 또는 형식이
  틀리면 세 항목 모두 '조회 실패(기준 목록)'다. 키: ``normal_sources``(정상 출발지 ``[{address, name}]``, 주소는 IP 또는 CIDR),
  ``internal_addresses``(인벤토리로 계산되지 않는 내부 주소 대응 ``[{address, host}]``), ``personal_info_systems``(관리번호 목록),
  ``excluded_sources``(6·7번에서 뺄 예외 출발지 ``[{address, name}]``, Semaphore 러너·점프 호스트 등. 뺀 로그인 묶음 수는 요약에 '예외 N건'으로 찍는다).
- ``managed_addresses``: 인벤토리에서 계산한 내부 주소 대응 ``{주소: 관리번호}``(``host_audit_log_review_managed_addresses``).
- ``window_seconds``·``min_sources``: 12번 임곗값(role 기본값 2분·출발지 2개).
"""

import ipaddress
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import AUTO, PARTIAL, VERDICT_CHECK, VERDICT_OK, failed, result  # noqa: E402
from host_audit_log_review_common import pii_cell, to_int as _int, tz as _tz  # noqa: E402

RELOGIN = 'part1.relogin_from_managed_host'
UNAUTHORIZED = 'part1.unauthorized_source'
MULTI = 'part1.multi_source_login'

LOGINS = 'source_logins'
LOGIN_MINUTES = 'source_login_minutes'

REFERENCE_FAILURE = '기준 목록'


class _BadReference(ValueError):
    pass


def _network(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise _BadReference(text)


def _reference(settings):
    """기준 목록 문서를 판정용으로 바꾼다. 문서가 없거나 형식이 틀리면 ``None``."""
    ref = (settings.get('sources') or {}).get('reference')
    if not isinstance(ref, dict) or not isinstance(ref.get('normal_sources'), list) or not ref['normal_sources']:
        return None
    try:
        normal = [(_network(s['address']), str(s.get('name') or '')) for s in ref['normal_sources']]
        internal = [(_network(s['address']), str(s['host'])) for s in (ref.get('internal_addresses') or [])]
        pii = None if ref.get('personal_info_systems') is None else set(str(h) for h in ref['personal_info_systems'])
        excluded = [_network(s['address']) for s in (ref.get('excluded_sources') or [])]
    except (_BadReference, KeyError, TypeError, AttributeError):
        return None
    return {'normal': normal, 'internal': internal, 'pii': pii, 'excluded': excluded}


def _is_excluded(address, ref):
    ip = _ip(address)
    return ip is not None and any(ip.version == net.version and ip in net for net in ref['excluded'])


def _with_exceptions(summary, count):
    return summary + (' · 예외 %d건' % count if count else '')


def _pii_cell(ref, host):
    """개인정보처리시스템 표시. 1~5번(host_audit_log_review_accounts)과 같은 문구(공용 ``pii_cell``)."""
    return pii_cell(ref['pii'], host)


def _ip(text):
    """주소 문자열을 주소 값으로. IPv4-mapped IPv6(``::ffff:a.b.c.d``)은 IPv4로 접는다(sshd가 그렇게 남기는 출발지가 있다)."""
    try:
        ip = ipaddress.ip_address(str(text or '').strip())
    except ValueError:
        return None
    return getattr(ip, 'ipv4_mapped', None) or ip


def _managed_host(address, ctx, ref):
    """출발지 주소가 관리 호스트의 것이면 그 관리번호. 인벤토리 계산 값이 먼저, 그다음 문서의 내부 주소 대응."""
    managed = (ctx['settings'].get('sources') or {}).get('managed_addresses') or {}
    ip = _ip(address)
    if ip is None:
        return ''
    if managed.get(str(ip)):  # 키는 host_audit_log_review_managed_addresses가 정규화한 주소 문자열이다
        return str(managed[str(ip)])
    for net, host in ref['internal']:
        if ip.version == net.version and ip in net:
            return host
    return ''


def _normal_name(address, ref):
    """정상 출발지면 (True, 이름)."""
    ip = _ip(address)
    if ip is None:
        return False, ''
    for net, name in ref['normal']:
        if ip.version == net.version and ip in net:
            return True, name
    return False, ''


def _local(us, ctx):
    stamp = _int(us)
    if not stamp:
        return ''
    tz = _tz(ctx['period'].get('timezone'))
    return datetime.fromtimestamp(stamp / 1000000.0, tz=timezone.utc).astimezone(tz).strftime('%Y-%m-%d %H:%M')


def _gap_hosts(ctx):
    hosts = set(str(h) for h in ((ctx['settings'].get('collection_targets') or {}).get('hosts') or []))
    return sorted(n for n in ctx['collection_gap'] if n in hosts)


def _verdict(rows, ctx, summary, columns, method, criterion):
    """행이 있으면 확인 필요. 수집 공백 호스트가 있으면 그 호스트는 로그가 없어 판정 밖이므로 '일부 자동'이다(#544 이야기 21)."""
    gap = _gap_hosts(ctx)
    status = PARTIAL if gap else AUTO
    if gap:
        summary += ' · 수집 공백 호스트 %d대(%s)는 로그가 없어 판정 밖' % (len(gap), ', '.join(gap))
    return result(status, VERDICT_CHECK if rows else VERDICT_OK, summary=summary, columns=columns if rows else [],
                  rows=rows, method=method, criterion=criterion)


def _logins(ctx):
    r = ctx['results'].get(LOGINS) or {'ok': False, 'error': '조회하지 않음'}
    return r


RELOGIN_COLUMNS = ['출발 호스트', '출발지', '대상 호스트', '개인정보처리시스템', '계정', '건수', '처음', '마지막']
RELOGIN_METHOD = ('OpenObserve security_logs의 sshd 로그인 성공(event_action=ssh_login, event_outcome=success)을 대상 호스트·계정·'
                  '출발지별로 모아 출발지가 관리 호스트 주소(인벤토리 계산 + 작업 설정 문서의 내부 주소 대응)인 것을 고른다')
RELOGIN_CRITERION = '출발지가 다른 관리 호스트인 로그인 성공이 있으면 확인 필요(같은 호스트 자신에게서 온 로그인은 제외)'


def judge_relogin(ctx):
    ref = _reference(ctx['settings'])
    if ref is None:
        return failed(REFERENCE_FAILURE)
    r = _logins(ctx)
    if not r['ok']:
        return failed(r['error'])
    rows, excepted = [], 0
    for h in r['hits']:
        target, source = str(h.get('host_name') or ''), str(h.get('source_address') or '')
        origin = _managed_host(source, ctx, ref)
        if not origin or origin == target:
            continue
        if _is_excluded(source, ref):
            excepted += 1
            continue
        rows.append([origin, source, target, _pii_cell(ref, target), str(h.get('user_name') or ''),
                     _int(h.get('logins')), _local(h.get('first_us'), ctx), _local(h.get('last_us'), ctx)])
    rows.sort(key=lambda x: (x[0], x[2], x[4], x[1]))
    summary = _with_exceptions('관리 호스트에서 온 로그인 %d묶음(출발·대상 호스트·계정별)' % len(rows), excepted)
    return _verdict(rows, ctx, summary, RELOGIN_COLUMNS, RELOGIN_METHOD, RELOGIN_CRITERION)


UNAUTHORIZED_COLUMNS = ['출발지', '대상 호스트', '개인정보처리시스템', '계정', '건수', '처음', '마지막']
UNAUTHORIZED_METHOD = ('OpenObserve security_logs의 sshd 로그인 성공을 대상 호스트·계정·출발지별로 모아 출발지를 작업 설정 문서의 '
                       '정상 출발지 목록(IP·CIDR)과 대조')
UNAUTHORIZED_CRITERION = ('정상 출발지 목록 밖에서 온 로그인 성공이 있으면 확인 필요. 출발지가 관리 호스트 주소인 로그인은 6번에서 보고 '
                          '여기서는 뺀다')


def judge_unauthorized(ctx):
    ref = _reference(ctx['settings'])
    if ref is None:
        return failed(REFERENCE_FAILURE)
    r = _logins(ctx)
    if not r['ok']:
        return failed(r['error'])
    rows, excepted = [], 0
    for h in r['hits']:
        target, source = str(h.get('host_name') or ''), str(h.get('source_address') or '').strip()
        if _normal_name(source, ref)[0] or _managed_host(source, ctx, ref):
            continue
        if _is_excluded(source, ref):
            excepted += 1
            continue
        rows.append([source or '(출발지 없음)', target, _pii_cell(ref, target), str(h.get('user_name') or ''),
                     _int(h.get('logins')), _local(h.get('first_us'), ctx), _local(h.get('last_us'), ctx)])
    rows.sort(key=lambda x: (x[0], x[1], x[3]))
    summary = _with_exceptions('정상 출발지 목록 밖 로그인 %d묶음(출발지·대상 호스트·계정별)' % len(rows), excepted)
    return _verdict(rows, ctx, summary, UNAUTHORIZED_COLUMNS, UNAUTHORIZED_METHOD, UNAUTHORIZED_CRITERION)


MULTI_COLUMNS = ['계정', '시작', '끝', '출발지', '건수']
MULTI_METHOD = ('OpenObserve security_logs의 sshd 로그인 성공을 계정·출발지·분 단위로 모아(분마다 처음·마지막 시각) 같은 계정의 '
                '서로 다른 출발지 로그인 간격을 잰다. 계정은 호스트를 가리지 않는 로그인 이름이다')


def _label(address, ctx, ref):
    host = _managed_host(address, ctx, ref)
    if host:
        return '%s(%s)' % (address, host)
    normal, name = _normal_name(address, ref)
    return '%s(%s)' % (address, name) if normal and name else (address or '(출발지 없음)')


def _hits_of_account(buckets, window_us, min_sources):
    """시간순 분 묶음에서 window 안에 출발지가 min_sources개 이상 모이는 구간들을 겹치면 합쳐 돌려준다."""
    found = []
    for i, b in enumerate(buckets):
        group = [i]
        for j in range(i + 1, len(buckets)):
            # 시작 시각순이라 이 묶음이 window를 넘으면 뒤의 것도 넘는다. 간격은 앞 묶음의 마지막 로그인부터 잰다.
            if buckets[j]['first'] - b['last'] > window_us:
                break
            group.append(j)
        if len(set(buckets[k]['source'] for k in group)) < min_sources:
            continue
        start, end = min(buckets[k]['first'] for k in group), max(buckets[k]['last'] for k in group)
        if found and start <= found[-1]['end']:
            found[-1]['end'] = max(found[-1]['end'], end)
            found[-1]['index'].update(group)
        else:
            found.append({'start': start, 'end': end, 'index': set(group)})
    for hit in found:
        hit['buckets'] = [buckets[k] for k in sorted(hit.pop('index'))]
    return found


def judge_multi_source(ctx):
    ref = _reference(ctx['settings'])
    if ref is None:
        return failed(REFERENCE_FAILURE)
    r = ctx['results'].get(LOGIN_MINUTES) or {'ok': False, 'error': '조회하지 않음'}
    if not r['ok']:
        return failed(r['error'])
    sources = ctx['settings'].get('sources') or {}
    window = _int(sources.get('window_seconds')) or 120
    min_sources = _int(sources.get('min_sources')) or 2
    accounts = {}
    for h in r['hits']:
        first = _int(h.get('first_us'))
        accounts.setdefault(str(h.get('user_name') or ''), []).append({
            'source': str(h.get('source_address') or '').strip(), 'first': first,
            'last': max(first, _int(h.get('last_us'))), 'logins': _int(h.get('logins')) or 1})
    rows = []
    for user in sorted(accounts):
        buckets = sorted(accounts[user], key=lambda x: (x['first'], x['last'], x['source']))
        for hit in _hits_of_account(buckets, window * 1000000, min_sources):
            srcs = sorted(set(b['source'] for b in hit['buckets']))
            rows.append([user, _local(hit['start'], ctx), _local(hit['end'], ctx),
                         ', '.join(_label(s, ctx, ref) for s in srcs), sum(b['logins'] for b in hit['buckets'])])
    criterion = '같은 계정이 %d초 안(경계 포함)에 출발지 %d개 이상에서 로그인 성공하면 확인 필요' % (window, min_sources)
    summary = '해당 %d건(계정 %d개)' % (len(rows), len(set(x[0] for x in rows)))
    return _verdict(rows, ctx, summary, MULTI_COLUMNS, MULTI_METHOD, criterion)


def host_audit_log_review_managed_addresses(records, declared=None):
    """인벤토리에서 계산되는 내부 주소 대응 ``{주소: 관리번호}``.

    ``records``: 이번 실행의 호스트별 기록(``declared.ip``와 호스트에서 수집한 ``identity.ips``), ``declared``: 인벤토리 변수
    ``{관리번호: [ip, ansible_host, ...]}``. IP가 아닌 값(이름)과 루프백은 버린다. 여러 호스트에 걸친 주소(도커 브리지·VIP)는
    어느 호스트에서 왔는지 말할 수 없어 뺀다. 그런 주소가 관리 호스트이면 작업 설정 문서의 ``internal_addresses``에 둔다.
    """
    owners = {}

    def add(host, value):
        ip = _ip(value)
        if host and ip is not None and not ip.is_loopback and not ip.is_unspecified:
            owners.setdefault(str(ip), set()).add(str(host))

    for record in records or []:
        if not isinstance(record, dict):  # 깨진 기록을 조용히 넘기지 않는다(호출한 태스크가 '작성 중단'으로 알린다)
            raise TypeError('호스트 기록이 객체가 아님: %r' % (type(record).__name__,))
        host = record.get('inventory_hostname')
        add(host, (record.get('declared') or {}).get('ip'))
        for value in (record.get('identity') or {}).get('ips') or []:
            add(host, value)
    for host, values in (declared or {}).items():
        for value in values or []:
            add(host, value)
    return dict((addr, next(iter(hosts))) for addr, hosts in owners.items() if len(hosts) == 1)


_SUCCESS = "FROM \"security_logs\" WHERE event_action = 'ssh_login' AND event_outcome = 'success' "
# 6·7번은 (대상 호스트, 계정, 출발지) 묶음이라 행 수가 작다. 12번은 (계정, 출발지, 분) 묶음이라 자동화 계정이 자주 들어오면
# 많아질 수 있다. 한도에 닿으면 잘린 결과로 판정하지 않고 '조회 실패(결과가 조회 한도…)'가 된다(host_audit_log_review_results).
QUERIES = {
    RELOGIN: [{'name': LOGINS, 'size': 20000,
               'sql': "SELECT host_name, user_name, source_address, count(*) AS logins, min(_timestamp) AS first_us, "
                      "max(_timestamp) AS last_us " + _SUCCESS + "GROUP BY host_name, user_name, source_address"}],
    MULTI: [{'name': LOGIN_MINUTES, 'size': 50000,
             'sql': "SELECT user_name, source_address, date_format(_timestamp, '%Y-%m-%d %H:%M', '{offset}') AS minute, "
                    "count(*) AS logins, min(_timestamp) AS first_us, max(_timestamp) AS last_us " + _SUCCESS
                    + "GROUP BY user_name, source_address, minute"}],
}
JUDGES = {RELOGIN: judge_relogin, UNAUTHORIZED: judge_unauthorized, MULTI: judge_multi_source}


class FilterModule(object):
    def filters(self):
        return {'host_audit_log_review_managed_addresses': host_audit_log_review_managed_addresses}
