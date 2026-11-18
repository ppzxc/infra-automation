"""Log Review Report 3부 수집 공백 (Spec #544 / Ticket-3 #558).

수집 대상 호스트·장비 중 점검 기간에 로그가 하루도 없거나(전월 로그 없음) 중간에 하루 이상 비는(끊김) 것을 찾는다.
- 호스트: ``system_logs``의 ``host_name``(인벤토리 호스트명 = 관리번호)별 KST 일자 건수.
- 장비: 스위치(``system_logs``, ``service_name='switch-syslog'``)와 FortiGate(``security_logs``, ``service_name='fortigate-syslog'``)의
  ``coalesce(device_id, device_name)``별 KST 일자 건수. 두 스트림 중 어디든 있으면 그날은 수집된 것이다.
수집 대상 목록은 기준 설정 ``collection_targets``(``{'hosts': [...], 'devices': [...]}``)다(tasks/log_review.yml이 인벤토리에서 만든다).
판정 결과의 공백 이름 집합은 ``ctx['collection_gap']``에 남아 1부 판정이 '이상 없음'으로 단정하지 않게 한다.
"""

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_log_review_items import AUTO, VERDICT_CHECK, VERDICT_OK, failed, result, unavailable  # noqa: E402

ITEM = 'part3.collection_gap'
HOSTS_DAILY = 'collection_hosts_daily'
SWITCH_DAILY = 'collection_switch_daily'
FORTIGATE_DAILY = 'collection_fortigate_daily'
# 일자별 집계라 행 수는 (대상 수 × 31)이다. 한도에 닿으면 잘린 결과로 보고 조회 실패로 남긴다(host_audit_log_review_results).
_SIZE = 20000

QUERIES = {ITEM: [
    {'name': HOSTS_DAILY, 'size': _SIZE,
     'sql': "SELECT host_name AS name, date_format(_timestamp, '%Y-%m-%d', '{offset}') AS day, count(*) AS records "
            "FROM \"system_logs\" GROUP BY name, day"},
    {'name': SWITCH_DAILY, 'size': _SIZE,
     'sql': "SELECT coalesce(device_id, device_name) AS name, date_format(_timestamp, '%Y-%m-%d', '{offset}') AS day, "
            "count(*) AS records FROM \"system_logs\" WHERE service_name = 'switch-syslog' GROUP BY name, day"},
    {'name': FORTIGATE_DAILY, 'size': _SIZE,
     'sql': "SELECT coalesce(device_id, device_name) AS name, date_format(_timestamp, '%Y-%m-%d', '{offset}') AS day, "
            "count(*) AS records FROM \"security_logs\" WHERE service_name = 'fortigate-syslog' GROUP BY name, day"},
]}

METHOD = ('OpenObserve system_logs(호스트 host_name), 스위치 system_logs·FortiGate security_logs(장비 device_id)의 '
          '전월 KST 일자별 건수를 수집 대상 목록과 대조')
CRITERION = '점검 기간 중 로그가 하루도 없으면 "전월 로그 없음", 하루 이상 빈 날이 있으면 "끊김"'
COLUMNS = ['구분', '이름', '상태', '빈 날짜', '빈 일수']


def _days_by_name(hits):
    seen = {}
    for h in hits:
        name, day = str(h.get('name') or '').strip(), str(h.get('day') or '').strip()
        try:
            records = int(h.get('records') or 0)
        except (TypeError, ValueError):
            records = 0
        if name and day and records > 0:
            seen.setdefault(name, set()).add(day)
    return seen


def _ranges(days):
    """['2026-10-03','2026-10-04','2026-10-05','2026-10-20'] -> '10-03~10-05, 10-20'."""
    parts, run = [], []
    for d in sorted(days):
        cur = date.fromisoformat(d)
        if run and (cur - date.fromisoformat(run[-1])).days == 1:
            run.append(d)
            continue
        if run:
            parts.append(run)
        run = [d]
    if run:
        parts.append(run)
    return ', '.join(r[0][5:] if len(r) == 1 else '%s~%s' % (r[0][5:], r[-1][5:]) for r in parts)


def _gap_rows(kind, targets, seen, all_days):
    rows = []
    for name in sorted(set(targets)):
        days = seen.get(name, set())
        if not days:
            rows.append([kind, name, '전월 로그 없음', '전체', len(all_days)])
            continue
        missing = [d for d in all_days if d not in days]
        if missing:
            rows.append([kind, name, '끊김', _ranges(missing), len(missing)])
    return rows


def judge_collection_gap(ctx):
    targets = ctx['settings'].get('collection_targets') or {}
    hosts = [str(h) for h in (targets.get('hosts') or [])]
    devices = [str(d) for d in (targets.get('devices') or [])]
    if not hosts and not devices:
        return unavailable('수집 대상 목록 없음')
    results, all_days = ctx['results'], ctx['period']['days']
    problems, rows = [], []
    if hosts:
        r = results.get(HOSTS_DAILY) or {'ok': False, 'error': '조회하지 않음'}
        if r['ok']:
            rows += _gap_rows('호스트', hosts, _days_by_name(r['hits']), all_days)
        else:
            problems.append('호스트 로그 %s' % r['error'])
    if devices:
        dev = [results.get(n) or {'ok': False, 'error': '조회하지 않음'} for n in (SWITCH_DAILY, FORTIGATE_DAILY)]
        bad = [r for r in dev if not r['ok']]
        if bad:
            problems.append('장비 로그 %s' % bad[0]['error'])
        else:
            seen = {}
            for r in dev:
                for name, days in _days_by_name(r['hits']).items():
                    seen.setdefault(name, set()).update(days)
            rows += _gap_rows('장비', devices, seen, all_days)
    ctx['collection_gap'].update(r[1] for r in rows)
    summary = '대상 호스트 %d대 · 장비 %d대 중 공백 %d' % (len(hosts), len(devices), len(rows))
    if problems:
        out = failed('; '.join(problems))
        out.update(summary=summary + ' (조회한 부분만)', columns=COLUMNS if rows else [], rows=rows,
                   method=METHOD, criterion=CRITERION)
        return out
    return result(AUTO, VERDICT_CHECK if rows else VERDICT_OK, summary=summary, columns=COLUMNS if rows else [],
                  rows=rows, method=METHOD, criterion=CRITERION)


JUDGES = {ITEM: judge_collection_gap}


class FilterModule(object):
    """판정 모듈(필터 없음). 등록은 host_audit_log_review._JUDGE_MODULES가 한다."""

    def filters(self):
        return {}
