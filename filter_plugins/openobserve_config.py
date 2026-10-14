"""OpenObserve configuration as code (ADR-0008, Spec #93 / Ticket-2).

Pure functions so the desired state and the change plan are unit-testable without Ansible or a server.

``o2c_desired``  builds the objects (alert template, destination, VRL function, pipeline, alerts) from the role variables.
``o2c_plan``     compares them with what the OpenObserve API returned and lists only the writes that are needed.
"""

KINDS = ('template', 'destination', 'function', 'pipeline', 'alert')   # apply order: dependencies first
LIST_PATHS = {
    'template': '/api/{org}/alerts/templates',
    'destination': '/api/{org}/alerts/destinations',
    'function': '/api/{org}/functions',
    'pipeline': '/api/{org}/pipelines',
    'alert': '/api/v2/{org}/alerts',
}
ITEM_PATHS = {
    'template': '/api/{org}/alerts/templates/{key}',
    'destination': '/api/{org}/alerts/destinations/{key}',
    'function': '/api/{org}/functions/{key}',
    'pipeline': '/api/{org}/pipelines/{key}',
    'alert': '/api/v2/{org}/alerts/{key}',
}
ID_FIELD = {'pipeline': 'pipeline_id', 'alert': 'alert_id'}   # update by id; the others by name
CONTEXT_KEYS = ('severity', 'severity_icon', 'title', 'what', 'why', 'action', 'runbook')
INJECT_ID = ('pipeline',)   # the pipeline body carries its own id on update; alerts take it from the path only
MANAGED_PREFIX = 'infra-'   # 이 접두어의 알림만 이 저장소가 소유한다
SECRET_KINDS = ('destination',)                               # url and headers carry the webhook credentials


def o2c_desired(spec):
    """Desired OpenObserve objects as a list of ``{kind, name, body, match, secret}`` in apply order."""
    org = spec['org']
    stream = spec['stream']
    dest = spec['destination_name']
    out = [
        {'kind': 'template', 'name': spec['template_name'],
         'body': {'name': spec['template_name'], 'body': spec['template_body'], 'type': 'http', 'title': ''}},
        {'kind': 'destination', 'name': dest,
         'body': {'name': dest, 'type': 'http', 'url': spec['webhook_url'], 'method': 'post',
                  'headers': dict(spec.get('webhook_headers') or {}), 'template': spec['template_name'],
                  'skip_tls_verify': False, 'output_format': 'json'}},
        {'kind': 'function', 'name': spec['function_name'],
         'body': {'name': spec['function_name'], 'function': spec['vrl'].strip(), 'params': 'row', 'transType': 0}},
        _pipeline(org, stream, spec['pipeline_name'], spec['function_name']),
    ]
    for alert in list(spec['alerts']) + ([spec['selftest_alert']] if spec.get('selftest_alert') else []):
        out.append({'kind': 'alert', 'name': alert['name'], 'body': {
            'name': alert['name'], 'stream_type': alert.get('stream_type', 'logs'), 'stream_name': alert['stream'], 'is_real_time': False,
            'query_condition': {'type': 'sql', 'sql': alert['sql']},
            'trigger_condition': {'period': alert['period'], 'operator': '>=', 'threshold': alert.get('threshold', 1),
                                  'frequency': alert['frequency'], 'frequency_type': 'minutes', 'silence': alert['silence']},
            'destinations': [dest], 'enabled': True, 'description': alert['description'],
            # 행동 가능한 알림: 통지 템플릿이 {severity}·{title}·{what}·{why}·{action}·{runbook}로 쓰는 알림별 변수,
            # {rows}의 한 줄 모양(대상 호스트·출발지·사용자·건수)
            'context_attributes': {k: alert[k] for k in CONTEXT_KEYS},
            'row_template': alert['row_template'], 'row_template_type': 'String',
        }})
    for item in out:
        if item['kind'] == 'function':   # the server fills in defaults for the rest (num_args, streams, ...)
            item['match'] = {k: item['body'][k] for k in ('name', 'function')}
        item.setdefault('match', item['body'])
        item['secret'] = item['kind'] in SECRET_KINDS
    return out


def _pipeline(org, stream, name, function_name):
    source = {'source_type': 'realtime', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    node = lambda nid, data, io, x: {'id': nid, 'data': data, 'io_type': io, 'position': {'x': x, 'y': 100}}  # noqa: E731
    stream_node = {'node_type': 'stream', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    body = {
        'name': name, 'description': 'ADR-0008: sshd/sudo semantics (managed by infra-automation)', 'enabled': True,
        'source': source,
        'nodes': [
            node('input', dict(stream_node), 'input', 50),
            node('function', {'node_type': 'function', 'name': function_name, 'after_flatten': True, 'num_args': 0},
                 'default', 300),
            node('output', dict(stream_node), 'output', 550),
        ],
        'edges': [{'id': 'input-function', 'source': 'input', 'target': 'function'},
                  {'id': 'function-output', 'source': 'function', 'target': 'output'}],
    }
    # the server rewrites ids/positions; what makes the pipeline "the same" is its source, its state and the function it runs
    match = {'name': name, 'enabled': True, 'source': {'stream_name': stream, 'source_type': 'realtime'},
             'function': {'name': function_name, 'after_flatten': True}}
    return {'kind': 'pipeline', 'name': name, 'body': body, 'match': match}


def _items(payload):
    if isinstance(payload, dict):
        payload = payload.get('list', [])
    return [i for i in (payload or []) if isinstance(i, dict)]


def _project_pipeline(item):
    fn = next((n.get('data', {}) for n in item.get('nodes', []) if n.get('data', {}).get('node_type') == 'function'), {})
    return {'name': item.get('name'), 'enabled': item.get('enabled'), 'source': item.get('source', {}),
            'function': {'name': fn.get('name'), 'after_flatten': fn.get('after_flatten')}}


def _subset(want, have):
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and _subset(v, have[k]) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(have, list) and len(want) == len(have) and all(_subset(w, h) for w, h in zip(want, have))
    return want == have


def o2c_read_requests(org):
    """GET list requests (``{kind, path}``) for every managed kind, from the same table the plan creates with."""
    return [{'kind': kind, 'path': LIST_PATHS[kind].format(org=org)} for kind in KINDS]


def o2c_plan(desired, existing, org):
    """Writes needed to reach ``desired``. ``existing`` maps kind -> API payload (list or ``{"list": [...]}``).

    Each action: ``{kind, name, op (create|update), method, path, body, secret}``. Nothing is returned for objects that already match.
    """
    plan = []
    for kind in KINDS:
        have = {i.get('name'): i for i in _items(existing.get(kind))}
        for want in (d for d in desired if d['kind'] == kind):
            cur = have.get(want['name'])
            body = want['body']
            if cur is None:
                plan.append(_action(kind, want, 'create', 'POST', LIST_PATHS[kind].format(org=org), body))
                continue
            seen = _project_pipeline(cur) if kind == 'pipeline' else cur
            if _subset(want['match'], seen):
                continue
            key = cur.get(ID_FIELD[kind]) if kind in ID_FIELD else want['name']
            if kind in INJECT_ID:
                body = dict(body, **{ID_FIELD[kind]: key})
            plan.append(_action(kind, want, 'update', 'PUT', ITEM_PATHS[kind].format(org=org, key=key), body))
    # 저장소 정의에서 빠지거나 이름이 바뀐 관리 대상(infra- 접두어) 알림은 서버에서 지운다. 접두어 밖 알림은 건드리지 않는다
    wanted = {d['name'] for d in desired if d['kind'] == 'alert'}
    for cur in _items(existing.get('alert')):
        name = cur.get('name') or ''
        if name.startswith(MANAGED_PREFIX) and name not in wanted and cur.get('alert_id'):
            plan.append({'kind': 'alert', 'name': name, 'op': 'delete', 'method': 'DELETE', 'secret': False, 'body': {},
                         'path': ITEM_PATHS['alert'].format(org=org, key=cur['alert_id'])})
    return plan


def _action(kind, want, op, method, path, body):
    return {'kind': kind, 'name': want['name'], 'op': op, 'method': method, 'path': path, 'body': body,
            'secret': want['secret']}


def o2c_alert_state(detail_results):
    """Full alert objects from the per-alert GET results (``item`` = list entry, ``json`` = detail)."""
    out = []
    for res in detail_results or []:
        item, detail = res.get('item', {}), res.get('json') or {}
        out.append(dict(detail, alert_id=item.get('alert_id'), name=item.get('name', detail.get('name'))))
    return out


def o2c_plan_summary(plan):
    """Lines safe to print (no bodies: the destination holds the webhook credentials)."""
    return ['%s %s %s' % (a['op'], a['kind'], a['name']) for a in plan]


# --- 리소스 고갈 알림 SQL (Spec #184 / Ticket-3) ------------------------------------------------------------------------
# 사용률은 _timestamp별로 묶은 뒤(구간 전체 max()는 근사, 메모리 합계는 중복 합산) 구간 최솟값으로 판정한다.
# P2는 [p2, p1) 구간만, P1은 p1 이상만 잡아 같은 대상에 동시 통지하지 않는다.
_RESOURCE = {
    'disk': {'stream': 'system_filesystem_usage', 'mount': True,
             'used': "state = 'used'", 'total': "state IN ('used', 'free')"},
    'inode': {'stream': 'system_filesystem_inodes_usage', 'mount': True,
              'used': "state = 'used'", 'total': "state IN ('used', 'free')"},
    'memory': {'stream': 'system_memory_usage', 'mount': False,
               'used': "state = 'used'", 'total': "state <> 'slab_unreclaimable'"},
}


def _q(value):
    return "'%s'" % str(value).replace("'", "''")


def _num(value):
    value = float(value)
    return str(int(value)) if value % 1 == 0 else str(value)


def _applies(entry, metric):
    return entry.get('metric') in (None, '', metric) and (not entry.get('mount') or _RESOURCE[metric]['mount'])


def _target(entry):
    cond = ['host_name = %s' % _q(entry['host'])]
    if entry.get('mount'):
        cond.append('mountpoint = %s' % _q(entry['mount']))
    return ' AND '.join(cond)


def _threshold(metric, key, default, overrides):
    hits = [e for e in (overrides or []) if e.get('host') and e.get(key) is not None and _applies(e, metric)]
    hits.sort(key=lambda e: not e.get('mount'))   # 마운트까지 지정한 항목이 먼저
    if not hits:
        return _num(default)
    whens = ' '.join('WHEN %s THEN %s' % (_target(e), _num(e[key])) for e in hits)
    return 'CASE %s ELSE %s END' % (whens, _num(default))


def o2c_resource_sql(metric, level, cfg):
    """SQL of a resource alert. ``cfg``: p2, p1, fstypes, exclusions, thresholds (OpenBao overrides, may be empty)."""
    r = _RESOURCE[metric]
    keys = ['host_name'] + (['mountpoint'] if r['mount'] else [])
    inner_keys = keys + (['device'] if r['mount'] else [])
    where = []
    if r['mount']:
        where.append('type NOT IN (%s)' % ', '.join(_q(t) for t in cfg['fstypes']))
    for e in cfg.get('exclusions') or []:
        if e.get('host') and _applies(e, metric):
            where.append('NOT (%s)' % _target(e))
    lo = _threshold(metric, 'p2', cfg['p2'], cfg.get('thresholds'))
    hi = _threshold(metric, 'p1', cfg['p1'], cfg.get('thresholds'))
    cond = ('min(pct) >= %s AND min(pct) < %s' % (lo, hi)) if level == 'P2' else 'min(pct) >= %s' % hi
    return ('SELECT %s, round(min(pct), 1) AS usage_pct FROM (SELECT %s, _timestamp, '
            'sum(CASE WHEN %s THEN value ELSE 0 END) * 100.0 / sum(CASE WHEN %s THEN value ELSE 0 END) AS pct '
            'FROM "%s"%s GROUP BY %s, _timestamp HAVING sum(CASE WHEN %s THEN value ELSE 0 END) > 0) '
            'GROUP BY %s HAVING %s') % (
        ', '.join(keys), ', '.join(inner_keys), r['used'], r['total'], r['stream'],
        (' WHERE ' + ' AND '.join(where)) if where else '', ', '.join(inner_keys), r['total'], ', '.join(keys), cond)


# --- 로스터와 부재 감지 (Spec #184 / Ticket-4) --------------------------------------------------------------------------
# 로스터는 실행 시 인벤토리 그룹에서 만든다. 부재 감지는 호스트마다 `HAVING count(*) < 1` 가지를 UNION ALL로 이은 SQL이다
# (인라인 VALUES/unnest JOIN은 이 OpenObserve 버전에서 틀린 결과를 낸다 — docs/research 참고).
import re as _re
_HOST_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
_DATE_RE = _re.compile(r'^\d{4}-\d{2}-\d{2}$')
SILENT_RECENT_US = 15 * 60 * 1000000   # P2: 최근 15분 없음


def _group(groups, name):
    return set((groups or {}).get(name) or [])


def o2c_roster(groups, kind):
    """Inventory hostnames of a roster. ``collect``: servers - Exclusion - Backup Only. ``maintenance``: servers - Exclusion."""
    if kind not in ('collect', 'maintenance'):
        raise ValueError('알 수 없는 로스터 종류: %s' % kind)
    hosts = _group(groups, 'servers') - _group(groups, 'host_agents_excluded')
    if kind == 'collect':
        hosts -= _group(groups, 'host_agents_backup_only')
    bad = sorted(h for h in hosts if not _HOST_RE.match(str(h)))
    if bad:
        raise ValueError('SQL에 넣을 수 없는 인벤토리 호스트 이름: %s' % ', '.join(bad))
    return sorted(hosts)


def o2c_valid_exceptions(exceptions):
    """True when every planned-stop exception has a safe ``host`` and a mandatory ``YYYY-MM-DD`` ``expires``."""
    return all(isinstance(e, dict) and _HOST_RE.match(str(e.get('host') or '')) and _DATE_RE.match(str(e.get('expires') or ''))
               for e in exceptions or [])


def o2c_without_exceptions(roster, exceptions, today):
    """Roster minus the hosts of planned-stop exceptions that have not expired (``expires`` >= ``today``); expired ones are ignored."""
    stopped = {e['host'] for e in exceptions or [] if str(e['expires']) >= str(today)}
    return [h for h in roster if h not in stopped]


def _absence_branch(host, stream, level):
    head = 'SELECT \'%s\' AS host_name, count(*) AS n FROM "%s" WHERE host_name = \'%s\' HAVING ' % (host, stream, host)
    if level == 'p1':   # 조회 구간(3시간) 전체에 없음
        return head + 'count(*) < 1'
    # p2: 조회 구간에는 있었지만(P1 대상 아님) 최근 15분은 없음
    return head + ('count(*) >= 1 AND sum(CASE WHEN _timestamp >= to_unixtime(now()) * 1000000 - %d THEN 1 ELSE 0 END) < 1'
                   % SILENT_RECENT_US)


def o2c_absence_sql(hosts, stream, level):
    """One row per roster host that has no data. An empty roster yields a branch that can never return a row."""
    if level not in ('p1', 'p2'):
        raise ValueError('알 수 없는 등급: %s' % level)
    if not hosts:
        return 'SELECT \'none\' AS host_name, count(*) AS n FROM "%s" HAVING count(*) < 0' % stream
    return ' UNION ALL '.join(_absence_branch(h, stream, level) for h in hosts)


def o2c_missing_sql(hosts, stream, field, cond):
    """One row per roster host without a record matching ``cond`` (e.g. no successful backup) in the alert window.

    ``field`` is the stream's host column (``host`` for backup_logs, ``host_name`` elsewhere). Same UNION ALL branch shape as
    the Silent Host SQL; an empty roster yields a branch that can never return a row.
    """
    if not _HOST_RE.match(field):
        raise ValueError('SQL에 넣을 수 없는 필드 이름: %s' % field)
    if not hosts:
        return 'SELECT \'none\' AS %s, count(*) AS n FROM "%s" WHERE %s HAVING count(*) < 0' % (field, stream, cond)
    return ' UNION ALL '.join(
        'SELECT \'%s\' AS %s, count(*) AS n FROM "%s" WHERE %s = \'%s\' AND %s HAVING count(*) < 1' % (h, field, stream, field, h, cond)
        for h in hosts)


# --- 알림 검증 단계 (Spec #184 / Ticket-1) -----------------------------------------------------------------------------
# 합성 레코드를 검증 전용 스트림(운영 스트림명 + 접미사)에 넣고, 알림 SQL의 스트림명만 바꿔 검색한 결과를 기대와 비교한다.
# 호스트 이름에 실행 ID를 붙여 이전 실행의 잔여 데이터와 섞이지 않게 하고, 알림마다 자기 케이스의 호스트만 판정한다.
SEARCH_PATH = '/api/{org}/_search?type=logs'
INGEST_PATH = '/api/{org}/{stream}/_json'
DEFAULT_ROW_KEY = 'host_name'


def _host(case, run_id):
    return '%s-%s' % (case['host'], run_id)


def _verify_stream(stream, suffix):
    return stream + suffix


def _rewrite_sql(sql, stream, suffix):
    quoted, target = '"%s"' % stream, '"%s"' % _verify_stream(stream, suffix)
    if quoted not in sql:
        raise ValueError('알림 SQL에 스트림 %s 이(가) 없어 검증 스트림으로 바꿀 수 없습니다' % quoted)
    return sql.replace(quoted, target)


def o2c_verify_plan(alerts, fixtures, org, suffix, run_id, start_us, window_us=3600 * 1000000, sources=None, rosters=None):
    """Requests of the verification step: ``{ingest: [{stream, path, records}], searches: [...]}``.

    Every alert needs fixtures (a firing and a non-firing case at least); a missing one is a configuration error.
    A record's ``source_address`` may be ``@<kind>`` (e.g. ``@semaphore``): it resolves to the first normal source of that
    kind in ``sources`` (OpenBao, never committed). A case with an unresolvable placeholder is skipped.
    An alert with ``absence: {level, roster}`` gets its SQL rebuilt from ``rosters[roster]`` plus the fake host of every case,
    so "no data" is verified against hosts that really are on the roster. A case may have no records at all.
    """
    by_kind = {}
    for src in sources or []:
        by_kind.setdefault(src.get('kind'), src.get('address'))
    ingest, searches = {}, []
    for alert in alerts:
        name, stream = alert['name'], alert['stream']
        spec = (fixtures or {}).get(name)
        if not spec or not spec.get('cases'):
            raise ValueError('알림 %s 에 검증 픽스처(files/alert_fixtures.yml)가 없습니다' % name)
        hosts = {}
        absence = alert.get('absence')
        sql = alert['sql']
        for case in spec['cases']:
            records = [_resolve(r, by_kind) for r in case['records']]
            if any(r is None for r in records):
                continue
            host = _host(case, run_id)
            hosts[host] = {'case': case['name'], 'fires': bool(case['fires']), 'known_failure': case.get('known_failure') or ''}
            for rec in records:
                rec = dict(rec)
                repeat = rec.pop('repeat', 1)
                ts = rec.pop('ts', None)   # 합성 스크레이프 시각(시작 기준 초) — 메트릭은 _timestamp별로 묶어 판정한다
                stamps = [{}] * repeat if ts is None else [{'_timestamp': start_us + int(t) * 1000000} for t in
                                                           (ts if isinstance(ts, list) else [ts])]
                ingest.setdefault(stream, []).extend(dict(rec, **{spec.get('host_field', DEFAULT_ROW_KEY): host}, **st) for st in stamps)
        missing = alert.get('missing')
        if missing:
            roster = list((rosters or {}).get(missing['roster']) or []) + sorted(hosts)
            sql = o2c_missing_sql(roster, stream, missing['field'], missing['cond'])
        if absence:
            roster = list((rosters or {}).get(absence['roster']) or []) + sorted(hosts)
            sql = o2c_absence_sql(roster, stream, absence['level'])
        period_us = int(alert.get('period', 0)) * 60 * 1000000   # 알림의 조회 구간만큼 거슬러 올라가 검색한다
        searches.append({
            'alert': name, 'stream': _verify_stream(stream, suffix), 'row_key': spec.get('row_key', DEFAULT_ROW_KEY),
            'path': SEARCH_PATH.format(org=org), 'hosts': hosts,
            'body': {'query': {'sql': _rewrite_sql(sql, stream, suffix), 'start_time': start_us - period_us,
                               'end_time': start_us + window_us, 'from': 0, 'size': 1000}}})
    return {'ingest': [{'stream': _verify_stream(s, suffix), 'path': INGEST_PATH.format(org=org, stream=_verify_stream(s, suffix)),
                        'records': recs} for s, recs in ingest.items()],
            'searches': searches}


def _resolve(rec, by_kind):
    addr = rec.get('source_address')
    if isinstance(addr, str) and addr.startswith('@'):
        if not by_kind.get(addr[1:]):
            return None
        rec = dict(rec, source_address=by_kind[addr[1:]])
    return rec


def _judge(hits, search):
    seen = {h.get(search['row_key']) for h in (hits or []) if isinstance(h, dict)}
    for host, exp in search['hosts'].items():
        got = host in seen
        if got != exp['fires']:
            yield exp, ("알림 %s / 케이스 '%s': 발화해야 하는데 발화하지 않았습니다" % (search['alert'], exp['case']) if exp['fires']
                        else "알림 %s / 케이스 '%s': 발화하면 안 되는데 발화했습니다" % (search['alert'], exp['case']))


def o2c_verify_failures(hits, search):
    """Mismatches that fail the job (cases flagged ``known_failure`` are excluded)."""
    return [msg for exp, msg in _judge(hits, search) if not exp['known_failure']]


def o2c_verify_known(hits, search):
    """Mismatches on cases flagged ``known_failure`` — reported but never blocking."""
    return ['%s [알려진 실패: %s]' % (msg, exp['known_failure']) for exp, msg in _judge(hits, search) if exp['known_failure']]


def o2c_alert_history_errors(history, alert_names):
    """Names of managed alerts whose most recent evaluation ended in ``error``."""
    hits = history.get('hits', history.get('list', [])) if isinstance(history, dict) else (history or [])
    latest = {}
    for h in hits:
        if isinstance(h, dict) and h.get('alert_name') in alert_names:
            if h['alert_name'] not in latest or (h.get('timestamp') or 0) >= (latest[h['alert_name']].get('timestamp') or 0):
                latest[h['alert_name']] = h
    return sorted(n for n, h in latest.items() if str(h.get('status', '')).lower() == 'error')


def o2c_as_requests(items, path=None, path_key='path', method_key=None, default_method='GET', body_key=None, label=None):
    """Turn ``items`` into the ``requests`` list of the ``o2c_http`` module, keeping each original item for the results.

    ``path`` is a format string over the item (e.g. ``/api/v2/org/alerts/{alert_id}``); otherwise ``item[path_key]`` is used.
    ``label`` (format string over the item) names the request in failure messages — never put secrets in it.
    """
    out = []
    for item in items or []:
        out.append({'path': path.format(**item) if path else item[path_key],
                    'method': item.get(method_key, default_method) if method_key else default_method,
                    'body': item.get(body_key) if body_key else None,
                    'label': label.format(**item) if label else (path.format(**item) if path else item[path_key]),
                    'item': item})
    return out


def o2c_verify_pending(results):
    """Names of the alerts whose verification search still mismatches (or whose request failed) — the retry loop waits on these."""
    pending = []
    for r in results or []:
        search = r['item']
        hits = (r.get('json') or {}).get('hits', []) if r.get('status') == 200 else []
        if r.get('status') != 200 or o2c_verify_failures(hits, search):
            pending.append(search['alert'])
    return pending


class FilterModule(object):
    def filters(self):
        return {'o2c_desired': o2c_desired, 'o2c_plan': o2c_plan, 'o2c_plan_summary': o2c_plan_summary,
                'o2c_alert_state': o2c_alert_state, 'o2c_as_requests': o2c_as_requests, 'o2c_verify_pending': o2c_verify_pending, 'o2c_resource_sql': o2c_resource_sql,
                'o2c_read_requests': o2c_read_requests, 'o2c_verify_plan': o2c_verify_plan,
                'o2c_verify_failures': o2c_verify_failures, 'o2c_verify_known': o2c_verify_known,
                'o2c_alert_history_errors': o2c_alert_history_errors,
                'o2c_roster': o2c_roster, 'o2c_valid_exceptions': o2c_valid_exceptions,
                'o2c_without_exceptions': o2c_without_exceptions, 'o2c_absence_sql': o2c_absence_sql,
                'o2c_missing_sql': o2c_missing_sql}
