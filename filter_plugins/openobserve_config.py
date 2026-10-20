"""OpenObserve configuration as code (ADR-0008, Spec #93 / Ticket-2).

Pure functions so the desired state and the change plan are unit-testable without Ansible or a server.

``o2c_desired``  builds the objects (alert template, destination, VRL function, pipeline, alerts) from the role variables.
``o2c_plan``     compares them with what the OpenObserve API returned and lists only the writes that are needed.
"""

KINDS = ('template', 'destination', 'function', 'pipeline', 'alert', 'trace_stream')   # apply order: dependencies first
LIST_PATHS = {
    'template': '/api/{org}/alerts/templates',
    'destination': '/api/{org}/alerts/destinations',
    'function': '/api/{org}/functions',
    'pipeline': '/api/{org}/pipelines',
    'alert': '/api/v2/{org}/alerts',
    'trace_stream': '/api/{org}/streams?type=traces',   # 트레이스 스트림 목록(이름·설정). 스트림은 첫 span이 들어와야 생긴다
}
ITEM_PATHS = {
    'template': '/api/{org}/alerts/templates/{key}',
    'destination': '/api/{org}/alerts/destinations/{key}',
    'function': '/api/{org}/functions/{key}',
    'pipeline': '/api/{org}/pipelines/{key}',
    'alert': '/api/v2/{org}/alerts/{key}',
    'trace_stream': '/api/{org}/streams/{key}/settings?type=traces',
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
    ]
    # 의미 해석 함수와 파이프라인: 보안 로그(security_semantics)가 기본이고, 스위치 syslog(Spec #277)는 system_logs에 하나 더 건다
    semantics = [{'stream': stream, 'function_name': spec['function_name'], 'pipeline_name': spec['pipeline_name'], 'vrl': spec['vrl'],
                  'description': 'ADR-0008: sshd/sudo semantics (managed by infra-automation)'}]
    if spec.get('switch_syslog'):
        semantics.append(dict(spec['switch_syslog'], description='ADR-0008: switch syslog semantics (managed by infra-automation)'))
    out += [{'kind': 'function', 'name': sem['function_name'],
             'body': {'name': sem['function_name'], 'function': sem['vrl'].strip(), 'params': 'row', 'transType': 0}} for sem in semantics]
    out += [_pipeline(org, sem['stream'], sem['pipeline_name'], sem['function_name'], sem['description']) for sem in semantics]
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
    # 트레이스 스트림 보존 기간(Spec #253 / Ticket-8): 스트림이 이미 있을 때만 맞춘다(없으면 o2c_plan이 건너뛴다)
    if spec.get('traces_stream'):
        out.append({'kind': 'trace_stream', 'name': spec['traces_stream'], 'optional': True,
                    'body': {'data_retention': spec['traces_retention_days']},
                    'match': {'settings': {'data_retention': spec['traces_retention_days']}}})
    for item in out:
        if item['kind'] == 'function':   # the server fills in defaults for the rest (num_args, streams, ...)
            item['match'] = {k: item['body'][k] for k in ('name', 'function')}
        item.setdefault('match', item['body'])
        item['secret'] = item['kind'] in SECRET_KINDS
    return out


def _pipeline(org, stream, name, function_name, description):
    source = {'source_type': 'realtime', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    node = lambda nid, data, io, x: {'id': nid, 'data': data, 'io_type': io, 'position': {'x': x, 'y': 100}}  # noqa: E731
    stream_node = {'node_type': 'stream', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    body = {
        'name': name, 'description': description, 'enabled': True,
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
            if cur is None and want.get('optional'):
                continue   # 대상이 아직 없으면 만들지 않고 건너뛴다(스트림은 서버가 첫 수집 때 만든다)
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
    'disk': {'streams': ('system_filesystem_usage',), 'mount': True,
             'used': "state = 'used'", 'total': "state IN ('used', 'free')"},
    'inode': {'streams': ('system_filesystem_inodes_usage',), 'mount': True,
              'used': "state = 'used'", 'total': "state IN ('used', 'free')"},
    # 메모리는 1 - available / limit (Spec #253 / Ticket-6): 두 스트림을 UNION ALL로 이어 _timestamp별로 짝짓는다(스트림 JOIN은 쓰지 않는다)
    # streams는 (조회 스트림, 함께 읽는 스트림...) 순서다. 메모리는 (available, limit).
    'memory': {'streams': ('system_linux_memory_available', 'system_memory_limit'), 'mount': False},
}
# 메모리 SQL의 UNION ALL 가지가 어느 스트림 값인지 구분하는 src 열의 값
_SRC_AVAILABLE, _SRC_LIMIT = 1, 2


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
    if metric == 'memory':
        return _memory_sql(r, level, cfg)
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
        ', '.join(keys), ', '.join(inner_keys), r['used'], r['total'], r['streams'][0],
        (' WHERE ' + ' AND '.join(where)) if where else '', ', '.join(inner_keys), r['total'], ', '.join(keys), cond)


def _memory_sql(r, level, cfg):
    # 나눗셈을 실수로 한다: 정수로 적재된 값(합성 검증 레코드)이면 available/limit이 0으로 잘려 사용률이 100%가 된다.
    # 두 스트림 중 한쪽만 있는 _timestamp는 HAVING에서 걸러져 판정하지 않는다(데이터 결손은 Silent Host가 맡는다).
    where = ''.join(' AND NOT (%s)' % _target(e) for e in cfg.get('exclusions') or [] if e.get('host') and _applies(e, 'memory'))
    lo = _threshold('memory', 'p2', cfg['p2'], cfg.get('thresholds'))
    hi = _threshold('memory', 'p1', cfg['p1'], cfg.get('thresholds'))
    cond = ('min(pct) >= %s AND min(pct) < %s' % (lo, hi)) if level == 'P2' else 'min(pct) >= %s' % hi
    branch = 'SELECT host_name, _timestamp, %d AS src, value FROM "%s" WHERE value IS NOT NULL%s'
    avail = 'max(CASE WHEN src = %d THEN value END)' % _SRC_AVAILABLE
    limit = 'max(CASE WHEN src = %d THEN value END)' % _SRC_LIMIT
    available_stream, limit_stream = r['streams']
    return ('SELECT host_name, round(min(pct), 1) AS usage_pct FROM (SELECT host_name, _timestamp, '
            '(1.0 - %s * 1.0 / %s) * 100.0 AS pct FROM (%s UNION ALL %s) GROUP BY host_name, _timestamp '
            'HAVING %s IS NOT NULL AND %s > 0) GROUP BY host_name HAVING %s') % (
        avail, limit, branch % (_SRC_AVAILABLE, available_stream, where), branch % (_SRC_LIMIT, limit_stream, where), avail, limit, cond)


# --- 로스터와 부재 감지 (Spec #184 / Ticket-4) --------------------------------------------------------------------------
# 로스터는 실행 시 인벤토리 그룹에서 만든다. 부재 감지는 호스트마다 `HAVING count(*) < 1` 가지를 UNION ALL로 이은 SQL이다
# (인라인 VALUES/unnest JOIN은 이 OpenObserve 버전에서 틀린 결과를 낸다 — docs/research 참고).
import re as _re
_HOST_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
_DATE_RE = _re.compile(r'^\d{4}-\d{2}-\d{2}$')
SILENT_RECENT_US = 15 * 60 * 1000000   # P2: 최근 15분 없음


def o2c_app_telemetry_roster(roster, kv_by_host):
    """Roster hosts whose OpenBao ``hosts/<host>/agents`` has ``otel_app_telemetry: true`` (a real boolean; absent means off)."""
    return [h for h in roster or [] if ((kv_by_host or {}).get(h) or {}).get('otel_app_telemetry') is True]


def o2c_host_items(hosts):
    """``[{host: <name>}, ...]`` so a host list can go through ``o2c_as_requests`` (path ``.../{host}/agents``)."""
    return [{'host': h} for h in hosts or []]


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


def o2c_missing_sql(hosts, stream, field, cond, body_match=False):
    """One row per roster host without a record matching ``cond`` (e.g. no successful backup) in the alert window.

    ``field`` is the stream's host column (``host`` for backup_logs, ``host_name`` elsewhere). Same UNION ALL branch shape as
    the Silent Host SQL; an empty roster yields a branch that can never return a row.

    ``body_match``: a record also counts for the host when its raw ``body`` names the host (``lower(body) LIKE '% <host>%'``).
    ``field`` only exists on records the ingest pipeline already processed, so without this the first evaluation after a pipeline
    change sees no data for any host and reports every host as silent.
    """
    if not _HOST_RE.match(field):
        raise ValueError('SQL에 넣을 수 없는 필드 이름: %s' % field)
    if not hosts:
        return 'SELECT \'none\' AS %s, count(*) AS n FROM "%s" WHERE %s HAVING count(*) < 0' % (field, stream, cond)

    def who(h):
        if body_match:
            return "(%s = '%s' OR lower(body) LIKE '%% %s%%')" % (field, h, h.lower())
        return "%s = '%s'" % (field, h)

    return ' UNION ALL '.join(
        'SELECT \'%s\' AS %s, count(*) AS n FROM "%s" WHERE %s AND %s HAVING count(*) < 1' % (h, field, stream, who(h), cond)
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


def _alert_streams(alert):
    """All streams an alert's SQL reads: its own ``stream`` first, then ``extra_streams``."""
    return (alert['stream'],) + tuple(alert.get('extra_streams') or ())


def _rewrite_sql(sql, streams, suffix):
    for name in streams:
        quoted, target = '"%s"' % name, '"%s"' % _verify_stream(name, suffix)
        if quoted not in sql:
            raise ValueError('알림 SQL에 스트림 %s 이(가) 없어 검증 스트림으로 바꿀 수 없습니다' % quoted)
        sql = sql.replace(quoted, target)
    return sql


def o2c_verify_plan(alerts, fixtures, org, suffix, run_id, start_us, window_us=3600 * 1000000, sources=None, rosters=None):
    """Requests of the verification step: ``{ingest: [{stream, path, records}], searches: [...]}``.

    Every alert needs fixtures (a firing and a non-firing case at least); a missing one is a configuration error.
    A record's ``source_address`` may be ``@<kind>`` (e.g. ``@semaphore``): it resolves to the first normal source of that
    kind in ``sources`` (OpenBao, never committed). A case with an unresolvable placeholder is skipped.
    An alert with ``absence: {level, roster}`` gets its SQL rebuilt from ``rosters[roster]`` plus the fake host of every case,
    so "no data" is verified against hosts that really are on the roster (a case with ``off_roster: true`` stays off it).
    A case may have no records at all. An alert with ``uplinks`` (the configured list of ``{device, port}``, may be empty) gets its
    SQL rebuilt with the ``watch_port`` of every case appended as a watched port of that case's fake device.
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
            hosts[host] = {'case': case['name'], 'fires': bool(case['fires']), 'known_failure': case.get('known_failure') or '',
                           'off_roster': bool(case.get('off_roster'))}
            for rec in records:
                rec = dict(rec)
                # omit_host_field: 변환 전 레코드(호스트 필드 없이 원문만 있음)를 흉내 낸다. 원문의 {host}가 가짜 호스트로 바뀐다
                host_fields = {} if rec.pop('omit_host_field', False) else {spec.get('host_field', DEFAULT_ROW_KEY): host}
                if not host_fields and isinstance(rec.get('body'), str):
                    rec['body'] = rec['body'].replace('{host}', host)
                repeat = rec.pop('repeat', 1)
                rec_stream = rec.pop('stream', stream)   # 한 알림이 여러 스트림을 보면 레코드마다 대상 스트림을 지정한다
                ts = rec.pop('ts', None)   # 합성 스크레이프 시각(시작 기준 초) — 메트릭은 _timestamp별로 묶어 판정한다
                stamps = [{}] * repeat if ts is None else [{'_timestamp': start_us + int(t) * 1000000} for t in
                                                           (ts if isinstance(ts, list) else [ts])]
                ingest.setdefault(rec_stream, []).extend(dict(rec, **host_fields, **st) for st in stamps)
        missing = alert.get('missing')
        if missing:
            roster = list((rosters or {}).get(missing['roster']) or []) + sorted(h for h, exp in hosts.items() if not exp['off_roster'])
            sql = o2c_missing_sql(roster, stream, missing['field'], missing['cond'], bool(missing.get('body_match')))
        if absence:
            roster = list((rosters or {}).get(absence['roster']) or []) + sorted(h for h, exp in hosts.items() if not exp['off_roster'])
            sql = o2c_absence_sql(roster, stream, absence['level'])
        if alert.get('uplinks') is not None:
            # 업링크 목록(장비, 포트)에 케이스의 가짜 장비를 `watch_port`로 더해 "목록에 있으면 발화, 없으면 발화하지 않음"을 검증한다
            watched = list(alert['uplinks'] or []) + [{'device': _host(c, run_id), 'port': c['watch_port']}
                                                      for c in spec['cases'] if c.get('watch_port') and _host(c, run_id) in hosts]
            sql = o2c_switch_uplink_sql(watched, alert.get('noise_events'))
        period_us = int(alert.get('period', 0)) * 60 * 1000000   # 알림의 조회 구간만큼 거슬러 올라가 검색한다
        searches.append({
            'alert': name, 'stream': _verify_stream(stream, suffix), 'row_key': spec.get('row_key', DEFAULT_ROW_KEY),
            'path': SEARCH_PATH.format(org=org), 'hosts': hosts,
            'body': {'query': {'sql': _rewrite_sql(sql, _alert_streams(alert), suffix), 'start_time': start_us - period_us,
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


# --- 스위치 syslog 알림 (Spec #277) -------------------------------------------------------------------------------------
# 스위치 syslog는 system_logs에 service_name=switch-syslog로 들어오고, switch_syslog_semantics VRL이 장비(device_id/device_name)·
# Cisco 메시지 코드(event_name)·심각도(log_syslog_severity_code)를 붙인다. 알림 SQL은 파싱된 모든 줄이 갖는 필드와 body만 참조한다
# (일부 메시지에만 생기는 필드를 참조하면 그 메시지가 한 번도 오지 않은 동안 스트림에 컬럼이 없어 알림이 unknown field로 계속 오류가 난다).
# 목록(잡음·설정 변경·로그인 실패·MAC 플랩 메시지 코드, 업링크 (장비, 포트), 수신 중단 감시 장비)은 SQL에 들어가므로 요청 전에 형식을 검증한다.
_EVENT_RE = _re.compile(r'^[A-Za-z0-9_]+-[0-7]-[A-Za-z0-9_]+$')
_MANAGEMENT_RE = _re.compile(r'^ns[0-9]+$')
_PORT_RE = _re.compile(r'^[A-Za-z][A-Za-z-]*[0-9][0-9/.:]*$')
_IFACE_SPLIT = _re.compile(r'^([A-Za-z-]+?)([0-9].*)$')
# 약어 → 로그에 찍히는 전체 이름. LINK-3-UPDOWN은 전체 이름(GigabitEthernet1/0/49), MAC 플랩은 약어(Gi1/0/49)로 찍힌다.
_IFACE_PREFIX = {'gi': 'GigabitEthernet', 'fa': 'FastEthernet', 'te': 'TenGigabitEthernet', 'fo': 'FortyGigabitEthernet',
                 'twe': 'TwentyFiveGigE', 'hu': 'HundredGigE', 'po': 'Port-channel', 'eth': 'Ethernet'}
UPLINK_EVENTS = ('LINK-3-UPDOWN', 'LINEPROTO-5-UPDOWN', 'LINK-5-CHANGED')   # 링크 다운, 라인 프로토콜 다운, 관리자 shutdown


def o2c_valid_switch_events(events):
    """True when every item is a Cisco message code as printed without the percent sign (``SW_MATM-4-MACFLAP_NOTIF``)."""
    return all(isinstance(e, str) and _EVENT_RE.match(e) for e in events or [])


def o2c_valid_switch_roster(devices):
    """True when every item is a management number (``ns0250``) — what the VRL stores in ``device_id``."""
    return all(isinstance(d, str) and _MANAGEMENT_RE.match(d) for d in devices or [])


def o2c_valid_switch_uplinks(entries):
    """True when every entry is ``{device: <management number>, port: <interface name>}`` with a safe port name (``/`` allowed)."""
    return all(isinstance(e, dict) and _MANAGEMENT_RE.match(str(e.get('device') or '')) and _PORT_RE.match(str(e.get('port') or ''))
               for e in entries or [])


def _canonical_interface(port):
    """The port as the link-state messages print it (``Gi1/0/49`` -> ``GigabitEthernet1/0/49``); other names are kept."""
    m = _IFACE_SPLIT.match(port)
    if m and m.group(1).lower() in _IFACE_PREFIX:
        return _IFACE_PREFIX[m.group(1).lower()] + m.group(2)
    return port


def o2c_switch_noise_filter(events):
    """`` AND event_name NOT IN (...)`` for the noise message codes; empty when the list is empty."""
    return (' AND event_name NOT IN (%s)' % ', '.join(_q(e) for e in events)) if events else ''


def o2c_switch_uplink_sql(entries, noise_events=None):
    """SQL of the uplink-down alert: a link/line-protocol message saying ``down`` (or ``administratively down``) for a listed (device, port).

    The port is matched in ``body`` (``Interface <name>, changed state to down``) so the query needs no port column. The trailing
    comma keeps ``Gi1/0/1`` from matching ``Gi1/0/10``. An empty list yields a condition that can never be true.
    """
    pairs = []
    for e in entries or []:
        name = _canonical_interface(str(e['port'])).lower()
        down, admin = ("lower(body) LIKE %s" % _q('%%interface %s, changed state to %s%%' % (name, tail)) for tail in ('down', 'administratively down'))
        pairs.append('(device_id = %s AND (%s OR %s))' % (_q(e['device']), down, admin))
    return ('SELECT coalesce(device_id, device_name) AS device, '
            "regexp_replace(body, '^.*[Ii]nterface ([^ ,]+),.*$', '\\1') AS port, count(*) AS downs FROM \"system_logs\" "
            "WHERE service_name = 'switch-syslog' AND event_name IN (%s)%s AND (%s) GROUP BY device, port") % (
        ', '.join(_q(ev) for ev in UPLINK_EVENTS), o2c_switch_noise_filter(noise_events), ' OR '.join(pairs) if pairs else '1 = 0')


def o2c_enabled_alerts(alerts):
    """The alerts that are created: an alert whose ``enabled`` renders false (e.g. the uplink alert with an empty port list) is left out."""
    return [a for a in alerts or [] if str(a.get('enabled', True)).strip().lower() not in ('false', '0', '')]


class FilterModule(object):
    def filters(self):
        return {'o2c_desired': o2c_desired, 'o2c_plan': o2c_plan, 'o2c_plan_summary': o2c_plan_summary,
                'o2c_alert_state': o2c_alert_state, 'o2c_as_requests': o2c_as_requests, 'o2c_verify_pending': o2c_verify_pending, 'o2c_resource_sql': o2c_resource_sql,
                'o2c_read_requests': o2c_read_requests, 'o2c_verify_plan': o2c_verify_plan,
                'o2c_verify_failures': o2c_verify_failures, 'o2c_verify_known': o2c_verify_known,
                'o2c_alert_history_errors': o2c_alert_history_errors,
                'o2c_roster': o2c_roster, 'o2c_valid_exceptions': o2c_valid_exceptions,
                'o2c_without_exceptions': o2c_without_exceptions, 'o2c_absence_sql': o2c_absence_sql,
                'o2c_missing_sql': o2c_missing_sql, 'o2c_app_telemetry_roster': o2c_app_telemetry_roster,
                'o2c_host_items': o2c_host_items,
                'o2c_valid_switch_events': o2c_valid_switch_events, 'o2c_valid_switch_roster': o2c_valid_switch_roster,
                'o2c_valid_switch_uplinks': o2c_valid_switch_uplinks, 'o2c_switch_noise_filter': o2c_switch_noise_filter,
                'o2c_switch_uplink_sql': o2c_switch_uplink_sql, 'o2c_enabled_alerts': o2c_enabled_alerts}
