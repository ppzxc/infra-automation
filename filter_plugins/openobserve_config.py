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
SECRET_KINDS =('destination',)                                # url and headers carry the webhook credentials


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
    for alert in spec['alerts']:
        out.append({'kind': 'alert', 'name': alert['name'], 'body': {
            'name': alert['name'], 'stream_type': 'logs', 'stream_name': alert['stream'], 'is_real_time': False,
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


def o2c_verify_plan(alerts, fixtures, org, suffix, run_id, start_us, window_us=3600 * 1000000):
    """Requests of the verification step: ``{ingest: [{stream, path, records}], searches: [...]}``.

    Every alert needs fixtures (a firing and a non-firing case at least); a missing one is a configuration error.
    """
    ingest, searches = {}, []
    for alert in alerts:
        name, stream = alert['name'], alert['stream']
        spec = (fixtures or {}).get(name)
        if not spec or not spec.get('cases'):
            raise ValueError('알림 %s 에 검증 픽스처(files/alert_fixtures.yml)가 없습니다' % name)
        hosts = {}
        for case in spec['cases']:
            host = _host(case, run_id)
            hosts[host] = {'case': case['name'], 'fires': bool(case['fires']), 'known_failure': case.get('known_failure') or ''}
            for rec in case['records']:
                rec = dict(rec)
                repeat = rec.pop('repeat', 1)
                ingest.setdefault(stream, []).extend(dict(rec, host_name=host) for _ in range(repeat))
        searches.append({
            'alert': name, 'stream': _verify_stream(stream, suffix), 'row_key': spec.get('row_key', DEFAULT_ROW_KEY),
            'path': SEARCH_PATH.format(org=org), 'hosts': hosts,
            'body': {'query': {'sql': _rewrite_sql(alert['sql'], stream, suffix), 'start_time': start_us,
                               'end_time': start_us + window_us, 'from': 0, 'size': 1000}}})
    return {'ingest': [{'stream': _verify_stream(s, suffix), 'path': INGEST_PATH.format(org=org, stream=_verify_stream(s, suffix)),
                        'records': recs} for s, recs in ingest.items()],
            'searches': searches}


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


class FilterModule(object):
    def filters(self):
        return {'o2c_desired': o2c_desired, 'o2c_plan': o2c_plan, 'o2c_plan_summary': o2c_plan_summary,
                'o2c_alert_state': o2c_alert_state,
                'o2c_read_requests': o2c_read_requests, 'o2c_verify_plan': o2c_verify_plan,
                'o2c_verify_failures': o2c_verify_failures, 'o2c_verify_known': o2c_verify_known,
                'o2c_alert_history_errors': o2c_alert_history_errors}
