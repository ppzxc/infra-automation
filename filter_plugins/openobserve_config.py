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
INJECT_ID = ('pipeline',)   # the pipeline body carries its own id on update; alerts take it from the path only
SECRET_KINDS = ('destination',)                                # url and headers carry the webhook credentials


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


class FilterModule(object):
    def filters(self):
        return {'o2c_desired': o2c_desired, 'o2c_plan': o2c_plan, 'o2c_plan_summary': o2c_plan_summary,
                'o2c_alert_state': o2c_alert_state}
