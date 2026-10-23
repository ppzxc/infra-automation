"""OpenObserve configuration as code (ADR-0008, Spec #93 / Ticket-2).

Pure functions so the desired state and the change plan are unit-testable without Ansible or a server.

``o2c_desired``  builds the objects (alert template, destination, VRL function, pipeline, alerts) from the role variables.
``o2c_plan``     compares them with what the OpenObserve API returned and lists only the writes that are needed.
"""

import base64
import hashlib
import re
from urllib.parse import quote

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
    'pipeline': '/api/{org}/pipelines',   # 갱신은 PUT /pipelines(본문의 pipeline_id). /pipelines/{id}는 조회·삭제 전용이라 PUT이 405다
    'alert': '/api/v2/{org}/alerts/{key}',
    'trace_stream': '/api/{org}/streams/{key}/settings?type=traces',
}
ID_FIELD = {'pipeline': 'pipeline_id', 'alert': 'alert_id'}   # update by id; the others by name
STREAM_CHANGED = 'stream changed'   # 삭제 후 재생성의 이유(알림의 스트림 이름·종류는 PUT으로 못 바꾼다)
CONTEXT_KEYS = ('severity', 'severity_icon', 'title', 'what', 'why', 'runbook')
ACTION_SLOTS = 4   # 조치 항목 칸 수: 통지 본문이 {action_1}~{action_4}를 줄마다 하나씩 쓴다(정의의 조치는 최대 4항목)
INJECT_ID = ('pipeline',)   # the pipeline body carries its own id on update; alerts take it from the path only
MANAGED_PREFIX = 'infra-'   # 알림 이름 접두어. 서버에서 지우는 근거는 아니다: 삭제는 폐기 목록(o2c_retired_alerts)의 이름뿐이고, 접두어만 있는 알림은 건드리지 않고 알려 준다
LINK_LABEL_LOG, LINK_LABEL_METRIC = '로그 보기', '상세 보기'   # 통지 본문의 ▶ {link_label}: {alert_url}
RAW_LOG_PERIOD = '1d'   # 원문 로그 링크의 조회 구간. 웹 UI의 `period=<N><m|h|d>` 상대 구간이라 링크를 연 시점부터 거슬러 올라간다
RAW_LOG_LIMIT = 200
SECRET_KINDS = ('destination',)                               # url and headers carry the webhook credentials


_CIRCLED = re.compile('[\u2460-\u2473]')   # ①~⑳


def o2c_action_items(text):
    """``① a ② b`` -> ``{'action_1': '1. a', 'action_2': '2. b', 'action_3': '', 'action_4': ''}``: 조치를 항목마다 칸 하나로 나눈다.

    OpenObserve는 치환하는 값 안의 개행을 ``\\n`` 두 글자로 이스케이프해 text/plain 본문에 그대로 보이므로 개행은 값이 아니라 템플릿 본문에 둔다
    (``{action_1}`` ... ``{action_4}``를 줄마다 하나씩). 항목이 칸보다 적으면 남는 칸은 빈 문자열이다. ①이 없는 문장은 ``1.`` 한 줄이 된다.
    알림 정의는 한 줄(① … ② …)로 두고 렌더링 단계에서만 바꾼다.
    """
    items = [i.strip() for i in _CIRCLED.split(str(text or ''))]
    items = [i for i in items if i]
    if len(items) > ACTION_SLOTS:
        raise ValueError('action has %d items, at most %d fit the notification template' % (len(items), ACTION_SLOTS))
    return {'action_%d' % n: ('%d. %s' % (n, items[n - 1]) if n <= len(items) else '') for n in range(1, ACTION_SLOTS + 1)}


_SQL_KEYWORDS = ('select', 'from', 'where', 'group', 'having', 'order', 'limit', 'union', 'intersect', 'except', 'join', 'with', 'offset')


def _top_level_keywords(sql):
    """``[(keyword, start, end)]``: 따옴표 문자열·큰따옴표 식별자·괄호 밖(깊이 0)의 SQL 키워드 위치. 괄호 안에 SELECT가 있으면 ``('subselect', ...)``."""
    found, depth, i, n = [], 0, 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in ('\'', '"'):   # 따옴표 안은 건너뛴다(같은 따옴표 두 개는 이스케이프)
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
        elif ch == '(':
            depth += 1
            i += 1
        elif ch == ')':
            depth -= 1
            i += 1
        elif ch.isalpha() or ch == '_':
            j = i
            while j < n and (sql[j].isalnum() or sql[j] == '_'):
                j += 1
            word = sql[i:j].lower()
            if depth == 0 and word in _SQL_KEYWORDS:
                found.append((word, i, j))
            elif depth > 0 and word in ('select', 'union', 'with'):
                found.append(('subselect', i, j))
            i = j
        else:
            i += 1
    return found


def o2c_raw_log_sql(sql, stream, limit=RAW_LOG_LIMIT):
    """집계 알림 SQL에서 원문 로그 조회 SQL을 만든다: ``SELECT * FROM "<스트림>" WHERE <기존 조건> ORDER BY _timestamp DESC LIMIT N``.

    SELECT 목록·GROUP BY·HAVING은 버리고 WHERE 식은 글자 그대로 둔다. 안전하게 못 만들면 빈 문자열이다(링크 없음):
    조건(WHERE)이 없는 SQL(HAVING만으로 거르는 집계는 원문이 알림 대상을 대변하지 못한다), UNION·JOIN·WITH·서브쿼리,
    FROM이 알림 스트림 하나가 아닌 SQL.
    """
    text = ' '.join(str(sql or '').split())
    kws = _top_level_keywords(text)
    names = [k for k, _, _ in kws]
    if not names or names[0] != 'select' or names.count('select') != 1 or names.count('from') != 1 or names.count('where') != 1:
        return ''
    if any(k in names for k in ('subselect', 'union', 'intersect', 'except', 'join', 'with', 'limit', 'offset')):
        return ''
    start = {k: (a, b) for k, a, b in kws}
    from_end = start['from'][1]
    where_start, where_end = start['where']
    if from_end > where_start or text[from_end:where_start].strip() != '"%s"' % stream:
        return ''
    stops = [a for k, a, _ in kws if k in ('group', 'having', 'order') and a > where_end]
    cond = text[where_end:min(stops) if stops else len(text)].strip()
    if not cond:
        return ''
    return 'SELECT * FROM "%s" WHERE %s ORDER BY _timestamp DESC LIMIT %d' % (stream, cond, int(limit))


def o2c_raw_log_url(web_url, org, stream, sql, period=RAW_LOG_PERIOD):
    """OpenObserve 웹 UI가 원문 로그를 바로 여는 URL(단축 URL이 가리키는 `/web/logs?...` 형태).

    SQL은 UTF-8 base64(표준 알파벳)를 쿼리 문자열로 퍼센트 인코딩한다(`+`·`/`·`=`가 값 안에서 깨지지 않게). 조회 구간은 `period`
    상대값이라 from/to를 정적으로 박지 않는다.
    """
    query = quote(base64.b64encode(sql.encode('utf-8')).decode('ascii'), safe='')
    return ('%s/web/logs?stream_type=logs&stream=%s&period=%s&sql_mode=true&query=%s&org_identifier=%s&type=alerts&show_histogram=false'
            % (str(web_url).rstrip('/'), quote(stream, safe=''), period, query, quote(org, safe='')))


def o2c_short_url(web_url, org, original_url):
    """OpenObserve 단축 URL을 서버에 묻지 않고 계산한다(계획 단계는 쓰기 없이 비교해야 한다).

    서버 규칙: short_id = md5(original_url) 32자 중 가운데 16자(src/config/src/utils/md5.rs ``short_hash``),
    URL = <web_url>/web/short/<short_id>?org_identifier=<org>(src/core/src/short_url.rs). 해시 충돌 시 서버는 시각을 섞은
    다른 id를 주므로, 반영 단계(O2C-019)가 등록 응답과 이 값을 대조해 다르면 실패한다.
    """
    digest = hashlib.md5(original_url.encode('utf-8')).hexdigest()
    return '%s/web/short/%s?org_identifier=%s' % (str(web_url).rstrip('/'), digest[8:24], quote(org, safe=''))


def o2c_short_url_requests(desired, org):
    """원문 로그 링크마다 단축 URL 등록 요청(POST /api/{org}/short)을 만든다. 같은 원본이면 서버가 같은 id를 돌려준다(멱등)."""
    links = sorted({(o['short_link']['original'], o['short_link']['short']) for o in desired or [] if o.get('short_link')})
    return [{'method': 'POST', 'path': '/api/%s/short' % org, 'body': {'original_url': original}, 'expected': short}
            for original, short in links]


def _short_id(url):
    m = re.search(r'/web/short/([0-9a-f]+)', str(url or ''))
    return m.group(1) if m else None


def o2c_short_url_mismatches(results):
    """등록 응답의 단축 id가 계산값과 다르거나 요청이 실패한 항목(계산값 목록). 비어 있어야 통지 본문의 링크가 열린다.

    호스트 부분은 비교하지 않는다: 서버는 자기 ZO_WEB_URL로 답하고 통지 본문은 o2c_web_url을 쓰는데, 둘 다 같은 서버를 가리키면 링크가 열린다.
    """
    return [r['item']['expected'] for r in results or []
            if r.get('status') not in (200, 201) or _short_id((r.get('json') or {}).get('short_url')) != _short_id(r['item']['expected'])]


def _raw_log_sql(alert):
    """알림 정의가 원문 조회 SQL을 갖는가: ``raw_sql`` 직접 지정이 먼저, 없으면 로그 SQL 알림에서 파생. 메트릭·PromQL·자가 시험은 없다."""
    if alert.get('promql') or alert.get('stream_type', 'logs') != 'logs' or alert.get('raw_link') is False:   # raw_link: false는 명시적 거절(부재 알림)
        return ''
    return str(alert.get('raw_sql') or '').strip() or o2c_raw_log_sql(alert.get('sql'), alert['stream'])


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
    # 방화벽 로그(Spec #282)도 security_logs에 들어오지만 소스 스트림당 파이프라인은 하나라, 보안 로그 파이프라인에서 함수를 이어 붙인다
    # (security_semantics → fortigate_semantics). 서비스 검사는 각 함수 안에 있어 서로의 레코드를 건드리지 않는다.
    chained = []
    if spec.get('fortigate'):
        fortigate = dict(spec['fortigate'], vrl=o2c_fortigate_vrl(spec['fortigate']['vrl'], spec['fortigate'].get('aliases')))
        chained.append(fortigate)
        semantics[0]['then'] = [spec['fortigate']['function_name']]
    out += [{'kind': 'function', 'name': sem['function_name'],
             'body': {'name': sem['function_name'], 'function': sem['vrl'].strip(), 'params': 'row', 'transType': 0}}
            for sem in semantics[:1] + chained + semantics[1:]]
    out += [_pipeline(org, sem['stream'], sem['pipeline_name'], [sem['function_name']] + sem.get('then', []), sem['description'])
            for sem in semantics]
    p1_dest = spec.get('p1_destination') or dest   # 비어 있으면(기본) 모든 알림이 같은 대상이다. 값이 있으면 P1만 그 대상으로 간다
    selftest = spec.get('selftest_alert')
    for alert in list(spec['alerts']) + ([selftest] if selftest else []):
        promql = alert.get('promql')
        if promql:
            if alert.get('stream_type') != 'metrics':
                raise ValueError('PromQL 알림 %s 은(는) stream_type이 metrics여야 합니다' % alert['name'])
            # 통지 행의 {value}가 소수점 없이 나오도록 결과를 정수로 반올림한다(OpenObserve PromQL round() 지원 실측).
            # 임계 비교도 반올림 값으로 하므로 경계에서 ±0.5 차이가 날 수 있다.
            query = {'type': 'promql', 'promql': 'round(%s)' % promql,
                     'promql_condition': {'column': 'value', 'operator': alert.get('promql_operator', '>='), 'value': alert['promql_value']}}
        else:
            query = {'type': 'sql', 'sql': alert['sql']}
        trigger = {'period': alert['period'], 'operator': '>=', 'threshold': alert.get('threshold', 1),
                   'frequency': alert['frequency'], 'frequency_type': 'minutes', 'silence': alert['silence']}
        if promql:
            trigger['align_time'] = True   # 평가 시각을 frequency 경계에 맞춘다(PromQL은 시각이 어긋나면 구간 창이 달라진다)
        raw_sql = _raw_log_sql(alert) if spec.get('web_url') and alert is not selftest else ''
        raw_url = o2c_raw_log_url(spec['web_url'], org, alert['stream'], raw_sql) if raw_sql else ''
        raw_short = o2c_short_url(spec['web_url'], org, raw_url) if raw_url else ''
        out.append(dict({'kind': 'alert', 'name': alert['name'], 'body': {
            'name': alert['name'], 'stream_type': alert.get('stream_type', 'logs'), 'stream_name': alert['stream'], 'is_real_time': False,
            'query_condition': query, 'trigger_condition': trigger,
            'destinations': [p1_dest if str(alert.get('severity', '')).startswith('P1') else dest],
            'enabled': True, 'description': alert['description'],
            # 지속 조건(#318): 첫 일치 뒤 이 초만큼 조건이 이어져야 발화한다(Prometheus `for:`). 알림 최상위 필드이고 서버 기본값은 0(즉시 발화)이다.
            # 0도 항상 보낸다: 빼면 60분 → 0으로 줄인 정의가 부분집합 비교에서 같게 보여 서버에 옛 값이 남는다.
            'pending_period_sec': int(alert.get('pending_minutes') or 0) * 60,
            # 알림 평가 시각대: 최상위 tz_offset(분 단위 UTC 오프셋, trigger_condition 안이 아님 — OpenObserve 테스트 데이터 AlertMultiRealTime.json 구조)
            'tz_offset': int(spec.get('tz_offset', 0)),
            # 행동 가능한 알림: 통지 템플릿이 {severity}·{title}·{what}·{why}·{action_1}~{action_4}·{runbook}로 쓰는 알림별 변수,
            # {rows}의 한 줄 모양(대상 호스트·출발지·사용자·건수). link_label은 {alert_url}의 라벨이다(로그 알림 "로그 보기", 메트릭 알림 "상세 보기").
            'context_attributes': dict({k: alert[k] for k in CONTEXT_KEYS}, **o2c_action_items(alert['action']),
                                       link_label=LINK_LABEL_METRIC if promql or raw_sql else LINK_LABEL_LOG,
                                       # 원문 링크는 단축 URL로 싣는다(긴 base64 쿼리 대신). 등록은 반영 단계 O2C-019가 한다
                                       raw_log_line=('▶ %s: %s' % (LINK_LABEL_LOG, raw_short) if raw_short else '')),
            'row_template': alert['row_template'], 'row_template_type': 'String',
        }}, **({'short_link': {'original': raw_url, 'short': raw_short}} if raw_short else {})))
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


def _pipeline(org, stream, name, function_names, description):
    source = {'source_type': 'realtime', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    node = lambda nid, data, io, x: {'id': nid, 'data': data, 'io_type': io, 'position': {'x': x, 'y': 100}}  # noqa: E731
    stream_node = {'node_type': 'stream', 'org_id': org, 'stream_name': stream, 'stream_type': 'logs'}
    fn_nodes = [node('function' if i == 0 else 'function-%d' % (i + 1),
                     {'node_type': 'function', 'name': fn, 'after_flatten': True, 'num_args': 0}, 'default', 300 + 250 * i)
                for i, fn in enumerate(function_names)]
    chain = ['input'] + [n['id'] for n in fn_nodes] + ['output']
    body = {
        'name': name, 'description': description, 'enabled': True,
        'source': source,
        'nodes': [node('input', dict(stream_node), 'input', 50)] + fn_nodes + [node('output', dict(stream_node), 'output', 300 + 250 * len(fn_nodes))],
        'edges': [{'id': '%s-%s' % (a, b), 'source': a, 'target': b} for a, b in zip(chain, chain[1:])],
    }
    # the server rewrites ids/positions; what makes the pipeline "the same" is its source, its state and the functions it runs, in order
    match = {'name': name, 'enabled': True, 'source': {'stream_name': stream, 'source_type': 'realtime'},
             'functions': [{'name': fn, 'after_flatten': True} for fn in function_names]}
    return {'kind': 'pipeline', 'name': name, 'body': body, 'match': match}


def _items(payload):
    if isinstance(payload, dict):
        payload = payload.get('list', [])
    return [i for i in (payload or []) if isinstance(i, dict)]


def _project_pipeline(item):
    fns = [n.get('data', {}) for n in item.get('nodes', []) if n.get('data', {}).get('node_type') == 'function']
    return {'name': item.get('name'), 'enabled': item.get('enabled'), 'source': item.get('source', {}),
            'functions': [{'name': fn.get('name'), 'after_flatten': fn.get('after_flatten')} for fn in fns]}


def _subset(want, have):
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and _subset(v, have[k]) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(have, list) and len(want) == len(have) and all(_subset(w, h) for w, h in zip(want, have))
    return want == have


def o2c_read_requests(org):
    """GET list requests (``{kind, path}``) for every managed kind, from the same table the plan creates with."""
    return [{'kind': kind, 'path': LIST_PATHS[kind].format(org=org)} for kind in KINDS]


def o2c_plan(desired, existing, org, retired=()):
    """Writes needed to reach ``desired``. ``existing`` maps kind -> API payload (list or ``{"list": [...]}``).

    Each action: ``{kind, name, op (create|update|delete), method, path, body, secret}``. Nothing is returned for objects that already match.
    An alert is deleted only when it exists on the server and its name is in ``retired`` (the explicit list); the prefix alone never deletes.
    The one exception is an alert whose ``stream_name``/``stream_type`` differs from the definition: the server cannot move an alert to another
    stream with PUT, so the plan has ``recreate`` (DELETE) immediately followed by ``create`` (POST, ``reason`` = ``stream changed``) of the same name.
    """
    missing = o2c_missing_destinations(desired, existing)
    if missing:
        raise ValueError('알림 대상(destination)이 서버에도 저장소 정의에도 없습니다: %s' % ', '.join(missing))
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
            if kind == 'alert' and cur.get('alert_id') and _stream_changed(body, cur):
                # PUT은 stream_name/stream_type을 바꾸지 못해 update가 반영되지 않고 매번 계획에 남는다 → 삭제 후 재생성(항상 짝으로 계획)
                plan.append({'kind': kind, 'name': want['name'], 'op': 'recreate', 'method': 'DELETE', 'secret': False, 'body': {},
                             'reason': STREAM_CHANGED, 'path': ITEM_PATHS[kind].format(org=org, key=cur['alert_id'])})
                plan.append(dict(_action(kind, want, 'create', 'POST', LIST_PATHS[kind].format(org=org), body), reason=STREAM_CHANGED))
                continue
            if _subset(want['match'], seen):
                continue
            key = cur.get(ID_FIELD[kind]) if kind in ID_FIELD else want['name']
            if kind in INJECT_ID:
                body = dict(body, **{ID_FIELD[kind]: key})
            plan.append(_action(kind, want, 'update', 'PUT', ITEM_PATHS[kind].format(org=org, key=key), body))
    # 삭제는 명시적 폐기 목록에 있는 알림뿐이다. 접두어(infra-)만 보고 지우면 다른 곳에서 만든 알림까지 지운다(사고)
    retired = set(retired or ()) - {a['name'] for a in plan if a['op'] == 'recreate'}
    for cur in _items(existing.get('alert')):
        name = cur.get('name') or ''
        if name in retired and cur.get('alert_id'):
            plan.append({'kind': 'alert', 'name': name, 'op': 'delete', 'method': 'DELETE', 'secret': False, 'body': {},
                         'path': ITEM_PATHS['alert'].format(org=org, key=cur['alert_id'])})
    return plan


def _stream_changed(body, cur):
    """True when the server alert reports a stream (name or type) other than the definition's. A field the server did not report is not a difference."""
    return any(k in cur and cur[k] != body.get(k) for k in ('stream_name', 'stream_type'))


def o2c_missing_destinations(desired, existing):
    """Sorted destination names that alerts use but neither the repository (the managed destination) nor the server has.

    Matters for the optional P1 destination (``o2c_p1_destination``): it is only a name, so an alert that points at a
    destination nobody created would be rejected by the server midway through the writes; this fails the plan first.
    """
    known = {d['name'] for d in desired if d['kind'] == 'destination'} | {i.get('name') for i in _items(existing.get('destination'))}
    used = {n for d in desired if d['kind'] == 'alert' for n in d['body'].get('destinations') or []}
    return sorted(used - known)


def o2c_unmanaged_alerts(desired, existing, retired=()):
    """Sorted names of ``infra-`` alerts on the server that are neither defined in the repository nor retired: kept untouched, only reported."""
    known = {d['name'] for d in desired if d['kind'] == 'alert'} | set(retired or ())
    return sorted({i.get('name') for i in _items(existing.get('alert'))
                   if str(i.get('name') or '').startswith(MANAGED_PREFIX) and i.get('name') not in known})


_RETIRED_RE = re.compile(r'^infra-[a-z0-9-]+$')


def o2c_valid_retired_alerts(names):
    """True when ``names`` is a list of ``infra-`` alert names (``^infra-[a-z0-9-]+$``) without duplicates."""
    return (isinstance(names, (list, tuple)) and all(isinstance(n, str) and _RETIRED_RE.match(n) for n in names)
            and len(set(names)) == len(names))


def o2c_retired_conflicts(retired, current_names):
    """Retired names that are also current alert definitions (deleting them would remove a live alert)."""
    return sorted(set(retired or ()) & set(current_names or ()))


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
    lines = []
    for a in plan:
        if a['op'] == 'recreate':   # 삭제와 재생성이 한 쌍이다: 한 줄로 보이고, 짝인 create는 따로 적지 않는다
            lines.append('recreate %s %s (%s)' % (a['kind'], a['name'], a['reason']))
        elif not (a['op'] == 'create' and a.get('reason')):
            lines.append('%s %s %s' % (a['op'], a['kind'], a['name']))
    return lines


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
import json
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


_SAFE_HOST_NAME = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
_SAFE_ADDRESS = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')   # IPv4·IPv6·호스트 이름. 알림 SQL에 문자열로 들어가므로 따옴표·공백 등은 받지 않는다


def _host_kv(name, raw):
    """OpenBao ``hosts/<host>`` 본문을 평면 dict로 푼다(resolve_connection.yml과 같은 규칙: 호스트명 키 → 키가 하나뿐인 오브젝트 → 평면)."""
    if not isinstance(raw, dict):
        return {}
    if isinstance(raw.get(name), dict):
        return raw[name]
    if len(raw) == 1 and isinstance(next(iter(raw.values())), dict):
        return next(iter(raw.values()))
    return raw


# host_agents.host_agents_tcpcheck_targets의 KV 주소 우선순위와 같아야 한다(tests가 두 쪽이 어긋나지 않는지 본다)
KV_ADDRESS_KEYS = ('ansible_host', 'public_ip', 'ip', 'host')


def o2c_host_addresses(roster, kv_by_host):
    """``{호스트: 접속 주소}`` — 도달성 검사 대상(``host_agents_tcpcheck_targets``)과 같은 우선순위로 고른다: KV ``ansible_host`` → ``public_ip`` → ``ip`` → ``host``.

    주소가 없거나 SQL에 안전하지 않은 값이면 그 호스트는 빠진다(알림에는 관리번호만 보인다). 짐작해서 채우지 않는다.
    """
    out = {}
    for name in roster or []:
        if not _SAFE_HOST_NAME.match(str(name)):
            continue
        kv = _host_kv(name, (kv_by_host or {}).get(name))
        address = next((str(v).strip() for v in (kv.get(k) for k in KV_ADDRESS_KEYS) if v is not None and str(v).strip()), '')
        if _SAFE_ADDRESS.match(address):
            out[name] = address
    return out


def o2c_host_label(column, addresses):
    """알림 SQL의 서버 행 표시 이름 컬럼: ``CASE <column> WHEN '<호스트>' THEN '<호스트> (<주소>)' … ELSE <column> END AS host_label``.

    주소 표는 Config 실행 때 OpenBao에서 읽어 SQL에 고정한다(알림이 울릴 때는 OpenBao에 접속하지 않는다). 표가 비면 관리번호 그대로다.
    """
    if column not in ('host_name', 'host'):
        raise ValueError('표시 이름 컬럼은 host_name 또는 host여야 합니다: %s' % column)
    pairs = sorted((h, a) for h, a in (addresses or {}).items() if _SAFE_HOST_NAME.match(str(h)) and _SAFE_ADDRESS.match(str(a)))
    if not pairs:
        return '%s AS host_label' % column
    whens = ' '.join("WHEN '%s' THEN '%s (%s)'" % (h, h, a) for h, a in pairs)
    return 'CASE %s %s ELSE %s END AS host_label' % (column, whens, column)


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


def o2c_missing_sql(hosts, stream, field, cond, body_match=False, field_column=True):
    """One row per roster host without a record matching ``cond`` (e.g. no successful backup) in the alert window.

    ``field`` is the stream's host column (``host`` for backup_logs, ``host_name`` elsewhere). Same UNION ALL branch shape as
    the Silent Host SQL; an empty roster yields a branch that can never return a row.

    ``body_match``: a record also counts for the host when its raw ``body`` names the host (``lower(body) LIKE '% <host>%'``; a string
    such as ``devname`` matches the key's value instead: ``lower(body) LIKE '%devname="<host>%'``). A host ``a+b`` is an HA pair: either member counts.
    ``field`` only exists on records the ingest pipeline already processed, so without this the first evaluation after a pipeline
    change sees no data for any host and reports every host as silent.

    ``field_column=False``: ``field`` is only the output column alias and the WHERE clause never reads it (needs ``body_match``).
    Use it when the column may not exist yet (it is created by the first processed record); referencing a missing column makes
    every evaluation fail.
    """
    if not _HOST_RE.match(field):
        raise ValueError('SQL에 넣을 수 없는 필드 이름: %s' % field)
    if not field_column and not body_match:
        raise ValueError('field_column=False에는 body_match가 필요하다')
    if not hosts:
        return 'SELECT \'none\' AS %s, count(*) AS n FROM "%s" WHERE %s HAVING count(*) < 0' % (field, stream, cond)

    def who(h):
        # `a+b`는 HA 멤버 쌍이다: 어느 한쪽이라도 보내면 수신 중이다(대기 멤버는 평소 조용하고 장애 전환 뒤에는 반대가 된다)
        members = h.split('+')
        conds = ["%s = '%s'" % (field, m) for m in members] if field_column else []
        if body_match:
            for m in members:
                # True: 스위치 syslog 머리말(`... ns0250-3750X:`)에서 `' <호스트>'`. 문자열: 그 키의 값(`devname="ns0399"`, 따옴표 없는 `devname=ns0399`도)
                prefixes = [' '] if body_match is True else ['%s="' % body_match, '%s=' % body_match]
                conds += ["lower(body) LIKE '%%%s%s%%'" % (prefix, m.lower()) for prefix in prefixes]
        return '(%s)' % ' OR '.join(conds) if len(conds) > 1 else conds[0]

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
        if alert.get('promql'):
            continue   # PromQL 알림은 합성 레코드로 검증하지 않는다(메트릭 스트림에 넣지 않는다). 평가 오류는 O2C-036이 본다
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
                if isinstance(rec.get('body'), str):
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
            sql = o2c_missing_sql(roster, stream, missing['field'], missing['cond'], missing.get('body_match') or False,
                                 missing.get('field_column', True))
        if absence:
            roster = list((rosters or {}).get(absence['roster']) or []) + sorted(h for h, exp in hosts.items() if not exp['off_roster'])
            sql = o2c_absence_sql(roster, stream, absence['level'])
        if alert.get('uplinks') is not None:
            # 업링크 목록(장비, 포트)에 케이스의 가짜 장비를 `watch_port`로 더해 "목록에 있으면 발화, 없으면 발화하지 않음"을 검증한다
            watched = list(alert['uplinks'] or []) + [{'device': _host(c, run_id), 'port': c['watch_port']}
                                                      for c in spec['cases'] if c.get('watch_port') and _host(c, run_id) in hosts]
            sql = o2c_switch_uplink_sql(watched, alert.get('noise_events'), alert.get('extra_columns', ''))
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


def o2c_switch_uplink_sql(entries, noise_events=None, extra_columns=''):
    """SQL of the uplink-down alert: a link/line-protocol message saying ``down`` (or ``administratively down``) for a listed (device, port).

    The port is matched in ``body`` (``Interface <name>, changed state to down``) so the query needs no port column. The trailing
    comma keeps ``Gi1/0/1`` from matching ``Gi1/0/10``. ``extra_columns`` (e.g. the event time column) is appended to the SELECT list. An empty list yields a condition that can never be true.
    """
    pairs = []
    for e in entries or []:
        name = _canonical_interface(str(e['port'])).lower()
        down, admin = ("lower(body) LIKE %s" % _q('%%interface %s, changed state to %s%%' % (name, tail)) for tail in ('down', 'administratively down'))
        pairs.append('(device_id = %s AND (%s OR %s))' % (_q(e['device']), down, admin))
    return ('SELECT coalesce(device_id, device_name) AS device, '
            "regexp_replace(body, '^.*[Ii]nterface ([^ ,]+),.*$', '\\1') AS port, count(*) AS downs%s FROM \"system_logs\" "
            "WHERE service_name = 'switch-syslog' AND event_name IN (%s)%s AND (%s) GROUP BY device, port ORDER BY downs DESC") % (
        (', ' + extra_columns) if extra_columns else '', ', '.join(_q(ev) for ev in UPLINK_EVENTS), o2c_switch_noise_filter(noise_events), ' OR '.join(pairs) if pairs else '1 = 0')


# --- 방화벽(포티게이트) 알림 (Spec #282 / Ticket-3) ---------------------------------------------------------------------
# 방화벽 줄은 security_logs에 service_name=fortigate-syslog로 들어온다. 이 스트림에는 첫 방화벽 줄이 들어오기 전까지 방화벽 컬럼
# (device_id, fortigate_log_subtype ...)이 없으므로 알림 SQL은 service_name과 원문 body의 key=value만 읽는다(없는 컬럼은 평가 오류가 된다).
# FortiOS 기본 형식은 값을 따옴표로 감싸지만 실장비 샘플로 확인하기 전이라 따옴표 있는 값과 없는 값을 모두 받는다.
_KEY_RE = _re.compile(r'^[a-z][a-z0-9_]*$')
_LOGID_RE = _re.compile(r'^[0-9]+$')
_VALUE_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
# 수신 중단 감시 목록 항목: 관리번호(ns0399) 또는 장비 이름 그대로(hostname을 관리번호로 못 바꾼 장비). `+`로 HA 멤버를 묶는다.
# SQL LIKE에 들어가므로 따옴표·%·공백은 막는다(`_`는 LIKE에서 한 글자 와일드카드지만 더 넓게 맞출 뿐이다).
_FORTIGATE_NAME = r'[A-Za-z0-9][A-Za-z0-9_-]*'
_FORTIGATE_MEMBER_RE = _re.compile(r'^%s(\+%s)*$' % (_FORTIGATE_NAME, _FORTIGATE_NAME))
_FORTIGATE_ALIAS_KEY_RE = _re.compile(r'^[a-z0-9][a-z0-9_-]*$')   # 소문자 정규화한 devname(도메인 제외)
_FORTIGATE_ALIAS_VALUE_RE = _re.compile(r'^ns[0-9]+$')
_FORTIGATE_ALIAS_MARKER_RE = _re.compile(r'^device_aliases = \{\}.*$', _re.M)


def o2c_valid_fortigate_values(values):
    """True when every item is safe to put in a ``key=value`` match (letters, digits, ``.``, ``_``, ``-``)."""
    return all(isinstance(v, str) and _VALUE_RE.match(v) for v in values or [])


def o2c_valid_fortigate_roster(devices):
    """True when every item is a management number (``ns0399``), a device name as sent in ``devname`` or an HA pair joined with ``+`` (``ns0380+ns0381``)."""
    return all(isinstance(d, str) and _FORTIGATE_MEMBER_RE.match(d) for d in devices or [])


def o2c_valid_fortigate_aliases(aliases):
    """True when ``aliases`` maps normalized device names (lower case, no domain) to management numbers (``ns`` + digits)."""
    if aliases is None:
        return True
    return isinstance(aliases, dict) and all(
        isinstance(k, str) and isinstance(v, str) and _FORTIGATE_ALIAS_KEY_RE.match(k) and _FORTIGATE_ALIAS_VALUE_RE.match(v) for k, v in aliases.items())


def o2c_fortigate_vrl(source, aliases):
    """The firewall VRL with the alias table written into its ``device_aliases = {}`` line (an empty table leaves the source as is)."""
    if not aliases:
        return source
    if not o2c_valid_fortigate_aliases(aliases):
        raise ValueError('방화벽 장비 이름 별칭 형식이 올바르지 않다')
    if not _FORTIGATE_ALIAS_MARKER_RE.search(source):
        raise ValueError('VRL 소스에 `device_aliases = {}` 줄이 없다')
    literal = json.dumps(dict(sorted(aliases.items())))   # JSON 객체는 VRL 객체 리터럴이다(키·값은 위에서 안전한 문자만 허용)
    return _FORTIGATE_ALIAS_MARKER_RE.sub(lambda _m: 'device_aliases = %s' % literal, source, count=1)


def o2c_fortigate_match(key, values):
    """``(body LIKE '% key="v"%' OR body LIKE '% key=v %' ...)`` — the line has ``key`` set to one of ``values`` (quoted or bare)."""
    if not _KEY_RE.match(str(key)) or not values or not o2c_valid_fortigate_values(values):
        raise ValueError('방화벽 로그 조건에 넣을 수 없는 키 또는 값: %s' % key)
    parts = []
    for v in values:
        parts += ["body LIKE '%% %s=\"%s\"%%'" % (key, v), "body LIKE '%% %s=%s %%'" % (key, v)]
    return '(%s)' % ' OR '.join(parts)


def o2c_valid_fortigate_logids(logids):
    """True when ``logids`` is a list of digit strings (a FortiOS ``logid``), safe to put in a ``NOT LIKE`` condition."""
    return isinstance(logids, (list, tuple)) and all(isinstance(v, str) and _LOGID_RE.match(v) for v in logids)


def o2c_fortigate_exclude_logids(logids):
    """`` AND body NOT LIKE '%logid="<id>"%' ...`` for each logid ('' when the list is empty) — lines of these logids are left out of the count."""
    if not o2c_valid_fortigate_logids(logids or []):
        raise ValueError('방화벽 로그 조건에 넣을 수 없는 logid')
    return ''.join(" AND body NOT LIKE '%%logid=\"%s\"%%'" % v for v in logids or [])


# --- 보안 로그 알림의 문구 목록 (#318) ---------------------------------------------------------------------------------
# 위험 명령 sudo 알림은 sudo 명령 줄(process_command_line, 소문자)에 목록의 문구가 들어 있는지 LIKE로 본다. 목록은 역할 변수이고
# SQL에 들어가므로 문구는 소문자·숫자·공백·`.`·`_`·`/`·`=`·`-`만, 라벨은 따옴표·역슬래시·%가 없는 글자만 허용한다(O2C-002에서 검증).
_LIKE_PATTERN_RE = _re.compile(r'^[a-z0-9 ._/=-]+$')
_LIKE_LABEL_RE = _re.compile(r'^[^\'"\\%\n]+$')
_GROUP_NAME_RE = _re.compile(r'^[a-z_][a-z0-9_-]*$')
SERVICE_STOP_VERBS = ('systemctl stop %s', 'systemctl disable %s', 'systemctl disable --now %s', 'systemctl mask %s',
                      'systemctl kill %s', 'service %s stop')


def o2c_valid_like_groups(groups):
    """True when ``groups`` is a list of ``{label, patterns}`` with safe labels and lower-case LIKE phrases (no quote, no ``%``)."""
    return isinstance(groups, (list, tuple)) and all(
        isinstance(g, dict) and isinstance(g.get('label'), str) and _LIKE_LABEL_RE.match(g['label'])
        and isinstance(g.get('patterns'), (list, tuple)) and g['patterns']
        and all(isinstance(p, str) and _LIKE_PATTERN_RE.match(p) for p in g['patterns']) for g in groups)


def o2c_valid_group_names(names):
    """True when every item is a Unix group or service name (lower case letters, digits, ``_``, ``-``)."""
    return isinstance(names, (list, tuple)) and all(isinstance(n, str) and _GROUP_NAME_RE.match(n) for n in names)


def o2c_sudo_risky_groups(groups, services, label):
    """The risky command groups plus one group (``label``) that stops, disables or masks each protected service."""
    if not o2c_valid_group_names(services):
        raise ValueError('보호 서비스 이름 형식이 올바르지 않다')
    extra = [{'label': label, 'patterns': [verb % s for s in services for verb in SERVICE_STOP_VERBS]}] if services else []
    out = list(groups or []) + extra
    if not o2c_valid_like_groups(out):
        raise ValueError('위험 명령 목록 형식이 올바르지 않다')
    return out


def o2c_like_any(groups, column):
    """``(lower(<column>) LIKE '%p1%' OR ...)`` over every phrase of every group."""
    if not _GROUP_NAME_RE.match(column) or not o2c_valid_like_groups(groups):
        raise ValueError('LIKE 조건에 넣을 수 없는 열 또는 문구')
    return '(%s)' % ' OR '.join("lower(%s) LIKE '%%%s%%'" % (column, p) for g in groups for p in g['patterns'])


def o2c_like_label(groups, column):
    """``CASE WHEN <group 1 phrases> THEN '<label 1>' ... ELSE '기타' END``: which group a line matched (first match wins)."""
    if not _GROUP_NAME_RE.match(column) or not o2c_valid_like_groups(groups):
        raise ValueError('LIKE 조건에 넣을 수 없는 열 또는 문구')
    whens = ' '.join("WHEN %s THEN '%s'" % (o2c_like_any([g], column), g['label']) for g in groups)
    return 'CASE %s ELSE \'기타\' END' % whens


def o2c_enabled_alerts(alerts):
    """The alerts that are created: an alert whose ``enabled`` renders false (e.g. the uplink alert with an empty port list) is left out."""
    return [a for a in alerts or [] if str(a.get('enabled', True)).strip().lower() not in ('false', '0', '')]


class FilterModule(object):
    def filters(self):
        return {'o2c_action_items': o2c_action_items, 'o2c_desired': o2c_desired, 'o2c_plan': o2c_plan, 'o2c_missing_destinations': o2c_missing_destinations, 'o2c_unmanaged_alerts': o2c_unmanaged_alerts,
                'o2c_valid_retired_alerts': o2c_valid_retired_alerts, 'o2c_retired_conflicts': o2c_retired_conflicts, 'o2c_plan_summary': o2c_plan_summary,
                'o2c_alert_state': o2c_alert_state, 'o2c_raw_log_sql': o2c_raw_log_sql, 'o2c_raw_log_url': o2c_raw_log_url, 'o2c_short_url': o2c_short_url, 'o2c_short_url_requests': o2c_short_url_requests, 'o2c_short_url_mismatches': o2c_short_url_mismatches, 'o2c_as_requests': o2c_as_requests, 'o2c_verify_pending': o2c_verify_pending, 'o2c_resource_sql': o2c_resource_sql,
                'o2c_read_requests': o2c_read_requests, 'o2c_verify_plan': o2c_verify_plan,
                'o2c_verify_failures': o2c_verify_failures, 'o2c_verify_known': o2c_verify_known,
                'o2c_alert_history_errors': o2c_alert_history_errors,
                'o2c_valid_fortigate_logids': o2c_valid_fortigate_logids, 'o2c_fortigate_exclude_logids': o2c_fortigate_exclude_logids,
                'o2c_roster': o2c_roster, 'o2c_valid_exceptions': o2c_valid_exceptions,
                'o2c_without_exceptions': o2c_without_exceptions, 'o2c_absence_sql': o2c_absence_sql,
                'o2c_missing_sql': o2c_missing_sql, 'o2c_app_telemetry_roster': o2c_app_telemetry_roster,
                'o2c_host_items': o2c_host_items, 'o2c_host_addresses': o2c_host_addresses, 'o2c_host_label': o2c_host_label,
                'o2c_valid_switch_events': o2c_valid_switch_events, 'o2c_valid_switch_roster': o2c_valid_switch_roster,
                'o2c_valid_switch_uplinks': o2c_valid_switch_uplinks, 'o2c_switch_noise_filter': o2c_switch_noise_filter,
                'o2c_switch_uplink_sql': o2c_switch_uplink_sql, 'o2c_enabled_alerts': o2c_enabled_alerts,
                'o2c_valid_fortigate_values': o2c_valid_fortigate_values, 'o2c_valid_fortigate_aliases': o2c_valid_fortigate_aliases,
                'o2c_fortigate_vrl': o2c_fortigate_vrl, 'o2c_valid_fortigate_roster': o2c_valid_fortigate_roster,
                'o2c_fortigate_match': o2c_fortigate_match,
                'o2c_valid_like_groups': o2c_valid_like_groups, 'o2c_valid_group_names': o2c_valid_group_names,
                'o2c_sudo_risky_groups': o2c_sudo_risky_groups, 'o2c_like_any': o2c_like_any, 'o2c_like_label': o2c_like_label}
