#!/usr/bin/python
# -*- coding: utf-8 -*-
# 이 role 전용 모듈이라 FQCN이 없다(role의 library/에서 자동으로 찾는다).
# ansible.builtin.uri를 loop로 돌리면 항목마다 모듈 프로세스를 새로 띄워(약 0.4초) 알림 수에 비례해 느려진다.
# 이 모듈은 요청 목록을 한 번의 실행으로 보낸다: 결과는 uri loop의 results(item/status/json)와 같은 모양이다.
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: o2c_http
short_description: Send a list of JSON HTTP requests to OpenObserve in one module run
description:
  - Sends C(requests) in order, or in parallel with C(parallel=true) (reads and searches only). Returns C(results) in request order.
  - In check mode only GET requests are sent; others are returned as C(skipped).
options:
  base_url: {description: URL prefix for every request path, type: str, required: true}
  requests:
    description: List of C({path, method, body, label, item}). C(item) is returned untouched; C(label) names the request in failures.
    type: list
    elements: dict
    required: true
  headers: {description: HTTP headers (hidden from logs), type: dict, default: {}}
  status_code: {description: Statuses that count as success, type: list, elements: int, default: [200]}
  fail_on_status: {description: Fail on the first status outside status_code; when false the status is only recorded, type: bool, default: true}
  parallel: {description: Send requests concurrently (results keep request order), type: bool, default: false}
  timeout: {description: Seconds per request, type: int, default: 15}
  validate_certs: {description: Validate TLS certificates, type: bool, default: true}
  ca_path: {description: CA bundle path, type: path}
author: infra-automation
'''

EXAMPLES = r'''
- o2c_http:
    base_url: "https://o2.example"
    headers: "{{ o2c_auth_headers }}"
    requests: "{{ items | o2c_as_requests(path='/api/v2/default/alerts/{alert_id}') }}"
    parallel: true
'''

RETURN = r'''
results:
  description: One entry per request in order - C(item), C(status) (-1 on a connection failure), C(json) when the body is JSON, C(skipped) in check mode.
  returned: always
  type: list
'''

import json
from concurrent.futures import ThreadPoolExecutor

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import open_url


def _send(params, headers, req):
    """One request -> ``{item, status[, json]}``. Never raises: failures become status codes (-1 = no HTTP answer)."""
    result = {'item': req.get('item')}
    body = req.get('body')
    hdrs = dict(headers)
    data = None
    if body is not None:
        data = json.dumps(body)
        hdrs.setdefault('Content-Type', 'application/json')
    try:
        resp = open_url(params['base_url'] + req['path'], method=req.get('method') or 'GET', data=data, headers=hdrs,
                        timeout=params['timeout'], validate_certs=params['validate_certs'], ca_path=params.get('ca_path'))
        status, raw = resp.getcode(), resp.read()
    except HTTPError as e:
        status, raw = e.code, e.read()
    except Exception:   # 연결 거부·시간 초과 등 — 응답이 없다
        return dict(result, status=-1)
    result['status'] = status
    try:
        result['json'] = json.loads(raw.decode('utf-8')) if raw and raw.strip() else {}
    except ValueError:
        pass
    return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            base_url=dict(type='str', required=True),
            requests=dict(type='list', elements='dict', required=True),
            headers=dict(type='dict', default={}, no_log=True),
            status_code=dict(type='list', elements='int', default=[200]),
            fail_on_status=dict(type='bool', default=True),
            parallel=dict(type='bool', default=False),
            timeout=dict(type='int', default=15),
            validate_certs=dict(type='bool', default=True),
            ca_path=dict(type='path'),
        ),
        supports_check_mode=True,
    )
    p = module.params
    reqs = p['requests']
    send = [r for r in reqs if not module.check_mode or (r.get('method') or 'GET').upper() == 'GET']
    if p['parallel'] and len(send) > 1:
        with ThreadPoolExecutor(max_workers=min(len(send), 8)) as pool:
            done = list(pool.map(lambda r: _send(p, p['headers'], r), send))
    else:
        done = []
        for r in send:   # 쓰기는 순서가 의미가 있어 앞 요청이 실패하면 뒤 요청을 보내지 않는다
            res = _send(p, p['headers'], r)
            done.append(res)
            if p['fail_on_status'] and res['status'] not in p['status_code']:
                break
    by_id = {id(r): d for r, d in zip(send, done)}
    results = [by_id.get(id(r), {'item': r.get('item'), 'status': None, 'skipped': True}) for r in reqs]
    if p['fail_on_status']:
        for r, res in zip(reqs, results):
            if not res.get('skipped') and res['status'] not in p['status_code']:
                code = 'no response' if res['status'] == -1 else 'HTTP %s' % res['status']
                module.fail_json(msg='%s: %s %s' % (code, (r.get('method') or 'GET').upper(), r.get('label') or r['path']), results=results)
    module.exit_json(changed=False, results=results)


if __name__ == '__main__':
    main()
