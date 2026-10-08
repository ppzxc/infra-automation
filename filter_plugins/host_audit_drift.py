"""Configuration Drift for Host Audit (ADR-0009 §1, #124).

Configuration Drift is the difference between the state Git declares for a host
(provisioning ``site.yml`` and Host Agents Config) and the state it actually has.
The runner re-runs those playbooks with ``--check --diff`` and the
``ansible.posix.json`` stdout callback; every declared task that *would change*
a host is one Drift row.

The callback output carries the raw diff (before/after file contents), which can
hold secrets. Nothing here copies diff text: a row keeps only the SPEC-ID, the
task name and a summary made of paths, changed attribute names and line counts.

Public entry points (pure functions, no I/O):
  host_audit_drift_plan     audit records -> which hosts each sub-run checks
  host_audit_drift_parse    one sub-run's callback JSON -> per-host result
  host_audit_drift_section  plan + parsed sub-runs -> report section model
"""

import difflib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from raw_provisioning import raw_classify_os_path  # noqa: E402

SECTION = 'Configuration Drift'
UNAVAILABLE_LABEL = '점검불가'

# Sub-runs: key -> (label, playbook and arguments shown in the report).
SUBRUNS = {
    'site': ('프로비저닝 (site.yml)', 'site.yml --check --diff'),
    'agents': ('Host Agents Config', 'host_agents.yml --tags agents_config --check --diff'),
}
SUBRUN_ORDER = ('site', 'agents')

HOST_OK = 'ok'
HOST_UNREACHABLE = 'unreachable'
HOST_FAILED = 'failed'
HOST_NO_RESULT = 'no_result'
HOST_LABELS = {
    HOST_UNREACHABLE: '점검불가(접속 실패)',
    HOST_FAILED: '점검불가(점검 중 오류)',
    HOST_NO_RESULT: '점검불가(결과 없음)',
}

REASON_RAW = ('Raw Provisioning Path(CentOS 6/7) 호스트 — raw 태스크는 --check에서 스킵되므로 '
              'Drift를 판정할 수 없음 (ADR-0005)')
REASON_NOT_COLLECTED = 'Host Audit 수집 단계에서 점검불가인 호스트라 Drift 점검 대상에서 제외'
REASON_OUT_OF_SCOPE = '선언 범위 밖'

SPEC_ID_RE = re.compile(r'\[([A-Z][A-Z0-9]*-[A-Z0-9]+(?:-[A-Z0-9]+)*)\]')
ROLE_PREFIX_RE = re.compile(r'^[\w.-]+ : ')
MAX_PATHS = 3
MAX_REASON = 200


def _first_line(text, limit=MAX_REASON):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def _is_raw_path(record, declared):
    """Same decision as playbooks/common/detect_raw_path.yml: an explicit
    inventory ``raw_provisioning_path`` wins over /etc/redhat-release detection."""
    if declared not in (None, '', 'None'):
        if isinstance(declared, bool):
            return declared
        return str(declared).strip().lower() in ('1', 'true', 'yes', 'on')
    release = ((record or {}).get('os') or {}).get('redhat_release') or ''
    return raw_classify_os_path(release) != 'modern'


def host_audit_drift_plan(records, site_scope, agents_scope, raw_declared=None):
    """Decide which hosts each Drift sub-run checks.

    ``records``: the run's per-host audit records. ``site_scope`` /
    ``agents_scope``: audit targets the playbook declares state for
    (site.yml: servers/loadbalancers; Host Agents: servers minus Host Agents
    Exclusion). ``raw_declared``: {host: inventory raw_provisioning_path}.

    Hosts not inspected by the audit and Raw Provisioning Path hosts are never
    sent to a sub-run; they are reported as not inspectable with the reason.
    """
    raw_declared = raw_declared or {}
    by_host = {r.get('inventory_hostname'): r for r in (records or []) if r.get('inventory_hostname')}
    site_scope, agents_scope = set(site_scope or []), set(agents_scope or [])
    plan = {'site': [], 'agents': [], 'excluded': {}}
    for host in sorted(site_scope | agents_scope):
        record = by_host.get(host)
        if not record or record.get('status') != 'ok':
            plan['excluded'][host] = REASON_NOT_COLLECTED
            continue
        if _is_raw_path(record, raw_declared.get(host)):
            plan['excluded'][host] = REASON_RAW
            continue
        if host in site_scope:
            plan['site'].append(host)
        if host in agents_scope:
            plan['agents'].append(host)
    return plan


def _line_counts(before, after):
    added = removed = 0
    for line in difflib.ndiff(str(before).splitlines(), str(after).splitlines()):
        if line.startswith('+ '):
            added += 1
        elif line.startswith('- '):
            removed += 1
    return added, removed


ANSIBLE_TMP_RE = re.compile(r'/ansible-(local|tmp)-|/\.ansible/tmp/')


def _clean_header(header):
    header = re.sub(r' \((content|file attributes)\)$', '', str(header or '').strip())
    if ANSIBLE_TMP_RE.search(header):
        # template on a missing destination: the only header is the controller's rendered temp file.
        return '새 파일(템플릿 %s)' % os.path.basename(header)
    return header


def _diff_entries(result):
    """Yield the diff dicts of a result, including those of loop items that changed."""
    items = result.get('results')
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get('changed'):
                for entry in _as_list(item.get('diff')):
                    yield entry
    for entry in _as_list(result.get('diff')):
        yield entry


def _as_list(value):
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else []


def summarize_diff(result):
    """Summarize a changed result without any diff content: paths touched,
    names of attributes that change and added/removed line counts."""
    if result.get('_ansible_no_log') or 'censored' in result:
        return '비공개(no_log) — 변경 예정, 내용 미표시'
    paths, attrs = [], set()
    added = removed = 0
    prepared = False
    for entry in _diff_entries(result):
        if not isinstance(entry, dict):
            continue
        # before_header is the managed path; for template the after_header is the controller's
        # rendered temp file, which means nothing to the reader.
        header = _clean_header(entry.get('before_header') or entry.get('after_header'))
        if header and header not in paths:
            paths.append(header)
        before, after = entry.get('before'), entry.get('after')
        if isinstance(before, dict) or isinstance(after, dict):
            before, after = before or {}, after or {}
            attrs.update(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        elif before is not None or after is not None:
            a, r = _line_counts(before or '', after or '')
            added, removed = added + a, removed + r
        if entry.get('prepared'):
            prepared = True
    parts = []
    if paths:
        shown = ', '.join(paths[:MAX_PATHS])
        parts.append(shown + (' 외 %d개' % (len(paths) - MAX_PATHS) if len(paths) > MAX_PATHS else ''))
    if added or removed:
        parts.append('+%d/-%d줄' % (added, removed))
    if attrs:
        parts.append('속성: ' + ', '.join(sorted(attrs)))
    if prepared and not (added or removed):
        parts.append('변경 예정(모듈 요약)')
    items = result.get('results')
    if isinstance(items, list):
        changed = sum(1 for i in items if isinstance(i, dict) and i.get('changed'))
        parts.append('반복 %d/%d건 변경' % (changed, len(items)))
    return ' · '.join(parts) or '변경 예정(diff 없음)'


def _task_identity(task):
    name = ROLE_PREFIX_RE.sub('', str(task.get('name') or '')).strip()
    match = SPEC_ID_RE.search(name)
    spec_id = match.group(1) if match else ''
    title = SPEC_ID_RE.sub('', name, count=1).strip() if match else name
    return spec_id, title


def _ignored(spec_id, title, ignore):
    for rule in ignore or []:
        if not isinstance(rule, dict):
            continue
        if rule.get('spec_id') and rule['spec_id'] == spec_id:
            return rule
        if rule.get('task') and rule['task'] == title:
            return rule
    return None


def _load(callback_json):
    if isinstance(callback_json, dict):
        return callback_json
    text = str(callback_json or '')
    # Other callbacks share stdout: warnings can precede the document and the timer
    # callback's recap follows it. The document starts with a '{' at a line start.
    match = re.search(r'(?m)^\{', text)
    if not match:
        raise ValueError('no JSON document in the callback output')
    doc, _ = json.JSONDecoder().raw_decode(text, match.start())
    if not isinstance(doc, dict):
        raise ValueError('callback output is not a JSON object')
    return doc


def host_audit_drift_parse(callback_json, hosts, declared_plays, ignore=None):
    """Parse one sub-run's ``ansible.posix.json`` output into per-host results.

    Only tasks of ``declared_plays`` (the plays that apply declared state) make
    Drift rows; tasks in other plays (connection resolution, cleanup) only
    count when they fail or cannot reach a host. Handler results are the
    consequence of a changed task, not Drift of their own, and are skipped.
    ``ignore``: [{spec_id | task, reason}] — check-mode noise exclusions; a
    matching row is kept aside as excluded with its reason.

    Returns {'status': 'ok'|'error', 'reason', 'hosts': {host: {status, reason,
    rows, excluded}}}. A document that cannot be parsed is a sub-run error.
    """
    try:
        doc = _load(callback_json)
        plays = doc.get('plays') or []
    except (ValueError, AttributeError) as exc:
        return {'status': 'error', 'reason': '결과 해석 실패: %s' % _first_line(exc), 'hosts': {}}
    declared_plays = set(declared_plays or [])
    out = {h: {'status': HOST_NO_RESULT, 'reason': '', 'rows': [], 'excluded': []} for h in hosts or []}
    seen = set()
    for play in plays:
        play_name = ((play.get('play') or {}).get('name') or '').strip()
        declared = play_name in declared_plays
        for task in play.get('tasks') or []:
            info = task.get('task') or {}
            is_handler = '/handlers/' in str(info.get('path') or '')
            spec_id, title = _task_identity(info)
            for host, result in (task.get('hosts') or {}).items():
                if host not in out or not isinstance(result, dict):
                    continue
                entry = out[host]
                if declared:
                    seen.add(host)
                if result.get('unreachable'):
                    entry['status'] = HOST_UNREACHABLE
                    entry['reason'] = _first_line(result.get('msg')) or '접속 실패'
                    continue
                if result.get('failed') and not result.get('ignore_errors'):
                    if entry['status'] != HOST_UNREACHABLE:
                        entry['status'] = HOST_FAILED
                        entry['reason'] = '%s 태스크 실패 — 이후 태스크는 판정되지 않음' % (
                            '[%s] %s' % (spec_id, title) if spec_id else title)
                    continue
                if not declared or is_handler or not result.get('changed'):
                    continue
                row = {'spec_id': spec_id, 'task': title, 'summary': summarize_diff(result)}
                rule = _ignored(spec_id, title, ignore)
                if rule:
                    row['reason'] = str(rule.get('reason') or '')
                    entry['excluded'].append(row)
                else:
                    entry['rows'].append(row)
    for host, entry in out.items():
        if entry['status'] == HOST_NO_RESULT and host in seen:
            entry['status'] = HOST_OK
        elif entry['status'] == HOST_NO_RESULT:
            entry['reason'] = '하위 실행 결과에 이 호스트가 없음 (접속 정보 해석 실패 등)'
    return {'status': 'ok', 'reason': '', 'hosts': out}


def host_audit_drift_section(plan, runs):
    """Build the Configuration Drift section model.

    ``plan``: host_audit_drift_plan output. ``runs``: {'site'|'agents':
    {'ran': bool, 'rc': int, 'error': str, 'parsed': host_audit_drift_parse
    output}}. A sub-run that failed as a whole (no parsable result, timeout)
    makes only its part of the section not inspectable; the audit run goes on.
    """
    plan = plan or {}
    runs = runs or {}
    subruns, rows, excluded, unavailable = [], [], [], []
    host_rows = {}
    for key in SUBRUN_ORDER:
        label, command = SUBRUNS[key]
        hosts = plan.get(key) or []
        run = runs.get(key) or {}
        parsed = run.get('parsed') or {}
        sub = {'key': key, 'label': label, 'command': command, 'hosts': len(hosts),
               'status': 'ok', 'reason': '', 'changed_hosts': 0, 'rows': 0}
        if not hosts:
            sub['status'], sub['reason'] = 'skipped', '대상 호스트 없음'
            subruns.append(sub)
            continue
        if not run.get('ran') or parsed.get('status') != 'ok':
            sub['status'] = 'error'
            sub['reason'] = (run.get('error') or parsed.get('reason')
                             or '하위 실행 결과 없음 (rc=%s)' % run.get('rc', '-'))
            subruns.append(sub)
            unavailable.append({'host': '%d대' % len(hosts), 'item': '%s — %s' % (SECTION, label),
                                'label': UNAVAILABLE_LABEL, 'reason': sub['reason']})
            continue
        for host in hosts:
            result = (parsed.get('hosts') or {}).get(host) or {
                'status': HOST_NO_RESULT, 'reason': '하위 실행 결과에 이 호스트가 없음', 'rows': [], 'excluded': []}
            state = host_rows.setdefault(host, {'host': host, 'rows': [], 'excluded': [], 'unavailable': []})
            if result['status'] != HOST_OK:
                label_text = HOST_LABELS.get(result['status'], UNAVAILABLE_LABEL)
                state['unavailable'].append({'subrun': label, 'label': label_text, 'reason': result.get('reason') or '-'})
                unavailable.append({'host': host, 'item': '%s — %s' % (SECTION, label),
                                    'label': label_text, 'reason': result.get('reason') or '-'})
            for row in result.get('rows') or []:
                full = dict(row, host=host, subrun=label)
                rows.append(full)
                state['rows'].append(full)
            for row in result.get('excluded') or []:
                full = dict(row, host=host, subrun=label)
                excluded.append(full)
                state['excluded'].append(full)
            if result.get('rows'):
                sub['changed_hosts'] += 1
            sub['rows'] += len(result.get('rows') or [])
        subruns.append(sub)
    for host, reason in sorted((plan.get('excluded') or {}).items()):
        state = host_rows.setdefault(host, {'host': host, 'rows': [], 'excluded': [], 'unavailable': []})
        state['unavailable'].append({'subrun': '전체', 'label': UNAVAILABLE_LABEL, 'reason': reason})
        if reason == REASON_RAW:
            unavailable.append({'host': host, 'item': SECTION, 'label': UNAVAILABLE_LABEL, 'reason': reason})
    baseline_findings = _baseline_findings(plan, subruns, host_rows)
    order = {SUBRUNS[k][0]: i for i, k in enumerate(SUBRUN_ORDER)}
    rows.sort(key=lambda r: (r['host'], order.get(r['subrun'], 99), r['spec_id'] or '~', r['task']))
    excluded_summary = {}
    for row in excluded:
        key = (row['spec_id'], row['task'], row.get('reason', ''))
        excluded_summary.setdefault(key, set()).add(row['host'])
    return {
        'title': SECTION,
        'subruns': subruns,
        'rows': rows,
        'hosts_with_drift': len({r['host'] for r in rows}),
        'excluded': [{'spec_id': k[0], 'task': k[1], 'reason': k[2], 'hosts': len(v)}
                     for k, v in sorted(excluded_summary.items())],
        'by_host': host_rows,
        'unavailable': unavailable,
        'baseline_findings': baseline_findings,
    }


def finding_id(subrun_key, spec_id, task):
    """Stable identity of a Drift row across runs (Audit Baseline, #125): sub-run + SPEC-ID,
    or the task name when the task has no SPEC-ID."""
    return '%s:%s' % (subrun_key, spec_id or 'task:' + task)


def _baseline_findings(plan, subruns, host_rows):
    """Audit Baseline participation: a host counts as inspected only when every sub-run it
    was planned for produced its result, so a failed or timed-out sub-run never turns the
    previous run's Drift into 해소."""
    labels = {SUBRUNS[k][0]: k for k in SUBRUN_ORDER}
    failed = {s['key'] for s in subruns if s['status'] == 'error'}
    hosts, findings = [], []
    for host, state in sorted(host_rows.items()):
        planned = [k for k in SUBRUN_ORDER if host in (plan.get(k) or [])]
        if not planned or failed & set(planned) or state['unavailable']:
            continue
        hosts.append(host)
        for row in state['rows']:
            key = labels.get(row['subrun'], row['subrun'])
            findings.append({'host': host, 'id': finding_id(key, row['spec_id'], row['task']),
                             'label': '%s %s' % (row['spec_id'] or '-', row['task'])})
    return {'hosts': hosts, 'findings': findings}


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_drift_plan': host_audit_drift_plan,
            'host_audit_drift_parse': host_audit_drift_parse,
            'host_audit_drift_section': host_audit_drift_section,
        }
