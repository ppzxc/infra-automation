"""Host Audit storage and Audit Baseline filters (ADR-0009 §5, #125).

Every run is kept in the RustFS Host Audit bucket under ``<YYYY-MM>/<run_id>/``.
A scheduled run also writes a small pointer ``baseline/<run_id>.json`` so the next
run finds its Audit Baseline (the latest earlier scheduled run) and the findings
that scheduled runs of the past twelve months marked resolved with one List and a
few Gets. On-demand runs are kept but write no pointer, so they never become the
baseline.

The runner talks to RustFS with ``ansible.builtin.uri`` and an AWS Signature V4
header computed here (stdlib only — the stock Semaphore image has no boto3/aws-cli).

Section interface (how a report section takes part in the Audit Baseline):
  A section exposes its findings as ``{'hosts': [hosts it inspected],
  'findings': [{'host': ..., 'id': ..., 'label': ...}]}``. The three sections that
  exist today are read from their model shape by ``_extractors`` below; a new
  section only has to put that dict under ``model[<section>]['baseline_findings']``.
  The identity of a finding is (Inventory Hostname, section, id).

Statuses: 신규 (not in the baseline), 지속 (in the baseline too), 재발 (not in the
baseline, but a scheduled run in the past twelve months marked it resolved),
해소 (in the baseline, gone now, host inspected), 확인 불가 (in the baseline, host
not inspected this run). Asset Inventory items (accounts, listening ports,
privileged users) are changes, not findings: they are only 신규 or 삭제.
"""

import hashlib
import hmac
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

try:
    from urllib.parse import quote, urlsplit
except ImportError:  # pragma: no cover - Python 2 controller
    from urllib import quote
    from urlparse import urlsplit

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_kisa import EXCEPTION, ITEMS as KISA_ITEMS, VULNERABLE  # noqa: E402

DOC_SCHEMA_VERSION = 1
POINTER_PREFIX = 'baseline/'
WINDOW_DAYS = 365
LIST_LIMIT = 300  # rows per table in the report; the rest stays in findings.json

NEW = '신규'
PERSIST = '지속'
RECUR = '재발'
RESOLVED = '해소'
UNKNOWN = '확인 불가'
FIRST = '첫 실행'
REMOVED = '삭제'
STATUSES = [NEW, RECUR, PERSIST, RESOLVED, UNKNOWN]
STATUS_CLASSES = {NEW: 'crit', RECUR: 'crit', PERSIST: 'warn', RESOLVED: 'ok', UNKNOWN: 'na',
                  FIRST: 'na', REMOVED: 'na'}

SECTION_ASSET = 'asset_inventory'
SECTION_KISA = 'config_vulnerability'
SECTION_PACKAGE = 'package_vulnerability'
SECTION_TITLES = {
    SECTION_ASSET: 'Asset Inventory',
    SECTION_KISA: 'Configuration Vulnerability',
    SECTION_PACKAGE: 'Package Vulnerability',
    'configuration_drift': 'Configuration Drift',
}
ASSET_KINDS = {'account': '계정', 'port': 'listening 포트', 'privileged': '특수권한자'}
# KISA verdicts that count as a finding. 점검불가(수동) is not one: it is the same every run.
KISA_FINDING_VERDICTS = (VULNERABLE, EXCEPTION)

EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()


# ------------------------------------------------------------------------------
# 1. S3 (RustFS) requests — AWS Signature Version 4, path-style
# ------------------------------------------------------------------------------
def _hmac(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _uri_encode(value, safe='-_.~'):
    return quote(str(value), safe=safe)


def _canonical_query(query):
    pairs = sorted((_uri_encode(k), _uri_encode(v if v is not None else '')) for k, v in (query or {}).items())
    return '&'.join('%s=%s' % kv for kv in pairs)


def sigv4_authorization(method, host, path, query, headers, payload_sha256,
                        access_key, secret_key, region, amz_date, service='s3'):
    """Return the Authorization header value for an already canonical ``path``.

    ``headers`` are the extra headers to sign besides host, x-amz-content-sha256
    and x-amz-date (which are always signed). ``amz_date`` is 'YYYYMMDDTHHMMSSZ'.
    """
    signed = {'host': host, 'x-amz-content-sha256': payload_sha256, 'x-amz-date': amz_date}
    for name, value in (headers or {}).items():
        signed[name.lower()] = str(value).strip()
    names = sorted(signed)
    canonical_headers = ''.join('%s:%s\n' % (n, signed[n]) for n in names)
    signed_headers = ';'.join(names)
    canonical_request = '\n'.join([method.upper(), path, _canonical_query(query),
                                   canonical_headers, signed_headers, payload_sha256])
    scope = '%s/%s/%s/aws4_request' % (amz_date[:8], region, service)
    string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                                hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
    key = _hmac(('AWS4' + secret_key).encode('utf-8'), amz_date[:8])
    for part in (region, service, 'aws4_request'):
        key = _hmac(key, part)
    signature = hmac.new(key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    return 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (
        access_key, scope, signed_headers, signature)


def host_audit_s3_request(storage, method, key='', query=None, payload_sha256=None, now=None, headers=None):
    """Build ``{'url', 'headers'}`` for one path-style S3 request to the Host Audit bucket.

    ``storage``: {endpoint, bucket, access_key, secret_key, region}. ``key`` '' means
    the bucket itself (ListObjectsV2). ``payload_sha256`` is the hex SHA-256 of the
    body (PUT) — default the empty body. ``headers``: extra headers to sign and send
    (S3 rejects unsigned ``x-amz-*`` headers). ``now`` (datetime, tests only) fixes the clock.
    """
    storage = storage or {}
    endpoint = str(storage.get('endpoint') or '').rstrip('/')
    parts = urlsplit(endpoint)
    host = parts.hostname or ''
    default_port = {'http': 80, 'https': 443}.get(parts.scheme)
    if parts.port and parts.port != default_port:
        host = '%s:%d' % (host, parts.port)
    path = '%s/%s' % (parts.path.rstrip('/'), _uri_encode(storage.get('bucket', ''), safe=''))
    if key:
        path += '/' + _uri_encode(key, safe='/-_.~')
    stamp = (now or datetime.now(timezone.utc)).strftime('%Y%m%dT%H%M%SZ')
    payload = payload_sha256 or EMPTY_SHA256
    region = storage.get('region') or 'us-east-1'
    auth = sigv4_authorization(method, host, path, query, headers, payload,
                               storage.get('access_key', ''), storage.get('secret_key', ''), region, stamp)
    query_text = _canonical_query(query)
    out_headers = dict(headers or {})
    out_headers.update({'Authorization': auth, 'x-amz-date': stamp, 'x-amz-content-sha256': payload})
    return {
        'url': '%s://%s%s%s' % (parts.scheme, parts.netloc, path, ('?' + query_text) if query_text else ''),
        'headers': out_headers,
    }


def host_audit_s3_list(xml_text):
    """ListObjectsV2 response XML -> {'keys': [{'key', 'last_modified'}], 'truncated', 'next_token'}."""
    root = ET.fromstring(xml_text)

    def local(tag):
        return tag.rsplit('}', 1)[-1]

    out = {'keys': [], 'truncated': False, 'next_token': ''}
    for child in root:
        name = local(child.tag)
        if name == 'Contents':
            item = dict((local(c.tag), c.text or '') for c in child)
            out['keys'].append({'key': item.get('Key', ''), 'last_modified': item.get('LastModified', '')})
        elif name == 'IsTruncated':
            out['truncated'] = (child.text or '').strip().lower() == 'true'
        elif name == 'NextContinuationToken':
            out['next_token'] = child.text or ''
    return out


def _parse_utc(text):
    text = str(text or '')
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ'):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def host_audit_storage_prefix(run, tz_name='Asia/Seoul'):
    """``<YYYY-MM>/<run_id>/`` — the month of the run start in the report time zone."""
    started = _parse_utc((run or {}).get('started_at')) or datetime.now(timezone.utc)
    if ZoneInfo is not None:
        started = started.astimezone(ZoneInfo(tz_name or 'Asia/Seoul'))
    return '%s/%s/' % (started.strftime('%Y-%m'), run['run_id'])


def host_audit_pointer_keys(listing, started_at, window_days=WINDOW_DAYS):
    """Pointer object keys worth fetching: modified within the window before this run (+1 day slack)."""
    start = _parse_utc(started_at) or datetime.now(timezone.utc)
    floor = start - timedelta(days=int(window_days) + 1)
    keys = []
    for item in (listing or {}).get('keys') or []:
        key = item.get('key', '')
        if not key.startswith(POINTER_PREFIX) or not key.endswith('.json'):
            continue
        modified = _parse_utc(item.get('last_modified'))
        if modified is not None and modified < floor:
            continue
        keys.append(key)
    return sorted(keys)


# ------------------------------------------------------------------------------
# 2. Findings of every section (identity: host, section, id)
# ------------------------------------------------------------------------------
def _asset_findings(model):
    section = model.get(SECTION_ASSET) or {}
    hosts, findings = [], []
    for h in section.get('hosts') or []:
        if not h.get('collected'):
            continue
        hosts.append(h['host'])
        for a in h.get('accounts') or []:
            findings.append({'host': h['host'], 'id': 'account:%s' % a['name'], 'label': a['name']})
            if a.get('privilege'):
                findings.append({'host': h['host'], 'id': 'privileged:%s' % a['name'],
                                 'label': '%s (%s)' % (a['name'], a['privilege'])})
        seen = set()
        for p in h.get('ports') or []:
            pid = 'port:%s/%s' % (p.get('proto'), p.get('port'))
            if pid in seen:
                continue
            seen.add(pid)
            findings.append({'host': h['host'], 'id': pid,
                             'label': '%s/%s %s' % (p.get('proto'), p.get('port'), p.get('process') or '')})
    return {'hosts': hosts, 'findings': findings}


def _kisa_findings(model):
    section = model.get(SECTION_KISA) or {}
    appendix = section.get('appendix') or {}
    findings = []
    for host, rows in appendix.items():
        for row in rows:
            if row.get('verdict') in KISA_FINDING_VERDICTS:
                findings.append({'host': host, 'id': row['code'],
                                 'label': '%s %s' % (row['code'], row.get('title', ''))})
    return {'hosts': sorted(appendix), 'findings': findings}


def _package_findings(model, package_results):
    section = model.get(SECTION_PACKAGE) or {}
    if not section or section.get('status') not in (None, 'ok'):
        return {'hosts': [], 'findings': []}
    hosts, findings = [], []
    for hr in package_results or []:
        if hr.get('status') != 'ok':
            continue
        hosts.append(hr['host'])
        for f in hr.get('findings') or []:
            findings.append({'host': hr['host'], 'id': f['id'], 'label': '%s %s' % (f['cve'], f['package'])})
    return {'hosts': hosts, 'findings': findings}


def host_audit_findings_index(model, package_results=None):
    """{section: {'hosts': [...], 'findings': [...]}} for every section of the model."""
    model = model or {}
    index = {}
    if model.get(SECTION_ASSET):
        index[SECTION_ASSET] = _asset_findings(model)
    if model.get(SECTION_KISA):
        index[SECTION_KISA] = _kisa_findings(model)
    if model.get(SECTION_PACKAGE):
        index[SECTION_PACKAGE] = _package_findings(model, package_results)
    for name, value in model.items():
        if isinstance(value, dict) and isinstance(value.get('baseline_findings'), dict):
            index[name] = {'hosts': list(value['baseline_findings'].get('hosts') or []),
                           'findings': list(value['baseline_findings'].get('findings') or [])}
    return index


def _key(section, host, fid):
    return '%s|%s|%s' % (section, host, fid)


def _split_key(key):
    section, host, fid = key.split('|', 2)
    return section, host, fid


def _compact(index):
    """Stored form: {section: {'hosts': [...], 'ids': {host: [ids]}}} (labels are rebuilt from ids)."""
    out = {}
    for section, part in index.items():
        ids = {}
        for f in part['findings']:
            ids.setdefault(f['host'], []).append(f['id'])
        out[section] = {'hosts': sorted(set(part['hosts'])), 'ids': dict((h, sorted(set(v))) for h, v in ids.items())}
    return out


def _label(section, fid):
    if section == SECTION_KISA:
        return '%s %s' % (fid, (KISA_ITEMS.get(fid.split(':', 1)[-1]) or {}).get('title', ''))
    if section == SECTION_PACKAGE:
        return fid.replace('|', ' ')
    if section == SECTION_ASSET:
        kind, _, name = fid.partition(':')
        return '%s %s' % (ASSET_KINDS.get(kind, kind), name)
    return fid


# ------------------------------------------------------------------------------
# 3. Audit Baseline — status of every finding against the previous scheduled run
# ------------------------------------------------------------------------------
def _local_text(iso_utc, tz_name):
    stamp = _parse_utc(iso_utc)
    if stamp is None:
        return iso_utc or ''
    if ZoneInfo is None:
        return stamp.strftime('%Y-%m-%d %H:%M (UTC)')
    local = stamp.astimezone(ZoneInfo(tz_name))
    return '%s (%s)' % (local.strftime('%Y-%m-%d %H:%M'), local.tzname())


def _badge(status):
    return {'status': status, 'class': STATUS_CLASSES.get(status, 'na')}


def host_audit_baseline_compare(index, baseline, pointers, run, window_days=WINDOW_DAYS):
    """Mark every finding of ``index`` against the Audit Baseline.

    ``baseline``: the stored findings document of the previous scheduled run, or None
    (first run). ``pointers``: pointer documents of scheduled runs (each with
    ``started_at`` and ``resolved`` keys) used for 재발 within ``window_days``.
    Returns {'status': {key: status}, 'resolved': [keys], 'unknown': [keys],
    'asset_changes': [{'host', 'id', 'change'}]}.
    """
    run = run or {}
    started = _parse_utc(run.get('started_at')) or datetime.now(timezone.utc)
    floor = started - timedelta(days=int(window_days))
    recurring = set()
    for p in pointers or []:
        when = _parse_utc(p.get('started_at'))
        if p.get('run_kind') != 'scheduled' or p.get('run_id') == run.get('run_id'):
            continue
        if when is None or when >= started or when < floor:
            continue
        recurring.update(p.get('resolved') or [])

    out = {'status': {}, 'resolved': [], 'unknown': [], 'asset_changes': []}
    base_sections = (baseline or {}).get('sections') or {}
    for section, part in (index or {}).items():
        cur_keys = set(_key(section, f['host'], f['id']) for f in part['findings'])
        cur_hosts = set(part['hosts'])
        base = base_sections.get(section)
        base_hosts = set((base or {}).get('hosts') or [])
        base_keys = set(_key(section, h, i) for h, ids in ((base or {}).get('ids') or {}).items() for i in ids)
        if section == SECTION_ASSET:
            if baseline is None:
                continue
            for k in sorted(cur_keys - base_keys):
                host = _split_key(k)[1]
                if host in base_hosts:  # a host new to Host Audit is not a pile of new accounts
                    out['asset_changes'].append({'key': k, 'change': NEW})
            for k in sorted(base_keys - cur_keys):
                if _split_key(k)[1] in cur_hosts:
                    out['asset_changes'].append({'key': k, 'change': REMOVED})
            continue
        for k in cur_keys:
            if baseline is None:
                out['status'][k] = FIRST
            elif k in base_keys:
                out['status'][k] = PERSIST
            elif k in recurring:
                out['status'][k] = RECUR
            else:
                out['status'][k] = NEW
        for k in sorted(base_keys - cur_keys):
            if _split_key(k)[1] in cur_hosts:
                out['resolved'].append(k)
            else:
                out['unknown'].append(k)
    return out


def _annotate(model, compare):
    """Copy the model, adding a ``baseline`` badge to the rows other sections already draw."""
    status = compare['status']
    kisa = model.get(SECTION_KISA)
    if kisa:
        kisa = dict(kisa)
        findings = []
        for f in kisa.get('findings') or []:
            f = dict(f)
            hosts = []
            for h in f.get('hosts') or []:
                h = dict(h)
                s = status.get(_key(SECTION_KISA, h['host'], f['code']))
                if s:
                    h['baseline'] = _badge(s)
                hosts.append(h)
            f['hosts'] = hosts
            findings.append(f)
        kisa['findings'] = findings
        model[SECTION_KISA] = kisa
    pkg = model.get(SECTION_PACKAGE)
    if pkg:
        pkg = dict(pkg)
        details = []
        for d in pkg.get('details') or []:
            d = dict(d)
            s = status.get(_key(SECTION_PACKAGE, d['host'], d.get('id') or '%s|%s' % (d['cve'], d['package'])))
            if s:
                d['baseline'] = _badge(s)
            details.append(d)
        pkg['details'] = details
        model[SECTION_PACKAGE] = pkg
    return model


def _rows(keys, status_label):
    rows = []
    for k in keys[:LIST_LIMIT]:
        section, host, fid = _split_key(k)
        rows.append({'host': host, 'section': SECTION_TITLES.get(section, section),
                     'item': _label(section, fid), 'status': status_label,
                     'class': STATUS_CLASSES.get(status_label, 'na')})
    return rows


def host_audit_baseline_section(model, history=None, meta=None):
    """Return a copy of the report model with the Audit Baseline applied.

    ``history`` (from the storage lookup): {'state': 'ok' | 'failed' | 'disabled',
    'reason', 'baseline': stored findings document or None, 'pointers': [...]}.
    The findings index of this run (``model['baseline']['document']``) is what the
    run stores as ``findings.json``; a scheduled run also stores its pointer.
    """
    model = dict(model or {})
    meta = meta or {}
    history = history or {'state': 'disabled'}
    tz_name = meta.get('timezone') or 'Asia/Seoul'
    run = {'run_id': meta.get('run_id', ''), 'run_kind': meta.get('run_kind') or 'on_demand',
           'started_at': meta.get('started_at', '')}
    index = host_audit_findings_index(model, meta.get('package_results'))
    state = history.get('state') or 'disabled'
    baseline = history.get('baseline') if state == 'ok' else None
    cover = dict(model.get('cover') or {})

    if state == 'ok':
        compare = host_audit_baseline_compare(index, baseline, history.get('pointers'), run)
        if baseline is None:
            cover['baseline'] = '없음 — 첫 정기 실행 전이라 비교하지 않음 (모든 발견을 첫 실행으로 표시)'
        else:
            cover['baseline'] = '%s (정기, %s 시작) — 신규·지속·재발·해소 표시, 재발은 지난 12개월 정기 실행 기준' % (
                baseline.get('run_id', ''), _local_text(baseline.get('started_at'), tz_name))
        model = _annotate(model, compare)
    else:
        compare = {'status': {}, 'resolved': [], 'unknown': [], 'asset_changes': []}
        cover['baseline'] = ('조회 실패 — %s (이번 보고서는 비교하지 않음, 실행은 실패로 끝남)' % (history.get('reason') or '-')
                             if state == 'failed' else '비교 안 함 — 보관이 비활성화된 실행')
    model['cover'] = cover

    counts = {}
    for k, s in compare['status'].items():
        section = _split_key(k)[0]
        counts.setdefault(section, dict((x, 0) for x in STATUSES + [FIRST]))[s] += 1
    for k in compare['resolved']:
        counts.setdefault(_split_key(k)[0], dict((x, 0) for x in STATUSES + [FIRST]))[RESOLVED] += 1
    for k in compare['unknown']:
        counts.setdefault(_split_key(k)[0], dict((x, 0) for x in STATUSES + [FIRST]))[UNKNOWN] += 1
    count_rows = [{'section': SECTION_TITLES.get(s, s), 'counts': [c[x] for x in STATUSES], 'first': c[FIRST]}
                  for s, c in sorted(counts.items())]

    recurring = sorted(k for k, s in compare['status'].items() if s == RECUR)
    asset_rows = []
    for change in compare['asset_changes'][:LIST_LIMIT]:
        _section, host, fid = _split_key(change['key'])
        kind, _, name = fid.partition(':')
        asset_rows.append({'host': host, 'kind': ASSET_KINDS.get(kind, kind), 'item': name,
                           'change': change['change'], 'class': STATUS_CLASSES[change['change']]})

    document = {
        'schema_version': DOC_SCHEMA_VERSION,
        'run_id': run['run_id'],
        'run_kind': run['run_kind'],
        'started_at': run['started_at'],
        'baseline_run_id': (baseline or {}).get('run_id', ''),
        'sections': _compact(index),
        # Only a scheduled run marks findings resolved for the 12-month 재발 rule.
        'resolved': compare['resolved'] if run['run_kind'] == 'scheduled' else [],
    }
    model['baseline'] = {
        'state': state,
        'reason': history.get('reason', ''),
        'failed': state == 'failed',
        'compared': state == 'ok' and baseline is not None,
        'baseline_run_id': (baseline or {}).get('run_id', ''),
        'statuses': STATUSES,
        'status_classes': [STATUS_CLASSES[s] for s in STATUSES],
        'count_rows': count_rows,
        'recurring': _rows(recurring, RECUR),
        'resolved': _rows(compare['resolved'], RESOLVED),
        'unknown': _rows(compare['unknown'], UNKNOWN),
        'asset_changes': asset_rows,
        'truncated': max(0, len(compare['resolved']) - LIST_LIMIT) + max(0, len(recurring) - LIST_LIMIT),
        'document': document,
        'pointer': {'run_id': run['run_id'], 'run_kind': run['run_kind'], 'started_at': run['started_at'],
                    'findings_key': '', 'resolved': document['resolved']},
    }
    return model


def host_audit_baseline_pick(pointers, run):
    """The pointer of the Audit Baseline: latest scheduled run that started before this run."""
    started = _parse_utc((run or {}).get('started_at')) or datetime.now(timezone.utc)
    candidates = []
    for p in pointers or []:
        when = _parse_utc(p.get('started_at'))
        if p.get('run_kind') != 'scheduled' or when is None or when >= started:
            continue
        if p.get('run_id') == (run or {}).get('run_id'):
            continue
        candidates.append((when, p.get('run_id', ''), p))
    return max(candidates, key=lambda c: (c[0], c[1]))[2] if candidates else None


def host_audit_json_loads(text):
    """Parse JSON text, None when empty or invalid (a damaged object must not break the run)."""
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_s3_request': host_audit_s3_request,
            'host_audit_s3_list': host_audit_s3_list,
            'host_audit_storage_prefix': host_audit_storage_prefix,
            'host_audit_pointer_keys': host_audit_pointer_keys,
            'host_audit_baseline_pick': host_audit_baseline_pick,
            'host_audit_json_loads': host_audit_json_loads,
        }
