"""Filters for Host Audit Configuration Vulnerability (ADR-0009, #121).

Configuration Vulnerability is judged against the KISA technical vulnerability
checklist for Unix servers, 2026 edition. Each item is named with its edition
(``KISA-2026:U-13``) because the editions reuse item numbers; CIS Benchmark is a
cross-reference column only.

The checks themselves are POSIX sh (``roles/host_audit/files/kisa``) run on the
host through ``ansible.builtin.raw``; they print one ``U-NN|STATUS|evidence``
line per item. This module turns that output into one of five verdicts, applies
the exception register, and adds the report section to the model built by
``host_audit_report_model``. Every judgement is made here, never in the template.

Entry points:
  host_audit_kisa_result   (filter) registered raw check run -> ``config_vulnerability`` of a record
  host_audit_kisa_section  report model + records -> model with the section added; called by
                           ``host_audit_report_model``, the single report builder
"""

import functools
import os
import re
from types import MappingProxyType
from datetime import datetime, timezone

import yaml

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

EDITION = 'KISA-2026'
BEGIN = '__HOST_AUDIT_KISA_BEGIN__'
END = '__HOST_AUDIT_KISA_END__'
REPORT_TIMEZONE = 'Asia/Seoul'

GOOD = '양호'
VULNERABLE = '취약'
EXCEPTION = '예외(승인)'
NOT_APPLICABLE = '해당없음'
MANUAL = '점검불가(수동)'
VERDICTS = [VULNERABLE, MANUAL, EXCEPTION, NOT_APPLICABLE, GOOD]
RAW_VERDICTS = {'GOOD': GOOD, 'VULN': VULNERABLE, 'NA': NOT_APPLICABLE, 'MANUAL': MANUAL}
VERDICT_CLASSES = {VULNERABLE: 'crit', MANUAL: 'warn', EXCEPTION: 'exc', NOT_APPLICABLE: 'na', GOOD: 'ok'}
SEVERITY_ORDER = {'상': 0, '중': 1, '하': 2}

STATUS_OK = 'ok'
STATUS_FAILED = 'failed'

CATEGORY_ACCOUNT = '계정 관리'
CATEGORY_FILE = '파일 및 디렉토리 관리'
CATEGORY_SERVICE = '서비스 관리'
CATEGORY_PATCH = '패치 관리'
CATEGORY_LOG = '로그 관리'
CATEGORIES = [CATEGORY_ACCOUNT, CATEGORY_FILE, CATEGORY_SERVICE, CATEGORY_PATCH, CATEGORY_LOG]

# KISA-2026 Unix items U-01~U-67. The item list lives only in host_audit_kisa_items.yml next to this
# module (title/severity/category/criteria/cis) and is never edited here.
#
# The catalog is read at import time on purpose (Spec #488 / Ticket-1, #489: "the filter only reads the YAML
# when imported"). A broken or missing catalog must fail loudly at that point with the cause named in the
# RuntimeError, instead of surfacing later as a missing item inside a report. _load_items caches per path, so
# each process parses the file once however often it is called.
CODE_PATTERN = re.compile(r'^U-\d\d$')
ITEM_FIELDS = ('title', 'severity', 'category', 'criteria', 'cis')
# Text fields added by Spec #488 / Ticket-2 (#490), plus the nested remediation, remediation_impact,
# remediation_effort mappings and the guide_page number validated in _validate_remediation.
TEXT_FIELDS = ('check', 'purpose', 'threat')
REMEDIATION_FIELDS = TEXT_FIELDS + ('guide_page', 'remediation', 'remediation_impact', 'remediation_effort')
STEP_FAMILIES = ('rhel', 'debian')
LEVELS = (1, 2, 3)
CATALOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'host_audit_kisa_items.yml')


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses a mapping key written twice (safe_load would silently keep the last one)."""

    def construct_mapping(self, node, deep=False):
        # Check the keys written in this mapping before merge flattening: an explicit key may legitimately
        # override a merged one. (construct_object memoizes, so the parent does not rebuild the key nodes.)
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == 'tag:yaml.org,2002:merge':
                continue
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.YAMLError('duplicate key %r (line %d)' % (key, key_node.start_mark.line + 1))
            seen.add(key)
        self.flatten_mapping(node)
        return super().construct_mapping(node, deep)


def _deep_freeze(value):
    """Read-only view of nested mappings; lists become tuples, scalars pass through."""
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(v) for v in value)
    return value


SUMMARY_MAX = 300  # the body table prints remediation.summary on one line; longer notes belong in steps/reason


def _blank(value):
    return not isinstance(value, str) or not value.strip()


def _untrimmed(value, block=False):
    """Blank text, or text with surrounding whitespace (it would show as a stray gap in report cells).

    ``block`` is for YAML ``|`` blocks (steps), which always end with a newline: only leading space is refused.
    """
    if _blank(value):
        return True
    return value != value.lstrip() if block else value != value.strip()


def _validate_remediation(code, meta, path):
    """Check the remediation fields of one item; bool is rejected on purpose (True == 1 in Python)."""
    def fail(field, why):
        raise RuntimeError('KISA item %s field %s %s in %s' % (code, field, why, path))

    for field in REMEDIATION_FIELDS:
        if field not in meta:
            fail(field, 'is missing')
    for field in TEXT_FIELDS:
        if _untrimmed(meta[field]):
            fail(field, 'must be non-blank text without surrounding whitespace')
    page = meta['guide_page']
    if type(page) is not int or page < 1:
        fail('guide_page', 'must be a positive integer')
    rem = meta['remediation']
    if not isinstance(rem, dict) or set(rem) - {'summary', 'steps'} or _untrimmed(rem.get('summary')):
        fail('remediation', 'must be a mapping of summary (trimmed text) and optional steps')
    if len(rem['summary']) > SUMMARY_MAX or '\n' in rem['summary']:
        fail('remediation.summary', 'must be one line of at most %d characters' % SUMMARY_MAX)
    steps = rem.get('steps')
    if steps is not None and (not isinstance(steps, dict) or not steps or set(steps) - set(STEP_FAMILIES)
                              or any(_untrimmed(v, block=True) for v in steps.values())):
        fail('remediation.steps', 'must map rhel/debian to non-blank text')
    for field in ('remediation_impact', 'remediation_effort'):
        part = meta[field]
        if (not isinstance(part, dict) or set(part) != {'level', 'reason'} or type(part['level']) is not int
                or part['level'] not in LEVELS or _untrimmed(part['reason'])):
            fail(field, 'must be {level: 1..3, reason: text}')


def _validate(items, path):
    if not isinstance(items, dict) or not items:
        raise RuntimeError('KISA item catalog %s is empty or not a mapping' % path)
    for code, meta in items.items():
        if not isinstance(code, str) or not CODE_PATTERN.match(code):
            raise RuntimeError('KISA item code %r is not U-NN in %s' % (code, path))
        if not isinstance(meta, dict):
            raise RuntimeError('KISA item %s is not a mapping in %s' % (code, path))
        for field in ITEM_FIELDS:
            if field not in meta:
                raise RuntimeError('KISA item %s lacks field %s in %s' % (code, field, path))
            if not isinstance(meta[field], str):
                raise RuntimeError('KISA item %s field %s must be a string (quote it) in %s' % (code, field, path))
        for field in ('title', 'criteria'):
            if not meta[field].strip() or meta[field] != meta[field].strip():
                raise RuntimeError('KISA item %s field %s is blank or has surrounding whitespace in %s'
                                   % (code, field, path))
        _validate_remediation(code, meta, path)
        extra = sorted(set(meta) - set(ITEM_FIELDS) - set(REMEDIATION_FIELDS))
        if extra:
            raise RuntimeError('KISA item %s has unknown field %s in %s' % (code, ', '.join(map(str, extra)), path))
        if meta['severity'] not in SEVERITY_ORDER:
            raise RuntimeError('KISA item %s field severity %r is not 상/중/하 in %s' % (code, meta['severity'], path))
        if meta['category'] not in CATEGORIES:
            raise RuntimeError('KISA item %s field category %r is unknown in %s' % (code, meta['category'], path))


@functools.lru_cache(maxsize=None)
def _parse_catalog(path):
    try:
        with open(path, encoding='utf-8') as fh:
            items = yaml.load(fh, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        raise RuntimeError('KISA item catalog %s cannot be loaded: %s' % (path, exc)) from exc
    _validate(items, path)
    return _deep_freeze(items)


def _load_items(path=None):
    """Read-only item catalog of ``path`` (default: the YAML next to this module), parsed once per path."""
    return _parse_catalog(os.path.realpath(path or CATALOG_PATH))


def _require_all_items(items):
    """The shipped catalog must hold every KISA-2026 Unix item, U-01..U-67 (the check scripts are U-NN.sh)."""
    missing = sorted(set('U-%02d' % i for i in range(1, 68)) - set(items))
    if missing:
        raise RuntimeError('KISA item catalog %s lacks %s' % (CATALOG_PATH, ', '.join(missing)))
    return items


ITEMS = _require_all_items(_load_items())

# Values derived from the guide severity (Spec #488 / #479). They are never stored in the catalog, so they
# cannot drift from it, and they are the same for every host and every verdict.
RISK_BY_SEVERITY = {'상': 3, '중': 2, '하': 1}
PRIORITY_BY_SEVERITY = {'상': 1, '중': 2, '하': 3}
URGENCY_BY_PRIORITY = {1: '단기', 2: '중기', 3: '장기'}
REMEDIATION_SOURCE = ('조치방법은 KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」를 '
                      '바탕으로 요약함')


def risk_level(severity):
    """Risk of the finding itself, from the guide severity: 상 3, 중 2, 하 1."""
    return RISK_BY_SEVERITY[severity]


def priority_of(severity):
    """Priority 1 (most urgent) to 3, from the guide severity: 상 1, 중 2, 하 3."""
    return PRIORITY_BY_SEVERITY[severity]


def urgency_of(severity):
    """Urgency label of the priority: 단기, 중기, 장기 (no deadline is defined)."""
    return URGENCY_BY_PRIORITY[priority_of(severity)]


def remediation_view(code, items=None):
    """Remediation columns of one item (``U-NN`` or ``KISA-2026:U-NN``): text plus the derived values.

    ``risk`` and ``urgency`` are not shown in the body table; the Remediation Plan xlsx (a later Spec #488 ticket)
    has columns for them and reads them from this one view, so they are computed and tested here once.
    """
    meta = (ITEMS if items is None else items).get(code.split(':', 1)[-1])
    if meta is None:  # a stored record can carry a code this catalog lacks; the section tolerates that
        return {'remediation_summary': '', 'impact_level': '', 'effort_level': '', 'risk': '', 'priority': '',
                'urgency': ''}
    return {
        'remediation_summary': meta['remediation']['summary'],
        'impact_level': meta['remediation_impact']['level'],
        'effort_level': meta['remediation_effort']['level'],
        'risk': risk_level(meta['severity']),
        'priority': priority_of(meta['severity']),
        'urgency': urgency_of(meta['severity']),
    }


def order_findings(findings, items=None):
    """Order findings by priority, then Remediation Impact, then Remediation Effort (both ascending: easy and
    low-risk fixes first). Ties keep verdict order (취약 first) and then item code, so the order is stable."""
    def key(finding):
        view = remediation_view(finding['code'], items)  # unknown codes (blank values) sort last
        return (view['priority'] or 9, view['impact_level'] or 9, view['effort_level'] or 9,
                VERDICTS.index(finding['verdict']), finding['code'])

    return sorted(findings, key=key)

REGISTER_REQUIRED = ('code', 'reason', 'risk', 'mitigation')
REGISTER_PENDING = '승인 대기'
REGISTER_EXPIRED = '만료'
REGISTER_ACTIVE = '유효'
REGISTER_INVALID = '형식 오류'


def full_code(code):
    return '%s:%s' % (EDITION, code)


def _first_line(text, limit=200):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def _parse(stdout):
    """Return {code: (raw_status, evidence)} from lines between the markers, or None."""
    lines = str(stdout or '').splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == BEGIN)
        end = next(i for i, ln in enumerate(lines) if i > start and ln.strip() == END)
    except StopIteration:
        return None
    found = {}
    for line in lines[start + 1:end]:
        parts = line.rstrip('\r').split('|', 2)
        if len(parts) == 3 and parts[0] in ITEMS and parts[1] in RAW_VERDICTS:
            found[parts[0]] = (parts[1], parts[2].strip())
    return found


def _date(value):
    """'2027-10-31' or a YAML date -> 'YYYY-MM-DD', '' when absent or malformed."""
    text = str(value or '').strip()[:10]
    try:
        datetime.strptime(text, '%Y-%m-%d')
    except ValueError:
        return ''
    return text


def run_date(started_at, tz_name=REPORT_TIMEZONE):
    """ISO-8601 UTC run start -> the run's calendar date in tz_name (exception expiry is by date)."""
    try:
        stamp = datetime.strptime(started_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        stamp = datetime.now(timezone.utc)
    if ZoneInfo is not None:
        stamp = stamp.astimezone(ZoneInfo(tz_name or REPORT_TIMEZONE))
    return stamp.strftime('%Y-%m-%d')


def register_state(entry, today):
    """State of one exception register entry on the run date."""
    entry = entry or {}
    if any(not str(entry.get(k) or '').strip() for k in REGISTER_REQUIRED):
        return REGISTER_INVALID
    if not str(entry.get('approver') or '').strip() or not _date(entry.get('approved_on')):
        return REGISTER_PENDING
    expires = _date(entry.get('expires_on'))
    if not expires:
        return REGISTER_INVALID
    return REGISTER_EXPIRED if expires < today else REGISTER_ACTIVE


def _in_scope(entry, host, groups):
    hosts = entry.get('hosts') or []
    scope_groups = entry.get('groups') or []
    if not hosts and not scope_groups:
        return True
    return host in hosts or bool(set(scope_groups) & set(groups or []))


def _exception_view(entry, state):
    return {
        'state': state,
        'reason': entry.get('reason', ''),
        'risk': entry.get('risk', ''),
        'mitigation': entry.get('mitigation', ''),
        'approver': entry.get('approver', ''),
        'approved_on': _date(entry.get('approved_on')),
        'expires_on': _date(entry.get('expires_on')),
    }


def _apply_register(code, verdict, register, host, groups, today):
    """Return (verdict, exception view or None) after the exception register.

    An approved, unexpired exception turns 취약 and 점검불가(수동) into 예외(승인).
    Once expired it no longer covers the finding, which reverts to 취약. A pending
    (unapproved) entry changes nothing but is noted. 양호 and 해당없음 are untouched.
    """
    if verdict in (GOOD, NOT_APPLICABLE):
        return verdict, None
    matches = [e for e in (register or [])
               if (e or {}).get('code') == full_code(code) and _in_scope(e, host, groups)]
    states = [(register_state(e, today), e) for e in matches]
    for state, entry in states:
        if state == REGISTER_ACTIVE:
            return EXCEPTION, _exception_view(entry, state)
    for state, entry in states:
        if state == REGISTER_EXPIRED:
            return VULNERABLE, _exception_view(entry, state)
    for state, entry in states:
        if state == REGISTER_PENDING:
            return verdict, _exception_view(entry, state)
    return verdict, None


def host_audit_kisa_result(probe, register, inventory_hostname, groups, today):
    """Build the ``config_vulnerability`` part of a per-host record.

    ``probe`` is the registered result of the KISA check run, ``register`` the
    exception register (list of entries), ``groups`` the host's inventory groups
    and ``today`` the run date ('YYYY-MM-DD') against which expiry is judged.
    An item the checks did not report is 점검불가(수동) with that reason.
    """
    probe = probe or {}
    result = {'edition': EDITION, 'status': STATUS_OK, 'reason': '', 'results': []}
    found = None if (probe.get('unreachable') or probe.get('skipped')) else _parse(probe.get('stdout'))
    if found is None:
        result['status'] = STATUS_FAILED
        result['reason'] = (('SSH 접속 실패: ' + _first_line(probe.get('msg'))) if probe.get('unreachable')
                            else _first_line(probe.get('stderr')) or _first_line(probe.get('msg'))
                            or '점검 결과 표식 없음 (rc=%s)' % probe.get('rc'))
        return result
    for code in sorted(ITEMS):
        raw, evidence = found.get(code, ('', '점검 스크립트가 결과를 내지 않음'))
        verdict = RAW_VERDICTS.get(raw, MANUAL)
        verdict, exception = _apply_register(code, verdict, register, inventory_hostname, groups, today)
        result['results'].append({
            'code': full_code(code),
            'result': raw or 'NONE',
            'verdict': verdict,
            'evidence': evidence,
            'exception': exception,
        })
    return result


def _item_meta(code):
    """Base columns of an item (what summary rows and the per-host appendix may show)."""
    short = code.split(':', 1)[-1]
    known = ITEMS.get(short, {})
    meta = {field: known.get(field, short if field == 'title' else '') for field in ITEM_FIELDS}
    meta['code'] = code
    return meta


def _register_rows(register, applied, today):
    rows = []
    for entry in register or []:
        entry = entry or {}
        state = register_state(entry, today)
        scope = ', '.join((entry.get('hosts') or []) + ['그룹 ' + g for g in (entry.get('groups') or [])]) or '전체'
        rows.append({
            'code': entry.get('code', ''),
            'scope': scope,
            'reason': entry.get('reason', ''),
            'risk': entry.get('risk', ''),
            'mitigation': entry.get('mitigation', ''),
            'approver': entry.get('approver') or '-',
            'approved_on': _date(entry.get('approved_on')) or '-',
            'expires_on': _date(entry.get('expires_on')) or '-',
            'state': state,
            'state_class': {REGISTER_ACTIVE: 'ok', REGISTER_EXPIRED: 'crit',
                            REGISTER_PENDING: 'warn', REGISTER_INVALID: 'crit'}[state],
            'applied': applied.get(entry.get('code', ''), 0) if state == REGISTER_ACTIVE else 0,
        })
    return rows


def host_audit_kisa_section(model, records, register=None, today=None):
    """Return a copy of the report model with the Configuration Vulnerability section.

    Section shape: per-item verdict counts over every inspected host, findings
    (verdict other than 양호/해당없음) grouped by item and verdict with the hosts,
    a per-host appendix with every item including 양호, and the exception register.
    Hosts whose checks could not run are added to the model's 점검불가 list.
    """
    model = dict(model or {})
    cover = dict(model.get('cover') or {})
    today = today or run_date(None)
    by_host = {}
    unavailable = list(model.get('unavailable') or [])
    for record in sorted(records or [], key=lambda r: r.get('inventory_hostname', '')):
        if record.get('status') != 'ok':
            continue  # already listed as not inspected by the core model
        host = record['inventory_hostname']
        part = record.get('config_vulnerability')
        if part is None:
            continue  # record made before this section existed
        if part.get('status') != STATUS_OK:
            unavailable.append({
                'host': host, 'item': 'Configuration Vulnerability', 'label': '점검불가(수집 실패)',
                'reason': (part or {}).get('reason') or '점검 결과 없음',
            })
            continue
        by_host[host] = part['results']

    codes = sorted({it['code'] for items in by_host.values() for it in items} | {full_code(c) for c in ITEMS})
    counts = {code: dict.fromkeys(VERDICTS, 0) for code in codes}
    totals = dict.fromkeys(VERDICTS, 0)
    groups = {}
    applied = {}
    appendix = {}
    for host, items in by_host.items():
        rows = []
        for it in items:
            verdict = it['verdict']
            counts.setdefault(it['code'], dict.fromkeys(VERDICTS, 0))[verdict] += 1
            totals[verdict] += 1
            exc = it.get('exception')
            note = ''
            if exc:
                note = {REGISTER_ACTIVE: '예외 승인 (만료 %s)' % exc['expires_on'],
                        REGISTER_EXPIRED: '예외 만료 %s — 취약으로 복귀' % exc['expires_on'],
                        REGISTER_PENDING: '예외 승인 대기'}.get(exc['state'], '')
                if exc['state'] == REGISTER_ACTIVE:
                    applied[it['code']] = applied.get(it['code'], 0) + 1
            if verdict not in (GOOD, NOT_APPLICABLE):
                key = (it['code'], verdict)
                groups.setdefault(key, []).append({'host': host, 'evidence': it['evidence'], 'note': note})
            rows.append(dict(_item_meta(it['code']), verdict=verdict, verdict_class=VERDICT_CLASSES[verdict],
                             evidence=it['evidence'], note=note))
        appendix[host] = rows

    findings = []
    for (code, verdict), hosts in groups.items():
        meta = _item_meta(code)
        findings.append(dict(meta, **remediation_view(code), verdict=verdict,
                             verdict_class=VERDICT_CLASSES[verdict], hosts=hosts, host_count=len(hosts)))
    findings = order_findings(findings)

    summary = [dict(_item_meta(code), counts=[counts[code][v] for v in VERDICTS]) for code in codes]
    implemented = sorted(ITEMS)
    categories = [c for c in CATEGORIES if any(m['category'] == c for m in ITEMS.values())]
    scope_text = '%s Unix — %s~%s (%d개 항목: %s)' % (
        EDITION, implemented[0], implemented[-1], len(implemented), '·'.join(categories))

    cover['contents'] = list(cover.get('contents') or []) + [
        'Configuration Vulnerability — %s, 판정 5종(양호·취약·예외(승인)·해당없음·점검불가(수동)), CIS는 참조' % scope_text]
    model['cover'] = cover
    model['unavailable'] = unavailable
    model['config_vulnerability'] = {
        'edition': EDITION,
        'scope': scope_text,
        'verdicts': VERDICTS,
        'verdict_classes': [VERDICT_CLASSES[v] for v in VERDICTS],
        'hosts_checked': len(by_host),
        'totals': [totals[v] for v in VERDICTS],
        'summary': summary,
        'findings': findings,
        'remediation_source': REMEDIATION_SOURCE,
        'appendix': appendix,
        'register': _register_rows(register, applied, today),
        'run_date': today,
    }
    return model


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_kisa_result': host_audit_kisa_result,
            'host_audit_kisa_run_date': run_date,
        }
