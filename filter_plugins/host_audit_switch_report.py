"""Switch part of the Host Audit report model (Spec #568 / Ticket-5, #587).

``host_audit_switch_section`` adds ``switch_vulnerability`` to the report model from the per-switch records
(``device_type: SWITCH``, written by the switch phase, ``host_audit_switch``). It reuses the server code path for what is
the same by design: the five verdicts and their classes, the exception register rows, finding order and the finding
builder (``host_audit_kisa``). It never touches the server keys (``config_vulnerability``, ``hosts``, ``inventory`` ...):
the server part of the report stays as it was, and a model without switch input gets no ``switch_vulnerability`` key.

The item list is the registry ``host_audit_switch.CHECKS`` (title, severity and category come from there; nothing here
counts items). The text the report adds per item (criteria and a short IOS remediation summary) is
``host_audit_switch_items.yml``, read only for registered codes; a registered code without an entry shows a blank, never
an error.
"""

import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_audit_switch as switch  # noqa: E402
from host_audit_kisa import (  # noqa: E402
    EDITION, GOOD, NOT_APPLICABLE, REGISTER_ACTIVE, REGISTER_EXPIRED, REGISTER_PENDING, REMEDIATION_SOURCE,
    STATUS_OK, VERDICT_CLASSES, VERDICTS, _build_findings, _is_switch_entry, _item_meta, _register_rows, full_code, run_date,
)

DEVICE_TYPE = 'SWITCH'
ITEM_LABEL = '스위치 전체 점검'
CATALOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'host_audit_switch_items.yml')
STATUS_LABELS = {  # the same words as the server rows (host_audit.STATUS_LABELS)
    'ok': '점검 완료',
    'unreachable': '점검불가(접속 실패)',
    'probe_failed': '점검불가(수집 실패)',
    'no_record': '점검불가(접속 준비 실패)',
}
NO_RECORD_REASON = '스위치 점검 단계에서 기록을 남기지 못함 (Semaphore 로그 참고)'


def _load_catalog(path=CATALOG_PATH):
    with open(path, encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


CATALOG = _load_catalog()


def switch_items():
    """Items of the registry in the shape the server builders read (``ITEMS``-like), codes as ``N-NN``."""
    items = {}
    for code, meta in switch.CHECKS.items():
        text = CATALOG.get(code) or {}
        items[code] = {
            'title': meta['title'], 'severity': meta['severity'], 'category': meta['category'],
            'criteria': text.get('criteria', ''), 'cis': '',
            'remediation': {'summary': text.get('remediation', '')},
            'remediation_impact': {'level': None}, 'remediation_effort': {'level': None},
        }
    return items


def _row(host, record):
    status = (record or {}).get('status') or 'no_record'
    part = (record or {}).get('config_vulnerability') or {}
    inspected = status == 'ok' and part.get('status') == STATUS_OK
    info = (record or {}).get('switch') or {}
    return {
        'host': host,
        'status': status,
        'status_label': STATUS_LABELS.get(status, STATUS_LABELS['no_record']),
        'inspected': inspected,
        'role': info.get('role') or '-',
        'version': info.get('version') or '-',
        'access': info.get('access') or '-',
        'reason': (record or {}).get('reason') or (NO_RECORD_REASON if not record else '-'),
    }


def _guide(findings, items):
    blocks = {}
    for f in findings:
        block = blocks.get(f['code'])
        if block is None:
            meta = items.get(f['code'].split(':', 1)[-1]) or {}
            block = {'code': f['code'], 'title': f['title'], 'severity': f['severity'], 'criteria': f['criteria'],
                     'summary': (meta.get('remediation') or {}).get('summary', ''), 'verdict_hosts': []}
            blocks[f['code']] = block
        block['verdict_hosts'].append({'verdict': f['verdict'], 'verdict_class': f['verdict_class'],
                                       'hosts': [h['host'] for h in f['hosts']]})
    return list(blocks.values())


def host_audit_switch_section(model, records, targets=None, register=None, today=None):
    """Return a copy of the report model with the switch part (or the model itself when there is no switch input).

    ``records`` are the per-switch records, ``targets`` every switch selected for the run (a target without a record is
    reported as not inspected, never dropped), ``register`` the exception register (only ``N-NN`` entries are read).
    Switches that were not inspected are added to the model's 점검불가 list (item ``스위치 전체 점검``).
    """
    by_host = {r['inventory_hostname']: r for r in (records or [])
               if r.get('device_type') == DEVICE_TYPE and r.get('inventory_hostname')}
    hosts = sorted(set(targets or []) | set(by_host))
    if not hosts:
        return model
    today = today or run_date(None)
    items = switch_items()
    rows = [_row(host, by_host.get(host)) for host in hosts]
    unavailable = [{'host': r['host'], 'item': ITEM_LABEL, 'label': r['status_label'], 'reason': r['reason']}
                   for r in rows if not r['inspected']]

    results = {r['host']: by_host[r['host']]['config_vulnerability']['results'] for r in rows if r['inspected']}
    codes = sorted({full_code(c) for c in switch.CHECKS} | {it['code'] for items_ in results.values() for it in items_})
    counts = {code: dict.fromkeys(VERDICTS, 0) for code in codes}
    totals = dict.fromkeys(VERDICTS, 0)
    groups, applied, appendix = {}, {}, {}
    for host, host_results in results.items():
        table = []
        for it in host_results:
            verdict = it['verdict']
            counts[it['code']][verdict] += 1
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
                groups.setdefault((it['code'], verdict), []).append(
                    {'host': host, 'evidence': it['evidence'], 'note': note, 'exception': dict(exc) if exc else None})
            table.append(dict(_item_meta(it['code'], items), verdict=verdict, verdict_class=VERDICT_CLASSES[verdict],
                              evidence=it['evidence'], note=note))
        appendix[host] = table

    findings = _build_findings(groups, items)
    categories = []
    for meta in switch.CHECKS.values():
        if meta['category'] not in categories:
            categories.append(meta['category'])
    registered = sorted(switch.CHECKS)
    scope_text = ('%s 네트워크 장비 — %s~%s (%d개 항목: %s)' % (
        EDITION, registered[0], registered[-1], len(registered), '·'.join(categories))) if registered else EDITION

    model = dict(model or {})
    cover = dict(model.get('cover') or {})
    cover['switch_scope'] = 'cisco_switches — %d대' % len(hosts)
    cover['out_of_scope'] = '방화벽 등 Linux 서버·스위치 외 자산'
    cover['contents'] = list(cover.get('contents') or []) + [
        'Configuration Vulnerability (스위치) — %s, 판정 5종, 읽기 전용 show 명령' % scope_text]
    model['cover'] = cover
    model['summary'] = dict(model.get('summary') or {}, switch={
        'hosts_total': len(rows),
        'hosts_inspected': sum(1 for r in rows if r['inspected']),
        'hosts_unavailable': sum(1 for r in rows if not r['inspected']),
    })
    model['unavailable'] = list(model.get('unavailable') or []) + unavailable
    model['switch_vulnerability'] = {
        'edition': EDITION,
        'scope': scope_text,
        'rows': rows,
        'hosts': [r['host'] for r in rows if r['inspected']],
        'unavailable': unavailable,
        'hosts_checked': len(results),
        'verdicts': VERDICTS,
        'verdict_classes': [VERDICT_CLASSES[v] for v in VERDICTS],
        'totals': [totals[v] for v in VERDICTS],
        'summary': [dict(_item_meta(code, items), counts=[counts[code][v] for v in VERDICTS]) for code in codes],
        'findings': findings,
        'remediation_guide': _guide(findings, items),
        'remediation_source': REMEDIATION_SOURCE,
        'appendix': appendix,
        'register': _register_rows([e for e in (register or []) if _is_switch_entry(e)],
                                   applied, today),
        'run_date': today,
    }
    return model


class FilterModule(object):
    def filters(self):
        return {'host_audit_switch_section': host_audit_switch_section}
