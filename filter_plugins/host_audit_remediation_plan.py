"""Remediation Plan rows of Host Audit (Spec #488 / Ticket-6, #494; docs/host_audit.md section 17).

Pure filters: the report model of a run and one Inventory Hostname go in, the header, the rows and the footer lines of
that host's Remediation Plan sheet come out. Nothing is read from anywhere else (no file, no lookup, no secret), and
every cell is made of strings the report model or the item catalog already holds (the cell source rule). Writing
the bytes is the job of the ``host_audit_xlsx_write`` module.

Entry points:
  host_audit_remediation_plan       (filter) model, host -> {'sheet', 'headers', 'widths', 'rows', 'footer'}
  host_audit_remediation_plans      (filter) model -> the plan of every host with its file name (AUD-025)
  host_audit_remediation_file_name  (filter) run id, host -> ``host-audit-<run_id>-<inventory_hostname>.xlsx``
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_kisa import (  # noqa: E402
    EXCEPTION, ITEMS, MANUAL, REGISTER_ACTIVE, REGISTER_EXPIRED, REGISTER_PENDING, REMEDIATION_SOURCE,
    order_findings)
from host_audit_baseline import NEW, PERSIST, RECUR  # noqa: E402

SHEET = '이행계획서'
# SolidStep 이행계획서 column order. 구현내용 is three columns.
HEADERS = ['그룹', '자산명', '담당자', '통제내용', '취약점현황', '점검방법', '조치방법', '위험도', '이행과제', '시급성',
           '영향도', '환경성', '우선순위', '이행 결과', '비고']
WIDTHS = [14, 12, 14, 32, 40, 40, 60, 8, 24, 8, 8, 8, 8, 24, 48]
NO_FINDINGS = '양호 외 항목 없음'
NO_RESULT = '점검 결과 없음(점검불가)'
UNASSIGNED = '미지정'  # the Asset Inventory label when the host has no declared value (same as the report)
FILE_NAME = 'host-audit-%s-%s.xlsx'
BASELINE_PREFIXED = (NEW, PERSIST, RECUR)  # the only Audit Baseline states the remark shows (not 첫 실행 or others)
BLANK_DATE = '-'  # what the register table shows for a date that is absent or malformed


def _item(finding):
    """Catalog entry of a finding (its code is ``KISA-2026:U-NN``); {} for a code the catalog lacks."""
    return ITEMS.get(finding['code'].split(':', 1)[-1], {})


def _number(value):
    """Level cell: an integer, or blank for the None a code missing from the catalog gets from remediation_view."""
    return value if isinstance(value, int) else ''


def _admin_role(model, host):
    """The administrator role exactly as the Asset Inventory shows it ('미지정'/'조회 실패' included)."""
    for entry in ((model.get('asset_inventory') or {}).get('hosts') or []):
        if entry.get('host') == host:
            for field in entry.get('declared') or []:
                if field.get('key') == 'admin_role':
                    return field.get('value') or UNASSIGNED
    return UNASSIGNED


def _family(model, host):
    for row in model.get('inventory') or []:
        if row.get('host') == host:
            return row.get('os_family') or ''
    return ''


def _remark(verdict, entry):
    """Audit Baseline state prefix plus the exception register state of one host row."""
    state = ((entry.get('baseline') or {}).get('status') or '')
    prefix = '[%s] ' % state if state in BASELINE_PREFIXED and verdict != MANUAL else ''
    exc = entry.get('exception') or {}
    text = ''
    if verdict == EXCEPTION and exc.get('state') == REGISTER_ACTIVE:
        text = '예외(승인) — 사유: %s / 위험: %s / 보완: %s / 승인: %s %s / 만료: %s' % (
            exc['reason'], exc['risk'], exc['mitigation'], exc['approver'], exc['approved_on'] or BLANK_DATE,
            exc['expires_on'] or BLANK_DATE)
    elif exc.get('state') == REGISTER_EXPIRED:
        text = '예외 만료(%s)' % (exc['expires_on'] or BLANK_DATE)
    elif exc.get('state') == REGISTER_PENDING:
        text = '예외 승인 대기'
    return (prefix + text).strip()


def _steps(finding, family):
    """Steps of the host's OS family, else the summary shared by every family."""
    rem = _item(finding).get('remediation') or {}
    return (rem.get('steps') or {}).get(family, '').strip() or finding['remediation_summary']


def _status(finding, entry):
    cell = '%s: %s' % (finding['verdict'], entry['evidence'])
    return cell + '\n' + entry['note'] if entry.get('note') else cell


def _plan(rows, host, run_id, admin):
    if not rows:
        rows = [['', host, admin, NO_FINDINGS] + [''] * (len(HEADERS) - 4)]
    return {'sheet': SHEET, 'headers': list(HEADERS), 'widths': list(WIDTHS), 'rows': rows,
            'footer': [REMEDIATION_SOURCE, '실행 ID: %s' % run_id]}


def host_audit_remediation_plan(model, host):
    """Rows of one host's Remediation Plan: every item that is not 양호 (and not 해당없음), in priority order."""
    model = model or {}
    cv = model.get('config_vulnerability') or {}
    run_id = (model.get('cover') or {}).get('run_id', '')
    admin = _admin_role(model, host)
    if host not in (cv.get('appendix') or {}):
        row = ['', host, admin, NO_RESULT] + [''] * (len(HEADERS) - 4)
        return _plan([row], host, run_id, admin)
    family = _family(model, host)
    mine = [dict(finding, entry=entry) for finding in cv.get('findings') or []
            for entry in finding.get('hosts') or [] if entry.get('host') == host]
    rows = []
    # Same key as the HTML table (order_findings: priority, impact, effort, verdict, code).
    for finding in order_findings(mine):
        entry = finding['entry']
        values = {
            '그룹': finding['category'], '자산명': host, '담당자': admin,
            '통제내용': '%s %s' % (finding['code'].split(':', 1)[-1], finding['title']),
            '취약점현황': _status(finding, entry), '점검방법': _item(finding).get('check', ''),
            '조치방법': _steps(finding, family),
            '위험도': _number(finding['risk']), '이행과제': '', '시급성': finding['urgency'] or '',
            '영향도': _number(finding['impact_level']), '환경성': _number(finding['effort_level']),
            '우선순위': _number(finding['priority']), '이행 결과': '', '비고': _remark(finding['verdict'], entry),
        }
        rows.append([values[h] for h in HEADERS])
    return _plan(rows, host, run_id, admin)


def host_audit_remediation_plans(model):
    """The plan of every host of the run (one evaluation for AUD-025), each with its ``host`` and ``file_name``."""
    model = model or {}
    run_id = (model.get('cover') or {}).get('run_id', '')
    return [dict(host_audit_remediation_plan(model, host), host=host,
                 file_name=host_audit_remediation_file_name(run_id, host)) for host in model.get('hosts') or []]


def host_audit_remediation_file_name(run_id, host):
    """ASCII file name of a host's xlsx; anything outside [A-Za-z0-9._-] in the parts becomes '_'."""
    safe = re.compile(r'[^A-Za-z0-9._-]')
    return FILE_NAME % (safe.sub('_', str(run_id)), safe.sub('_', str(host)))


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_remediation_plan': host_audit_remediation_plan,
            'host_audit_remediation_plans': host_audit_remediation_plans,
            'host_audit_remediation_file_name': host_audit_remediation_file_name,
        }
