"""Remediation Plan rows of Host Audit (Spec #488 / Ticket-6, #494; docs/host_audit.md section 17).

Pure filters: the report model of a run and one Inventory Hostname go in, the header, the rows and the footer lines of
that host's Remediation Plan sheet come out. Nothing is read from anywhere else (no file, no lookup, no secret), and
every cell is made of strings the report model or the item catalog already holds (the cell source rule). Writing
the bytes is the job of the ``host_audit_xlsx_write`` module.

Entry points:
  host_audit_remediation_plan       (filter) model, host -> {'sheet', 'headers', 'widths', 'rows', 'footer'}
  host_audit_remediation_plans      (filter) model -> the plan of every host with its file name (AUD-025)
  host_audit_remediation_files      (filter) model -> ``{file_name: plan}`` of every xlsx of the run (hosts and total)
  host_audit_remediation_zip_members (filter) that map -> ``{file_name: name inside the zip}`` (``total.xlsx``, ``hosts/<host>.xlsx``)
  host_audit_remediation_file_name  (filter) run id, host -> ``host-audit-<run_id>-<inventory_hostname>.xlsx``
  host_audit_remediation_zip_name   (filter) run id -> ``host-audit-<run_id>-xlsx.zip``
"""

import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_kisa import (  # noqa: E402
    BLANK, EXCEPTION, ITEMS, MANUAL, REGISTER_ACTIVE, REGISTER_EXPIRED, REGISTER_PENDING, REMEDIATION_SOURCE,
    order_findings)
from host_audit_baseline import NEW, PERSIST, RECUR  # noqa: E402
from host_audit_inventory import LOOKUP_FAILED, UNASSIGNED  # noqa: E402  (the Asset Inventory labels)
from host_audit_unsafe import unsafe as _unsafe  # noqa: E402

SHEET = '이행계획서'
# SolidStep 이행계획서 column order. 구현내용 is three columns.
HEADERS = ['그룹', '자산명', '담당자', '통제내용', '취약점현황', '점검방법', '조치방법', '위험도', '이행과제', '시급성',
           '영향도', '환경성', '우선순위', '이행 결과', '비고']
WIDTHS = [14, 12, 14, 32, 40, 40, 60, 8, 24, 8, 8, 8, 8, 24, 48]
COL = dict((name, i) for i, name in enumerate(HEADERS))
NO_FINDINGS = '양호 외 항목 없음'
NO_RESULT = '점검 결과 없음(점검불가)'
PLAN_FAILED = '이행계획서 생성 실패'
UNKNOWN_ITEM = '(카탈로그에 없는 항목)'
FILE_NAME = 'host-audit-%s-%s.xlsx'
ZIP_NAME = 'host-audit-%s-xlsx.zip'
TOTAL_LABEL = '합계 xlsx'  # what a failure message calls the total (a host may be named ``total``; Inventory Hostnames
# are ASCII management numbers, so no host is named like this label)
TOTAL_PART = 'total'  # the name part of the total workbook: ``host-audit-<run_id>-total.xlsx``
TOTAL_MEMBER = 'total.xlsx'  # the folder names exist only inside the zip: the files on disk stay flat in xlsx/
HOST_MEMBER = 'hosts/%s.xlsx'
MAX_NAME_PART = 80  # characters of the run id and of the host name kept in the file name
BASELINE_PREFIXED = (NEW, PERSIST, RECUR)  # the only Audit Baseline states the remark shows (not 첫 실행 or others)


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
                    if field.get('state') == 'unassigned' and not _inspected(model, host):
                        # A host that was not reached has no declaration to read (its record is empty or missing):
                        # that is no data, not "nobody assigned".
                        return LOOKUP_FAILED
                    return field.get('value') or UNASSIGNED
    return LOOKUP_FAILED  # the Asset Inventory has no entry for the host: no data, not "nobody assigned"


def _inspected(model, host):
    for row in model.get('inventory') or []:
        if row.get('host') == host:
            return bool(row.get('inspected'))
    return False


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
            exc.get('reason') or BLANK, exc.get('risk') or BLANK, exc.get('mitigation') or BLANK,
            exc.get('approver') or BLANK, exc.get('approved_on') or BLANK, exc.get('expires_on') or BLANK)
    elif exc.get('state') == REGISTER_EXPIRED:
        text = '예외 만료(%s)' % (exc.get('expires_on') or BLANK)
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


def _plan(rows, host, run_id, admin, kind='items'):
    """One sheet. ``kind`` tells the total how to take it: items, clean (the one 양호 외 항목 없음 line), no_result
    (점검 결과 없음) or failed (the plan could not be built)."""
    if not rows:
        rows = [['', host, admin, NO_FINDINGS] + [''] * (len(HEADERS) - 4)]
        kind = 'clean'
    # Cells hold host evidence and register text. They go to the writer module as task arguments, which Ansible
    # templates, so the rows are marked unsafe: '{{ ... }}' in a cell stays text (needed before ansible-core 2.19).
    return {'sheet': SHEET, 'headers': list(HEADERS), 'widths': list(WIDTHS), 'rows': _unsafe(rows),
            'footer': _unsafe([REMEDIATION_SOURCE, '실행 ID: %s' % run_id]), 'kind': kind}


def _host_findings(model, host):
    """The findings of one host (each with its host ``entry``), in priority order (same key as the HTML table)."""
    cv = model.get('config_vulnerability') or {}
    mine = [dict(finding, entry=entry) for finding in cv.get('findings') or []
            for entry in finding.get('hosts') or [] if entry.get('host') == host]
    return order_findings(mine)


def _row(finding, host, admin, family):
    entry = finding['entry']
    values = {
        '그룹': finding['category'], '자산명': host, '담당자': admin,
        '통제내용': ('%s %s' % (finding['code'].split(':', 1)[-1], finding['title'])) if _item(finding)
        else '%s %s' % (finding['code'].split(':', 1)[-1], UNKNOWN_ITEM),
        '취약점현황': _status(finding, entry), '점검방법': _item(finding).get('check', ''),
        '조치방법': _steps(finding, family),
        '위험도': _number(finding['risk']), '이행과제': '', '시급성': finding['urgency'] or '',
        '영향도': _number(finding['impact_level']), '환경성': _number(finding['effort_level']),
        '우선순위': _number(finding['priority']), '이행 결과': '', '비고': _remark(finding['verdict'], entry),
    }
    return [values[h] for h in HEADERS]


def host_audit_remediation_plan(model, host):
    """Rows of one host's Remediation Plan: every item that is not 양호 (and not 해당없음), in priority order."""
    model = model or {}
    cv = model.get('config_vulnerability') or {}
    run_id = (model.get('cover') or {}).get('run_id', '')
    admin = _admin_role(model, host)
    if host not in (cv.get('appendix') or {}):
        row = ['', host, admin, NO_RESULT] + [''] * (len(HEADERS) - 4)
        return _plan([row], host, run_id, admin, 'no_result')
    family = _family(model, host)
    rows = [_row(finding, host, admin, family) for finding in _host_findings(model, host)]
    return _plan(rows, host, run_id, admin)


def _failed_plan(model, host, run_id, exc):
    """The one-line plan of a host whose plan could not be built (the error text is unsafe-marked like the cells)."""
    error = '%s: %s' % (type(exc).__name__, str(exc)[:200])
    try:
        admin = _admin_role(model, host)
    except Exception:  # the lookup itself may be what broke
        admin = LOOKUP_FAILED
    row = ['', host, admin, '%s (%s)' % (PLAN_FAILED, error)] + [''] * (len(HEADERS) - 4)
    # error is exception text that can echo record data: marked unsafe like the cells (it is templated later)
    return dict(_plan([row], host, run_id, '', 'failed'), error=_unsafe(error))


def host_audit_remediation_plans(model):
    """The plan of every host of the run (one evaluation for AUD-025), each with its ``host`` and ``file_name``."""
    model = model or {}
    run_id = (model.get('cover') or {}).get('run_id', '')
    plans = []
    for host in model.get('hosts') or []:
        try:
            plan = host_audit_remediation_plan(model, host)
        except Exception as exc:  # one odd record must not stop the evidence of every other host
            plan = _failed_plan(model, host, run_id, exc)
        plans.append(dict(plan, host=host, label=host, file_name=host_audit_remediation_file_name(run_id, host),
                          zip_member=HOST_MEMBER % _host_part(host)))
    return plans


def _level(row):
    """Sort key of a row: the levels as in order_findings (a blank level sorts last)."""
    return tuple(row[COL[name]] or 9 for name in ('우선순위', '영향도', '환경성'))


def _total(plans, run_id):
    """The ``total`` plan made of the plans of the hosts (their rows, so a host has the same lines in both files).

    Items are sorted by priority, impact and effort, ties by host name and item code (the decision of #488's total
    workbook; a host's own sheet also orders equal levels by verdict, which the total leaves out). A host that has no
    check result or whose plan could not be built keeps its one line after the items: it is not clean. A clean host adds
    nothing, and when no host has an item or a line the sheet has the one line 양호 외 항목 없음.
    """
    items = [row for plan in plans if plan['kind'] == 'items' for row in plan['rows']]
    items.sort(key=lambda row: (_level(row), row[COL['자산명']], row[COL['통제내용']].split(' ', 1)[0]))
    rows = items + [plan['rows'][0] for plan in plans if plan['kind'] in ('no_result', 'failed')]
    if not rows:
        rows = [[''] * 3 + [NO_FINDINGS] + [''] * (len(HEADERS) - 4)]
    return dict(_plan(rows, '', run_id, ''), label=TOTAL_LABEL, file_name=host_audit_remediation_total_file_name(run_id),
                zip_member=TOTAL_MEMBER)


def host_audit_remediation_files(model):
    """``{file_name: plan}`` of every xlsx of the run (AUD-025, AUD-026): each host's plan and the total, one evaluation."""
    model = model or {}
    # one plan per file: a host listed twice gets one file, and its rows are not counted twice in the total.
    # (_total only sorts the strings and numbers that _row already normalized, so it has no guard of its own.)
    files = dict((plan['file_name'], plan) for plan in host_audit_remediation_plans(model))
    plans = list(files.values())
    if plans:
        total = _total(plans, (model.get('cover') or {}).get('run_id', ''))
        files[total['file_name']] = total
    return files


def host_audit_remediation_zip_members(files):
    """``{file_name: name inside the zip}`` of every xlsx of the run."""
    return dict((name, plan['zip_member']) for name, plan in files.items())


def _name_part(value):
    """A file name part: anything outside [A-Za-z0-9._-] becomes '_' and a short hash of the original keeps the name unique."""
    value = str(value)
    clean = re.sub(r'[^A-Za-z0-9._-]', '_', value)
    if len(clean) > MAX_NAME_PART:  # a file name must stay under the 255-byte limit
        clean = clean[:MAX_NAME_PART - 8]
        value = value + ' '  # forces the hash suffix below even when nothing was replaced
    # Names that differ only in replaced characters must not share a file (the last write would win).
    return clean if clean == value else '%s-%s' % (clean, hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:8])


def _host_part(host):
    """The name part of a host: ``_name_part``, and never the total's own part (a host called ``total`` must not take its file)."""
    part = _name_part(host)
    # lower(): a case-folding disk (a recipient's laptop) would also merge ``TOTAL`` with the total's file
    return part if part.lower() != TOTAL_PART else '%s-%s' % (part, hashlib.sha256(str(host).encode('utf-8', 'replace')).hexdigest()[:8])


def host_audit_remediation_file_name(run_id, host):
    """ASCII file name of a host's xlsx (``_name_part`` rule for both parts)."""
    return FILE_NAME % (_name_part(run_id), _host_part(host))


def host_audit_remediation_total_file_name(run_id):
    """ASCII file name of the total xlsx: ``host-audit-<run_id>-total.xlsx``."""
    return FILE_NAME % (_name_part(run_id), TOTAL_PART)


def host_audit_remediation_zip_name(run_id):
    """ASCII file name of the zip of every host's xlsx: ``host-audit-<run_id>-xlsx.zip`` (AUD-026)."""
    return ZIP_NAME % _name_part(run_id)


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_remediation_plan': host_audit_remediation_plan,
            'host_audit_remediation_plans': host_audit_remediation_plans,
            'host_audit_remediation_files': host_audit_remediation_files,
            'host_audit_remediation_zip_members': host_audit_remediation_zip_members,
            'host_audit_remediation_file_name': host_audit_remediation_file_name,
            'host_audit_remediation_zip_name': host_audit_remediation_zip_name,
        }
