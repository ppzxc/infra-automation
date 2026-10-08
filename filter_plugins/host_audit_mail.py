"""Host Audit mail filters (ADR-0009 §6, #126).

After the run is kept in the Host Audit bucket, the runner mails a short summary
(inline-CSS table, no images or SVG — Gmail and Outlook drop them) with the A4
report attached as one self-contained ``.html`` whose file name is ASCII. The body
carries the SHA-256 of the attachment and where the original is kept, so a reader
can check the attachment against the archive.

The summary is a plain dict saved next to the report as ``mail_summary.json`` and
kept with the run. A resend reads it back from the bucket, so the same report is
sent again without re-auditing and the hash stays identical.

Recipients and the sender are personal data: they never enter the summary, the
report, the per-host JSON or the run metadata, and every error text that could
carry them goes through ``host_audit_mail_redact`` before it is shown.
"""

import re
from datetime import datetime, timezone

try:
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - pytest without ansible
    AnsibleFilterError = ValueError

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

SUMMARY_SCHEMA_VERSION = 1
REPORT_TIMEZONE = 'Asia/Seoul'
REDACTED = '<수신자>'
# community.general.mail's success exit message (an exit with refused recipients says otherwise).
SENT_MSG = 'Mail sent successfully'

# Deliberately simple: one @, no spaces or angle brackets, a dot in the domain.
# The relay is the authority on deliverability; this only catches typos and junk.
_ADDRESS = re.compile(r'^[^@\s<>,;"]+@[^@\s<>,;"]+\.[^@\s<>,;".]+$')
_SPLIT = re.compile(r'[,;\s]+')
# 'ha-20261001T070000Z' — the default run id is the UTC start time (prepare.yml AUD-003).
_RUN_ID_STAMP = re.compile(r'(\d{8}T\d{6}Z)')
_SAFE_RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')

LEVEL_CRIT = 'crit'
LEVEL_WARN = 'warn'
LEVEL_OK = 'ok'
LEVEL_NA = 'na'


def host_audit_mail_recipients(value):
    """Normalize a recipient setting into ``{'addresses': [...], 'invalid': n}``.

    Accepts a list or a string separated by commas, semicolons or white space
    (OpenBao KV values are often one string). Duplicates are dropped case-
    insensitively, order kept. Invalid entries are only counted — never echoed,
    since they are still someone's address.
    """
    if value is None:
        items = []
    elif isinstance(value, (list, tuple)):
        items = []
        for v in value:
            items.extend(_SPLIT.split(str(v or '')))
    else:
        items = _SPLIT.split(str(value))
    addresses, seen, invalid = [], set(), 0
    for item in items:
        item = item.strip()
        if not item:
            continue
        if not _ADDRESS.match(item):
            invalid += 1
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        addresses.append(item)
    return {'addresses': addresses, 'invalid': invalid}


def host_audit_mail_redact(text, addresses):
    """Replace every recipient/sender address (and bare local part@domain) in ``text``."""
    text = '' if text is None else str(text)
    for address in sorted({a for a in (addresses or []) if a}, key=len, reverse=True):
        text = re.sub(re.escape(address), REDACTED, text, flags=re.IGNORECASE)
    # Anything else shaped like an address (e.g. a rewritten envelope) is hidden too.
    return re.sub(r'[^@\s<>\'",;:()\[\]]+@[^@\s<>\'",;:()\[\]]+', REDACTED, text)


def host_audit_mail_attachment_name(run_id):
    """ASCII file name of the attachment: ``host-audit-<run_id>.html``."""
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', str(run_id or 'report')).strip('-.') or 'report'
    return 'host-audit-%s.html' % safe


def host_audit_mail_resend_prefix(run_id, month='', tz_name=REPORT_TIMEZONE):
    """Bucket prefix ``<YYYY-MM>/<run_id>/`` of an archived run.

    The month is the run start month in the report time zone (#125). It is read
    from the default run id (``ha-<UTC start>``); a run id without the stamp needs
    ``month`` (YYYY-MM). Raises AnsibleFilterError with an operator-readable message.
    """
    run_id = str(run_id or '').strip()
    if not _SAFE_RUN_ID.match(run_id):
        raise AnsibleFilterError('재발송할 실행 ID가 비었거나 형식이 맞지 않음(영문·숫자·._- 만 허용): %r' % run_id)
    month = str(month or '').strip()
    if month:
        if not re.match(r'^\d{4}-(0[1-9]|1[0-2])$', month):
            raise AnsibleFilterError('host_audit_resend_month는 YYYY-MM 형식이어야 함: %r' % month)
        return '%s/%s/' % (month, run_id)
    stamp = _RUN_ID_STAMP.search(run_id)
    if not stamp:
        raise AnsibleFilterError('실행 ID에서 시작 시각을 읽을 수 없음 — host_audit_resend_month(YYYY-MM)를 함께 지정: %s' % run_id)
    started = datetime.strptime(stamp.group(1), '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    if ZoneInfo is not None:
        started = started.astimezone(ZoneInfo(tz_name or REPORT_TIMEZONE))
    return '%s/%s/' % (started.strftime('%Y-%m'), run_id)


def _line(section, text, level):
    return {'section': section, 'text': text, 'level': level}


def _level(count, level_when_any=LEVEL_CRIT):
    return level_when_any if count else LEVEL_OK


def host_audit_mail_summary(model, report):
    """Build the mail summary (saved as ``mail_summary.json``) from the report model.

    ``report``: {'sha256', 'file_name' (attachment name), 'archive' (where the
    original is kept), 'size'}. Only counts and host names go in — no addresses.
    """
    model = model or {}
    report = report or {}
    cover = model.get('cover') or {}
    summary = model.get('summary') or {}
    lines = []

    unavailable = model.get('unavailable') or []
    lines.append(_line('점검불가', '%d건 (호스트·항목)' % len(unavailable), _level(len(unavailable), LEVEL_WARN)))

    ai = model.get('asset_inventory') or {}
    counts = ai.get('counts') or {}
    if counts:
        lines.append(_line('Asset Inventory', '지원 종료(EOS) OS %d대 · 선언 외 특수권한자 %d · 장기 미사용 계정 %d · 선언 미지정 호스트 %d' % (
            counts.get('eos', 0), counts.get('not_declared', 0), counts.get('inactive', 0),
            counts.get('unassigned_hosts', 0)),
            LEVEL_CRIT if counts.get('eos') or counts.get('not_declared') else
            (LEVEL_WARN if counts.get('inactive') or counts.get('unassigned_hosts') else LEVEL_OK)))

    cv = model.get('config_vulnerability') or {}
    if cv.get('verdicts'):
        totals = dict(zip(cv.get('verdicts') or [], cv.get('totals') or []))
        vuln = totals.get('취약', 0)
        lines.append(_line('Configuration Vulnerability', '%s — 취약 %d · 점검불가(수동) %d · 예외(승인) %d (호스트 %d대)' % (
            cv.get('edition', 'KISA'), vuln, totals.get('점검불가(수동)', 0), totals.get('예외(승인)', 0),
            cv.get('hosts_checked', 0)), _level(vuln)))

    pv = model.get('package_vulnerability') or {}
    if pv:
        if pv.get('status') != 'ok':
            lines.append(_line('Package Vulnerability', '점검불가 — %s' % (pv.get('reason') or '-'), LEVEL_NA))
        else:
            totals = pv.get('totals') or {}
            classes = pv.get('classes') or {}
            crit_high = totals.get('CRITICAL', 0) + totals.get('HIGH', 0)
            text = '긴급 %d · 높음 %d · 중간 %d · 낮음 %d (전체 %d)' % (
                totals.get('CRITICAL', 0), totals.get('HIGH', 0), totals.get('MEDIUM', 0),
                totals.get('LOW', 0), pv.get('total', 0))
            if pv.get('db_label'):
                text += ' · DB %s' % pv['db_label']
            lines.append(_line('Package Vulnerability', text, _level(crit_high)))
            if classes:
                lines.append(_line('', '수정 분류: ' + ' · '.join(
                    '%s %d' % (row.get('label', row.get('key')), row.get('count', 0))
                    for row in pv.get('class_rows') or []), LEVEL_NA))

    cd = model.get('configuration_drift') or {}
    if cd:
        rows = cd.get('rows') or []
        failed = [s.get('label', s.get('key')) for s in cd.get('subruns') or [] if s.get('status') == 'error']
        text = 'Drift 호스트 %d대 · 바뀔 태스크 %d건' % (cd.get('hosts_with_drift', 0), len(rows))
        if failed:
            text += ' · 하위 실행 점검불가: %s' % ', '.join(failed)
        lines.append(_line('Configuration Drift', text, LEVEL_WARN if rows or failed else LEVEL_OK))

    bl = model.get('baseline') or {}
    if bl:
        if bl.get('failed'):
            lines.append(_line('Audit Baseline', '비교 기준 조회 실패 — %s' % (bl.get('reason') or '-'), LEVEL_WARN))
        elif bl.get('compared'):
            statuses = bl.get('statuses') or []
            agg = dict((s, 0) for s in statuses)
            for row in bl.get('count_rows') or []:
                for s, c in zip(statuses, row.get('counts') or []):
                    agg[s] = agg.get(s, 0) + c
            text = '기준 %s — %s' % (bl.get('baseline_run_id', ''), ' · '.join('%s %d' % (s, agg[s]) for s in statuses))
            lines.append(_line('Audit Baseline', text,
                               LEVEL_CRIT if agg.get('재발') or agg.get('신규') else LEVEL_OK))
        elif bl.get('state') == 'ok':
            lines.append(_line('Audit Baseline', '첫 정기 실행 — 비교 기준 없음', LEVEL_NA))

    eos = [{'host': e.get('host', ''), 'os': e.get('os', ''), 'date': e.get('date', '')}
           for e in (ai.get('eos') or [])][:20]

    run_kind = cover.get('run_kind', '')
    cv_vuln = dict(zip(cv.get('verdicts') or [], cv.get('totals') or [])).get('취약', 0)
    pv_ch = ((pv.get('totals') or {}).get('CRITICAL', 0) + (pv.get('totals') or {}).get('HIGH', 0)) if pv.get('status') == 'ok' else None
    subject = '[Host Audit] %s 점검 보고서 %s — 취약 %d · 긴급/높음 %s · 점검불가 %d' % (
        run_kind, (cover.get('started_at') or '').split(' ')[0], cv_vuln,
        '-' if pv_ch is None else pv_ch, len(unavailable))

    return {
        'schema_version': SUMMARY_SCHEMA_VERSION,
        'subject': subject,
        'title': model.get('title', 'Host Audit 점검 보고서'),
        'run_id': cover.get('run_id', ''),
        'run_kind': run_kind,
        'started_at': cover.get('started_at', ''),
        'generated_at': cover.get('generated_at', ''),
        'scope': cover.get('scope', ''),
        'baseline': cover.get('baseline', ''),
        'hosts': {
            'total': summary.get('hosts_total', 0),
            'inspected': summary.get('hosts_inspected', 0),
            'unavailable': summary.get('hosts_unavailable', 0),
        },
        'lines': lines,
        'eos': eos,
        'report': {
            'file_name': report.get('file_name') or host_audit_mail_attachment_name(cover.get('run_id')),
            'sha256': (report.get('sha256') or '').lower(),
            'size': int(report.get('size') or 0),
            'archive': report.get('archive') or cover.get('archive', ''),
        },
    }


def host_audit_mail_resend_summary(summary, run_id, archive, sha256, size=0):
    """Summary for a resend: the kept one (marked as resent), or a minimal one if it is missing."""
    if isinstance(summary, dict) and summary.get('schema_version'):
        out = dict(summary)
        out['subject'] = '[재발송] ' + str(summary.get('subject') or '')
        out['resent'] = True
        out['report'] = dict(summary.get('report') or {})
        out['report']['archive'] = archive
        return out
    return {
        'schema_version': SUMMARY_SCHEMA_VERSION,
        'subject': '[재발송] [Host Audit] 점검 보고서 %s' % run_id,
        'title': 'Host Audit 점검 보고서',
        'run_id': run_id,
        'run_kind': '',
        'started_at': '',
        'generated_at': '',
        'scope': '',
        'baseline': '',
        'hosts': {},
        'lines': [_line('요약', '보관된 요약(mail_summary.json)이 없어 첨부 보고서만 다시 보냄', LEVEL_NA)],
        'eos': [],
        'resent': True,
        'report': {
            'file_name': host_audit_mail_attachment_name(run_id),
            'sha256': (sha256 or '').lower(),
            'size': int(size or 0),
            'archive': archive,
        },
    }


def host_audit_mail_outcome(result, addresses):
    """Judge a community.general.mail result: ``{'sent': bool, 'error': redacted text}``.

    The module exits OK with a non-empty ``result`` dict when some recipients were
    refused — that is a failure too. Error texts quote addresses, so they are redacted.
    """
    result = result or {}
    if result.get('skipped'):
        return {'sent': False, 'error': ''}
    if 'results' in result:  # one send per recipient (loop)
        judged = [host_audit_mail_outcome(r, addresses) for r in result.get('results') or []]
        failed = [j for j in judged if not j['sent']]
        if not judged:
            return {'sent': False, 'error': '보낸 메일 없음'}
        if failed:
            return {'sent': False, 'error': '수신자 %d명 중 %d명 실패 — %s' % (len(judged), len(failed), failed[0]['error'])}
        return {'sent': True, 'error': ''}
    refused = result.get('result') or {}
    if result.get('failed') or result.get('rc'):
        return {'sent': False, 'error': host_audit_mail_redact(result.get('msg') or '메일 전송 실패', addresses)}
    if refused:
        codes = sorted({str((v or [''])[0]) for v in refused.values()})
        return {'sent': False, 'error': '수신자 %d명 거부(SMTP %s)' % (len(refused), ', '.join(codes))}
    # Only the module's own success exit counts as sent (a result reshaped by failed_when would not).
    if result.get('msg') != SENT_MSG:
        return {'sent': False, 'error': host_audit_mail_redact(result.get('msg') or '메일 모듈 오류(SMTP 접속 실패·시간 초과 등 — 모듈이 성공을 알리지 않음)', addresses)}
    return {'sent': True, 'error': ''}


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_mail_recipients': host_audit_mail_recipients,
            'host_audit_mail_redact': host_audit_mail_redact,
            'host_audit_mail_attachment_name': host_audit_mail_attachment_name,
            'host_audit_mail_resend_prefix': host_audit_mail_resend_prefix,
            'host_audit_mail_summary': host_audit_mail_summary,
            'host_audit_mail_resend_summary': host_audit_mail_resend_summary,
            'host_audit_mail_outcome': host_audit_mail_outcome,
        }
