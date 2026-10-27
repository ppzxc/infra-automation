"""Host Audit Security Regression section (Spec #364 / Ticket-10, #377).

The spec #364 hardening expectations (management web loopback bind, receiver and SSH source restriction, detection
and log retention, backup key policy, secret file permissions) are checked again on every Host Audit run. Items are
read-only and the result carries item ids and verdicts only: no address, port, path or secret value.

Public entry points:
  host_audit_regression_env      declared expectations -> {ENV_VAR: value} for the probe (safe tokens only)
  host_audit_regression_result   registered raw probe -> the ``security_regression`` part of a per-host record
  host_audit_regression_backup   repo policy JSON + collector snapshot text -> the run-level backup policy items
  host_audit_regression_section  records + backup items -> report model section (and Audit Baseline findings)
"""

import ast
import json
import re

PASS, FAIL, NA, UNKNOWN = '통과', '실패', '해당없음', '점검불가'
VERDICTS = [FAIL, UNKNOWN, PASS, NA]
VERDICT_CLASSES = {FAIL: 'crit', UNKNOWN: 'na', PASS: 'ok', NA: 'na'}
RAW = {'PASS': PASS, 'FAIL': FAIL, 'UNK': UNKNOWN}
STATUS_OK, STATUS_FAILED = 'ok', 'probe_failed'
BACKUP_HOST = 'backup-storage'
SECTION = 'security_regression'
BEGIN, END = '__HOST_AUDIT_REGRESSION_BEGIN__', '__HOST_AUDIT_REGRESSION_END__'

# area, title, criteria, expectation keys that declare the item (any of them)
ITEMS = {}


def _item(code, area, title, criteria, keys=()):
    ITEMS[code] = {'code': code, 'area': area, 'title': title, 'criteria': criteria, 'keys': tuple(keys)}


_item('EXP-MGMT-1', '관리 웹 접점', '관리 웹 접점은 루프백에만 바인드',
      '선언한 관리 웹 접점 중 루프백 밖 주소에 열린 것이 없다', ['mgmt_web_ports'])
_item('EXP-MGMT-2', '관리 웹 접점', '모든 주소 청취는 허용 목록(프록시 경로)뿐',
      '모든 주소에서 청취하는 접점이 선언한 허용 목록 안에 있다', ['mgmt_wildcard_allowed'])
_item('EXP-MGMT-3', '관리 웹 접점', '제거한 관리 인터페이스가 다시 올라오지 않음',
      '제거 목록의 게시 포트·컨테이너·서비스가 없다', ['mgmt_removed_ports', 'mgmt_removed_names'])
_item('EXP-RECV-1', '수신 접점', '로그 수신 출발지 필터가 켜져 있음',
      '수신 설정에 출발지 필터 정의가 있고 log 경로에 연결돼 있다', ['recv_syslog_conf'])
_item('EXP-RECV-2', '수신 접점', '트랩 수신 인증이 켜져 있고 기본 허용이 꺼져 있음',
      '인증 지시어가 있고 disableAuthorization이 켜져 있지 않다', ['recv_trap_conf'])
_item('EXP-RECV-3', '수신 접점', '트랩 기본 인증 문자열이 없음',
      '인증 지시어에 흔한 기본 문자열(default-string)이 없다', ['recv_trap_conf'])
_item('EXP-SSH-1', '원격 접속', 'sshd 출발지 제한 블록이 있음',
      'sshd_config에 관리형 Match Address 블록과 DenyUsers *가 있다', ['ssh_restricted'])
_item('EXP-SSH-2', '원격 접속', '허용 목록 밖 출발지는 거부',
      'sshd -T -C 평가에서 허용 밖 출발지가 DenyUsers *로 나온다', ['ssh_restricted'])
_item('EXP-SSH-3', '원격 접속', '루프백과 허용 출발지는 거부되지 않음',
      'sshd -T -C 평가에서 루프백·선언한 허용 출발지가 거부되지 않는다', ['ssh_restricted'])
_item('EXP-SSH-4', '원격 접속', '허용 목록이 비어 있지 않음',
      'Match Address 블록에 루프백 외 제외 항목이 하나 이상 있다', ['ssh_restricted'])
_item('EXP-DET-1', '탐지·로그 보존', 'journald 영구 저장',
      'Storage=persistent(또는 auto)이고 영구 저널 디렉터리가 있다', ['det_journald'])
_item('EXP-DET-2', '탐지·로그 보존', 'fail2ban sshd jail 동작',
      'fail2ban-client status sshd가 성공한다', ['det_fail2ban', 'det_fail2ban_no_firewall'])
_item('EXP-DET-3', '탐지·로그 보존', 'fail2ban 차단 동작이 방화벽을 건드리지 않음',
      'sshd jail의 동작이 dummy뿐이다', ['det_fail2ban_no_firewall'])
_item('EXP-DET-4', '탐지·로그 보존', '감사 규칙 적재',
      'auditctl -l에 identity, auth_config, sudo_config, sshd_config 키가 있다', ['det_auditd', 'det_audit_secret'])
_item('EXP-DET-5', '탐지·로그 보존', '전체 execve 추적이 없음',
      '적재된 규칙이 있고 execve 규칙이 없다', ['det_auditd', 'det_audit_secret'])
_item('EXP-DET-6', '탐지·로그 보존', '시크릿 접근 감사 규칙',
      'auditctl -l에 secret_access 키가 있다', ['det_audit_secret'])
_item('EXP-DET-7', '탐지·로그 보존', '중앙 수집 에이전트 동작',
      '로그 수집 에이전트 서비스가 active다', ['det_log_agent'])
_item('EXP-BAK-1', '백업 정책', '저장소의 호스트 키 정책은 삭제를 locks/*에만 허용',
      'host-key-policy.json에 와일드카드 동작이 없고 삭제는 locks/* 하나뿐이다')
_item('EXP-BAK-2', '백업 정책', '서버의 호스트 키 정책이 저장소 정책과 같은 모양',
      '수집기 스냅샷의 모든 호스트 서비스 계정 정책이 host-key-policy.json과 같은 모양이다')
_item('EXP-BAK-3', '백업 정책', '호스트 키는 자기 버킷 하나에만 접근',
      '수집기 스냅샷의 모든 호스트 서비스 계정 정책 리소스가 버킷 하나뿐이다')
_item('EXP-SEC-1', '시크릿 파일', '시크릿 후보 파일이 너무 열려 있지 않음',
      '선언한 경로의 시크릿 후보 파일 중 그룹·기타 쓰기 또는 기타 권한이 열린 것이 없다', ['sec_roots'])
_item('EXP-SEC-2', '시크릿 파일', '선언한 시크릿 파일은 0600 이하 root 소유',
      '모든 선언 파일이 있고 mode 0600 이하 root 소유다', ['sec_files'])
_item('EXP-SEC-3', '시크릿 파일', '선언한 시크릿 env 파일은 0640 root:dockermgmt 이하',
      '모든 선언 파일이 있고 mode 0640 이하 root:dockermgmt다', ['sec_env_files'])

# expectation key -> probe environment variable
ENV_KEYS = {
    'mgmt_web_ports': 'HA_MGMT_WEB_PORTS', 'mgmt_wildcard_allowed': 'HA_MGMT_WILDCARD_ALLOWED',
    'mgmt_removed_ports': 'HA_MGMT_REMOVED_PORTS', 'mgmt_removed_names': 'HA_MGMT_REMOVED_NAMES',
    'recv_syslog_conf': 'HA_RECV_SYSLOG_CONF', 'recv_trap_conf': 'HA_RECV_TRAP_CONF',
    'ssh_allowed_addrs': 'HA_SSH_ALLOWED_ADDRS', 'ssh_denied_addr': 'HA_SSH_DENIED_ADDR',
    'sec_roots': 'HA_SEC_ROOTS', 'sec_files': 'HA_SEC_FILES', 'sec_env_files': 'HA_SEC_ENV_FILES',
    'det_log_agent': 'HA_DET_AGENT',
}
FLAG_KEYS = {'ssh_restricted': 'HA_SSH', 'det_journald': 'HA_DET_JOURNALD', 'det_fail2ban': 'HA_DET_F2B',
             'det_fail2ban_no_firewall': 'HA_DET_F2B_NOFW', 'det_auditd': 'HA_DET_AUDIT',
             'det_audit_secret': 'HA_DET_AUDIT_SECRET'}
SAFE_TOKEN = re.compile(r'^[A-Za-z0-9_./:*,@+=\[\]-]+$')


def _tokens(value):
    if isinstance(value, str):
        value = value.split()
    return [str(v) for v in (value or []) if SAFE_TOKEN.match(str(v))]


def host_audit_regression_env(expect):
    """Probe environment from the declared expectations. Unsafe tokens are dropped (no shell metacharacters)."""
    expect = expect or {}
    env = {name: '' for name in list(ENV_KEYS.values()) + list(FLAG_KEYS.values())}
    for key, name in ENV_KEYS.items():
        env[name] = ' '.join(_tokens(expect.get(key)))
    for key, name in FLAG_KEYS.items():
        env[name] = '1' if expect.get(key) else ''
    # a declared agent service name is a single word; `true` declares the default
    if expect.get('det_log_agent') in (True, 'true'):
        env['HA_DET_AGENT'] = 'otelcol'
    return env


def _declared(code, expect):
    keys = ITEMS[code]['keys']
    if code == 'EXP-DET-6':
        return bool(expect.get('det_audit_secret'))
    if code == 'EXP-DET-3':
        return bool(expect.get('det_fail2ban_no_firewall'))
    return any(expect.get(k) for k in keys)


def _first_line(text, limit=200):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def host_audit_regression_result(probe, expect, inventory_hostname=''):
    """The ``security_regression`` part of a per-host record: verdict per item, no evidence values.

    A declared item the probe did not report (or reported ``UNK``) is 점검불가; an undeclared item is 해당없음.
    """
    probe = probe or {}
    out = {'status': STATUS_OK, 'reason': '', 'results': []}
    stdout = str(probe.get('stdout') or '')
    if probe.get('unreachable') or probe.get('skipped') or BEGIN not in stdout or END not in stdout:
        out['status'] = STATUS_FAILED
        out['reason'] = _first_line(probe.get('msg')) or _first_line(probe.get('stderr')) or '점검 결과 표식 없음'
        return out
    body = stdout.split(BEGIN, 1)[1].split(END, 1)[0]
    found = {}
    for line in body.splitlines():
        parts = line.strip().split('|')
        if len(parts) == 2 and parts[0] in ITEMS and parts[1] in RAW:
            found[parts[0]] = RAW[parts[1]]
    for code, meta in ITEMS.items():
        if meta['area'] == '백업 정책':
            continue  # run-level, judged on the runner
        if not _declared(code, expect or {}):
            verdict = NA
        else:
            verdict = found.get(code, UNKNOWN)
        out['results'].append({'code': code, 'verdict': verdict})
    return out


# ------------------------------------------------------------------------------
# Backup host key policy (#373): repo policy JSON + the read-only collector snapshot
# ------------------------------------------------------------------------------
def _as_list(value):
    return value if isinstance(value, list) else [value]


def _policy_problems(policy):
    """Same rules as BAK-220 (roles/backup/tasks/host_key_policy.yml): delete only on <bucket>/locks/*, no wildcard action."""
    problems = []
    unlock = 0
    for st in policy.get('Statement') or []:
        if st.get('Effect') != 'Allow' or 'NotAction' in st or 'NotResource' in st:
            problems.append('effect')
        for action in _as_list(st.get('Action', [])):
            if '*' in action:
                problems.append('wildcard')
            if 'delete' in action.lower():
                resources = _as_list(st.get('Resource', []))
                if action != 's3:DeleteObject' or not resources or any(r != 'arn:aws:s3:::${BUCKET}/locks/*' for r in resources):
                    problems.append('delete')
                else:
                    unlock += 1
    if unlock != 1:
        problems.append('unlock')
    return problems


def _shape(statements):
    return sorted((s['effect'], tuple(sorted(s['actions'])), tuple(sorted(s['resources']))) for s in statements)


def _bucket_of(resource):
    m = re.match(r'^arn:aws:s3:::([^/]*)(/.*)?$', resource)
    return m.group(1) if m else None


def _snapshot_accounts(text, prefix):
    """Service accounts of the collector snapshot whose name/parent starts with ``prefix``: [{'statements': [...]}]."""
    accounts, current, in_section = [], None, False
    for line in str(text or '').splitlines():
        if line.startswith('## '):
            in_section = line.strip() == '## service-accounts'
            current = None
            continue
        if not in_section or not line.strip():
            continue
        if not line.startswith(' '):
            match = re.search(r'\b(?:name|parent)=(\S+)', line)
            names = re.findall(r'\b(?:name|parent)=(\S+)', line)
            current = {'statements': []} if match and any(n.startswith(prefix) for n in names) else None
            if current is not None:
                accounts.append(current)
        elif current is not None:
            m = re.match(r"^\s+(\w+) actions=(\[.*\]) resources=(\[.*\])\s*$", line)
            if m:
                try:
                    current['statements'].append({'effect': m.group(1), 'actions': ast.literal_eval(m.group(2)),
                                                  'resources': ast.literal_eval(m.group(3))})
                except (ValueError, SyntaxError):
                    current['statements'].append({'effect': '?', 'actions': ['?'], 'resources': ['?']})
    return accounts


def host_audit_regression_backup(policy_text, snapshot_text='', prefix='backup-prod-'):
    """Run-level items EXP-BAK-1..3 as ``[{'code', 'verdict'}]``.

    ``policy_text``: roles/backup/files/host-key-policy.json (empty -> 점검불가). ``snapshot_text``: the
    read-only collector output (scripts/collect-rustfs-policy.py); empty -> BAK-2/3 점검불가 (not run).
    """
    try:
        policy = json.loads(policy_text)
    except (TypeError, ValueError):
        policy = None
    results = {}
    results['EXP-BAK-1'] = UNKNOWN if policy is None else (PASS if not _policy_problems(policy) else FAIL)
    accounts = _snapshot_accounts(snapshot_text, prefix) if str(snapshot_text or '').strip() else []
    if policy is None or not accounts:
        results['EXP-BAK-2'] = results['EXP-BAK-3'] = UNKNOWN
    else:
        template = _shape([{'effect': s['Effect'], 'actions': _as_list(s['Action']),
                            'resources': [r.replace('${BUCKET}', '@B') for r in _as_list(s['Resource'])]}
                           for s in policy['Statement']])
        shape_ok, bucket_ok = True, True
        for acct in accounts:
            buckets = {_bucket_of(r) for s in acct['statements'] for r in s['resources']}
            if len(buckets) != 1 or None in buckets or any('*' in (b or '') for b in buckets):
                bucket_ok = shape_ok = False
                continue
            bucket = next(iter(buckets))
            normal = _shape([dict(s, resources=[r.replace('arn:aws:s3:::' + bucket, 'arn:aws:s3:::@B', 1) for r in s['resources']])
                             for s in acct['statements']])
            if normal != template:
                shape_ok = False
        results['EXP-BAK-2'] = PASS if shape_ok else FAIL
        results['EXP-BAK-3'] = PASS if bucket_ok else FAIL
    return [{'code': c, 'verdict': results[c]} for c in ('EXP-BAK-1', 'EXP-BAK-2', 'EXP-BAK-3')]


# ------------------------------------------------------------------------------
# Report model section
# ------------------------------------------------------------------------------
def _row(code, verdict):
    return dict(ITEMS[code], verdict=verdict, verdict_class=VERDICT_CLASSES[verdict])


def host_audit_regression_section(model, records, backup=None):
    """Return a copy of the model with ``security_regression`` (only when some host or the backup items were judged).

    ``baseline_findings`` lists every 실패 item per inspected host so the Audit Baseline marks 신규/지속/해소 and the
    worsening alert can compare per item. Items are ids and verdicts only.
    """
    model = dict(model or {})
    hosts = {}
    unavailable = list(model.get('unavailable') or [])
    for record in sorted(records or [], key=lambda r: r.get('inventory_hostname', '')):
        part = record.get('security_regression')
        if record.get('status') != 'ok' or part is None:
            continue
        host = record['inventory_hostname']
        if part.get('status') != STATUS_OK:
            unavailable.append({'host': host, 'item': 'Security Regression', 'label': '점검불가(수집 실패)',
                                'reason': part.get('reason') or '점검 결과 없음'})
            continue
        hosts[host] = [_row(r['code'], r['verdict']) for r in part['results']]
    backup_rows = [_row(r['code'], r['verdict']) for r in (backup or [])]
    if not hosts and not backup_rows:
        return model

    counts = {v: 0 for v in VERDICTS}
    findings = []
    inspected = sorted(hosts)
    for host in inspected:
        for row in hosts[host]:
            counts[row['verdict']] += 1
            if row['verdict'] == FAIL:
                findings.append({'host': host, 'id': row['code'], 'label': '%s %s' % (row['code'], row['title'])})
    for row in backup_rows:
        counts[row['verdict']] += 1
        if row['verdict'] == FAIL:
            findings.append({'host': BACKUP_HOST, 'id': row['code'], 'label': '%s %s' % (row['code'], row['title'])})
    if any(r['verdict'] != UNKNOWN for r in backup_rows):
        inspected.append(BACKUP_HOST)

    cover = dict(model.get('cover') or {})
    cover['contents'] = list(cover.get('contents') or []) + [
        'Security Regression — 스펙 #364 기대치(관리 접점·수신·원격 접속·탐지·백업 정책·시크릿 권한)의 퇴행 점검, 항목 ID와 통과 여부만']
    model['cover'] = cover
    model['unavailable'] = unavailable
    model[SECTION] = {
        'verdicts': VERDICTS,
        'verdict_classes': [VERDICT_CLASSES[v] for v in VERDICTS],
        'totals': [counts[v] for v in VERDICTS],
        'hosts': [{'host': h, 'rows': hosts[h], 'failed': sum(1 for r in hosts[h] if r['verdict'] == FAIL)}
                  for h in sorted(hosts)],
        'backup': backup_rows,
        'failed_total': counts[FAIL],
        'unknown_total': counts[UNKNOWN],
        'baseline_findings': {'hosts': inspected, 'findings': findings},
    }
    return model


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_regression_env': host_audit_regression_env,
            'host_audit_regression_result': host_audit_regression_result,
            'host_audit_regression_backup': host_audit_regression_backup,
            'host_audit_regression_section': host_audit_regression_section,
        }
