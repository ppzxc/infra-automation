"""Asset Inventory for Host Audit (ADR-0009, #120).

Two pure steps, mirroring the rest of Host Audit:
  host_audit_inventory_record  registered inventory probe -> ``inventory`` part of the per-host record
  inventory_section            per-host records + run metadata -> the Asset Inventory part of the report model

Every judgement the report shows for Asset Inventory — '미지정' declarations,
'선언 외' privileged users, '장기 미사용' accounts, OS end-of-life status — is
made in ``inventory_section``; the template only draws it. The full package
list stays in the per-host JSON and never reaches the report model.
"""

import ipaddress
import re
from datetime import date, datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

INVENTORY_BEGIN = '__HOST_AUDIT_INVENTORY_BEGIN__'
INVENTORY_END = '__HOST_AUDIT_INVENTORY_END__'
INACTIVE_DAYS = 90
EOL_SOON_DAYS = 180
UNASSIGNED = '미지정'
NOT_DECLARED = '선언 외'
INACTIVE = '장기 미사용'

DECLARED_FIELDS = [
    ('purpose', '용도'),
    ('department', '관리 부서'),
    ('owner_role', '책임자(직책)'),
    ('admin_role', '관리자(직책)'),
    ('security_grade', '보안등급'),
]
LIST_KEYS = ('disk', 'pkg', 'listen_tcp', 'listen_udp', 'netstat', 'passwd', 'shadow', 'group',
             'sudoers', 'lastlog', 'recent_login', 'agent_bin', 'timesync_tool')
NOLOGIN_SHELLS = ('nologin', 'false', 'sync', 'shutdown', 'halt')
PRIVILEGED_GROUPS = ('wheel', 'sudo', 'admin')
# 주요 패키지: 보고서 표에 버전을 싣는 패키지 (rpm 이름 / dpkg 이름).
KEY_PACKAGES = [
    ('kernel', ('kernel', 'kernel-core'), re.compile(r'^linux-image-\d')),
    ('openssl', ('openssl', 'openssl-libs', 'libssl3', 'libssl3t64', 'libssl1.1', 'libssl1.0.0'), None),
    ('openssh', ('openssh-server',), None),
    ('glibc', ('glibc', 'libc6'), None),
    ('sudo', ('sudo',), None),
    ('docker', ('docker-ce',), None),
]


# ---------------------------------------------------------------------------
# probe -> record
# ---------------------------------------------------------------------------

def _first_line(text, limit=200):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def _parse(stdout):
    lines = str(stdout or '').splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == INVENTORY_BEGIN)
        end = next(i for i, ln in enumerate(lines) if i > start and ln.strip() == INVENTORY_END)
    except StopIteration:
        return None
    values = {k: [] for k in LIST_KEYS}
    for line in lines[start + 1:end]:
        key, sep, value = line.rstrip('\r').partition('=')
        if not sep:
            continue
        if key in values:
            values[key].append(value)
        else:
            values[key] = value.strip()
    return values


def _int(value, default=None):
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _hardware(v):
    disks = []
    for line in v['disk']:
        parts = line.split('|')
        if len(parts) == 4:
            disks.append({'mount': parts[0], 'fstype': parts[1],
                          'size_kb': _int(parts[2], 0), 'used_kb': _int(parts[3], 0)})
    return {
        'cpu_model': v.get('cpu_model', ''),
        'cpu_count': _int(v.get('cpu_count'), 0),
        'mem_total_kb': _int(v.get('mem_total_kb'), 0),
        'dmi': {'vendor': v.get('dmi_sys_vendor', ''), 'product': v.get('dmi_product_name', ''),
                'serial': v.get('dmi_product_serial', '')},
        'disks': disks,
    }


def _timesync(v):
    tools = sorted(set(v['timesync_tool']))
    synced = None
    leap = v.get('timesync_chrony_leap', '')
    if leap:
        synced = leap.strip().lower() == 'normal'
    if synced is not True and v.get('timesync_ntp_peer') not in (None, ''):
        synced = _int(v.get('timesync_ntp_peer'), 0) > 0
    if synced is not True and v.get('timesync_timedatectl'):
        synced = v['timesync_timedatectl'].strip().lower() == 'yes'
    return {'tools': tools, 'synced': synced}


def _operation(v):
    now = _int(v.get('now_epoch'))
    uptime = _int(v.get('uptime_s'))
    boot = now - uptime if now is not None and uptime is not None else None
    return {'probe_epoch': now, 'uptime_s': uptime, 'boot_epoch': boot, 'timesync': _timesync(v)}


def _packages(v):
    manager = v.get('pkg_manager', '')
    items = []
    last = None
    for line in v['pkg']:
        parts = line.split('|')
        if len(parts) < 3:
            continue
        name, version, arch = parts[0], parts[1], parts[2]
        if version.startswith('(none):'):
            version = version[len('(none):'):]
        elif version.startswith('0:'):
            version = version[2:]
        items.append({'name': name, 'version': version, 'arch': arch})
        installed = _int(parts[3]) if len(parts) > 3 else None
        if installed and (last is None or installed > last):
            last = installed
    if manager == 'dpkg':
        last = _int(v.get('pkg_dpkg_status_mtime'))
    items.sort(key=lambda p: (p['name'], p['version'], p['arch']))
    key = {}
    for label, names, pattern in KEY_PACKAGES:
        versions = [p['version'] for p in items
                    if p['name'] in names or (pattern is not None and pattern.match(p['name']))]
        key[label] = sorted(set(versions))
    return {'manager': manager, 'count': len(items), 'last_update_epoch': last, 'key': key, 'all': items}


_SS_PROC = re.compile(r'"([^"]+)",pid=(\d+)')
_ADDR = re.compile(r'^(.*):(\d+|\*)$')


def _listen_entry(proto, line, netstat=False):
    tokens = line.split()
    addrs = [t for t in tokens if _ADDR.match(t)]
    if not addrs:
        return None
    address, port = _ADDR.match(addrs[0]).groups()
    if port == '*':
        return None
    if netstat:
        proto = 'udp' if tokens[0].startswith('udp') else 'tcp'
        last = tokens[-1]
        process = last.split('/', 1)[1] if '/' in last else ''
    else:
        process = ','.join(sorted({name for name, _pid in _SS_PROC.findall(line)}))
    address = address.strip('[]').split('%', 1)[0] or '*'
    return {'proto': proto, 'address': address, 'port': int(port), 'process': process}


def _ports(v):
    entries = []
    for proto, key in (('tcp', 'listen_tcp'), ('udp', 'listen_udp')):
        entries += [e for e in (_listen_entry(proto, ln) for ln in v[key]) if e]
    entries += [e for e in (_listen_entry('', ln, netstat=True) for ln in v['netstat']) if e]
    unique = {(e['proto'], e['address'], e['port']): e for e in entries}
    return [unique[k] for k in sorted(unique, key=lambda k: (k[0], k[2], k[1]))]


def _is_loopback(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address == 'localhost'
    mapped = getattr(ip, 'ipv4_mapped', None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback)


def _accounts(v):
    shadow = {}
    for line in v['shadow']:
        name, _, status = line.partition('|')
        shadow[name] = status
    groups = {}
    for line in v['group']:
        name, _, members = line.partition('|')
        groups[name] = [m for m in members.split(',') if m]
    lastlog_available = v.get('lastlog_available') == '1'
    recent = set(v['recent_login'])
    last_login = {}
    for line in v['lastlog']:
        tokens = line.split()
        if not tokens:
            continue
        name = tokens[0]
        last_login[name] = 'never' if '**' in line else ' '.join(tokens[1:])

    users = []
    for line in v['passwd']:
        parts = line.split('|')
        if len(parts) != 4:
            continue
        name, uid, gid, shell = parts
        login = bool(shell) and not shell.rstrip('/').split('/')[-1] in NOLOGIN_SHELLS
        if not lastlog_available:
            recent_login = None
        else:
            recent_login = name in recent
        users.append({
            'name': name, 'uid': _int(uid), 'gid': _int(gid), 'shell': shell, 'login': login,
            'password': shadow.get(name, 'unknown') if shadow else 'unknown',
            'last_login': last_login.get(name, '') if lastlog_available else None,
            'recent_login': recent_login,
        })

    privileged = {}

    def grant(name, via, nopasswd=False):
        entry = privileged.setdefault(name, {'name': name, 'via': [], 'nopasswd': False})
        if via not in entry['via']:
            entry['via'].append(via)
        entry['nopasswd'] = entry['nopasswd'] or nopasswd

    for user in users:
        if user['uid'] == 0:
            grant(user['name'], 'uid 0')
    for group in PRIVILEGED_GROUPS:
        for member in groups.get(group, []):
            grant(member, 'group %s' % group)
    for line in v['sudoers']:
        path, _, rule = line.partition('|')
        rule = rule.strip()
        if not rule or rule.startswith(('#include', '@include', 'User_Alias', 'Runas_Alias',
                                         'Host_Alias', 'Cmnd_Alias')):
            continue
        who = rule.split()[0]
        nopasswd = 'NOPASSWD' in rule
        via = 'sudoers %s%s' % (path, ' NOPASSWD' if nopasswd else '')
        if who.startswith('%'):
            for member in groups.get(who[1:], []):
                grant(member, via, nopasswd)
            if who[1:] not in groups:
                grant(who, via, nopasswd)
        else:
            grant(who, via, nopasswd)
    return {
        'users': users,
        'privileged': [privileged[k] for k in sorted(privileged)],
        'shadow_readable': v.get('shadow_unreadable') != '1',
        'lastlog_available': lastlog_available,
    }


def _host_agents(v):
    bins = set(v['agent_bin'])
    otel_active = v.get('agent_otelcol_active', '')
    backup_scheduled = v.get('agent_backup_timer_active') == 'active' or v.get('agent_backup_cron') == '1'
    return {
        'otelcol': {'installed': 'otelcol-contrib' in bins, 'active': otel_active == 'active'},
        'backup': {'installed': 'resticprofile' in bins and 'restic' in bins, 'scheduled': backup_scheduled},
    }


def host_audit_inventory_record(probe):
    """Turn the registered inventory probe into the ``inventory`` part of the per-host record."""
    probe = probe or {}
    if probe.get('unreachable'):
        return {'status': 'unreachable', 'reason': _first_line(probe.get('msg')) or 'SSH 접속 실패'}
    values = None if probe.get('skipped') else _parse(probe.get('stdout'))
    if values is None:
        return {'status': 'probe_failed',
                'reason': (_first_line(probe.get('stderr')) or _first_line(probe.get('msg'))
                           or '수집 결과 표식 없음 (rc=%s)' % probe.get('rc'))}
    return {
        'status': 'ok',
        'reason': '',
        'hardware': _hardware(values),
        'operation': _operation(values),
        'packages': _packages(values),
        'ports': _ports(values),
        'accounts': _accounts(values),
        'host_agents': _host_agents(values),
    }


# ---------------------------------------------------------------------------
# records -> report model section
# ---------------------------------------------------------------------------

_REDHAT_RELEASE = re.compile(r'^(CentOS|Red Hat Enterprise Linux|Rocky Linux|AlmaLinux)\D*?(\d+)')
_RELEASE_IDS = {'CentOS': 'centos', 'Red Hat Enterprise Linux': 'rhel', 'Rocky Linux': 'rocky',
                'AlmaLinux': 'almalinux'}


def _os_key(os_info):
    """('centos', '7') style lookup key for the EOL table, or None."""
    os_info = os_info or {}
    os_id = (os_info.get('id') or '').lower()
    version = os_info.get('version_id') or ''
    if os_id in ('', 'rhel-family'):
        m = _REDHAT_RELEASE.match(os_info.get('redhat_release') or '')
        if not m:
            return None
        return '%s-%s' % (_RELEASE_IDS[m.group(1)], m.group(2))
    if os_id in ('ubuntu',):
        return '%s-%s' % (os_id, version)
    return '%s-%s' % (os_id, version.split('.')[0])


def _parse_date(text):
    try:
        return datetime.strptime(str(text)[:10], '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None


def _eol(os_info, table, today):
    key = _os_key(os_info)
    entry = next((e for e in (table or {}).get('entries', []) if e.get('match') == key), None)
    if entry is None:
        return {'key': key, 'date': '', 'status': 'unknown', 'label': '확인 불가(EOL 표에 없음)'}
    eol = _parse_date(entry.get('eol'))
    if eol is None or today is None:
        return {'key': key, 'date': entry.get('eol', ''), 'status': 'unknown', 'label': '확인 불가'}
    if eol < today:
        status, label = 'eos', '지원 종료(EOS)'
    elif eol - today <= timedelta(days=EOL_SOON_DAYS):
        status, label = 'soon', 'EOL 임박'
    else:
        status, label = 'supported', '지원 중'
    return {'key': key, 'date': eol.isoformat(), 'status': status, 'label': label}


def _fmt_kb(kb):
    if not kb:
        return '-'
    gib = kb / 1024.0 / 1024.0
    return '%.1f GiB' % gib if gib < 100 else '%d GiB' % round(gib)


def _fmt_epoch(epoch, tz):
    if epoch is None:
        return '-'
    stamp = datetime.fromtimestamp(epoch, timezone.utc)
    if tz is not None:
        stamp = stamp.astimezone(tz)
    return stamp.strftime('%Y-%m-%d %H:%M')


def _fmt_uptime(seconds):
    if seconds is None:
        return '-'
    days, rest = divmod(seconds, 86400)
    return '%d일 %d시간' % (days, rest // 3600)


def _declared(record):
    asset = ((record.get('declared') or {}).get('asset') or {})
    fields = []
    for key, label in DECLARED_FIELDS:
        value = str(asset.get(key) or '').strip()
        fields.append({'key': key, 'label': label, 'value': value or UNASSIGNED, 'unassigned': not value})
    return fields, [str(n) for n in (asset.get('privileged_allowlist') or [])]


def _account_rows(accounts, allowlist, audit_account):
    privileged = {p['name']: p for p in accounts.get('privileged', [])}
    allowed = set(allowlist) | {'root'}
    rows = []
    for user in accounts.get('users', []):
        if not user['login'] and user['name'] not in privileged:
            continue
        flags = []
        priv = privileged.get(user['name'])
        if priv and user['name'] not in allowed:
            flags.append(NOT_DECLARED)
        inactive = None
        if user['login'] and user['name'] != audit_account and user['uid'] != 0:
            if user['recent_login'] is False:
                inactive = 'never' if user['last_login'] == 'never' else 'old'
                flags.append(INACTIVE)
        rows.append({
            'name': user['name'], 'uid': user['uid'], 'shell': user['shell'], 'login': user['login'],
            'password': {'set': '설정', 'locked': '잠금', 'empty': '비밀번호 없음',
                         'unknown': '확인 불가'}.get(user['password'], user['password']),
            'privilege': ', '.join(priv['via']) if priv else '',
            'nopasswd': bool(priv and priv['nopasswd']),
            'last_login': ('기록 없음' if user['last_login'] == 'never' else (user['last_login'] or '-'))
            if user['last_login'] is not None else '확인 불가',
            'inactive': inactive,
            'flags': flags,
        })
    # sudoers 규칙의 대상이 passwd에 없는 이름(별칭·미해석 그룹)도 특수권한자로 남긴다.
    known = {u['name'] for u in accounts.get('users', [])}
    for name, priv in sorted(privileged.items()):
        if name not in known:
            rows.append({'name': name, 'uid': None, 'shell': '', 'login': False, 'password': '-',
                         'privilege': ', '.join(priv['via']), 'nopasswd': priv['nopasswd'],
                         'last_login': '-', 'inactive': None,
                         'flags': [] if name in allowed else [NOT_DECLARED]})
    return rows


def _agents_label(agents, excluded):
    if excluded:
        return '제외(Host Agents Exclusion)'
    otel, backup = agents['otelcol'], agents['backup']
    if otel['active'] and backup['installed'] and backup['scheduled']:
        return '정상'
    if not otel['installed'] and not backup['installed']:
        return '미설치'
    return '일부 이상'


def _host_section(record, eol_table, today, tz):
    host = record['inventory_hostname']
    declared, allowlist = _declared(record)
    os_info = record.get('os')
    inventory = record.get('inventory') or {}
    excluded = 'host_agents_excluded' in ((record.get('declared') or {}).get('groups') or [])
    base = {'host': host, 'declared': declared, 'eol': _eol(os_info, eol_table, today) if os_info else None,
            'collected': inventory.get('status') == 'ok', 'reason': inventory.get('reason', '')}
    unavailable = []
    # 식별부터 실패한 호스트는 '전체 점검' 점검불가로 이미 보고된다. inventory 키가 없는 기록
    # (schema_version 1)은 Asset Inventory를 수집하지 않은 실행이라 따로 점검불가를 만들지 않는다.
    if record.get('status') != 'ok' or 'inventory' not in record:
        return base, unavailable
    if inventory.get('status') != 'ok':
        unavailable.append({'host': host, 'item': 'Asset Inventory 상세', 'label': '점검불가(수집 실패)',
                            'reason': inventory.get('reason') or '-'})
        return base, unavailable

    hw, op, pkgs = inventory['hardware'], inventory['operation'], inventory['packages']
    accounts = inventory['accounts']
    audit_account = (record.get('identity') or {}).get('account') or ''
    account_rows = _account_rows(accounts, allowlist, audit_account)
    if not accounts.get('lastlog_available'):
        unavailable.append({'host': host, 'item': '마지막 로그인', 'label': '점검불가',
                            'reason': 'lastlog 명령 없음 — 장기 미사용 판정 불가'})
    if not accounts.get('shadow_readable'):
        unavailable.append({'host': host, 'item': '계정 잠금 상태', 'label': '점검불가',
                            'reason': '/etc/shadow 읽기 불가'})
    ports = inventory['ports']
    external = [p for p in ports if not _is_loopback(p['address'])]
    sync = op['timesync']['synced']
    disks = hw['disks']
    base.update({
        'hardware': {
            'cpu': '%s × %d' % (hw['cpu_model'] or 'CPU', hw['cpu_count']) if hw['cpu_count'] else '-',
            'memory': _fmt_kb(hw['mem_total_kb']),
            'dmi': ' · '.join(x for x in (hw['dmi']['vendor'], hw['dmi']['product']) if x) or '-',
            'serial': hw['dmi']['serial'] or '-',
            'disks': [{'mount': d['mount'], 'fstype': d['fstype'], 'size': _fmt_kb(d['size_kb']),
                       'used_pct': '%d%%' % round(100.0 * d['used_kb'] / d['size_kb']) if d['size_kb'] else '-'}
                      for d in disks],
            'disk_total': _fmt_kb(sum(d['size_kb'] for d in disks)),
        },
        'operation': {
            'uptime': _fmt_uptime(op['uptime_s']),
            'boot': _fmt_epoch(op['boot_epoch'], tz),
            'timesync': ('동기화' if sync else ('미동기화' if sync is False else '확인 불가')),
            'timesync_ok': sync is True,
            'timesync_tools': ', '.join(op['timesync']['tools']) or '없음',
        },
        'packages': {
            'manager': pkgs['manager'] or '-',
            'count': pkgs['count'],
            'last_update': _fmt_epoch(pkgs['last_update_epoch'], tz).split(' ')[0],
            'key': [{'name': name, 'versions': ', '.join(pkgs['key'].get(name, [])) or '-'}
                    for name, _n, _p in KEY_PACKAGES],
        },
        'ports': ports,
        'ports_external': len(external),
        'ports_local': len(ports) - len(external),
        'accounts': account_rows,
        'login_accounts': sum(1 for a in account_rows if a['login']),
        'privileged': [a for a in account_rows if a['privilege']],
        'not_declared': [a['name'] for a in account_rows if NOT_DECLARED in a['flags']],
        'inactive': [a['name'] for a in account_rows if INACTIVE in a['flags']],
        'host_agents': _agents_label(inventory['host_agents'], excluded),
        'host_agents_ok': _agents_label(inventory['host_agents'], excluded) in ('정상', '제외(Host Agents Exclusion)'),
    })
    return base, unavailable


def inventory_section(records, meta):
    """Asset Inventory part of the report model (called by host_audit_report_model)."""
    meta = meta or {}
    table = meta.get('eol_table') or {}
    started = _parse_date(meta.get('started_at'))
    today = started or date.today()
    offset = ZoneInfo(meta.get('timezone') or 'Asia/Seoul') if ZoneInfo else None
    hosts, unavailable = [], []
    for record in records:
        section, missing = _host_section(record, table, today, offset)
        hosts.append(section)
        unavailable.extend(missing)
    accounts = sorted({(r.get('identity') or {}).get('account') for r in records} - {None, ''})
    eos = [{'host': h['host'], 'os': next((r.get('os') or {}).get('name', '') for r in records
                                          if r['inventory_hostname'] == h['host']),
            'date': h['eol']['date'], 'label': h['eol']['label']}
           for h in hosts if h.get('eol') and h['eol']['status'] == 'eos']
    flagged = [{'host': h['host'], 'name': a['name'], 'flags': a['flags'],
                'privilege': a['privilege'] or '-', 'last_login': a['last_login']}
               for h in hosts if h['collected'] for a in h['accounts'] if a['flags']]
    return {
        'hosts': hosts,
        'declared_labels': [label for _key, label in DECLARED_FIELDS],
        'flagged': flagged,
        'eos': eos,
        'unavailable': unavailable,
        'eol_reviewed_on': table.get('reviewed_on', ''),
        'eol_source': table.get('source', ''),
        'cover_note': ('OS 지원 종료일은 role 내부 정적 표(기준일 %s) 기준. 장기 미사용(마지막 로그인 %d일 이상) '
                       '판정에서 점검 계정(%s)과 root는 제외.'
                       % (table.get('reviewed_on') or '-', INACTIVE_DAYS, ', '.join(accounts) or '-')),
        'counts': {
            'not_declared': sum(len(h.get('not_declared', [])) for h in hosts),
            'inactive': sum(len(h.get('inactive', [])) for h in hosts),
            'unassigned_hosts': sum(1 for h in hosts if any(f['unassigned'] for f in h['declared'])),
            'eos': len(eos),
        },
    }


def host_audit_privileged_allowlist(accounts, principals=None, extra=None):
    """Declared privileged users: sudo-capable common accounts + SSH CA principals + extra names."""
    names = []
    for account in accounts or []:
        if not isinstance(account, dict) or not account.get('name'):
            continue
        if account.get('state', 'present') == 'absent':
            continue
        sudo = account.get('sudo')
        if sudo is None:
            sudo = account.get('tier', 'user') == 'admin'
        if str(sudo).lower() in ('true', 'yes', '1'):
            names.append(str(account['name']))
    names += [str(p) for p in (principals or []) if p]
    names += [str(p) for p in (extra or []) if p]
    return sorted(set(names))


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_inventory_record': host_audit_inventory_record,
            'host_audit_privileged_allowlist': host_audit_privileged_allowlist,
        }
