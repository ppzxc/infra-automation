"""Filters for the Host Audit switch phase (Spec #568 / Ticket-3): KISA-2026 V chapter (N-NN) on Cisco IOS.

The collector (``roles/cisco_backup/files/cisco_cli_collector.py --audit``) prints one JSON object
``{"running_config", "version"}`` from the only two commands it may send (``show running-config``,
``show version``). Every judgement is made here from those two texts; the rule for each item is the row of
``docs/host_audit_switch.md`` (the application table). Verdicts, the exception register and the record shape are the
server code path (``host_audit_kisa``): five verdicts, ``_apply_register``, ``results`` rows of the same keys.

Adding an item (Ticket-4: N-17..N-38) is one decorated function::

    @switch_check('N-17', title='SNMP 서비스 확인', severity='상', category='기능', l2='적용', l3='적용')
    def _n17(ctx):
        return 'VULN', '근거 한 줄'          # raw status GOOD | VULN | NA | MANUAL and evidence (no secret/address values)

``ctx`` holds ``config`` (parsed running-config), ``version`` (``show version`` text), ``access`` ('ssh'|'telnet') and
``role`` ('L2'|'L3'). The decorator's ``l2``/``l3`` are the table's columns: a '해당없음' column yields 해당없음 with
``reason`` (the table's reason text) without calling the function. Items with no registered function are left out
of the record (never reported as 'not implemented').

Entry points:
  host_audit_switch_result  (filter) registered collector run -> ``config_vulnerability`` of a record
  host_audit_switch_record  (filter) the whole per-switch record written to ``hosts/<inventory_hostname>.json``
"""

import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_kisa import (  # noqa: E402
    EDITION, GOOD, MANUAL, NOT_APPLICABLE, RAW_VERDICTS, STATUS_FAILED, STATUS_OK, VULNERABLE,
    _apply_register, full_code,
)

DEVICE_TYPE = 'SWITCH'
RECORD_SCHEMA_VERSION = 2   # same record schema as the servers (filter_plugins/host_audit.py)
MIN_PASSWORD_LENGTH = 8     # N-02, provisional (docs/host_audit_switch.md)
MAX_LOGIN_ATTEMPTS = 5      # N-04
MAX_EXEC_TIMEOUT_SECONDS = 600   # N-07
MIN_BUFFER_BYTES = 16000    # N-13
APPLIES, NOT_APPLICABLE_STATE, UNVERIFIABLE_STATE = '적용', '해당없음', '점검불가'

# code -> {'title', 'severity', 'category', 'l2', 'l3', 'reason', 'fn'}
CHECKS = {}


def switch_check(code, title, severity, category, l2=APPLIES, l3=APPLIES, reason=''):
    """Register the judgement function of one item (see the module docstring)."""
    def register(fn):
        CHECKS[code] = {'title': title, 'severity': severity, 'category': category, 'l2': l2, 'l3': l3,
                        'reason': reason, 'fn': fn}
        return fn
    return register


# ------------------------------------------------------------------ running-config parsing

_BANNER = re.compile(r'^banner\s+(\S+)\s+(\S)(.*)$')


class Config(object):
    """Top-level lines, indented blocks and banners of a running-config. Nothing here keeps values out of memory;
    evidence strings are what must stay free of them."""

    def __init__(self, text):
        self.lines = []      # top-level lines (stripped), banner bodies excluded
        self.blocks = []     # (header, [child lines stripped])
        self.banners = {}    # type -> body text
        header, children = None, []
        raw = str(text or '').replace('\r', '').split('\n')
        i = 0
        while i < len(raw):
            line = raw[i]
            i += 1
            m = _BANNER.match(line)
            if m:
                kind, delim, rest = m.groups()
                body = rest
                if delim not in rest:
                    chunk = []
                    while i < len(raw) and delim not in raw[i]:
                        chunk.append(raw[i])
                        i += 1
                    if i < len(raw):
                        chunk.append(raw[i].split(delim)[0])
                        i += 1
                    body = '\n'.join([rest] + chunk)
                else:
                    body = rest.split(delim)[0]
                self.banners[kind] = body.strip()
                continue
            if not line.strip() or line.strip() == '!':
                if header is not None:
                    self.blocks.append((header, children))
                header, children = None, []
                continue
            if line[0] in ' \t':
                if header is not None:
                    children.append(line.strip())
                continue
            if header is not None:
                self.blocks.append((header, children))
            header, children = line.strip(), []
            self.lines.append(header)
        if header is not None:
            self.blocks.append((header, children))

    def top(self, pattern):
        """Top-level lines matching the regex at the start of the line."""
        rx = re.compile(pattern)
        return [ln for ln in self.lines if rx.match(ln)]

    def blocks_of(self, prefix):
        return [children for head, children in self.blocks if head == prefix or head.startswith(prefix + ' ')]

    def named_blocks(self, prefix):
        return [(head, children) for head, children in self.blocks if head.startswith(prefix)]

    @property
    def hostname(self):
        found = self.top(r'hostname\s+\S+')
        return found[0].split(None, 1)[1] if found else ''


def _tokens(line):
    return line.split()


def routed_interfaces(cfg):
    """Routing interfaces (table, section 1): SVI, routed port, Loopback or Tunnel with ``ip address <addr> <mask>``.
    Returns (header, children) pairs."""
    found = []
    for head, children in cfg.blocks:
        parts = head.split(None, 1)
        if parts[0] != 'interface' or len(parts) < 2:
            continue
        routed = parts[1].lower().startswith(('vlan', 'loopback', 'tunnel')) or 'no switchport' in children
        if routed and any(re.match(r'ip address\s+\S+\s+\S+', c) for c in children):
            found.append((head, children))
    return found


def device_role(config_text):
    """L3 when ``ip routing`` is on or any routing interface has ``ip address <addr> <mask>``; else L2 (table, section 1)."""
    cfg = config_text if isinstance(config_text, Config) else Config(config_text)
    if 'no ip routing' not in cfg.lines and 'ip routing' in cfg.lines:
        return 'L3'
    return 'L3' if routed_interfaces(cfg) else 'L2'


def _ios_version(text):
    m = re.search(r'Version\s+(\d+)\.(\d+)(?:\((\w+)\))?([A-Za-z0-9]*)', str(text or ''))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _version_string(text):
    m = re.search(r'Version\s+([0-9][0-9A-Za-z.()]*)', str(text or ''))
    return m.group(1).rstrip(',') if m else ''


def _is_old_or_unknown(version_text):
    ver = _ios_version(version_text)
    return ver is None or ver < (12, 2)


# ------------------------------------------------------------------ ACL helpers (N-06)

def _acl_entries(cfg, name):
    """Permit entries of ACL ``name`` as (kind, tokens after permit); None when the ACL is not defined."""
    entries, found = [], False
    for ln in cfg.top(r'access-list\s+%s\s' % re.escape(name)):
        found = True
        toks = _tokens(ln)[2:]
        if toks and toks[0] == 'permit':
            number = int(name) if name.isdigit() else 0
            kind = 'standard' if (1 <= number <= 99 or 1300 <= number <= 1999) else 'extended'
            entries.append((kind, toks[1:]))
    for head, children in cfg.blocks:
        m = re.match(r'ip access-list\s+(standard|extended)\s+(\S+)$', head)
        if m and m.group(2) == name:
            found = True
            for c in children:
                toks = _tokens(c)
                if toks and toks[0] == 'permit':
                    entries.append((m.group(1), toks[1:]))
    return entries if found else None


def _permits_any(entries):
    for kind, toks in entries:
        if kind == 'standard' and toks and toks[0] == 'any':
            return True
        if kind == 'extended' and len(toks) > 1 and toks[1] == 'any':
            return True
    return False


# ------------------------------------------------------------------ N-01 .. N-16

def _line_blocks(cfg, kind):
    return cfg.blocks_of('line ' + kind)


@switch_check('N-01', title='비밀번호 설정', severity='상', category='계정')
def _n01(ctx):
    cfg = ctx['config']
    problems = []
    if not (cfg.top(r'enable (secret|password)\b') or cfg.top(r'enable algorithm-type\s+\S+\s+secret\b')):
        problems.append('enable secret·password 없음')
    if any('no login' in b for b in _line_blocks(cfg, 'vty') + _line_blocks(cfg, 'con')):
        problems.append('line con·vty 블록에 no login')
    aaa = bool(cfg.top(r'aaa authentication login\b'))
    for block in _line_blocks(cfg, 'con'):
        if not aaa and not any(re.match(r'login\b(?! *$)|^login$', c) and not c.startswith('no ') for c in block):
            problems.append('line con 블록에 인증 설정 없음')
    if problems:
        return 'VULN', ', '.join(problems)
    return 'GOOD', 'enable 비밀번호와 line 인증 설정 있음'


@switch_check('N-02', title='비밀번호 복잡성 설정', severity='상', category='계정')
def _n02(ctx):
    found = ctx['config'].top(r'security passwords min-length\s+\d+')
    if not found:
        return 'VULN', 'security passwords min-length 없음'
    length = int(_tokens(found[-1])[3])
    if length < MIN_PASSWORD_LENGTH:
        return 'VULN', '최소 길이 %d (기준 %d 이상)' % (length, MIN_PASSWORD_LENGTH)
    return 'GOOD', '최소 길이 %d' % length


def _secret_is_plain(tokens):
    """tokens after secret/password: ``0 value`` or a bare value is plain text; ``<type> value`` with type 4..9 is not."""
    if tokens and tokens[0] == 'level':
        tokens = tokens[2:]
    if not tokens:
        return False
    if len(tokens) >= 2 and tokens[0].isdigit():
        return tokens[0] == '0'
    return True


@switch_check('N-03', title='암호화된 비밀번호 사용', severity='상', category='계정')
def _n03(ctx):
    cfg = ctx['config']
    problems = []
    encryption = [ln for ln in cfg.lines if ln in ('service password-encryption', 'no service password-encryption')]
    if not encryption or encryption[-1] != 'service password-encryption':
        problems.append('service password-encryption 꺼짐')
    secrets = cfg.top(r'enable secret\b') + cfg.top(r'enable algorithm-type\s+\S+\s+secret\b')
    if not secrets:
        problems.append('enable secret 없음')
    elif any(_secret_is_plain(_tokens(ln)[_tokens(ln).index('secret') + 1:]) for ln in secrets):
        problems.append('enable secret 평문')
    plain_users = 0
    for ln in cfg.top(r'username\s+\S+'):
        toks = _tokens(ln)
        for key in ('secret', 'password'):
            if key in toks:
                after = toks[toks.index(key) + 1:]
                if key == 'password' and after and after[0].isdigit() and after[0] != '0' and len(after) >= 2:
                    continue
                if _secret_is_plain(after):
                    plain_users += 1
                break
    if plain_users:
        problems.append('평문 계정 비밀번호 %d개' % plain_users)
    if problems:
        return 'VULN', ', '.join(problems)
    return 'GOOD', '암호화 저장 설정'


@switch_check('N-04', title='계정 잠금 임계값 설정', severity='상', category='계정')
def _n04(ctx):
    found = ctx['config'].top(r'login block-for\s+\d+\s+attempts\s+\d+')
    if not found:
        return 'VULN', 'login block-for 없음'
    attempts = int(_tokens(found[-1])[4])
    if attempts > MAX_LOGIN_ATTEMPTS:
        return 'VULN', '실패 허용 %d회 (기준 %d회 이하)' % (attempts, MAX_LOGIN_ATTEMPTS)
    return 'GOOD', '실패 허용 %d회' % attempts


@switch_check('N-05', title='사용자·명령어별 권한 설정', severity='중', category='계정')
def _n05(ctx):
    cfg = ctx['config']
    levels = []
    for ln in cfg.top(r'username\s+\S+'):
        toks = _tokens(ln)
        level = int(toks[toks.index('privilege') + 1]) if 'privilege' in toks and toks.index('privilege') + 1 < len(toks) \
            and toks[toks.index('privilege') + 1].isdigit() else None
        levels.append(level)
    if not levels:
        if cfg.top(r'aaa authorization exec\b'):
            return 'GOOD', '로컬 계정 없음, aaa authorization exec 설정'
        return 'VULN', '로컬 계정도 aaa authorization exec도 없음'
    if len(levels) == 1:
        return 'GOOD', '로컬 계정 1개 (가이드 예외)'
    if all(lv in (15, None) for lv in levels):
        return 'VULN', '로컬 계정 %d개가 모두 권한 15 또는 권한 미지정' % len(levels)
    return 'GOOD', '계정별 권한 수준이 나뉨'


@switch_check('N-06', title='VTY 접근(ACL) 설정', severity='상', category='접근')
def _n06(ctx):
    cfg = ctx['config']
    blocks = _line_blocks(cfg, 'vty')
    if not blocks:
        return 'NA', 'line vty 블록 없음'
    problems, checked = [], 0
    for block in blocks:
        if any(re.match(r'transport input none$', c) for c in block):
            continue
        checked += 1
        acl = next((m.group(1) for c in block for m in [re.match(r'access-class\s+(\S+)\s+in\b', c)] if m), None)
        if acl is None:
            problems.append('access-class in 없는 vty 블록')
            continue
        entries = _acl_entries(cfg, acl)
        if entries is None:
            problems.append('vty가 가리키는 ACL이 설정에 없음')
        elif _permits_any(entries):
            problems.append('vty ACL이 전체 허용')
    if problems:
        return 'VULN', ', '.join(sorted(set(problems)))
    if not checked:
        return 'GOOD', '모든 vty 블록이 transport input none'
    return 'GOOD', 'vty %d개 블록에 접속 제한 ACL 적용' % checked


@switch_check('N-07', title='Session Timeout 설정', severity='상', category='접근')
def _n07(ctx):
    cfg = ctx['config']
    blocks = _line_blocks(cfg, 'con') + _line_blocks(cfg, 'vty') + _line_blocks(cfg, 'aux')
    if not blocks:
        return 'MANUAL', '설정에서 line 블록을 찾지 못함'
    problems = set()
    for block in blocks:
        found = [c for c in block if re.match(r'exec-timeout\s+\d+', c)]
        if not found:
            problems.add('exec-timeout 없는 line 블록')
            continue
        toks = _tokens(found[-1])
        seconds = int(toks[1]) * 60 + (int(toks[2]) if len(toks) > 2 and toks[2].isdigit() else 0)
        if seconds == 0:
            problems.add('exec-timeout 0 0 (무제한)')
        elif seconds > MAX_EXEC_TIMEOUT_SECONDS:
            problems.add('exec-timeout 10분 초과')
    if problems:
        return 'VULN', ', '.join(sorted(problems))
    return 'GOOD', 'line 블록 %d개 모두 10분 이하' % len(blocks)


@switch_check('N-08', title='VTY 접속 시 안전한 프로토콜 사용', severity='중', category='접근')
def _n08(ctx):
    cfg, access = ctx['config'], ctx['access']
    problems = []
    if access == 'telnet':
        problems.append('Telnet으로 접속해 점검함 (접속 자체가 암호화 위반)')
    blocks = _line_blocks(cfg, 'vty')
    for block in blocks:
        found = [c for c in block if re.match(r'transport input\b', c)]
        protocols = set(_tokens(found[-1])[2:]) if found else None
        if protocols is None:
            problems.append('transport input 없는 vty 블록')
        elif protocols & {'telnet', 'all'}:
            problems.append('vty가 telnet·all 허용')
    if not cfg.top(r'ip ssh version 2$'):
        problems.append('ip ssh version 2 없음')
    if access != 'ssh' and ctx['version'].strip() and not re.search(r'k9', ctx['version'], re.I):
        problems.append('이미지에 k9 표기 없음(SSH 미지원)')
    if problems:
        return 'VULN', ', '.join(sorted(set(problems)))
    if not blocks:
        return 'NA', 'line vty 블록 없음'
    return 'GOOD', 'vty는 SSH만 허용, ip ssh version 2'


@switch_check('N-09', title='불필요한 보조 입출력 포트 사용 금지', severity='중', category='접근')
def _n09(ctx):
    blocks = _line_blocks(ctx['config'], 'aux')
    if not blocks:
        return 'NA', 'line aux 블록 없음 (AUX 포트 없는 기종)'
    if all(any(c in ('transport input none', 'no exec') for c in b) for b in blocks):
        return 'GOOD', 'AUX 포트가 막혀 있음'
    return 'VULN', 'line aux에 transport input none·no exec 없음'


_SYSTEM_INFO = re.compile(r'\$\((?:hostname|domain|line|line-desc)\)|\b(?:cisco|ios)\b', re.I)


@switch_check('N-10', title='로그인 시 경고 메시지 설정', severity='중', category='접근')
def _n10(ctx):
    cfg = ctx['config']
    banners = {k: b for k, b in cfg.banners.items() if k in ('login', 'motd', 'exec') and b}
    if not banners:
        return 'VULN', 'banner login·motd·exec 없음'
    host = cfg.hostname
    for body in banners.values():
        if _SYSTEM_INFO.search(body) or (len(host) >= 3 and re.search(r'\b%s\b' % re.escape(host), body, re.I)):
            return 'VULN', 'banner에 시스템 정보(호스트명·모델·버전) 포함'
    return 'GOOD', 'banner %s 설정, 시스템 정보 없음' % '·'.join(sorted(banners))


def _is_address(token):
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


@switch_check('N-11', title='원격로그 서버 사용', severity='중', category='접근')
def _n11(ctx):
    cfg = ctx['config']
    hosts = cfg.top(r'logging host\s+\S+') + [ln for ln in cfg.top(r'logging\s+\S+') if _is_address(_tokens(ln)[1])]
    if not hosts:
        return 'VULN', '원격 로그 서버(logging host) 없음'
    if 'no logging on' in cfg.lines:
        return 'VULN', 'no logging on'
    return 'GOOD', '원격 로그 서버 %d개' % len(hosts)


@switch_check('N-12', title='주기적 보안 패치 및 벤더 권고사항 적용', severity='상', category='패치', l2='점검불가', l3='점검불가',
              reason='벤더 권고·EoL 조회 출처가 정해지지 않아 버전만 수집하고 판정은 점검불가(수동 확인)로 고정')
def _n12(ctx):
    version = _version_string(ctx['version'])
    return 'MANUAL', ('소프트웨어 버전 %s 기록, 벤더 권고·EoL 출처 미정이라 수동 확인' % version) if version \
        else '버전을 읽지 못함, 수동 확인'


@switch_check('N-13', title='로깅 버퍼 크기 설정', severity='중', category='로그')
def _n13(ctx):
    cfg = ctx['config']
    found = [ln for ln in cfg.lines if ln == 'no logging buffered' or ln.startswith('logging buffered')]
    if not found or found[-1].startswith('no '):
        return 'VULN', 'logging buffered 없음'
    toks = _tokens(found[-1])[2:]
    if not toks or not toks[0].isdigit():
        return 'VULN', 'logging buffered 크기 미지정(기본값)'
    size = int(toks[0])
    if size < MIN_BUFFER_BYTES:
        return 'VULN', '버퍼 %d바이트 (기준 %d 이상)' % (size, MIN_BUFFER_BYTES)
    return 'GOOD', '버퍼 %d바이트' % size


_TRAP_LEVELS = {'emergencies': 0, 'alerts': 1, 'critical': 2, 'errors': 3, 'warnings': 4, 'notifications': 5,
                'informational': 6, 'debugging': 7}


@switch_check('N-14', title='정책에 따른 로깅 설정', severity='중', category='로그')
def _n14(ctx):
    cfg = ctx['config']
    if 'no logging on' in cfg.lines:
        return 'VULN', 'no logging on'
    traps = [ln for ln in cfg.lines if re.match(r'logging trap\s+\S+', ln)]
    if not traps:
        return 'GOOD', 'logging trap 기본 수준(informational)'
    level = _tokens(traps[-1])[2]
    number = int(level) if level.isdigit() else _TRAP_LEVELS.get(level)
    if number is None or number > 7:
        return 'VULN', 'logging trap 수준 값이 올바르지 않음'
    if number < 6:
        return 'VULN', 'logging trap 수준이 informational보다 덜 상세'
    return 'GOOD', 'logging trap 수준이 informational 이상으로 상세'


@switch_check('N-15', title='NTP 및 시각 동기화 설정', severity='중', category='로그')
def _n15(ctx):
    cfg = ctx['config']
    if not cfg.top(r'ntp (server|peer)\b'):
        return 'VULN', 'ntp server·peer 없음'
    if cfg.top(r'ntp access-group\b'):
        return 'GOOD', 'ntp 서버와 ntp access-group 설정'
    if _is_old_or_unknown(ctx['version']):
        return 'MANUAL', 'IOS 12.2 미만이거나 버전 불명인데 ntp access-group이 없어 수동 확인'
    return 'GOOD', 'ntp 서버 설정'


@switch_check('N-16', title='Timestamp 로그 설정', severity='하', category='로그')
def _n16(ctx):
    found = [ln for ln in ctx['config'].lines if re.match(r'(no )?service timestamps log\b', ln)]
    if found and found[-1].startswith('service timestamps log datetime'):
        return 'GOOD', 'service timestamps log datetime'
    return 'VULN', 'service timestamps log datetime 아님'


# ------------------------------------------------------------------ judgement

def _first_line(text, limit=200):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def _failed(reason):
    return {'edition': EDITION, 'status': STATUS_FAILED, 'reason': reason, 'results': []}


def _parse_probe(probe):
    """(running_config, version, None) or (None, None, reason). Reasons are fixed texts: the collector's own output
    and the target address never reach the record."""
    probe = probe or {}
    if probe.get('resolve_failed'):
        return None, None, '접속 정보 해석 실패 (OpenBao Endpoint·Credential 확인)'
    if probe.get('skipped'):
        return None, None, '점검을 건너뜀'
    if probe.get('unreachable'):
        return None, None, '접속 실패'
    rc = probe.get('rc')
    if rc == 3:
        return None, None, '접속·수집 실패 (수집기 종료 코드 3, 재시도하지 않음)'
    if rc == 2:
        return None, None, '수집한 출력이 설정으로 보이지 않음 (수집기 종료 코드 2)'
    if rc != 0:
        return None, None, '수집 실패 (rc=%s)' % rc
    try:
        data = json.loads(probe.get('stdout') or '')
        config, version = data['running_config'], data['version']
        if not isinstance(config, str) or not isinstance(version, str):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return None, None, '수집기 출력 형식 오류'
    if not config.strip():
        return None, None, '수집한 설정이 비어 있음'
    return config, version, None


def host_audit_switch_result(probe, access, register, inventory_hostname, groups, today):
    """Build the ``config_vulnerability`` part of a switch record.

    ``probe`` is the registered collector run, ``access`` the session protocol ('ssh' | 'telnet'), ``register`` the
    exception register, ``groups`` the switch's inventory groups, ``today`` the run date. The result also carries
    ``role`` ('L2' | 'L3') and ``version`` when the collection worked.
    """
    config_text, version, reason = _parse_probe(probe)
    if reason:
        return _failed(reason)
    cfg = Config(config_text)
    role = device_role(cfg)
    ctx = {'config': cfg, 'version': version, 'access': access, 'role': role}
    result = {'edition': EDITION, 'status': STATUS_OK, 'reason': '', 'role': role,
              'version': _version_string(version), 'results': []}
    for code in sorted(CHECKS):
        meta = CHECKS[code]
        state = meta['l2' if role == 'L2' else 'l3']
        try:
            if state == NOT_APPLICABLE_STATE:
                raw, evidence = 'NA', meta['reason']
            else:
                raw, evidence = meta['fn'](ctx)
        except Exception:  # noqa: BLE001 - one broken item must not stop the switch; the message could hold config text
            raw, evidence = 'MANUAL', '판정 중 오류가 나 수동 확인 필요'
        verdict = RAW_VERDICTS.get(raw, MANUAL)
        verdict, exception = _apply_register(code, verdict, register, inventory_hostname, groups, today)
        result['results'].append({'code': full_code(code), 'result': raw, 'verdict': verdict,
                                  'evidence': evidence, 'exception': exception})
    return result


def host_audit_switch_record(probe, inventory_hostname, declared, collected_at, access, register, today):
    """The per-switch JSON record: the server record's keys (``identity``/``os`` stay null) plus ``device_type`` and
    ``switch`` (access, role, version). A switch that could not be inspected has status ``unreachable`` (connection)
    or ``probe_failed`` (reached, but no usable output) with the reason, like a server."""
    declared = declared or {}
    groups = sorted(declared.get('groups') or [])
    verdict = host_audit_switch_result(probe, access, register, inventory_hostname, groups, today)
    record = {
        'schema_version': RECORD_SCHEMA_VERSION,
        'device_type': DEVICE_TYPE,
        'inventory_hostname': inventory_hostname,
        'collected_at': collected_at,
        'status': 'ok',
        'reason': '',
        'declared': {'fqdn': declared.get('fqdn') or '', 'ip': declared.get('ip') or '',
                     'environment': declared.get('environment') or '', 'groups': groups},
        'identity': None,
        'os': None,
    }
    if verdict['status'] != STATUS_OK:
        connection = ('접속' in verdict['reason'] and '출력' not in verdict['reason'] and '해석' not in verdict['reason']) \
            or '해석' in verdict['reason'] or '건너뜀' in verdict['reason']
        record['status'] = 'unreachable' if connection else 'probe_failed'
        record['reason'] = _first_line(verdict['reason'])
        record['config_vulnerability'] = verdict
        return record
    record['switch'] = {'access': access, 'role': verdict['role'], 'version': verdict['version']}
    record['config_vulnerability'] = {k: verdict[k] for k in ('edition', 'status', 'reason', 'results')}
    return record


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_switch_result': host_audit_switch_result,
            'host_audit_switch_record': host_audit_switch_record,
        }
