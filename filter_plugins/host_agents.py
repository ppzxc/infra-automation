"""Filters for the Host Agents entry point (ADR-0006).

Two concerns live here so they can be tested without a target host:

* OS probe parsing: the raw probe output is turned into ``host_agents_os_*``
  facts and the ``legacy_el6`` / ``legacy_el7`` / ``modern`` path.
* Agents input validation/merge: the Asset document ``agents`` clause and the per-host
  ``secrets/assets/<ns>/agents`` secrets (Spec #511) are checked (required keys, non-excludable paths)
  and merged with the Git standard lists. Problems are returned as messages (never raised) so the
  playbook can print them without hiding the task output behind ``no_log``.
"""

import fnmatch
import ipaddress
import json
import re

OS_MARKER = '__HOST_AGENTS_OS_RELEASE__'
REDHAT_MARKER = '__HOST_AGENTS_REDHAT_RELEASE__'
UNAME_MARKER = '__HOST_AGENTS_UNAME_M__'
MACHINE_ID_MARKER = '__HOST_AGENTS_MACHINE_ID__'
TIMEZONE_MARKER = '__HOST_AGENTS_TIMEZONE__'
CONNTRACK_MARKER = '__HOST_AGENTS_CONNTRACK__'
_MARKERS = (OS_MARKER, REDHAT_MARKER, UNAME_MARKER, MACHINE_ID_MARKER, TIMEZONE_MARKER, CONNTRACK_MARKER)
# IANA zone name as it appears under zoneinfo/ (e.g. Asia/Seoul, Etc/UTC). Anything else is not trusted.
_TIMEZONE = re.compile(r'^[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)*$')

_LEGACY_PATHS = {'6': 'legacy_el6', '7': 'legacy_el7'}
_ARCH = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
_DISTRIBUTIONS = {
    'rocky': 'Rocky', 'ubuntu': 'Ubuntu', 'debian': 'Debian', 'centos': 'CentOS',
    'rhel': 'RedHat', 'almalinux': 'AlmaLinux', 'ol': 'OracleLinux', 'fedora': 'Fedora',
}
_REDHAT_LIKE = {'rhel', 'centos', 'rocky', 'almalinux', 'fedora', 'ol'}
# CentOS 6 has no /etc/os-release: derive the os-release style ID from the redhat-release name.
_REDHAT_NAME_IDS = (('red hat', 'rhel'), ('centos', 'centos'), ('rocky', 'rocky'),
                    ('almalinux', 'almalinux'), ('oracle', 'ol'), ('fedora', 'fedora'))
_MACHINE_ID = re.compile(r'^[0-9a-f]{32}$')
_DEBIAN_LIKE = {'debian', 'ubuntu'}

REQUIRED_KEYS = ('ingest_token', 'rustfs_access_key', 'rustfs_secret_key', 'restic_password')
# Required only where otelcol is installed (not on Host Agents Backup Only hosts).
OTEL_ONLY_KEYS = ('ingest_token',)
LOG_STREAMS = ('security_logs', 'system_logs', 'app_logs')


def host_agents_os_probe_cmd(_unused=''):
    """Raw command whose output ``host_agents_parse_os_probe`` understands.

    Markers delimit the sections so login banners and missing files (CentOS 6
    has no /etc/os-release or /etc/machine-id, Ubuntu has no /etc/redhat-release)
    never confuse the parser.
    """
    return ("echo {o}; cat /etc/os-release 2>/dev/null; "
            "echo {r}; cat /etc/redhat-release 2>/dev/null; "
            "echo {m}; cat /etc/machine-id 2>/dev/null; "
            "echo {t}; readlink /etc/localtime 2>/dev/null; cat /etc/sysconfig/clock 2>/dev/null; "
            "echo {c}; if test -r /proc/sys/net/netfilter/nf_conntrack_count "
            "&& test -r /proc/sys/net/netfilter/nf_conntrack_max; then echo present; else echo absent; fi; "
            "echo {u}; uname -m").format(c=CONNTRACK_MARKER, o=OS_MARKER, r=REDHAT_MARKER, m=MACHINE_ID_MARKER,
                                         t=TIMEZONE_MARKER, u=UNAME_MARKER)


def _sections(stdout):
    sections, current = {}, None
    for line in (stdout or '').splitlines():
        stripped = line.strip()
        if stripped in _MARKERS:
            current = stripped
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def _os_release_dict(lines):
    result = {}
    for line in lines:
        key, sep, value = line.partition('=')
        if sep and re.match(r'^[A-Z_]+$', key.strip()):
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def _timezone(lines):
    """Host timezone from the probe: the /etc/localtime link target (systemd family), else ZONE= of
    /etc/sysconfig/clock (CentOS 6, where /etc/localtime is a plain copy). Empty when unreadable or
    not a plain zone name, so the caller can fall back and warn."""
    zone = ''
    for line in lines:
        line = line.strip()
        if 'zoneinfo/' in line and not line.startswith('#'):
            zone = line.split('zoneinfo/', 1)[1]
            break
    if not zone:
        for line in lines:
            match = re.match(r'^ZONE\s*=\s*["\']?([^"\']*)["\']?\s*$', line.strip())
            if match:
                zone = match.group(1)
                break
    return zone if _TIMEZONE.match(zone) else ''


def host_agents_parse_os_probe(stdout):
    """Probe output -> ``host_agents_os_*`` fact values (without the prefix).

    Raises ValueError for output that carries no recognisable OS release, so a
    host that cannot be classified fails instead of guessing a path.
    """
    sections = _sections(stdout)
    os_rel = _os_release_dict(sections.get(OS_MARKER, []))
    redhat_line = next((ln.strip() for ln in sections.get(REDHAT_MARKER, []) if ln.strip()), '')
    uname = next((ln.strip() for ln in sections.get(UNAME_MARKER, []) if ln.strip()), '')
    machine_id = next((ln.strip().lower() for ln in sections.get(MACHINE_ID_MARKER, []) if ln.strip()), '')
    conntrack = next((ln.strip() for ln in sections.get(CONNTRACK_MARKER, []) if ln.strip()), '') == 'present'
    if not _MACHINE_ID.match(machine_id):
        machine_id = ''

    if not os_rel and not redhat_line:
        raise ValueError('OS probe returned neither /etc/os-release nor /etc/redhat-release')

    ids = {os_rel.get('ID', '').lower()} | set(os_rel.get('ID_LIKE', '').lower().split())
    if redhat_line or ids & _REDHAT_LIKE:
        family = 'RedHat'
    elif ids & _DEBIAN_LIKE:
        family = 'Debian'
    else:
        raise ValueError('unsupported OS (ID=%r): only RedHat and Debian families are handled'
                         % os_rel.get('ID', ''))

    match = re.match(r'^(?P<name>.+?)\s+(?:Linux\s+)?release\s+(?P<version>\d+(?:\.\d+)*)', redhat_line)
    if match:
        version = match.group('version')
    else:
        version = os_rel.get('VERSION_ID', '')
    major = version.split('.')[0] if version else ''

    os_id = os_rel.get('ID', '').lower()
    if os_id in _DISTRIBUTIONS:
        distribution = _DISTRIBUTIONS[os_id]
    elif match:
        distribution = match.group('name').split()[0]
    else:
        distribution = os_rel.get('NAME', os_id)

    if os_id:
        os_name = os_id
    elif match:
        lowered = match.group('name').lower()
        os_name = next((ident for prefix, ident in _REDHAT_NAME_IDS if lowered.startswith(prefix)),
                       lowered.split()[0])
    else:
        os_name = ''

    # Only RedHat-family 6/7 hosts (redhat-release present) take a legacy path.
    path = _LEGACY_PATHS.get(major, 'modern') if (family == 'RedHat' and redhat_line) else 'modern'

    return {
        'path': path,
        'family': family,
        'distribution': distribution,
        'os_id': os_name,
        'machine_id': machine_id,
        'timezone': _timezone(sections.get(TIMEZONE_MARKER, [])),
        'conntrack': conntrack,
        'version': version,
        'major_version': major,
        'arch': _ARCH.get(uname, uname),
        'type': 'linux',
        'description': os_rel.get('PRETTY_NAME') or redhat_line,
    }


# --------------------------------------------------------------------------
# Log path globs -> anchored regex, and the service.name of each log entry
# --------------------------------------------------------------------------

# Characters whose glob meaning (char class, braces) is not translated, and which would break
# the quoted regex literal handed to the collector (quotes, backslash). Rejected up front.
_GLOB_UNSUPPORTED = re.compile(r'[\[\]{}\\^"\']')
_SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]*$')


def host_agents_glob_regex(path):
    """Anchored regex equivalent of a log path glob (``*``, ``**`` and ``?`` only).

    The result has no backslashes: every other special character becomes a one-character class,
    so it can be embedded in a collector expression string without escaping.
    """
    path = str(path)
    if _GLOB_UNSUPPORTED.search(path):
        raise ValueError('unsupported glob syntax in %r' % path)
    out, i = ['^'], 0
    while i < len(path):
        ch = path[i]
        if path.startswith('**', i):
            out.append('.*')
            i += 2
            continue
        if ch == '*':
            out.append('[^/]*')
        elif ch == '?':
            out.append('[^/]')
        elif re.match(r'[A-Za-z0-9/_-]', ch):
            out.append(ch)
        else:
            out.append('[' + ch + ']')
        i += 1
    out.append('$')
    return ''.join(out)


def _default_service(stream):
    return stream[:-len('_logs')] if stream.endswith('_logs') else stream


# --------------------------------------------------------------------------
# OTel resource attributes of a host (ADR-0006 §2.3)
# --------------------------------------------------------------------------

ENVIRONMENTS = ('production', 'staging', 'development', 'test')


def host_agents_resource_attributes(hostname, environment, os_facts, ip=None):
    """Resource attributes stamped on every log and metric of a host.

    Returns ``{'attributes': {...}, 'errors': [...], 'omitted': [...]}``. ``deployment.environment.name``
    is mandatory and limited to ``ENVIRONMENTS`` (a missing or misspelled value is an error, never a
    silent default). ``host.id`` (no /etc/machine-id, e.g. CentOS 6) and ``host.ip`` (no usable ``ip``
    in the inventory) are left out and named in ``omitted`` so the caller can warn.
    """
    import ipaddress
    facts = os_facts if isinstance(os_facts, dict) else {}
    errors, omitted = [], []
    env = '' if environment is None else str(environment).strip()
    if env not in ENVIRONMENTS:
        errors.append("host_agents_environment %s: %s 중 하나여야 합니다 (역할 기본값 또는 Extra variables host_agents_environment) — 호스트 %s"
                      % ("누락" if not env else "값 %r 허용 안 됨" % env, ' | '.join(ENVIRONMENTS), hostname))
    attrs = {'host.name': str(hostname)}
    if facts.get('machine_id'):
        attrs['host.id'] = facts['machine_id']
    else:
        omitted.append('host.id')
    ip_text = '' if ip is None else str(ip).strip()
    try:
        attrs['host.ip'] = str(ipaddress.ip_address(ip_text))
    except ValueError:
        omitted.append('host.ip')
    for key, fact in (('host.arch', 'arch'), ('os.type', 'type'), ('os.name', 'os_id'),
                      ('os.version', 'version'), ('os.description', 'description')):
        if facts.get(fact):
            attrs[key] = str(facts[fact])
    if env in ENVIRONMENTS:
        attrs['deployment.environment.name'] = env
    return {'attributes': attrs, 'errors': errors, 'omitted': omitted}


# --------------------------------------------------------------------------
# Agents KV validation / merge
# --------------------------------------------------------------------------

def _norm_path(path):
    """Compare paths ignoring duplicate slashes and a trailing ``/``, ``/*`` or ``/**``."""
    value = re.sub(r'/+', '/', str(path).strip())
    value = re.sub(r'(/\*\*?)$', '', value)
    return value.rstrip('/') or '/'


def _covers(pattern, path):
    """True when an exclude entry equals, globs over, or is a parent directory of ``path``."""
    norm, target = _norm_path(pattern), _norm_path(path)
    return (norm == target or fnmatch.fnmatchcase(target, norm)
            or target.startswith(norm.rstrip('/') + '/'))


def _is_blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _as_list(value, key, errors):
    if _is_blank(value):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            errors.append("%s: 목록이어야 합니다 (문자열 수신)" % key)
            return []
    if not isinstance(value, list):
        errors.append("%s: 목록이어야 합니다" % key)
        return []
    return value


def _as_bool(value, key, errors):
    if _is_blank(value):
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ('true', 'yes', '1'):
        return True
    if text in ('false', 'no', '0'):
        return False
    errors.append("%s: true/false만 허용됩니다 (수신: %r)" % (key, value))
    return False


def _string_list(value, key, errors):
    items = _as_list(value, key, errors)
    bad = [i for i in items if not isinstance(i, str) or not i.strip()]
    if bad:
        errors.append("%s: 비어 있지 않은 문자열만 허용됩니다" % key)
    return [i.strip() for i in items if isinstance(i, str) and i.strip()]


# SQLite 스냅샷 대상: sqlite3 `.backup '<경로>'`와 셸 명령줄에 그대로 실려도 안전한 글자만 허용한다.
_SQLITE_PATH = re.compile(r'^/[A-Za-z0-9._/@+:%-]+$')


def _sqlite_snapshot_paths(value, errors, kv_path):
    items = _string_list(value, _label('backup_sqlite_snapshots'), errors)
    out = []
    for path in items:
        parts = path.split('/')
        if not _SQLITE_PATH.match(path) or '..' in parts or path.endswith('/') or '//' in path:
            errors.append("agents.backup.sqlite_snapshots: 안전한 절대 경로(영문·숫자·._/@+:%%- 만, '..' 없음, 파일)여야 합니다: %s (OpenBao %s)" % (path, kv_path))
        else:
            out.append(path)
    return out


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


_BUCKET_NAME = re.compile(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]')


def host_agents_valid_bucket(value):
    """S3 버킷 이름 규칙(소문자·숫자·점·하이픈 3~63자)을 지키는 문자열인가. 끝의 줄바꿈도 거른다. backup·host_audit·입력 검증이 이 한 곳을 쓴다."""
    return isinstance(value, str) and _BUCKET_NAME.fullmatch(value) is not None


_SECTIONS = (('backup_', 'backup'), ('otel_', 'otel'), ('github_webhook_', 'github_webhook'))
_PATH_LABELS = {'backup_extra_paths': 'agents.backup.extra_paths', 'backup_exclude_paths': 'agents.backup.exclude_paths',
                'backup_pre_hooks': 'agents.backup.pre_hooks', 'backup_sqlite_snapshots': 'agents.backup.sqlite_snapshots'}


def _label(flat_key):
    """저장 위치 이름: 평면 키(`backup_extra_paths`)를 Asset 문서의 절 경로(`agents.backup.extra_paths`)로 돌린다."""
    if flat_key in REQUIRED_KEYS:
        return flat_key
    for prefix, section in _SECTIONS:
        if flat_key.startswith(prefix):
            return 'agents.%s.%s' % (section, flat_key[len(prefix):])
    return flat_key


def _flatten(agents, secrets):
    """Asset 문서의 `agents` 절과 `secrets/assets/<ns>/agents`를 검증기가 읽는 평면 dict로 합친다(저장 형태 → 내부 키)."""
    flat = {}
    for prefix, section in _SECTIONS:
        body = (agents or {}).get(section) if isinstance(agents, dict) else None
        for key, value in (body.items() if isinstance(body, dict) else ()):
            if section == 'github_webhook' and key == 'secret':
                continue    # 시크릿은 secrets/assets/<ns>/agents의 webhook_secret에서만 받는다(비밀 아닌 마운트의 값은 무시하고 오류로 알린다)
            flat[prefix + key] = value
    snaps = flat.get('backup_sqlite_snapshots')
    if isinstance(snaps, list):   # 스키마상 항목은 {path: ...} 오브젝트다
        flat['backup_sqlite_snapshots'] = [i.get('path', '') if isinstance(i, dict) else i for i in snaps]
    sec = secrets if isinstance(secrets, dict) else {}
    for key in REQUIRED_KEYS:
        if key in sec:
            flat[key] = sec[key]
    if 'webhook_secret' in sec:
        flat['github_webhook_secret'] = sec['webhook_secret']
    return flat


def host_agents_resolve_inputs(agents, secrets, standard_logs, security_paths, mandatory_backup_paths,
                               kv_path='inventory/assets/<ns>', shared=None, service_map=None,
                               otel_enabled=True, os_path=None):
    """Validate the Asset ``agents`` clause plus the agents secrets and merge them with the Git standard.

    Returns ``{'errors': [...], ...merged inputs...}``; the merged part never
    contains secret values. Missing required keys and excludes that target a
    ``security_logs`` path or a mandatory backup path are errors (fail-closed,
    the caller fails the host before any change).

    Every log entry carries the ``service`` (OTel ``service.name``) it is reported under: the
    ``service_map`` entry for a standard path, the ``service`` key of an ``otel_extra_logs`` item,
    otherwise the stream name without ``_logs``.

    ``os_path`` (the probed path) lets the opt-in webhook receiver fail on a legacy host instead of being silently ignored.

    With ``otel_enabled`` false (Host Agents Backup Only) the otelcol-only keys are not required.
    """
    kv = _flatten(agents, secrets)
    errors = []
    if isinstance((agents or {}).get('github_webhook') if isinstance(agents, dict) else None, dict) \
            and 'secret' in agents['github_webhook']:
        errors.append("agents.github_webhook.secret: 시크릿은 Asset 문서에 둘 수 없습니다 — secrets/assets/<ns>/agents의 webhook_secret을 쓰세요")

    for name, doc in sorted((shared or {}).items()):
        errors.extend(host_agents_shared_errors(doc, name))

    for key in REQUIRED_KEYS:
        if key in OTEL_ONLY_KEYS and not otel_enabled:
            continue
        if _is_blank(kv.get(key)):
            errors.append("필수 키 누락: %s (OpenBao secrets/assets/<ns>/agents)" % key)

    security = list(security_paths or [])
    extra_logs_in = _as_list(kv.get('otel_extra_logs'), _label('otel_extra_logs'), errors)
    exclude_logs = _string_list(kv.get('otel_exclude_logs'), _label('otel_exclude_logs'), errors)
    extra_paths = _string_list(kv.get('backup_extra_paths'), _label('backup_extra_paths'), errors)
    exclude_paths = _string_list(kv.get('backup_exclude_paths'), _label('backup_exclude_paths'), errors)
    pre_hooks = _string_list(kv.get('backup_pre_hooks'), _label('backup_pre_hooks'), errors)
    sqlite_snapshots = _sqlite_snapshot_paths(kv.get('backup_sqlite_snapshots'), errors, kv_path)
    backup_bucket = kv.get('backup_bucket')
    if _is_blank(backup_bucket):
        backup_bucket = ''
    elif not host_agents_valid_bucket(backup_bucket):
        errors.append("agents.backup.bucket: S3 버킷 이름 규칙(소문자·숫자·점·하이픈 3~63자)을 지켜야 합니다 (OpenBao %s)" % kv_path)
        backup_bucket = ''
    docker_metrics = _as_bool(kv.get('otel_docker_metrics'), _label('otel_docker_metrics'), errors)
    container_logs = _as_bool(kv.get('otel_container_logs'), _label('otel_container_logs'), errors)
    app_telemetry = _as_bool(kv.get('otel_app_telemetry'), _label('otel_app_telemetry'), errors)
    github_webhook = _as_bool(kv.get('otel_github_webhook'), _label('otel_github_webhook'), errors)
    if github_webhook:
        errors.extend(_github_webhook_errors(kv))
        if os_path not in (None, 'modern'):
            errors.append("agents.otel.github_webhook: modern 경로 호스트에서만 지원합니다(현재 %s, CentOS 6/7 제외)" % os_path)

    for path in exclude_logs:
        if any(_covers(path, sec) for sec in security):
            errors.append("agents.otel.exclude_logs: security_logs 경로는 제외할 수 없습니다: %s (OpenBao %s)"
                          % (path, kv_path))

    mandatory = [_norm_path(p) for p in (mandatory_backup_paths or [])]
    for path in exclude_paths:
        norm = _norm_path(path)
        if any(norm == m or m.startswith(norm.rstrip('/') + '/') for m in mandatory):
            errors.append("agents.backup.exclude_paths: 필수 백업 경로는 제외할 수 없습니다: %s (OpenBao %s)"
                          % (path, kv_path))

    for path in extra_paths:
        if not path.startswith('/'):
            errors.append("agents.backup.extra_paths: 절대 경로여야 합니다: %s" % path)

    services = service_map or {}
    logs = []
    for p in _dedupe(standard_logs or []):
        if any(_covers(x, p) for x in exclude_logs):
            continue
        stream = 'security_logs' if p in security else 'system_logs'
        if _GLOB_UNSUPPORTED.search(p):
            errors.append("otel_system_logs: 지원하지 않는 글롭 문법입니다 ([ ] { } \\ ^ 따옴표 제외): %s" % p)
            continue
        logs.append({'path': p, 'stream': stream, 'service': services.get(p) or _default_service(stream)})
    for entry in extra_logs_in:
        service = None
        if isinstance(entry, str) and entry.strip():
            path, stream = entry.strip(), 'app_logs'
        elif isinstance(entry, dict) and isinstance(entry.get('path'), str) and entry['path'].strip():
            path, stream = entry['path'].strip(), entry.get('stream') or 'app_logs'
            service = entry.get('service')
        else:
            errors.append("agents.otel.extra_logs: glob 문자열 또는 {path, stream} 항목만 허용됩니다")
            continue
        if not path.startswith('/'):
            errors.append("agents.otel.extra_logs: 절대 경로여야 합니다: %s" % path)
        elif stream not in LOG_STREAMS:
            errors.append("agents.otel.extra_logs: 알 수 없는 stream %r (%s): %s"
                          % (stream, ', '.join(LOG_STREAMS), path))
        elif _GLOB_UNSUPPORTED.search(path):
            errors.append("agents.otel.extra_logs: 지원하지 않는 글롭 문법입니다 ([ ] { } \\ ^ 따옴표 제외): %s" % path)
        elif service is not None and not (isinstance(service, str) and _SERVICE_NAME.match(service)):
            errors.append("agents.otel.extra_logs: service는 소문자·숫자·.-_ 로 된 이름이어야 합니다 (%r): %s"
                          % (service, path))
        elif not any(l['path'] == path for l in logs):
            logs.append({'path': path, 'stream': stream, 'service': service or _default_service(stream)})

    return {
        'errors': errors,
        'otel_logs': logs,
        'otel_home_log_dirs': _home_log_dirs(logs),
        'otel_docker_metrics': docker_metrics,
        'otel_container_logs': container_logs,
        'otel_app_telemetry': app_telemetry,
        'otel_github_webhook': github_webhook,
        'backup_paths': _dedupe(list(mandatory_backup_paths or []) + extra_paths),
        'backup_exclude_paths': _dedupe(exclude_paths),
        'backup_pre_hooks': pre_hooks,
        'backup_sqlite_snapshots': _dedupe(sqlite_snapshots),
        'backup_bucket': backup_bucket,
    }


def _home_log_dirs(logs):
    """수집 경로 중 /home 아래에 있는 것의 디렉터리 목록.

    otelcol 유닛이 ProtectHome 아래서 도니 /home은 보이지 않는다. 이 디렉터리만 읽기 전용으로 노출한다(전체 /home은 열지 않는다).
    글롭 문자가 나오기 직전의 디렉터리를 쓴다.
    """
    dirs = []
    for entry in logs:
        path = entry['path']
        if not path.startswith('/home/') or '..' in path.split('/'):
            continue
        static = re.split(r'[*?]', path, maxsplit=1)[0]
        directory = static.rsplit('/', 1)[0] if '/' in static else ''
        if directory.count('/') >= 2:
            dirs.append(directory)
    return _dedupe(sorted(dirs))


# GitHub 조직 웹훅 수신기(Spec #399): 주소·포트·경로·네트워크 이름은 Asset 문서의 `agents.github_webhook` 절, 시크릿은
# `secrets/assets/<ns>/agents`의 `webhook_secret`에서만 들어온다(저장소에 기본값 없음). 켰는데 하나라도 비면 배포가 실패한다
# (오류 메시지에는 키 이름만 쓰고 값은 쓰지 않는다).
GITHUB_WEBHOOK_FIELDS = ('address', 'port', 'path', 'secret', 'network')


def host_agents_github_webhook(agents, secrets=None):
    """The webhook receiver values (private; call from a ``no_log`` task). Blank or absent values become ``''``; others are kept verbatim (the validation rejects stray whitespace)."""
    return _webhook_values(_flatten(agents, secrets))


def _webhook_values(kv):
    return {f: ('' if _is_blank(kv.get('github_webhook_' + f)) else str(kv['github_webhook_' + f]))
            for f in GITHUB_WEBHOOK_FIELDS}


def _github_webhook_errors(kv):
    values = _webhook_values(kv)
    errors = [("필수 키 누락: webhook_secret (agents.otel.github_webhook가 켜져 있음)" if f == 'secret' else "필수 키 누락: agents.github_webhook.%s (agents.otel.github_webhook가 켜져 있음)" % f)
              for f in GITHUB_WEBHOOK_FIELDS if not values[f]]
    if values['address']:
        try:
            addr = ipaddress.IPv4Address(values['address'])
            if addr.is_unspecified or addr.is_loopback:
                raise ValueError
        except ValueError:
            errors.append("agents.github_webhook.address: 컨테이너 브리지 전용 IPv4 주소여야 합니다(모든 인터페이스·루프백 불가)")
    if values['port'] and not (re.fullmatch('[0-9]{1,5}', values['port']) and 1 <= int(values['port']) <= 65535):
        errors.append("agents.github_webhook.port: 1~65535 정수(ASCII 숫자)여야 합니다")
    if values['path']:
        segments = values['path'].split('/')[1:]
        if not (re.fullmatch(r'/[A-Za-z0-9._~/-]+', values['path']) and all(seg and seg not in ('.', '..') for seg in segments)):
            errors.append("agents.github_webhook.path: '/'로 시작하고 비어 있지 않은 세그먼트(영문·숫자·._~-)로만 이루어져야 합니다"
                          "('/' 단독, 빈·'.'·'..' 세그먼트, 끝 슬래시 불가)")
    if values['secret'] and not re.fullmatch('[\x20-\x7e]+', values['secret']):
        errors.append("webhook_secret: 인쇄 가능한 ASCII(공백 포함)만 허용됩니다(제어문자·비ASCII 불가, EnvironmentFile 이스케이프 한계)")
    return errors


def host_agents_github_webhook_gateway_errors(inspect_stdout, address):
    """Errors when the docker network gateway (``docker network inspect`` output) differs from the bind address."""
    gateway = (inspect_stdout or '').strip()
    if gateway != str(address or '').strip() or not gateway:
        return ["도커 네트워크 게이트웨이가 agents.github_webhook.address와 다릅니다(바인딩 설정과 불일치 — 배포 중단)"]
    return []


def host_agents_shared_errors(doc, name):
    """A shared Service document (``inventory/services/<name>``) must exist and carry a ``url``."""
    if not isinstance(doc, dict) or _is_blank(doc.get('url')):
        return ["공유 설정 누락 또는 url 없음: inventory/services/%s" % name]
    return []


def host_agents_secrets(secrets):
    """The required per-host secrets only (call from a ``no_log`` task)."""
    sec = secrets if isinstance(secrets, dict) else {}
    return {key: sec[key] for key in REQUIRED_KEYS if not _is_blank(sec.get(key))}


def host_agents_openbao_gaps(docs, required):
    """읽은 문서(`{index.yml 패턴: 문서}`)가 `<역할>_openbao_required` 선언을 채우는지 본다. 문서 없음·필수 키 누락의 이름만 돌려준다(값은 아님).

    선언에는 있지만 ``docs``에 없는 패턴(다른 태스크가 읽는 문서)은 건너뛴다.
    """
    gaps = []
    for pattern, doc in (docs or {}).items():
        if not isinstance(doc, dict):
            gaps.append("%s(문서 없음)" % pattern)
            continue
        gaps.extend("%s.%s" % (pattern, key) for key in (required or {}).get(pattern, []) if _is_blank(doc.get(key)))
    return gaps


def host_agents_warn(msg):
    """Emit ``msg`` as a real Ansible ``[WARNING]`` (counted, shown on stderr) and return it unchanged.

    There is no builtin warn action; a ``debug`` line is easy to miss in a long run. Keep the
    hostname in the message: Ansible prints each identical warning text only once.
    """
    from ansible.utils.display import Display
    Display().warning(str(msg))
    return msg


def _blank(value):
    return value is None or str(value).strip() == ''


def host_agents_tcpcheck_targets(roster, endpoints_by_host, endpoint='ssh', skip_unregistered=False):
    """서버 도달성(tcp_check) 대상 'address:port' 목록 — 실행 범위(target_hosts)와 무관하게 Asset의 Endpoint 문서로 만든다.

    ``endpoints_by_host``는 `{<관리번호>: inventory/assets/<ns>/endpoints 문서}`다. 이름이 ``endpoint``인 Endpoint의 주소·포트를 쓴다.
    없으면 22나 호스트명으로 짐작하지 않고 실패한다(대체값 없음). roster 순서를 유지한다.

    ``skip_unregistered``면 Endpoint 문서 자체가 아직 없는 Asset(편입 전 호스트)은 실패시키지 않고 경고와 함께 건너뛴다. 옛 코드는 이런
    호스트를 호스트명:22로 대체했지만 짐작한 대상은 오발화하므로 대체하지 않는다. 문서는 있는데 `endpoint`가 없거나 주소·포트가 잘못된
    것은 잘못 등록된 것이라 그대로 실패한다.
    """
    targets, missing = [], []
    for name in roster:
        if skip_unregistered and not (endpoints_by_host or {}).get(name):
            host_agents_warn("서버 도달성 검사 대상에서 뺐습니다: %s의 Endpoint 문서(inventory/assets/%s/endpoints)가 아직 없습니다" % (name, name))
            continue
        ep = ((endpoints_by_host or {}).get(name) or {}).get(endpoint)
        port = ep.get('port') if isinstance(ep, dict) else None
        if not isinstance(ep, dict) or _blank(ep.get('address')) or isinstance(port, bool) \
                or not re.fullmatch(r'[0-9]{1,5}', str(port).strip()) or not 1 <= int(str(port).strip()) <= 65535:
            missing.append(name)
            continue
        targets.append('%s:%d' % (str(ep['address']).strip(), int(str(port).strip())))
    if missing:
        from ansible.errors import AnsibleFilterError
        raise AnsibleFilterError("서버 도달성 대상을 만들 수 없습니다 — %s Endpoint가 없거나 주소·포트가 잘못된 Asset: %s" % (endpoint, ', '.join(missing)))
    return targets


class FilterModule(object):
    def filters(self):
        return {
            'host_agents_glob_regex': host_agents_glob_regex,
            'host_agents_valid_bucket': host_agents_valid_bucket,
            'host_agents_os_probe_cmd': host_agents_os_probe_cmd,
            'host_agents_parse_os_probe': host_agents_parse_os_probe,
            'host_agents_resolve_inputs': host_agents_resolve_inputs,
            'host_agents_resource_attributes': host_agents_resource_attributes,
            'host_agents_openbao_gaps': host_agents_openbao_gaps,
            'host_agents_secrets': host_agents_secrets,
            'host_agents_github_webhook': host_agents_github_webhook,
            'host_agents_github_webhook_gateway_errors': host_agents_github_webhook_gateway_errors,
            'host_agents_shared_errors': host_agents_shared_errors,
            'host_agents_tcpcheck_targets': host_agents_tcpcheck_targets,
            'host_agents_warn': host_agents_warn,
        }
