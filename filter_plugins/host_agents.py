"""Filters for the Host Agents entry point (ADR-0006).

Two concerns live here so they can be tested without a target host:

* OS probe parsing: the raw probe output is turned into ``host_agents_os_*``
  facts and the ``legacy_el6`` / ``legacy_el7`` / ``modern`` path.
* Agents KV validation/merge: the per-host OpenBao ``hosts/<host>/agents``
  secret is checked (required keys, non-excludable paths) and merged with the
  Git standard lists. Problems are returned as messages (never raised) so the
  playbook can print them without hiding the task output behind ``no_log``.
"""

import fnmatch
import json
import re

OS_MARKER = '__HOST_AGENTS_OS_RELEASE__'
REDHAT_MARKER = '__HOST_AGENTS_REDHAT_RELEASE__'
UNAME_MARKER = '__HOST_AGENTS_UNAME_M__'
MACHINE_ID_MARKER = '__HOST_AGENTS_MACHINE_ID__'
_MARKERS = (OS_MARKER, REDHAT_MARKER, UNAME_MARKER, MACHINE_ID_MARKER)

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

REQUIRED_KEYS = ('o2_ingest_token', 'rustfs_access_key', 'rustfs_secret_key', 'restic_password')
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
            "echo {u}; uname -m").format(o=OS_MARKER, r=REDHAT_MARKER, m=MACHINE_ID_MARKER, u=UNAME_MARKER)


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
        errors.append("host_agents_environment %s: %s 중 하나여야 합니다 (인벤토리 변수 host_agents_environment 또는 "
                      "OpenBao hosts/%s/agents의 같은 이름 키)"
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


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def host_agents_resolve_inputs(host_kv, standard_logs, security_paths, mandatory_backup_paths,
                               kv_path='hosts/<host>/agents', shared=None, service_map=None):
    """Validate the per-host agents KV and merge it with the Git standard.

    Returns ``{'errors': [...], ...merged inputs...}``; the merged part never
    contains secret values. Missing required keys and excludes that target a
    ``security_logs`` path or a mandatory backup path are errors (fail-closed,
    the caller fails the host before any change).

    Every log entry carries the ``service`` (OTel ``service.name``) it is reported under: the
    ``service_map`` entry for a standard path, the ``service`` key of an ``otel_extra_logs`` item,
    otherwise the stream name without ``_logs``.
    """
    kv = host_kv if isinstance(host_kv, dict) else {}
    errors = []

    for name, secret in sorted((shared or {}).items()):
        errors.extend(host_agents_shared_errors(secret, name))

    for key in REQUIRED_KEYS:
        if _is_blank(kv.get(key)):
            errors.append("필수 키 누락: %s (OpenBao %s)" % (key, kv_path))

    security = list(security_paths or [])
    extra_logs_in = _as_list(kv.get('otel_extra_logs'), 'otel_extra_logs', errors)
    exclude_logs = _string_list(kv.get('otel_exclude_logs'), 'otel_exclude_logs', errors)
    extra_paths = _string_list(kv.get('backup_extra_paths'), 'backup_extra_paths', errors)
    exclude_paths = _string_list(kv.get('backup_exclude_paths'), 'backup_exclude_paths', errors)
    pre_hooks = _string_list(kv.get('backup_pre_hooks'), 'backup_pre_hooks', errors)
    docker_metrics = _as_bool(kv.get('otel_docker_metrics'), 'otel_docker_metrics', errors)

    for path in exclude_logs:
        if any(_covers(path, sec) for sec in security):
            errors.append("otel_exclude_logs: security_logs 경로는 제외할 수 없습니다: %s (OpenBao %s)"
                          % (path, kv_path))

    mandatory = [_norm_path(p) for p in (mandatory_backup_paths or [])]
    for path in exclude_paths:
        norm = _norm_path(path)
        if any(norm == m or m.startswith(norm.rstrip('/') + '/') for m in mandatory):
            errors.append("backup_exclude_paths: 필수 백업 경로는 제외할 수 없습니다: %s (OpenBao %s)"
                          % (path, kv_path))

    for path in extra_paths:
        if not path.startswith('/'):
            errors.append("backup_extra_paths: 절대 경로여야 합니다: %s" % path)

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
            errors.append("otel_extra_logs: glob 문자열 또는 {path, stream} 항목만 허용됩니다")
            continue
        if not path.startswith('/'):
            errors.append("otel_extra_logs: 절대 경로여야 합니다: %s" % path)
        elif stream not in LOG_STREAMS:
            errors.append("otel_extra_logs: 알 수 없는 stream %r (%s): %s"
                          % (stream, ', '.join(LOG_STREAMS), path))
        elif _GLOB_UNSUPPORTED.search(path):
            errors.append("otel_extra_logs: 지원하지 않는 글롭 문법입니다 ([ ] { } \\ ^ 따옴표 제외): %s" % path)
        elif service is not None and not (isinstance(service, str) and _SERVICE_NAME.match(service)):
            errors.append("otel_extra_logs: service는 소문자·숫자·.-_ 로 된 이름이어야 합니다 (%r): %s"
                          % (service, path))
        elif not any(l['path'] == path for l in logs):
            logs.append({'path': path, 'stream': stream, 'service': service or _default_service(stream)})

    return {
        'errors': errors,
        'otel_logs': logs,
        'otel_docker_metrics': docker_metrics,
        'backup_paths': _dedupe(list(mandatory_backup_paths or []) + extra_paths),
        'backup_exclude_paths': _dedupe(exclude_paths),
        'backup_pre_hooks': pre_hooks,
    }


def host_agents_shared_errors(shared, name):
    """A shared ``agents/<name>`` secret must exist and carry at least one value."""
    if not isinstance(shared, dict) or not any(not _is_blank(v) for v in shared.values()):
        return ["공유 시크릿 누락 또는 비어 있음: agents/%s" % name]
    return []


def host_agents_secrets(host_kv):
    """The required per-host secrets only (call from a ``no_log`` task)."""
    kv = host_kv if isinstance(host_kv, dict) else {}
    return {key: kv[key] for key in REQUIRED_KEYS if not _is_blank(kv.get(key))}


def host_agents_warn(msg):
    """Emit ``msg`` as a real Ansible ``[WARNING]`` (counted, shown on stderr) and return it unchanged.

    There is no builtin warn action; a ``debug`` line is easy to miss in a long run. Keep the
    hostname in the message: Ansible prints each identical warning text only once.
    """
    from ansible.utils.display import Display
    Display().warning(str(msg))
    return msg


class FilterModule(object):
    def filters(self):
        return {
            'host_agents_glob_regex': host_agents_glob_regex,
            'host_agents_os_probe_cmd': host_agents_os_probe_cmd,
            'host_agents_parse_os_probe': host_agents_parse_os_probe,
            'host_agents_resolve_inputs': host_agents_resolve_inputs,
            'host_agents_resource_attributes': host_agents_resource_attributes,
            'host_agents_secrets': host_agents_secrets,
            'host_agents_shared_errors': host_agents_shared_errors,
            'host_agents_warn': host_agents_warn,
        }
