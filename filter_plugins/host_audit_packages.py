# -*- coding: utf-8 -*-
"""Host Audit — Package Vulnerability (ADR-0009, Spec #115 / Ticket-7).

Pure functions, no Ansible imports at module level, so pytest can load this file directly.

Flow (roles/host_audit/tasks/packages.yml → packages_scan.yml):

1. ``host_audit_package_record``: the raw package probe output (roles/host_audit/files/
   package_probe.sh) → per-host package record (release + every installed package).
2. ``host_audit_sbom``: package record → CycloneDX 1.5 SBOM that ``trivy sbom`` judges the same
   way as ``trivy image`` (Vuls PoC #112: identical (CVE, package) pairs on 7 OSes).
3. ``host_audit_trivy_db_state``: result of ``trivy image --download-db-only`` + the DB
   metadata → fresh / cached (≤ 7 days) / unavailable (> 7 days or none).
4. ``host_audit_package_findings``: Trivy JSON for one host → classified findings
   (업데이트 가능 · CentOS용 수정본 없음 · 수정 안 함(will not fix) · 벤더 미수정).
5. ``host_audit_package_section``: all hosts → the report section model the template draws.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
import uuid
from datetime import datetime, timedelta, timezone

try:
    from urllib.parse import quote
except ImportError:  # pragma: no cover - Python 2 is not supported by the runner
    from urllib import quote

PACKAGE_RECORD_SCHEMA = 1

SECTION = 'Package Vulnerability'

# os-release ID → Trivy OS family (also the purl namespace).
TRIVY_FAMILY = {
    'rocky': 'rocky',
    'centos': 'centos',
    'rhel': 'redhat',
    'almalinux': 'alma',
    'ol': 'oracle',
    'amzn': 'amazon',
    'fedora': 'fedora',
    'ubuntu': 'ubuntu',
    'debian': 'debian',
}
# /etc/redhat-release prefixes for hosts without /etc/os-release (CentOS 6, RHEL 6).
REDHAT_RELEASE_FAMILY = (
    ('CentOS', 'centos'),
    ('Red Hat Enterprise Linux', 'redhat'),
    ('Rocky Linux', 'rocky'),
    ('AlmaLinux', 'alma'),
    ('Oracle Linux', 'oracle'),
)
RPM_FAMILIES = ('rocky', 'centos', 'redhat', 'alma', 'oracle', 'amazon', 'fedora')

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
SEVERITY_LABELS = {
    'CRITICAL': '긴급',
    'HIGH': '높음',
    'MEDIUM': '중간',
    'LOW': '낮음',
    'UNKNOWN': '미분류',
}

CLASS_UPDATE = 'update'
CLASS_NO_CENTOS_FIX = 'no_centos_fix'
CLASS_WILL_NOT_FIX = 'will_not_fix'
CLASS_UNFIXED = 'unfixed'
CLASSES = (CLASS_UPDATE, CLASS_NO_CENTOS_FIX, CLASS_WILL_NOT_FIX, CLASS_UNFIXED)
CLASS_LABELS = {
    CLASS_UPDATE: '업데이트 가능',
    CLASS_NO_CENTOS_FIX: 'CentOS용 수정본 없음',
    CLASS_WILL_NOT_FIX: '수정 안 함 (will not fix)',
    CLASS_UNFIXED: '벤더 미수정',
}

DB_FRESH = 'fresh'
DB_CACHED = 'cached'
DB_UNAVAILABLE = 'unavailable'
DB_MAX_AGE_DAYS = 7

STATUS_OK = 'ok'
UNAVAILABLE_LABEL = '점검불가'


# ------------------------------------------------------------------------------
# rpm version comparison (rpmvercmp), used for the CentOS vault comparison
# ------------------------------------------------------------------------------
def _rpmvercmp(a, b):
    """rpm's rpmvercmp: -1, 0, 1. Handles '~' (pre-release) and '^' (post-release)."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in '~^':
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in '~^':
            j += 1
        for mark in '~^':
            ai = i < len(a) and a[i] == mark
            bj = j < len(b) and b[j] == mark
            if ai or bj:
                if not (ai and bj):
                    if mark == '~':
                        return -1 if ai else 1
                    # '^': the side that ends first is older
                    if i >= len(a):
                        return -1
                    if j >= len(b):
                        return 1
                    # '^' sorts after the base version but before any further segment
                    return -1 if ai else 1
                i += 1
                j += 1
                break
        else:
            if i >= len(a) or j >= len(b):
                break
            if a[i].isdigit():
                m1 = re.match(r'\d+', a[i:]).group()
                m2 = re.match(r'\d+', b[j:])
                if not m2:
                    return 1
                m2 = m2.group()
                n1, n2 = m1.lstrip('0'), m2.lstrip('0')
                if len(n1) != len(n2):
                    return 1 if len(n1) > len(n2) else -1
                if n1 != n2:
                    return 1 if n1 > n2 else -1
            else:
                m1 = re.match(r'[A-Za-z]+', a[i:]).group()
                m2 = re.match(r'[A-Za-z]+', b[j:])
                if not m2:
                    return -1
                m2 = m2.group()
                if m1 != m2:
                    return 1 if m1 > m2 else -1
            i += len(m1)
            j += len(m2)
            continue
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _split_evr(evr):
    """'1:2.17-326.el7_9.3' → ('1', '2.17', '326.el7_9.3'). Epoch defaults to '0'."""
    epoch = '0'
    if ':' in evr:
        epoch, evr = evr.split(':', 1)
    version, release = evr.rsplit('-', 1) if '-' in evr else (evr, '')
    return epoch or '0', version, release


def rpm_vr_compare(a, b):
    """Compare two rpm 'version-release' strings, ignoring epochs (vault file names carry none)."""
    _, va, ra = _split_evr(a)
    _, vb, rb = _split_evr(b)
    c = _rpmvercmp(va, vb)
    if c:
        return c
    return _rpmvercmp(ra, rb)


def parse_vault_final(text):
    """'name<TAB>version-release' lines → {name: 'version-release'}. Lines starting with '#' are comments."""
    table = {}
    for line in (text or '').splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 2:
            table[parts[0]] = parts[1]
    return table


# ------------------------------------------------------------------------------
# 1. probe output → package record
# ------------------------------------------------------------------------------
def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def _sections(stdout):
    sections = {}
    current = None
    for line in (stdout or '').splitlines():
        line = line.rstrip('\r')
        if line.startswith('===') and line.endswith('==='):
            current = line.strip('=')
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def _release(lines):
    values = {}
    for line in lines:
        if '=' in line:
            key, _, value = line.partition('=')
            values[key.strip()] = _unquote(value)
    os_id = values.get('ID', '').lower()
    redhat_release = values.get('REDHAT_RELEASE', '')
    family = TRIVY_FAMILY.get(os_id, '')
    if not family and redhat_release:
        for prefix, fam in REDHAT_RELEASE_FAMILY:
            if redhat_release.startswith(prefix):
                family = fam
                break
    version = ''
    if family in RPM_FAMILIES and redhat_release:
        m = re.search(r'release\s+([0-9][0-9.]*)', redhat_release)
        version = m.group(1).rstrip('.') if m else ''
    elif family == 'debian':
        version = values.get('DEBIAN_VERSION', '') or values.get('VERSION_ID', '')
    if not version:
        version = values.get('VERSION_ID', '')
    return {
        'family': family,
        'version': version,
        'major': version.split('.')[0] if version else '',
        'name': values.get('PRETTY_NAME') or redhat_release or os_id,
        'arch': values.get('ARCH', ''),
    }


def _parse_rpm(lines):
    packages = []
    for line in lines:
        parts = line.split('\t')
        if len(parts) < 6:
            continue
        name, epoch, version, release, arch, srpm = parts[:6]
        modularity = parts[6] if len(parts) > 6 else ''
        if name == 'gpg-pubkey':  # signing keys, not software
            continue
        pkg = {
            'name': name,
            'epoch': '' if epoch in ('', '0', '(none)') else epoch,
            'version': version,
            'release': release,
            'arch': '' if arch == '(none)' else arch,
            'src_name': '', 'src_epoch': '', 'src_version': '', 'src_release': '',
            'modularitylabel': '' if modularity in ('', '(none)') else modularity,
        }
        m = re.match(r'^(.+)-([^-]+)-([^-]+)\.(?:no)?src\.rpm$', srpm)
        if m:
            pkg['src_name'], pkg['src_version'], pkg['src_release'] = m.groups()
            pkg['src_epoch'] = pkg['epoch']
        packages.append(pkg)
    return packages


def _deb_split(full):
    """'1:3.8-0ubuntu2.1' → ('1', '3.8', '0ubuntu2.1'); native '3.118ubuntu5' → ('', '3.118ubuntu5', '')."""
    epoch = ''
    if ':' in full:
        epoch, full = full.split(':', 1)
    if '-' in full:
        upstream, revision = full.rsplit('-', 1)
    else:
        upstream, revision = full, ''
    return ('' if epoch == '0' else epoch), upstream, revision


def _parse_deb(lines):
    packages = []
    for line in lines:
        parts = line.split('\t')
        if len(parts) < 6:
            continue
        status, name, full_version, arch, src_name, src_version = parts[:6]
        if len(status) < 2 or status[1] != 'i':  # installed (ii, hi) only
            continue
        epoch, upstream, revision = _deb_split(full_version)
        s_epoch, s_upstream, s_revision = _deb_split(src_version or full_version)
        packages.append({
            'name': name,
            'epoch': epoch,
            'version': upstream,
            'release': revision,
            'arch': arch,
            'src_name': src_name or name,
            'src_epoch': s_epoch,
            'src_version': s_upstream,
            'src_release': s_revision,
            'modularitylabel': '',
        })
    return packages


def host_audit_package_record(probe, inventory_hostname, collected_at):
    """Raw package probe result (registered ``ansible.builtin.raw``) → package record.

    status: ok · unreachable · probe_failed · unsupported (no rpm/dpkg or unknown OS family).
    The full package list lives only in this record (and the runner JSON), never in the report.
    """
    probe = probe or {}
    record = {
        'schema_version': PACKAGE_RECORD_SCHEMA,
        'inventory_hostname': inventory_hostname,
        'collected_at': collected_at,
        'status': STATUS_OK,
        'reason': '',
        'os': None,
        'format': None,
        'packages': [],
    }
    if probe.get('unreachable'):
        record['status'] = 'unreachable'
        record['reason'] = (probe.get('msg') or '접속 실패').splitlines()[0][:200]
        return record
    sections = _sections(probe.get('stdout', ''))
    if 'RELEASE' not in sections or 'END' not in sections:
        record['status'] = 'probe_failed'
        text = probe.get('stderr') or probe.get('msg') or probe.get('stdout') or '패키지 수집 표식 없음'
        record['reason'] = text.strip().splitlines()[0][:200] if text.strip() else '패키지 수집 표식 없음'
        return record
    record['os'] = _release(sections['RELEASE'])
    if 'PKGS_RPM' in sections:
        record['format'] = 'rpm'
        record['packages'] = _parse_rpm(sections['PKGS_RPM'])
    elif 'PKGS_DEB' in sections:
        record['format'] = 'deb'
        record['packages'] = _parse_deb(sections['PKGS_DEB'])
    if not record['format'] or not record['os']['family'] or not record['os']['version']:
        record['status'] = 'unsupported'
        record['reason'] = '패키지 관리자(rpm/dpkg) 또는 OS 계열을 판별하지 못함'
    elif not record['packages']:
        record['status'] = 'probe_failed'
        record['reason'] = '설치 패키지 목록이 비어 있음'
    return record


# ------------------------------------------------------------------------------
# 2. package record → CycloneDX SBOM (trivy sbom input)
# ------------------------------------------------------------------------------
def _q(value):
    return quote(value, safe='.-_~')


def _purl(fmt, family, distro, pkg):
    version = '%s-%s' % (pkg['version'], pkg['release']) if pkg['release'] else pkg['version']
    qualifiers = []
    if pkg['arch']:
        qualifiers.append(('arch', pkg['arch']))
    qualifiers.append(('distro', distro))
    if pkg['epoch']:
        qualifiers.append(('epoch', pkg['epoch']))
    if pkg.get('modularitylabel'):
        qualifiers.append(('modularitylabel', pkg['modularitylabel']))
    return 'pkg:%s/%s/%s@%s?%s' % (
        fmt, family, _q(pkg['name']), _q(version),
        '&'.join('%s=%s' % (k, _q(v)) for k, v in sorted(qualifiers)))


def _pkg_id(fmt, pkg):
    vr = '%s-%s' % (pkg['version'], pkg['release']) if pkg['release'] else pkg['version']
    if fmt == 'rpm':
        return '%s@%s%s' % (pkg['name'], vr, ('.' + pkg['arch']) if pkg['arch'] else '')
    return '%s@%s%s' % (pkg['name'], (pkg['epoch'] + ':') if pkg['epoch'] else '', vr)


def host_audit_sbom(record, timestamp=None):
    """Package record → CycloneDX 1.5 SBOM dict for ``trivy sbom``.

    Shape follows Trivy's own CycloneDX output (``trivy image --format cyclonedx``):
    one ``operating-system`` component, packages as purls with ``aquasecurity:trivy:*``
    source properties, and a dependency from the OS to every package. The root
    (``metadata.component``) must be ``application``: with ``operating-system`` there
    Trivy sees two OS components, picks one at random and may report 0 findings
    (Vuls PoC #112, 함정 하나). Output is deterministic for a given record.
    """
    os_info = record['os']
    family, version, fmt = os_info['family'], os_info['version'], record['format']
    distro = '%s-%s' % (family, version)
    host = record['inventory_hostname']
    root_ref = 'host:%s' % host
    os_ref = 'os:%s' % distro
    components = [{
        'bom-ref': os_ref,
        'type': 'operating-system',
        'name': family,
        'version': version,
        'properties': [
            {'name': 'aquasecurity:trivy:Class', 'value': 'os-pkgs'},
            {'name': 'aquasecurity:trivy:Type', 'value': family},
        ],
    }]
    refs = []
    for pkg in sorted(record['packages'], key=lambda p: (p['name'], p['arch'], p['version'], p['release'])):
        purl = _purl(fmt, family, distro, pkg)
        if purl in refs:
            continue
        props = [
            ('PkgID', _pkg_id(fmt, pkg)),
            ('PkgType', family),
            ('SrcEpoch', pkg['src_epoch']),
            ('SrcName', pkg['src_name']),
            ('SrcRelease', pkg['src_release']),
            ('SrcVersion', pkg['src_version']),
            ('Modularitylabel', pkg.get('modularitylabel', '')),
        ]
        refs.append(purl)
        components.append({
            'bom-ref': purl,
            'type': 'library',
            'name': pkg['name'],
            'version': '%s-%s' % (pkg['version'], pkg['release']) if pkg['release'] else pkg['version'],
            'purl': purl,
            'properties': [{'name': 'aquasecurity:trivy:' + k, 'value': v} for k, v in props if v],
        })
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': 'urn:uuid:%s' % uuid.uuid5(uuid.NAMESPACE_URL, 'host-audit:%s:%s' % (host, record.get('collected_at', ''))),
        'version': 1,
        'metadata': {
            'timestamp': timestamp or record.get('collected_at', ''),
            'component': {'bom-ref': root_ref, 'type': 'application', 'name': host},
        },
        'components': components,
        'dependencies': [
            {'ref': root_ref, 'dependsOn': [os_ref]},
            {'ref': os_ref, 'dependsOn': refs},
        ] + [{'ref': r, 'dependsOn': []} for r in refs],
    }


# ------------------------------------------------------------------------------
# 3. Trivy DB freshness
# ------------------------------------------------------------------------------
def _parse_time(value):
    """RFC 3339 with optional fractional seconds of any length → aware datetime (UTC)."""
    if not value:
        return None
    m = re.match(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$', value.strip())
    if not m:
        return None
    stamp = datetime.strptime('%sT%s' % (m.group(1), m.group(2)), '%Y-%m-%dT%H:%M:%S')
    offset = m.group(3) or 'Z'
    if offset == 'Z':
        return stamp.replace(tzinfo=timezone.utc)
    sign = 1 if offset[0] == '+' else -1
    hours, minutes = int(offset[1:3]), int(offset[4:6])
    return (stamp - sign * timedelta(hours=hours, minutes=minutes)).replace(tzinfo=timezone.utc)


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else ''


def host_audit_trivy_db_state(refresh_ok, metadata, now, max_age_days=DB_MAX_AGE_DAYS, refresh_error=''):
    """Decide whether the vulnerability DB may be used for this run.

    ``refresh_ok``: ``trivy image --download-db-only`` succeeded this run.
    ``metadata``: parsed ``<cache>/db/metadata.json`` (``UpdatedAt``, ``DownloadedAt``) or None.
    ``now``: ISO-8601 UTC of the run.

    fresh: refreshed this run. cached: refresh failed, cached DB built ≤ ``max_age_days`` ago.
    unavailable: no DB, or refresh failed and the cache is older → the whole section is 점검불가.
    Age is measured from ``UpdatedAt`` (when the DB content was built), not the download time.
    """
    metadata = metadata or {}
    max_age_days = float(max_age_days)  # extra-vars arrive as strings
    updated = _parse_time(metadata.get('UpdatedAt'))
    downloaded = _parse_time(metadata.get('DownloadedAt'))
    now_dt = _parse_time(now) or datetime.now(timezone.utc)
    age_days = round((now_dt - updated).total_seconds() / 86400.0, 1) if updated else None
    state = {
        'updated_at': _iso(updated),
        'downloaded_at': _iso(downloaded),
        'age_days': age_days,
        'max_age_days': max_age_days,
        'refreshed': bool(refresh_ok),
        'refresh_error': (refresh_error or '').strip().splitlines()[-1].strip(' \t*')[:200] if (refresh_error or '').strip() else '',
    }
    if not updated:
        state.update(status=DB_UNAVAILABLE, usable=False,
                     reason='취약점 DB 없음 (갱신 실패, 캐시 없음)')
    elif refresh_ok:
        state.update(status=DB_FRESH, usable=True, reason='')
    elif age_days is not None and age_days <= max_age_days:
        state.update(status=DB_CACHED, usable=True,
                     reason='DB 갱신 실패 — %.1f일 전 캐시로 판정' % age_days)
    else:
        state.update(status=DB_UNAVAILABLE, usable=False,
                     reason='DB 갱신 실패, 캐시가 %g일 초과 (%.1f일 경과)' % (max_age_days, age_days))
    return state


# ------------------------------------------------------------------------------
# 4. Trivy JSON → classified findings for one host
# ------------------------------------------------------------------------------
def _is_legacy_centos(os_info):
    return (os_info or {}).get('family') == 'centos' and (os_info or {}).get('major') in ('6', '7')


def _classify(vuln, os_info, vault):
    status = (vuln.get('Status') or '').lower()
    if status == 'will_not_fix':
        return CLASS_WILL_NOT_FIX
    fixed = [v.strip() for v in (vuln.get('FixedVersion') or '').split(',') if v.strip()]
    if status != 'fixed' and not fixed:
        return CLASS_UNFIXED
    if not fixed:
        return CLASS_UNFIXED
    if _is_legacy_centos(os_info):
        final = (vault or {}).get(vuln.get('PkgName', ''))
        if not final or not any(rpm_vr_compare(f, final) <= 0 for f in fixed):
            return CLASS_NO_CENTOS_FIX
    return CLASS_UPDATE


def host_audit_package_findings(trivy_result, record, vault_final=None):
    """Trivy JSON (``trivy sbom --format json``) for one host → classified host result.

    Fails the host (status ``scan_failed``) when Trivy did not recognise the OS the host
    reported: an unrecognised OS silently yields 0 findings (Vuls PoC #112 §SBOM 변환기 검증).
    ``vault_final``: {package name: final 'version-release' in the CentOS vault} for CentOS 6/7.
    """
    host = record['inventory_hostname']
    os_info = record.get('os') or {}
    result = {
        'host': host,
        'status': STATUS_OK,
        'reason': '',
        'os': os_info.get('name', ''),
        'os_family': os_info.get('family', ''),
        'eosl': False,
        'packages': len(record.get('packages') or []),
        'findings': [],
    }
    if record.get('status') != STATUS_OK:
        result.update(status=record.get('status') or 'probe_failed',
                      reason='패키지 수집 실패 — %s' % (record.get('reason') or '-'))
        return result
    if not isinstance(trivy_result, dict):
        result.update(status='scan_failed', reason='Trivy 판정 결과 없음 (판정 실패, 러너 로그 참고)')
        return result
    meta_os = (trivy_result.get('Metadata') or {}).get('OS') or {}
    if meta_os.get('Family') != os_info.get('family') or str(meta_os.get('Name')) != str(os_info.get('version')):
        result.update(status='scan_failed',
                      reason='Trivy OS 인식 불일치 (수집 %s %s, Trivy %s %s)' % (
                          os_info.get('family'), os_info.get('version'),
                          meta_os.get('Family') or '-', meta_os.get('Name') or '-'))
        return result
    result['eosl'] = bool(meta_os.get('EOSL'))
    seen = set()
    for res in trivy_result.get('Results') or []:
        for v in res.get('Vulnerabilities') or []:
            key = (v.get('VulnerabilityID'), v.get('PkgName'), v.get('InstalledVersion'))
            if key in seen:
                continue
            seen.add(key)
            severity = (v.get('Severity') or 'UNKNOWN').upper()
            if severity not in SEVERITIES:
                severity = 'UNKNOWN'
            cls = _classify(v, os_info, vault_final)
            result['findings'].append({
                # identity key for the Audit Baseline: (host, section, CVE+package)
                'id': '%s|%s' % (v.get('VulnerabilityID'), v.get('PkgName')),
                'cve': v.get('VulnerabilityID', ''),
                'package': v.get('PkgName', ''),
                'installed': v.get('InstalledVersion', ''),
                'fixed': v.get('FixedVersion', ''),
                'status': v.get('Status', ''),
                'severity': severity,
                'class': cls,
                'title': (v.get('Title') or '')[:160],
            })
    result['findings'].sort(key=lambda f: (SEVERITIES.index(f['severity']), f['cve'], f['package']))
    return result


# ------------------------------------------------------------------------------
# 5. all hosts → report section model
# ------------------------------------------------------------------------------
BAR_MAX = 130.0  # SVG user units of the longest severity bar (viewBox width 200)


def _bars(counts):
    peak = max(counts.values()) if counts and max(counts.values()) else 1
    return [{
        'severity': s,
        'label': SEVERITY_LABELS[s],
        'count': counts.get(s, 0),
        'bar': round(BAR_MAX * counts.get(s, 0) / peak, 1),
    } for s in SEVERITIES]


def host_audit_package_section(host_results, db_state, trivy_version='', detail_limit=300):
    """Classified host results + DB state → the Package Vulnerability section model.

    The template only draws this. Counts are (CVE, package) pairs. The detail table lists
    긴급·높음 findings except will-not-fix (counted separately so actionable ones are not
    buried), capped at ``detail_limit`` rows; the rest stays in the runner JSON.
    """
    db_state = db_state or {}
    detail_limit = int(detail_limit)
    unavailable = []
    section = {
        'title': SECTION,
        'trivy_version': trivy_version,
        'db': db_state,
        'db_label': _db_label(db_state),
        'status': STATUS_OK,
        'reason': '',
        'severity_labels': SEVERITY_LABELS,
        'class_labels': CLASS_LABELS,
        'bars': [],
        'totals': {},
        'classes': {},
        'class_rows': [],
        'by_host': {},
        'total': 0,
        'hosts': [],
        'details': [],
        'details_truncated': 0,
        'unavailable': unavailable,
    }
    if not db_state.get('usable'):
        section.update(status=DB_UNAVAILABLE, reason=db_state.get('reason') or '취약점 DB 사용 불가')
        unavailable.append({'host': '전체', 'item': SECTION, 'label': UNAVAILABLE_LABEL,
                            'reason': section['reason']})
        return section

    totals = dict((s, 0) for s in SEVERITIES)
    classes = dict((c, 0) for c in CLASSES)
    details = []
    for hr in sorted(host_results or [], key=lambda h: h['host']):
        row = {
            'host': hr['host'],
            'os': hr.get('os', ''),
            'eosl': hr.get('eosl', False),
            'packages': hr.get('packages', 0),
            'inspected': hr.get('status') == STATUS_OK,
            'reason': hr.get('reason', ''),
            'severity': dict((s, 0) for s in SEVERITIES),
            'classes': dict((c, 0) for c in CLASSES),
            'total': 0,
        }
        if not row['inspected']:
            unavailable.append({'host': hr['host'], 'item': SECTION, 'label': UNAVAILABLE_LABEL,
                                'reason': hr.get('reason') or '-'})
        for f in hr.get('findings') or []:
            row['severity'][f['severity']] += 1
            row['classes'][f['class']] += 1
            row['total'] += 1
            totals[f['severity']] += 1
            classes[f['class']] += 1
            if f['severity'] in ('CRITICAL', 'HIGH') and f['class'] != CLASS_WILL_NOT_FIX:
                d = dict(f)
                d['host'] = hr['host']
                d['severity_label'] = SEVERITY_LABELS[f['severity']]
                d['class_label'] = CLASS_LABELS[f['class']]
                d['fixed_label'] = f['fixed'] or '-'
                details.append(d)
        section['hosts'].append(row)
    details.sort(key=lambda d: (SEVERITIES.index(d['severity']), d['host'], d['cve'], d['package']))
    section['totals'] = totals
    section['total'] = sum(totals.values())
    section['classes'] = classes
    section['class_rows'] = [{'key': c, 'label': CLASS_LABELS[c], 'count': classes[c]} for c in CLASSES]
    section['by_host'] = dict((h['host'], h) for h in section['hosts'])  # per-host appendix lookup
    section['bars'] = _bars(totals)
    section['details'] = details[:detail_limit]
    section['details_truncated'] = max(0, len(details) - detail_limit)
    return section


def _db_label(db_state):
    if not db_state or not db_state.get('updated_at'):
        return '취약점 DB 없음'
    label = 'Trivy DB %s 생성' % db_state['updated_at']
    if db_state.get('status') == DB_FRESH:
        label += ' · 이번 실행에서 갱신'
    elif db_state.get('status') == DB_CACHED:
        label += ' · 갱신 실패, 캐시 사용 (%.1f일 경과)' % db_state['age_days']
    else:
        label += ' · 사용 불가 (%s)' % (db_state.get('reason') or '-')
    return label


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_package_record': host_audit_package_record,
            'host_audit_sbom': host_audit_sbom,
            'host_audit_trivy_db_state': host_audit_trivy_db_state,
            'host_audit_package_findings': host_audit_package_findings,
            'host_audit_package_section': host_audit_package_section,
            'host_audit_parse_vault_final': parse_vault_final,
        }
