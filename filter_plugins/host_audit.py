"""Filters for Host Audit (ADR-0009).

Host Audit collects with read-only ``ansible.builtin.raw`` probes, stores one
JSON record per host on the runner, then turns the records into a report
model that the HTML template only draws. Every judgement (labels, counts,
which hosts could not be inspected) is made here, never in the template.

Public entry points:
  host_audit_host_record   registered raw probe -> per-host JSON record
  host_audit_report_model  per-host records + run metadata -> report model
"""

import ipaddress
import os
import sys
from datetime import datetime, timezone

# Section modules live beside this file; Ansible's plugin loader does not put
# filter_plugins/ on sys.path, so add it before importing them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from host_audit_inventory import inventory_section  # noqa: E402
from host_audit_kisa import host_audit_kisa_section, run_date as kisa_run_date  # noqa: E402

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

RECORD_SCHEMA_VERSION = 2
PROBE_BEGIN = '__HOST_AUDIT_BEGIN__'
PROBE_END = '__HOST_AUDIT_END__'
REPORT_TIMEZONE = 'Asia/Seoul'

STATUS_OK = 'ok'
STATUS_UNREACHABLE = 'unreachable'
STATUS_PROBE_FAILED = 'probe_failed'
STATUS_NO_RECORD = 'no_record'

STATUS_LABELS = {
    STATUS_OK: '점검 완료',
    STATUS_UNREACHABLE: '점검불가(접속 실패)',
    STATUS_PROBE_FAILED: '점검불가(수집 실패)',
    STATUS_NO_RECORD: '점검불가(접속 준비 실패)',
}
RUN_KIND_LABELS = {'scheduled': '정기', 'on_demand': '수시'}
UNASSIGNED = '미지정'
OUT_OF_SCOPE = '네트워크 장비(cisco_switches) 등 Linux 관리 호스트 외 자산'
METHOD = ('러너에서 관리 계정으로 SSH 접속해 읽기 전용 명령(ansible.builtin.raw)만 실행. '
          '호스트에 프로그램을 설치하거나 설정을 바꾸지 않음.')
CONTENTS = ['Asset Inventory — 식별, OS·EOL, 하드웨어, 운영, 패키지, listening 포트, 계정·특수권한, Host Agents']
SCOPE_GROUPS = 'servers · loadbalancers · overseer'
PACKAGE_CONTENTS = 'Package Vulnerability — 설치 패키지의 CVE·벤더 권고 해당 여부 (Trivy, SBOM 입력)'


def _first_line(text, limit=200):
    for line in str(text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def _parse_probe(stdout):
    """Return {key: value} (``ip`` -> list) from lines between the probe markers, or None."""
    lines = str(stdout or '').splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == PROBE_BEGIN)
        end = next(i for i, ln in enumerate(lines) if i > start and ln.strip() == PROBE_END)
    except StopIteration:
        return None
    values = {'ip': []}
    for line in lines[start + 1:end]:
        key, sep, value = line.rstrip('\r').partition('=')
        if not sep:
            continue
        value = value.strip()
        if key == 'ip':
            values['ip'].extend(value.split())
        else:
            values[key] = value
    return values


def _unquote(value):
    value = (value or '').strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def _global_ips(raw_ips):
    """Drop loopback/link-local, strip prefix length, keep first-seen order."""
    ips = []
    for token in raw_ips:
        addr = token.split('/', 1)[0].split('%', 1)[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        if addr not in ips:
            ips.append(addr)
    return ips


def _os_from_probe(values):
    pretty = _unquote(values.get('os_release_PRETTY_NAME'))
    redhat = values.get('redhat_release', '')
    return {
        'id': _unquote(values.get('os_release_ID')) or ('rhel-family' if redhat else ''),
        'version_id': _unquote(values.get('os_release_VERSION_ID')),
        'name': pretty or redhat,
        'redhat_release': redhat,
        'kernel': values.get('kernel', ''),
        'arch': values.get('arch', ''),
    }


def host_audit_host_record(probe, inventory_hostname, declared, collected_at):
    """Build the per-host JSON record from a registered raw probe result.

    ``probe`` is the registered result of the identity probe (run with
    ``ignore_unreachable``), ``declared`` the inventory values for the host
    (fqdn, ip, environment, groups), ``collected_at`` an ISO-8601 UTC string.
    """
    probe = probe or {}
    record = {
        'schema_version': RECORD_SCHEMA_VERSION,
        'inventory_hostname': inventory_hostname,
        'collected_at': collected_at,
        'status': STATUS_OK,
        'reason': '',
        'declared': {
            'fqdn': (declared or {}).get('fqdn') or '',
            'ip': (declared or {}).get('ip') or '',
            'environment': (declared or {}).get('environment') or '',
            'groups': sorted((declared or {}).get('groups') or []),
        },
        'identity': None,
        'os': None,
    }
    if probe.get('unreachable'):
        record['status'] = STATUS_UNREACHABLE
        record['reason'] = _first_line(probe.get('msg')) or 'SSH 접속 실패'
        return record
    values = None if probe.get('skipped') else _parse_probe(probe.get('stdout'))
    if values is None:
        record['status'] = STATUS_PROBE_FAILED
        record['reason'] = (_first_line(probe.get('stderr')) or _first_line(probe.get('msg'))
                            or '수집 결과 표식 없음 (rc=%s)' % probe.get('rc'))
        return record
    record['identity'] = {
        'hostname': values.get('hostname', ''),
        'fqdn': values.get('fqdn', ''),
        'ips': _global_ips(values.get('ip', [])),
        'account': values.get('account', ''),
    }
    record['os'] = _os_from_probe(values)
    return record


def _to_local(iso_utc, tz_name):
    """'2026-10-08T22:00:05Z' -> '2026-10-09 07:00 (KST)'-style text in tz_name."""
    if not iso_utc:
        return ''
    try:
        stamp = datetime.strptime(iso_utc, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return iso_utc
    if ZoneInfo is None:
        return stamp.strftime('%Y-%m-%d %H:%M (UTC)')
    local = stamp.astimezone(ZoneInfo(tz_name))
    return '%s (%s)' % (local.strftime('%Y-%m-%d %H:%M'), local.tzname())


def _inventory_row(record):
    declared = record.get('declared') or {}
    identity = record.get('identity') or {}
    os_info = record.get('os') or {}
    fqdn = identity.get('fqdn') or declared.get('fqdn') or ''
    if identity.get('fqdn') and declared.get('fqdn') and identity['fqdn'] != declared['fqdn']:
        fqdn = '%s (인벤토리: %s)' % (identity['fqdn'], declared['fqdn'])
    ips = identity.get('ips') or ([declared['ip']] if declared.get('ip') else [])
    kernel_arch = ' · '.join(v for v in (os_info.get('kernel'), os_info.get('arch')) if v)
    status = record.get('status', STATUS_NO_RECORD)
    return {
        'host': record['inventory_hostname'],
        'fqdn': fqdn or '-',
        'ips': ', '.join(ips) or '-',
        'environment': declared.get('environment') or UNASSIGNED,
        'environment_unassigned': not declared.get('environment'),
        'os': os_info.get('name') or '-',
        'kernel_arch': kernel_arch or '-',
        'status': status,
        'status_label': STATUS_LABELS.get(status, STATUS_LABELS[STATUS_NO_RECORD]),
        'inspected': status == STATUS_OK,
    }


def host_audit_report_model(records, meta):
    """Turn per-host records and run metadata into the report model the template draws.

    ``meta`` keys: run_id, run_kind ('scheduled' | 'on_demand'), started_at /
    generated_at (ISO-8601 UTC), targets (every Inventory Hostname selected for
    this run), target_hosts (the requested pattern, '' when none), archive
    (where the raw records are kept). A target without a record — e.g. its
    connection could not be resolved — is reported as not inspected, never
    dropped.
    """
    meta = meta or {}
    tz_name = meta.get('timezone') or REPORT_TIMEZONE
    by_host = {r['inventory_hostname']: r for r in (records or []) if r.get('inventory_hostname')}
    hosts = sorted(set(meta.get('targets') or []) | set(by_host))
    rows = []
    for host in hosts:
        record = by_host.get(host) or {
            'inventory_hostname': host,
            'status': STATUS_NO_RECORD,
            'reason': '접속 정보 해석 단계에서 실패해 수집하지 못함 (Semaphore 로그 참고)',
        }
        rows.append((record, _inventory_row(record)))

    unavailable = [
        {'host': row['host'], 'item': '전체 점검', 'label': row['status_label'],
         'reason': record.get('reason') or '-'}
        for record, row in rows if not row['inspected']
    ]
    asset_inventory = inventory_section([record for record, _ in rows], dict(meta, timezone=tz_name))
    unavailable += asset_inventory['unavailable']
    # Package Vulnerability section model (filter_plugins/host_audit_packages.py), when the run judged packages.
    package_vulnerability = meta.get('package_vulnerability')
    package_vulnerability = package_vulnerability if isinstance(package_vulnerability, dict) and package_vulnerability else None
    if package_vulnerability:
        unavailable += package_vulnerability.get('unavailable') or []
    accounts = sorted({(r.get('identity') or {}).get('account') for r, _ in rows} - {None, ''})
    run_kind = meta.get('run_kind') or 'on_demand'
    target_hosts = meta.get('target_hosts') or ''
    scope = '%s — %d대' % (SCOPE_GROUPS, len(hosts))
    if target_hosts:
        scope += ' (target_hosts: %s)' % target_hosts

    model = {
        'title': 'Host Audit 점검 보고서',
        'cover': {
            'run_id': meta.get('run_id', ''),
            'run_kind': RUN_KIND_LABELS.get(run_kind, run_kind),
            'started_at': _to_local(meta.get('started_at'), tz_name),
            'generated_at': _to_local(meta.get('generated_at'), tz_name),
            'scope': scope,
            'out_of_scope': OUT_OF_SCOPE,
            'method': METHOD,
            'contents': CONTENTS + ([PACKAGE_CONTENTS] if package_vulnerability else []),
            'baseline': '없음 — Audit Baseline 비교는 아직 적용되지 않음',
            'accounts': ', '.join(accounts) or '-',
            'archive': meta.get('archive', ''),
            'vuln_db': (package_vulnerability or {}).get('db_label', ''),
        },
        'summary': {
            'hosts_total': len(rows),
            'hosts_inspected': sum(1 for _, row in rows if row['inspected']),
            'hosts_unavailable': sum(1 for _, row in rows if not row['inspected']),
        },
        'unavailable': unavailable,
        'inventory': [row for _, row in rows],
        'hosts': [row['host'] for _, row in rows],
        'asset_inventory': asset_inventory,
        'package_vulnerability': package_vulnerability,
    }
    # Configuration Vulnerability (KISA-2026, #121): exception expiry is judged on the run date.
    return host_audit_kisa_section(model, records, meta.get('kisa_exceptions') or [],
                                   kisa_run_date(meta.get('started_at'), tz_name))


class FilterModule(object):
    def filters(self):
        return {
            'host_audit_host_record': host_audit_host_record,
            'host_audit_report_model': host_audit_report_model,
        }
