#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — judge one host's Trivy result in its own process and keep the findings in a file (#155, Spec #148).

The first custom module of this repository. Its reason to exist is memory: a filter runs inside the
``ansible-playbook`` process, so the transient peak of parsing a Trivy result (200~250 MB per host) and of every
finding that was ever classified stays in the maximum RSS of the run. A module is a separate process that gives the
memory back when it ends. It returns only a summary; the findings go to ``<results_dir>/<host>.json``.

The classification logic is the filter file ``filter_plugins/host_audit_packages.py`` (symlinked into this role's
``module_utils/``), so the module and the filters cannot drift apart.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host_audit_package_scan
short_description: Classify the Trivy findings of one Host Audit host and write them to a runner file
description:
  - Reads the package record and the Trivy result of one host, judges them with the same rules as
    C(host_audit_package_findings) (Trivy failure by rc, empty output, truncated JSON or missing file is
    C(scan_failed), the OS recognition check, the CentOS 6/7 vault rule) and writes the classified findings of the host
    to C(results_dir)/<host>.json with mode 0600.
  - Returns the summary only (counts per severity and class, the detail rows the report can draw, the file path).
options:
  record:
    description: Path of the package record of the host (C(packages/<host>.json) of the run).
    type: path
    required: true
  trivy_result:
    description: Path of the Trivy result (C(trivy/<host>.json)). A missing file is a failed scan.
    type: path
    required: true
  results_dir:
    description: Directory that receives C(<host>.json), the classified findings of the host.
    type: path
    required: true
  vault_dir:
    description: Directory with the CentOS vault final tables (C(centos-6.tsv), C(centos-7.tsv)).
    type: path
  scan_rc:
    description: rc of the Trivy run of this host. Not 0 means the result is not trusted.
    type: int
  detail_limit:
    description: Most detail rows (긴급·높음 except will-not-fix) returned for the host.
    type: int
    default: 300
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Classify the Trivy findings of one host
  host_audit_package_scan:
    record: /tmp/host_audit/run/packages/ns0001.json
    trivy_result: /tmp/host_audit/run/trivy/ns0001.json
    results_dir: /tmp/host_audit/run/package_findings
    scan_rc: 0
'''

RETURN = r'''
package_host:
  description: Summary of the host (status, reason, counts, details, details_total, findings_file). No findings.
  returned: always
  type: dict
findings_file:
  description: Path of the file that holds every finding of the host.
  returned: always
  type: str
'''

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.host_audit_packages import (
    host_audit_package_findings, host_audit_package_summary, parse_vault_final)


def _read_trivy(path):
    """None (no file), '' / raw text (to be judged as empty or truncated by the classifier) or the parsed dict."""
    try:
        with open(path, 'rb') as handle:
            text = handle.read().decode('utf-8', 'replace')
    except (IOError, OSError):
        return None
    if not text.strip():
        return ''
    try:
        parsed = json.loads(text)
    except ValueError:
        return text
    return parsed if isinstance(parsed, dict) else text


def _vault(record, vault_dir):
    os_info = record.get('os') or {}
    major = os_info.get('major')
    if not vault_dir or os_info.get('family') != 'centos' or major not in ('6', '7'):
        return {}
    try:
        with open(os.path.join(vault_dir, 'centos-%s.tsv' % major), 'rb') as handle:
            return parse_vault_final(handle.read().decode('utf-8'))
    except (IOError, OSError):
        return {}


def _write(path, content):
    """Write ``content`` (bytes) to ``path`` with mode 0600 through a temp file. Returns True when it changed."""
    try:
        with open(path, 'rb') as handle:
            if handle.read() == content:
                os.chmod(path, 0o600)
                return False
    except (IOError, OSError):
        pass
    tmp = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)
    os.replace(tmp, path)
    return True


def main():
    module = AnsibleModule(
        argument_spec=dict(
            record=dict(type='path', required=True),
            trivy_result=dict(type='path', required=True),
            results_dir=dict(type='path', required=True),
            vault_dir=dict(type='path'),
            scan_rc=dict(type='int'),
            detail_limit=dict(type='int', default=300),
        ),
        supports_check_mode=True,
    )
    p = module.params
    try:
        with open(p['record'], 'rb') as handle:
            record = json.loads(handle.read().decode('utf-8'))
    except (IOError, OSError, ValueError) as exc:
        module.fail_json(msg='패키지 기록을 읽을 수 없음: %s (%s)' % (p['record'], exc))
    host = str(record.get('inventory_hostname') or '')
    if not host or '/' in host or host in ('.', '..'):
        module.fail_json(msg='패키지 기록의 inventory_hostname이 파일 이름으로 쓸 수 없는 값: %r' % host)

    trivy = _read_trivy(p['trivy_result'])
    result = host_audit_package_findings(trivy, record, _vault(record, p['vault_dir']), p['scan_rc'])
    del trivy  # the parsed Trivy document is the big one; the process ends right after, but do not rely on that

    target = os.path.join(p['results_dir'], '%s.json' % host)
    changed = False
    if not module.check_mode:
        if not os.path.isdir(p['results_dir']):
            os.makedirs(p['results_dir'], 0o700)
        changed = _write(target, (json.dumps(result, ensure_ascii=False, sort_keys=True) + '\n').encode('utf-8'))
    summary = host_audit_package_summary(result, p['detail_limit'])
    summary['findings_file'] = target
    module.exit_json(changed=changed, package_host=summary, findings_file=target)


if __name__ == '__main__':
    main()
