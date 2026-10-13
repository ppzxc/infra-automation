#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — write the findings index (findings.json) without holding every Package finding in memory (#155).

The Audit Baseline document of a run lists the id of every finding (CVE|package) per host. For Package
Vulnerability that is hundreds of thousands of ids. The report model keeps only the small part of the document and a
``package_index`` (directory of the per-host files written by ``host_audit_package_scan`` and the inspected hosts).
This module streams the ids from those files into ``findings.json`` one host at a time.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host_audit_findings_write
short_description: Write findings.json of a Host Audit run, reading the Package findings from files
description:
  - Writes C(document) as JSON to C(dest) (mode 0600). When C(package_index) names a directory, the
    C(package_vulnerability) section (C(hosts) and the sorted unique C(ids) per host) is added from
    C(<dir>/<host>.json) one host at a time, so the ids are never all in memory.
  - The result is the document the Audit Baseline compares against in the next scheduled run.
options:
  document:
    description: The findings document without the Package Vulnerability section.
    type: dict
    required: true
  package_index:
    description: C(dir) (the per-host files of the run) and C(hosts) (the hosts judged OK). Empty means no section.
    type: dict
    default: {}
  dest:
    description: Path of findings.json.
    type: path
    required: true
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Save the findings index of this run on the runner
  host_audit_findings_write:
    document: "{{ host_audit_model.baseline.document }}"
    package_index: "{{ host_audit_model.baseline.package_index | default({}) }}"
    dest: /tmp/host_audit/run/findings.json
'''

RETURN = r'''
hosts:
  description: Number of hosts of the Package Vulnerability section written from files.
  returned: always
  type: int
ids:
  description: Number of Package finding ids written from files.
  returned: always
  type: int
'''

import json
import os

from ansible.module_utils.basic import AnsibleModule

SECTION = 'package_vulnerability'


def _dump(value):
    return json.dumps(value, ensure_ascii=False)


def _host_ids(directory, host):
    """Sorted unique finding ids of one host ([] when the host has no file)."""
    try:
        with open(os.path.join(directory, '%s.json' % host), 'rb') as handle:
            result = json.loads(handle.read().decode('utf-8'))
    except (IOError, OSError, ValueError):
        return []
    return sorted(set(f['id'] for f in result.get('findings') or []))


def _stream(handle, document, package_index):
    """Write the document; the package section is written host by host. Returns (hosts, ids)."""
    directory = (package_index or {}).get('dir')
    if not directory:
        handle.write(_dump(document) + '\n')
        return 0, 0
    sections = dict(document.get('sections') or {})
    sections.pop(SECTION, None)
    head = dict((k, v) for k, v in document.items() if k != 'sections')
    hosts = sorted(set(package_index.get('hosts') or []))
    handle.write(_dump(head)[:-1] + (', ' if head else '') + '"sections": {')
    for name in sorted(sections):
        handle.write('%s: %s, ' % (_dump(name), _dump(sections[name])))
    handle.write('%s: {"hosts": %s, "ids": {' % (_dump(SECTION), _dump(hosts)))
    written = 0
    first = True
    for host in hosts:
        ids = _host_ids(directory, host)
        if not ids:
            continue
        handle.write('%s%s: %s' % ('' if first else ', ', _dump(host), _dump(ids)))
        first = False
        written += len(ids)
    handle.write('}}}}\n')
    return len(hosts), written


def main():
    module = AnsibleModule(
        argument_spec=dict(
            document=dict(type='dict', required=True),
            package_index=dict(type='dict', default={}),
            dest=dict(type='path', required=True),
        ),
        supports_check_mode=True,
    )
    p = module.params
    hosts = ids = 0
    changed = True
    if not module.check_mode:
        tmp = '%s.%d.tmp' % (p['dest'], os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as handle:
            hosts, ids = _stream(handle, p['document'], p['package_index'])
        os.replace(tmp, p['dest'])
    module.exit_json(changed=changed, dest=p['dest'], hosts=hosts, ids=ids)


if __name__ == '__main__':
    main()
