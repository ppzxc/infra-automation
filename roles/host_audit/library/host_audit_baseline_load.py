#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — read the previous findings.json (Audit Baseline) from a runner file, keep its Package ids on disk (#156).

The previous scheduled run's ``findings.json`` lists every Package finding id (CVE|package) per host, hundreds of
thousands of them. Returning it as a task result would put all of it into the ``ansible-playbook`` process (facts,
report model). This module runs in its own process: it reads the file, writes the Package ids to one small file per
host and returns the rest of the document (run id, start time, the small sections) with a pointer to those files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host_audit_baseline_load
short_description: Load the previous findings.json of a Host Audit run, splitting the Package ids into per-host files
description:
  - Reads C(src) (the C(findings.json) of the Audit Baseline run, old or current format). The
    C(package_vulnerability) section of the result has C(hosts), C(ids_dir) and C(ids_hosts) instead of C(ids); the ids
    are in C(<ids_dir>/<host>.json) (a JSON list), one host per file. Other sections are returned as they are.
  - C(valid=false) and C(baseline=null) when the file is missing, is not JSON or is not an object.
options:
  src:
    description: Path of the previous findings.json.
    type: path
    required: true
  ids_dir:
    description: Directory for the per-host id files (created, files of an earlier call are removed). Not the directory of src.
    type: path
    required: true
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Read the previous findings of the Audit Baseline from the runner disk
  host_audit_baseline_load:
    src: /tmp/host_audit/run/package_findings/previous_findings.json
    ids_dir: /tmp/host_audit/run/package_findings/previous
'''

RETURN = r'''
valid:
  description: Whether C(src) held a findings document.
  returned: always
  type: bool
baseline:
  description: The document without the Package ids (null when not valid).
  returned: always
  type: dict
hosts:
  description: Number of hosts whose Package ids were written to files.
  returned: always
  type: int
ids:
  description: Number of Package ids written.
  returned: always
  type: int
'''

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.host_audit_files import host_audit_host_file

SECTION = 'package_vulnerability'


def load(src, ids_dir):
    """(document without the Package ids or None, hosts written, ids written)."""
    try:
        with open(src, 'rb') as handle:
            document = json.loads(handle.read().decode('utf-8'))
    except (IOError, OSError, ValueError):
        return None, 0, 0
    if not isinstance(document, dict):
        return None, 0, 0
    sections = dict(document.get('sections') or {})
    package = sections.pop(SECTION, None)
    if package is None:
        document['sections'] = sections
        return document, 0, 0
    ids_by_host = package.get('ids') or {}
    if not os.path.isdir(ids_dir):
        os.makedirs(ids_dir, 0o700)
    for name in os.listdir(ids_dir):
        if name.endswith('.json'):
            os.remove(os.path.join(ids_dir, name))
    total = 0
    for host, ids in ids_by_host.items():
        fd = os.open(host_audit_host_file(ids_dir, host), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(json.dumps(list(ids or []), ensure_ascii=False))
        total += len(ids or [])
    sections[SECTION] = {'hosts': sorted(set(package.get('hosts') or [])), 'ids_dir': ids_dir,
                         'ids_hosts': sorted(ids_by_host)}
    document['sections'] = sections
    return document, len(ids_by_host), total


def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(type='path', required=True),
            ids_dir=dict(type='path', required=True),
        ),
        supports_check_mode=True,
    )
    p = module.params
    if module.check_mode:
        module.exit_json(changed=False, valid=False, baseline=None, hosts=0, ids=0)
    document, hosts, ids = load(p['src'], p['ids_dir'])
    module.exit_json(changed=False, valid=document is not None, baseline=document, hosts=hosts, ids=ids)


if __name__ == '__main__':
    main()
