#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — pack the per-host xlsx files into one zip, deterministically (Spec #488 / Ticket-7, #495, AUD-026).

The report mail carries the Remediation Plan of every host as ONE zip (the second attachment), and the same file is kept
with the report. Standard library only (``zipfile``), like the xlsx writer, so the runner image does not change.
Members are the non-hidden ``*.xlsx`` files of ``src_dir`` in name order (or, with ``members``, the listed files under
their own zip names such as ``total.xlsx`` and ``hosts/<host>.xlsx``, in zip-name order), stored without compression
(deflate bytes depend on the zlib build) with a fixed timestamp, so the same xlsx files always give the same zip bytes.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host_audit_zip_write
short_description: Pack the xlsx files of a directory into one deterministic zip
description:
  - Writes C(dest) (mode 0600) holding every non-hidden C(*.xlsx) file directly inside C(src_dir), sorted by name,
    stored (not compressed), with a fixed timestamp, so the same files give the same bytes.
  - Hidden files (a killed writer's temp file), other extensions and sub-directories are not packed.
  - The file is left alone when it already holds these bytes with mode 0600.
options:
  src_dir:
    description: Directory that holds the xlsx files.
    type: path
    required: true
  dest:
    description: Path of the zip. Its directory must exist (normally C(src_dir) itself).
    type: path
    required: true
  names:
    description:
      - Exact file names (inside C(src_dir)) to pack, sorted by name. When given, files that are not listed are never packed
        (a rerun of the same run id must not pull in an earlier run's xlsx) and a listed file that is missing is an error.
    type: list
    elements: str
  members:
    description:
      - Mapping of a file name inside C(src_dir) to the name the file gets inside the zip (may hold folders such as
        C(hosts/ns0001.xlsx)). Only the listed files are packed, in zip-name order, and a listed file that is missing is an error.
        A zip name must be a relative path without C(..), empty parts, C(.) parts, a backslash, a colon or control characters, and unique (no name may also be a folder of another). Names are case-sensitive, like the host names they carry. The files on disk
        keep their flat names. Not together with C(names).
    type: dict
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Pack the Remediation Plan xlsx files of the run
  host_audit_zip_write:
    src_dir: /tmp/host_audit/run/xlsx
    dest: /tmp/host_audit/run/xlsx/host-audit-run-xlsx.zip

- name: Pack them with folders inside the zip
  host_audit_zip_write:
    src_dir: /tmp/host_audit/run/xlsx
    dest: /tmp/host_audit/run/xlsx/host-audit-run-xlsx.zip
    members:
      host-audit-run-total.xlsx: total.xlsx
      host-audit-run-ns0331.xlsx: hosts/ns0331.xlsx
'''

RETURN = r'''
dest:
  description: Path of the zip.
  returned: always
  type: str
files:
  description: Names of the packed files inside the zip, in zip order.
  returned: always
  type: list
'''

import io
import os
import zipfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.host_audit_atomic import same_file, write_atomic

FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest time a zip member can carry


def _members(src_dir):
    return sorted(name for name in os.listdir(src_dir)
                  if name.endswith('.xlsx') and not name.startswith('.') and os.path.isfile(os.path.join(src_dir, name)))


def _bad_zip_names(members):
    """Zip names that are not plain relative paths, or are used twice."""
    bad = []
    for name in members.values():
        parts = str(name).split('/')
        if (not name or '\\' in name or ':' in name or any(ord(ch) < 32 for ch in name)
                or any(part in ('', '.', '..') for part in parts)):
            bad.append(repr(str(name)))
    names = [str(name) for name in members.values()]
    bad += ['duplicate %r' % name for name in sorted(set(names)) if names.count(name) > 1]
    if any(other.startswith(name + '/') for name in names for other in names):  # a file that is also a folder
        bad.append('file and folder with the same name')
    return bad


def build_zip(src_dir, members):
    """The zip bytes of ``members`` (``[(file name in src_dir, name in the zip)]``, packed in zip-name order).

    Each plan is a few KB to a few hundred KB (tens of hosts), so the whole zip is built in memory and the report stage
    hashes it a second time (AUD-615 for the summary, AUD-513 for the upload): simpler than streaming at this size.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as archive:
        for name, arcname in sorted(members, key=lambda pair: pair[1]):
            with open(os.path.join(src_dir, name), 'rb') as handle:
                data = handle.read()
            info = zipfile.ZipInfo(arcname, FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (0o100000 | 0o600) << 16  # regular file, rw-------
            info.create_system = 3  # fixed (unix), not the platform the module happens to run on
            archive.writestr(info, data)
    return buffer.getvalue()


def main():
    module = AnsibleModule(
        argument_spec=dict(src_dir=dict(type='path', required=True), dest=dict(type='path', required=True),
                           names=dict(type='list', elements='str'), members=dict(type='dict')),
        mutually_exclusive=[('names', 'members')],
        supports_check_mode=True,
    )
    src_dir, dest = module.params['src_dir'], module.params['dest']
    if not os.path.isdir(src_dir):
        module.fail_json(msg='source directory %s does not exist' % src_dir)
    try:
        if module.params['members'] is not None:
            members = dict((str(k), str(v)) for k, v in module.params['members'].items())
            bad = _bad_zip_names(members) if members else ['no members']
            if bad:
                module.fail_json(msg='zip names must be unique relative paths without .. or backslash: %s' % ', '.join(bad))
        else:
            names = sorted(set(module.params['names'])) if module.params['names'] is not None else _members(src_dir)
            members = dict((name, name) for name in names)
        names = sorted(members)
        missing = [n for n in names if os.path.basename(n) != n or not os.path.isfile(os.path.join(src_dir, n))]
        if missing:
            module.fail_json(msg='files to pack are missing from %s: %s' % (src_dir, ', '.join(missing)))
        data = build_zip(src_dir, list(members.items()))
        changed = (not same_file(dest, data)) if module.check_mode else write_atomic(dest, data)
    except (IOError, OSError) as exc:
        module.fail_json(msg='cannot pack or write %s (%s): %s' % (dest, exc.filename or 'n/a', exc.strerror or exc))
    module.exit_json(changed=changed, dest=dest, files=sorted(members.values()))


if __name__ == '__main__':
    main()
