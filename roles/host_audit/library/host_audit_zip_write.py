#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — pack the per-host xlsx files into one zip, deterministically (Spec #488 / Ticket-7, #495, AUD-026).

The report mail carries the Remediation Plan of every host as ONE zip (the second attachment), and the same file is kept
with the report. Standard library only (``zipfile``), like the xlsx writer, so the runner image does not change.
Members are the non-hidden ``*.xlsx`` files of ``src_dir`` in name order, stored without compression (deflate bytes
depend on the zlib build) with a fixed timestamp, so the same xlsx files always give the same zip bytes.
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
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Pack the Remediation Plan xlsx files of the run
  host_audit_zip_write:
    src_dir: /tmp/host_audit/run/xlsx
    dest: /tmp/host_audit/run/xlsx/host-audit-run-xlsx.zip
'''

RETURN = r'''
dest:
  description: Path of the zip.
  returned: always
  type: str
files:
  description: Names of the packed files, in zip order.
  returned: always
  type: list
'''

import io
import os
import tempfile
import zipfile

from ansible.module_utils.basic import AnsibleModule

FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest time a zip member can carry


def _members(src_dir):
    return sorted(name for name in os.listdir(src_dir)
                  if name.endswith('.xlsx') and not name.startswith('.') and os.path.isfile(os.path.join(src_dir, name)))


def build_zip(src_dir, names):
    """The zip bytes of the named files of src_dir."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as archive:
        for name in names:
            with open(os.path.join(src_dir, name), 'rb') as handle:
                data = handle.read()
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            info.create_system = 3  # fixed (unix), not the platform the module happens to run on
            archive.writestr(info, data)
    return buffer.getvalue()


def _same(dest, data):
    try:
        with open(dest, 'rb') as handle:
            return handle.read() == data and (os.stat(dest).st_mode & 0o777) == 0o600
    except (IOError, OSError):
        return False


def _write(dest, data):
    """Write atomically with mode 0600 (mkstemp: unpredictable hidden name, so a leftover is never listed or kept)."""
    directory = os.path.dirname(dest) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def main():
    module = AnsibleModule(
        argument_spec=dict(src_dir=dict(type='path', required=True), dest=dict(type='path', required=True)),
        supports_check_mode=True,
    )
    src_dir, dest = module.params['src_dir'], module.params['dest']
    if not os.path.isdir(src_dir):
        module.fail_json(msg='source directory %s does not exist' % src_dir)
    try:
        names = _members(src_dir)
        data = build_zip(src_dir, names)
        changed = not _same(dest, data)
        if changed and not module.check_mode:
            _write(dest, data)
    except (IOError, OSError) as exc:
        module.fail_json(msg='cannot write %s: %s' % (dest, exc.strerror or exc))
    module.exit_json(changed=changed, dest=dest, files=names)


if __name__ == '__main__':
    main()
