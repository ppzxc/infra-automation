# -*- coding: utf-8 -*-
"""Host Audit — one naming rule for the per-host files on the runner (#148).

The per-host Package findings (``package_findings/<host>.json``) and the per-host ids of the previous findings.json
(``package_findings/previous/<host>.json``) are written by runner modules and read by the baseline filter and by
``host_audit_findings_write``. All of them build the path with ``host_audit_host_file`` so a host name that is not a
plain file name (``/``, spaces, unicode) can neither leave the directory nor be looked up under another name.

Pure function, no Ansible imports; ``roles/host_audit/module_utils/host_audit_files.py`` is a symlink to this file.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

try:
    from urllib.parse import quote
except ImportError:  # pragma: no cover - Python 2 is not supported by the runner
    from urllib import quote


def host_audit_host_file(directory, host):
    """``<directory>/<percent-encoded host>.json``."""
    return os.path.join(directory, '%s.json' % quote(str(host), safe=''))


class FilterModule(object):
    def filters(self):
        return {}
