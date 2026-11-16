# -*- coding: utf-8 -*-
"""Host Audit — write one runner file atomically with mode 0600 (Spec #488).

``host_audit_xlsx_write`` (AUD-025) and ``host_audit_zip_write`` (AUD-026) both write a file whose bytes they computed
in memory: skip the write when the file already holds exactly these bytes with mode 0600 (that is what keeps the task
idempotent), otherwise write a temporary file in the same directory and rename it over the destination. They share this
one implementation so the two cannot drift apart.

Pure standard library. Only the two runner modules use it, so it is a plain module_utils file (no filter plugin
copy, unlike ``host_audit_files``).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import tempfile

FILE_MODE = 0o600


def same_file(dest, data):
    """True when dest already holds exactly these bytes with mode 0600 (anything else is a change)."""
    try:
        with open(dest, 'rb') as handle:
            return handle.read() == data and (os.stat(dest).st_mode & 0o777) == FILE_MODE
    except (IOError, OSError):
        return False


def _sync_directory(directory):
    """Make the rename durable (best effort: not every platform can open a directory)."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomic(dest, data, create_parent=False):
    """Write ``data`` to ``dest`` atomically with mode 0600; returns True when the file changed.

    ``create_parent`` makes the missing directory one level only (mode 0700): a deeper missing path is an error, never a
    tree created with a mode the role did not choose.
    """
    if same_file(dest, data):
        return False
    directory = os.path.dirname(dest) or '.'
    if create_parent and not os.path.isdir(directory):
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o700)
    # mkstemp: exclusive create with an unpredictable name (no symlink to follow), mode 0600. The name starts with a
    # dot, so AUD-512 (ansible.builtin.find without hidden files) never lists a leftover of a killed run.
    fd, tmp = tempfile.mkstemp(prefix='.', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())  # the renamed file must not be empty after a crash
        os.replace(tmp, dest)
        _sync_directory(directory)
    except BaseException:
        # A leftover .tmp in xlsx/ would be found and kept by AUD-512.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return True

