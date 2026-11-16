# -*- coding: utf-8 -*-
"""Host Audit — the one place that marks text as ``unsafe`` so Ansible never templates it again (Spec #488).

Declared values (OpenBao ``hosts/<host>``) and Remediation Plan cells carry free text that may hold ``{{``. Marking them
unsafe when the filter returns them keeps a later ``set_fact`` or module argument from evaluating them. Without Ansible
(plain pytest) the mark is a no-op. Shared by ``host_audit_inventory`` and ``host_audit_remediation_plan``, which used to
reach into each other for a private name. The empty ``FilterModule`` is the same stub ``host_audit_files`` carries: Ansible
loads every file in this directory as a filter plugin.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    from ansible.utils.unsafe_proxy import wrap_var as unsafe
except ImportError:  # pragma: no cover - plain Python without ansible
    def unsafe(value):
        return value


class FilterModule(object):
    def filters(self):
        return {}
