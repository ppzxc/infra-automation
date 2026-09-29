"""Filters for the Raw Provisioning Path (ADR-0005).

CentOS 6/7 targets cannot run AnsiballZ modules, so files are pushed with
``ansible.builtin.raw`` using shell commands rendered here. The commands
replace a module's ``validate:``/``atomic_move`` safeguards and feed the
changed/unchanged sentinel contract.
"""

import base64
import hashlib
import re
import shlex


def _mode_octal(mode):
    """'0600' / 600 / '600' -> the value ``stat -c %a`` prints ('600')."""
    return '%o' % int(str(mode), 8)


def raw_sha256(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def raw_probe_cmd(dest):
    """Print '<sha256> <mode>' for dest; both fields are empty if it is absent."""
    d = shlex.quote(dest)
    return ("printf '%s %s\\n' "
            "\"$(sha256sum {d} 2>/dev/null | cut -d' ' -f1)\" "
            "\"$(stat -c %a {d} 2>/dev/null)\"").format(d=d)


def raw_push_changed(probe_stdout, content, mode):
    """Sentinel: changed when the remote hash OR mode differs.

    An absent dest yields an empty probe, which never equals the expected
    value, so first provisioning is reported as changed without special-casing.
    """
    expected = '%s %s' % (raw_sha256(content), _mode_octal(mode))
    return (probe_stdout or '').strip() != expected


def raw_push_cmd(content, dest, owner, group, mode, validate):
    """write-temp -> validate -> chown/chmod -> atomic mv -> best-effort restorecon.

    ``validate`` is a command containing ``%s`` for the temp path.
    """
    tmp = shlex.quote(dest + '.raw.tmp')
    d = shlex.quote(dest)
    b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
    check = validate.replace('%s', tmp)
    return (
        "{{ (umask 077 && printf %s {b64} | base64 -d > {tmp})"
        " && {{ {check} || {{ rm -f {tmp}; false; }}; }}"
        " && chown {own} {tmp} && chmod {mode} {tmp} && mv -f {tmp} {d}"
        " && {{ (restorecon -F {d} >/dev/null 2>&1 || true); }}; }}"
        " || {{ rm -f {tmp}; false; }}"
    ).format(
        b64=shlex.quote(b64), tmp=tmp, check=check, d=d,
        own=shlex.quote('%s:%s' % (owner, group)),
        mode=shlex.quote(str(mode)),
    )


def raw_set_directives(current, directives):
    """lineinfile equivalent: replace the last line matching each regexp, else append."""
    lines = (current or '').splitlines()
    for item in directives:
        rx = re.compile(item['regexp'])
        idx = [i for i, ln in enumerate(lines) if rx.search(ln)]
        if idx:
            lines[idx[-1]] = item['line']
        else:
            lines.append(item['line'])
    return '\n'.join(lines) + '\n'


class FilterModule(object):
    def filters(self):
        return {
            'raw_sha256': raw_sha256,
            'raw_probe_cmd': raw_probe_cmd,
            'raw_push_changed': raw_push_changed,
            'raw_push_cmd': raw_push_cmd,
            'raw_set_directives': raw_set_directives,
        }
