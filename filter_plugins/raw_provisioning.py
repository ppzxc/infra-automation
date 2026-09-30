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


PROBE_MARKER = '__RAW_PROBE__'
READ_BEGIN = '__RAW_BEGIN__'
READ_END = '__RAW_END__'


def raw_probe_cmd(dest):
    """Print '__RAW_PROBE__ <sha256> <mode>' for dest; fields are empty if absent.

    The marker lets the sentinel ignore login banners or other raw noise.
    """
    d = shlex.quote(dest)
    return ("printf '%s %s %s\\n' '{m}' "
            "\"$(sha256sum {d} 2>/dev/null | cut -d' ' -f1)\" "
            "\"$(stat -c %a {d} 2>/dev/null)\"").format(m=PROBE_MARKER, d=d)


def raw_push_changed(probe_stdout, content, mode):
    """Sentinel: changed when the remote hash OR mode differs.

    An absent dest (or unusable probe) never equals the expected value, so
    first provisioning is reported as changed without special-casing.
    """
    expected = '%s %s %s' % (PROBE_MARKER, raw_sha256(content), _mode_octal(mode))
    lines = [ln.strip() for ln in (probe_stdout or '').splitlines()
             if ln.strip().startswith(PROBE_MARKER)]
    return not lines or lines[-1] != expected


def raw_read_cmd(path):
    """cat path between markers, reporting cat's exit status."""
    return ("printf '\\n{b}\\n'; cat {p}; rc=$?; printf '\\n{e} %s\\n' \"$rc\"; exit 0"
            ).format(b=READ_BEGIN, e=READ_END, p=shlex.quote(path))


def raw_read_extract(stdout):
    """File content from raw_read_cmd output, or None if unreadable/empty."""
    m = re.search(r'%s\r?\n(.*)\r?\n%s (\d+)' % (READ_BEGIN, READ_END),
                  (stdout or '').replace('\r\n', '\n'), re.S)
    if not m or m.group(2) != '0' or not m.group(1).strip():
        return None
    return m.group(1)


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


_RELEASE_RE = re.compile(
    r'^(?P<name>.+?)\s+release\s+(?P<version>[0-9]+(?:\.[0-9]+)*)', re.MULTILINE)


def raw_parse_os_release(stdout):
    """Parse ``cat /etc/redhat-release`` raw output into OS facts.

    Replaces the ``setup`` module, which cannot run on CentOS 6/7 (ADR-0005).
    Raises ValueError when no ``<name> release <version>`` line is present, so
    a missing/foreign release file aborts the play instead of guessing.
    """
    m = _RELEASE_RE.search((stdout or '').replace('\r', ''))
    if not m:
        raise ValueError('cannot determine OS release from raw output: %r' % (stdout,))
    name = m.group('name').strip()
    version = m.group('version')
    return {
        'distribution': 'CentOS' if name.startswith('CentOS') else 'RedHat',
        'major_version': version.split('.')[0],
        'version': version,
    }


class FilterModule(object):
    def filters(self):
        return {
            'raw_parse_os_release': raw_parse_os_release,
            'raw_read_cmd': raw_read_cmd,
            'raw_read_extract': raw_read_extract,
            'raw_probe_cmd': raw_probe_cmd,
            'raw_push_changed': raw_push_changed,
            'raw_push_cmd': raw_push_cmd,
            'raw_set_directives': raw_set_directives,
        }
