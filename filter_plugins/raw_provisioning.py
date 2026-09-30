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


CHANGED_MARKER = '__RAW_CHANGED__'


def raw_changed(stdout):
    """Sentinel for state-check raw tasks: True when the command echoed the marker."""
    return any(ln.strip() == CHANGED_MARKER for ln in (stdout or '').splitlines())


def _render(template, **tokens):
    for key, value in tokens.items():
        template = template.replace('@%s@' % key, value)
    return template


def raw_group_cmd(name, gid=None):
    """Create the group (or fix its gid) only when needed; echo the marker if it did."""
    cmd = (
        "if ! getent group @N@ >/dev/null 2>&1; then groupadd@GID@ @N@ && echo @M@;"
        "@FIX@ fi"
    )
    fix = ''
    if gid not in (None, ''):
        fix = (" elif [ \"$(getent group @N@ | cut -d: -f3)\" != @G@ ]; then"
               " groupmod -g @G@ @N@ && echo @M@;")
    return _render(_render(cmd, GID=(' -g %s' % shlex.quote(str(gid))) if fix else '', FIX=fix),
                   N=shlex.quote(name), G=shlex.quote(str(gid)) if fix else '', M=CHANGED_MARKER)


def raw_user_cmd(name, group, groups, shell, comment, uid, state):
    """useradd/usermod/userdel equivalent of ``ansible.builtin.user`` (append semantics)."""
    n = shlex.quote(name)
    if state == 'absent':
        return _render("if getent passwd @N@ >/dev/null 2>&1; then userdel -r @N@ && echo @M@; fi",
                       N=n, M=CHANGED_MARKER)
    groups = [g for g in (groups or []) if g]
    create = ['useradd -m -g %s' % shlex.quote(group)]
    fix = ['set --',
           '[ "$(id -gn %s)" = %s ] || set -- "$@" -g %s' % (n, shlex.quote(group), shlex.quote(group)),
           '[ "$(getent passwd %s | cut -d: -f7)" = %s ] || set -- "$@" -s %s'
           % (n, shlex.quote(shell), shlex.quote(shell))]
    if groups:
        create.append('-G %s' % shlex.quote(','.join(groups)))
        fix.append('miss=""; for g in %s; do case " $(id -nG %s) " in *" $g "*) ;; '
                   '*) miss="$miss,$g";; esac; done' % (' '.join(shlex.quote(g) for g in groups), n))
        fix.append('[ -z "$miss" ] || set -- "$@" -a -G "${miss#,}"')
    create.append('-s %s' % shlex.quote(shell))
    if comment not in (None, ''):
        create.append('-c %s' % shlex.quote(comment))
        fix.append('[ "$(getent passwd %s | cut -d: -f5)" = %s ] || set -- "$@" -c %s'
                   % (n, shlex.quote(comment), shlex.quote(comment)))
    if uid not in (None, ''):
        create.append('-u %s' % shlex.quote(str(uid)))
        fix.append('[ "$(id -u %s)" = %s ] || set -- "$@" -u %s' % (n, shlex.quote(str(uid)), shlex.quote(str(uid))))
    # usermod flags must precede the login name; group append (-a -G) was queued last.
    return ("if ! getent passwd %s >/dev/null 2>&1; then %s %s && echo %s; else %s; "
            "if [ $# -gt 0 ]; then usermod \"$@\" %s && echo %s; fi; fi"
            % (n, ' '.join(create), n, CHANGED_MARKER, '; '.join(fix), n, CHANGED_MARKER))


def _key_blob(key):
    key = (key or '').strip()
    if '\n' in key or '\r' in key:
        raise ValueError('an authorized key must be a single line')
    for token in key.split():
        if token.startswith('AAAA'):
            return key, token
    raise ValueError('no base64 key blob found in authorized key: %r' % (key,))


def raw_authorized_key_cmd(user, key, state):
    """Add/remove one public key (matched by its blob) in ~user/.ssh/authorized_keys."""
    key, blob = _key_blob(key)
    tokens = dict(U=shlex.quote(user), B=shlex.quote(blob), K=shlex.quote(key), M=CHANGED_MARKER)
    lookup = 'h="$(getent passwd @U@ | cut -d: -f6)"; f="$h/.ssh/authorized_keys"; '
    if state == 'absent':
        # Nothing to revoke when the account or file is gone.
        body = ('if [ -n "$h" ] && [ -f "$f" ] && grep -qF -- @B@ "$f"; then T="$f.raw.tmp"; '
                '(umask 077; grep -vF -- @B@ "$f" > "$T"; [ $? -le 1 ]) && cat "$T" > "$f" '
                '&& rm -f "$T" && echo @M@ || { rm -f "$T"; false; }; fi')
    else:
        body = ('if [ -z "$h" ] || [ ! -d "$h" ]; then echo "no home directory for @U@" >&2; false; '
                'elif [ -f "$f" ] && grep -qF -- @B@ "$f"; then :; '
                'else g="$(id -gn @U@)" && (umask 077; install -d -m 0700 -o @U@ -g "$g" "$h/.ssh" '
                '&& touch "$f") && chown @U@:"$g" "$f" && chmod 0600 "$f" '
                '&& { [ ! -s "$f" ] || [ -z "$(tail -c1 "$f")" ] || echo >> "$f"; } '
                "&& printf '%s\\n' @K@ >> \"$f\" && echo @M@; fi")
    return _render(lookup + body, **tokens)


def raw_sysctl_directives(settings):
    """sysctl module equivalent as raw_set_directives input (``key = value`` lines)."""
    return [{'regexp': r'^\s*%s\s*=' % re.escape(str(k)), 'line': '%s = %s' % (k, v)}
            for k, v in (settings or {}).items()]


def raw_limits_content(limits):
    """/etc/security/limits.d file body from pam_limits-style items."""
    rows = ['%s\t%s\t%s\t%s' % (i['domain'], i['limit_type'], i['limit_item'], i['value'])
            for i in (limits or [])]
    return '\n'.join(['# Managed by Ansible'] + rows) + '\n'


def raw_sudoers_line(name):
    if not re.match(r'^[A-Za-z0-9._-]+$', name or ''):
        raise ValueError('unsafe account name for sudoers: %r' % (name,))
    return '%s ALL=(ALL) NOPASSWD:ALL\n' % name


_RELEASE_RE = re.compile(
    r'^(?P<name>(?:CentOS|Red Hat)[^\n]*?)\s+release\s+(?P<version>[0-9]+(?:\.[0-9]+)*)',
    re.MULTILINE)


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
            'raw_changed': raw_changed,
            'raw_group_cmd': raw_group_cmd,
            'raw_user_cmd': raw_user_cmd,
            'raw_authorized_key_cmd': raw_authorized_key_cmd,
            'raw_sysctl_directives': raw_sysctl_directives,
            'raw_limits_content': raw_limits_content,
            'raw_sudoers_line': raw_sudoers_line,
        }
