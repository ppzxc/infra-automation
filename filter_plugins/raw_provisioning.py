"""Filters for the Raw Provisioning Path (ADR-0005).

CentOS 6/7 targets cannot run AnsiballZ modules, so files are pushed with
``ansible.builtin.raw`` using shell commands rendered here. The commands
replace a module's ``validate:``/``atomic_move`` safeguards and feed the
changed/unchanged sentinel contract.
"""

import base64
import hashlib
import ipaddress
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
    """Print '__RAW_PROBE__ <sha256> <mode> <owner:group>' for dest; fields are empty if absent.

    The marker lets the sentinel ignore login banners or other raw noise.
    """
    d = shlex.quote(dest)
    return ("printf '%s %s %s %s\\n' '{m}' "
            "\"$(sha256sum {d} 2>/dev/null | cut -d' ' -f1)\" "
            "\"$(stat -c %a {d} 2>/dev/null)\" "
            "\"$(stat -c %U:%G {d} 2>/dev/null)\"").format(m=PROBE_MARKER, d=d)


def raw_push_changed(probe_stdout, content, mode, owner=None, group=None):
    """Sentinel: changed when the remote hash, mode OR (if given) owner:group differs.

    An absent dest (or unusable probe) never equals the expected value, so
    first provisioning is reported as changed without special-casing.
    """
    expected = ['__RAW_PROBE__', raw_sha256(content), _mode_octal(mode)]
    if owner is not None:
        expected.append('%s:%s' % (owner, group))
    lines = [ln.split() for ln in (probe_stdout or '').splitlines()
             if ln.strip().startswith(PROBE_MARKER)]
    return not lines or lines[-1][:len(expected)] != expected


def raw_read_cmd(path):
    """cat path between markers, reporting cat's exit status."""
    return ("printf '\\n{b}\\n'; cat {p}; rc=$?; printf '\\n{e} %s\\n' \"$rc\"; exit 0"
            ).format(b=READ_BEGIN, e=READ_END, p=shlex.quote(path))


def raw_read_extract(stdout, allow_empty=False):
    """File content from raw_read_cmd output, or None if unreadable/empty.

    With ``allow_empty`` a missing or empty file yields '' (first provisioning);
    output without the read markers is still None.
    """
    m = re.search(r'%s\r?\n(.*)\r?\n%s (\d+)' % (READ_BEGIN, READ_END),
                  (stdout or '').replace('\r\n', '\n'), re.S)
    if not m:
        return None
    if m.group(2) != '0' or not m.group(1).strip():
        return '' if allow_empty else None
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


def raw_rm_cmd(path):
    """rm -f path only when it exists; echo the marker if it did."""
    return _render('f=@PATH@; if [ -e "$f" ]; then rm -f "$f" && echo @MARK@; fi',
                   PATH=shlex.quote(path), MARK=CHANGED_MARKER)


def raw_group_cmd(name, gid=None):
    """Create the group (or fix its gid) only when needed; echo the marker if it did."""
    n = shlex.quote(name)
    if gid in (None, ''):
        return ("if ! getent group %s >/dev/null 2>&1; then groupadd %s && echo %s; fi"
                % (n, n, CHANGED_MARKER))
    g = shlex.quote(str(gid))
    return ("if ! getent group %s >/dev/null 2>&1; then groupadd -g %s %s && echo %s; "
            "elif [ \"$(getent group %s | cut -d: -f3)\" != %s ]; then groupmod -g %s %s && echo %s; fi"
            % (n, g, n, CHANGED_MARKER, n, g, g, n, CHANGED_MARKER))


def raw_user_cmd(name, groups, shell, comment, uid, state, group=None):
    """useradd/usermod/userdel equivalent of ``ansible.builtin.user`` (append semantics).

    ``group`` is the primary group and defaults to the account name.
    """
    n = shlex.quote(name)
    if state == 'absent':
        return _render("if getent passwd @USER@ >/dev/null 2>&1; then userdel -r @USER@ && echo @MARK@; fi",
                       USER=n, MARK=CHANGED_MARKER)
    primary = shlex.quote(group or name)
    groups = [g for g in (groups or []) if g]
    create = ['useradd -m -g %s' % primary]
    fix = ['set --',
           '[ "$(id -gn %s)" = %s ] || set -- "$@" -g %s' % (n, primary, primary),
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
    """Add/replace/remove one public key (matched by its blob) in ~user/.ssh/authorized_keys.

    Rewrites go through a temp file + mv, and ownership/mode of ~/.ssh and the
    file are corrected like the ``authorized_key`` module does.
    """
    key, blob = _key_blob(key)
    tokens = dict(USER=shlex.quote(user), BLOB=shlex.quote(blob), KEY=shlex.quote(key), MARK=CHANGED_MARKER)
    lookup = ('h="$(getent passwd @USER@ | cut -d: -f6)"; f="$h/.ssh/authorized_keys"; '
              'T="$f.raw.tmp"; c=0; ')
    if state == 'absent':
        # Nothing to revoke when the account or file is gone.
        body = ('if [ -n "$h" ] && [ -f "$f" ] && grep -qF -- @BLOB@ "$f"; then '
                'g="$(id -gn @USER@)" && (umask 077; grep -vF -- @BLOB@ "$f" > "$T"; [ $? -le 1 ]) '
                '&& chown @USER@:"$g" "$T" && chmod 0600 "$T" && mv -f "$T" "$f" && echo @MARK@ '
                '|| { rm -f "$T"; false; }; fi')
    else:
        body = (
            'if [ -z "$h" ] || [ ! -d "$h" ]; then echo "no home directory for @USER@" >&2; false; else '
            'g="$(id -gn @USER@)" || exit 1; '
            '[ -d "$h/.ssh" ] || { install -d -m 0700 -o @USER@ -g "$g" "$h/.ssh" && c=1; }; '
            '[ -f "$f" ] || { (umask 077; : > "$f") && c=1; }; '
            'if ! grep -qxF -- @KEY@ "$f"; then '
            '(umask 077; grep -vF -- @BLOB@ "$f" > "$T"; [ $? -le 1 ]) && printf \'%s\\n\' @KEY@ >> "$T" '
            '&& chown @USER@:"$g" "$T" && chmod 0600 "$T" && mv -f "$T" "$f" && c=1 '
            '|| { rm -f "$T"; false; }; fi; '
            '[ "$(stat -c %U:%G "$f")" = @USER@:"$g" ] && [ "$(stat -c %a "$f")" = 600 ] '
            '|| { chown @USER@:"$g" "$f" && chmod 0600 "$f" && c=1; }; '
            '[ "$(stat -c %U:%G "$h/.ssh")" = @USER@:"$g" ] && [ "$(stat -c %a "$h/.ssh")" = 700 ] '
            '|| { chown @USER@:"$g" "$h/.ssh" && chmod 0700 "$h/.ssh" && c=1; }; '
            '[ "$c" = 0 ] || echo @MARK@; fi')
    return _render(lookup + body, **tokens)


def raw_yum_cmd(packages, optional=False):
    """yum install of missing packages; echo the marker only when something was installed.

    Presence is checked with ``rpm -q --whatprovides`` so capability names such
    as ``nc`` count as installed. ``optional`` installs one by one and ignores
    failures (packages unavailable on the OS never make a run "changed").
    """
    pkgs = ' '.join(shlex.quote(p) for p in packages)
    if optional:
        return _render('for p in @PKGS@; do rpm -q --whatprovides "$p" >/dev/null 2>&1 || '
                       '{ yum -y install "$p" >/dev/null 2>&1 && echo @MARK@; }; done; true',
                       PKGS=pkgs, MARK=CHANGED_MARKER)
    return _render('miss=""; for p in @PKGS@; do rpm -q --whatprovides "$p" >/dev/null 2>&1 || miss="$miss $p"; done; '
                   'if [ -n "$miss" ]; then yum -y install $miss && echo @MARK@; fi',
                   PKGS=pkgs, MARK=CHANGED_MARKER)


def raw_service_cmd(name):
    """Ensure ``name`` is running and enabled on boot (systemd or SysV); marker if anything changed.

    CentOS 7 is systemd (``systemctl``), CentOS 6 is SysV/Upstart (``service`` +
    ``chkconfig``); the presence of ``systemctl`` selects the branch.
    """
    return _render(
        'c=0; rc=0; if command -v systemctl >/dev/null 2>&1; then '
        'systemctl is-active @N@ >/dev/null 2>&1 || { systemctl start @N@ && c=1 || rc=1; }; '
        'systemctl is-enabled @N@ >/dev/null 2>&1 || { systemctl enable @N@ >/dev/null 2>&1 && c=1 || rc=1; }; '
        'else '
        'service @N@ status >/dev/null 2>&1 || { service @N@ start >/dev/null && c=1 || rc=1; }; '
        'chkconfig --list @N@ 2>/dev/null | grep -q "3:on" || { chkconfig @N@ on && c=1 || rc=1; }; '
        'fi; [ "$c" = 0 ] || echo @MARK@; [ "$rc" = 0 ]',
        N=shlex.quote(name), MARK=CHANGED_MARKER)


def raw_timezone_cmd(name, zoneinfo='/usr/share/zoneinfo', localtime='/etc/localtime'):
    """``community.general.timezone`` equivalent for systemd hosts (CentOS 7); marker if it changed.

    The zone must exist under ``zoneinfo``. It is compared with what
    ``localtime`` resolves to, and ``timedatectl set-timezone`` runs only on drift.
    """
    if not re.match(r'^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$', name or ''):
        raise ValueError('unsafe timezone name: %r' % (name,))
    return _render(
        'z=@ZONE@/@NAME@; if [ ! -f "$z" ]; then echo "unknown timezone" @NAME@ >&2; false; '
        'elif [ "$(readlink -f @LOCAL@)" = "$(readlink -f "$z")" ]; then true; '
        'else timedatectl set-timezone @NAME@ && echo @MARK@; fi',
        ZONE=shlex.quote(zoneinfo), NAME=shlex.quote(name), LOCAL=shlex.quote(localtime), MARK=CHANGED_MARKER)


def raw_selinux_cmd(state, policy, config='/etc/selinux/config'):
    """``ansible.posix.selinux`` equivalent: persist SELINUX/SELINUXTYPE and align the running mode.

    A host without the SELinux config (container-like) is left alone. The
    runtime mode is only switched between enforcing and permissive, like the
    module (``disabled`` needs a reboot; it only relaxes enforcing to permissive).
    """
    if state not in ('enforcing', 'permissive', 'disabled'):
        raise ValueError('unsupported selinux state: %r' % (state,))
    if not re.match(r'^[A-Za-z0-9_-]+$', policy or ''):
        raise ValueError('unsafe selinux policy: %r' % (policy,))
    runtime = {'enforcing': ('Permissive', '1'), 'permissive': ('Enforcing', '0'), 'disabled': ('Enforcing', '0')}[state]
    return _render(
        'f=@CFG@; c=0; rc=0; '
        'if [ -f "$f" ]; then '
        'for kv in SELINUX=@STATE@ SELINUXTYPE=@POLICY@; do k="${kv%%=*}"; '
        'grep -qx "$kv" "$f" || { if grep -q "^$k=" "$f"; then sed -i "s/^$k=.*/$kv/" "$f"; '
        'else printf "%s\\n" "$kv" >> "$f"; fi && c=1 || rc=1; }; done; fi; '
        'if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = @FROM@ ]; then '
        'setenforce @TO@ && c=1 || rc=1; fi; '
        '[ "$c" = 0 ] || echo @MARK@; [ "$rc" = 0 ]',
        CFG=shlex.quote(config), STATE=state, POLICY=policy, FROM=runtime[0], TO=runtime[1], MARK=CHANGED_MARKER)


IPT_MARKER = '__RAW_IPT__'


def _iptables_rule(port, proto, source):
    """Canonical ``iptables -S INPUT`` spelling of the ACCEPT rule, plus its -I arguments."""
    port = str(port)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('invalid port for iptables: %r' % (port,))
    proto = str(proto or 'tcp')
    if proto not in ('tcp', 'udp'):
        raise ValueError('unsupported protocol for iptables: %r' % (proto,))
    src = ''
    if source not in (None, ''):
        try:
            net = ipaddress.IPv4Network(str(source), strict=False)
        except ValueError:
            raise ValueError('invalid IPv4 source for iptables: %r' % (source,))
        src = '-s %s ' % net.with_prefixlen
    return '%s-p %s -m %s --dport %d -j ACCEPT' % (src, proto, proto, int(port))


def raw_iptables_cmd(port, proto, source, mode):
    """CentOS 6 iptables ACCEPT rule (``ansible.builtin.iptables`` equivalent) for INPUT.

    ``probe`` prints ``__RAW_IPT__ present|absent|error`` (always exit 0) by
    matching the normalized ``iptables -S INPUT`` line; ``insert`` puts the rule
    at position 1 and propagates iptables' exit status. Only IPv4 tcp/udp.
    """
    rule = _iptables_rule(port, proto, source)
    if mode == 'insert':
        return 'iptables -I INPUT 1 %s' % rule
    if mode != 'probe':
        raise ValueError('unknown iptables mode: %r' % (mode,))
    return _render(
        'out="$(iptables -S INPUT 2>/dev/null)"; if [ $? -ne 0 ]; then echo @M@ error; '
        'elif printf \'%s\\n\' "$out" | grep -qxF -- @LINE@; then echo @M@ present; else echo @M@ absent; fi; exit 0',
        M=IPT_MARKER, LINE=shlex.quote('-A INPUT ' + rule))


def raw_iptables_absent(stdout):
    """True only when the probe positively reported the rule missing (never on error/noise)."""
    lines = [ln.split() for ln in (stdout or '').splitlines() if ln.strip().startswith(IPT_MARKER)]
    return bool(lines) and lines[-1][1:] == ['absent']


def raw_iptables_failed(stdout):
    """True unless the probe ran and answered present/absent."""
    lines = [ln.split() for ln in (stdout or '').splitlines() if ln.strip().startswith(IPT_MARKER)]
    return not lines or lines[-1][1:] not in (['present'], ['absent'])


def raw_sysctl_directives(settings):
    """sysctl module equivalent as raw_set_directives input (``key = value`` lines)."""
    return [{'regexp': r'^\s*%s\s*=' % re.escape(str(k)), 'line': '%s = %s' % (k, v)}
            for k, v in (settings or {}).items()]


def raw_sysctl_live_cmd(settings):
    """Align live kernel values with ``settings`` (module ``sysctl_set``); marker if any changed.

    Keys the running kernel does not know (e.g. IPv6 disabled) are skipped. The
    kernel clamps some values to others (``rmem_default`` <= ``rmem_max``), so
    the keys are applied twice; only failures of the second pass count.
    """
    norm = '"$(sysctl -n {k} 2>/dev/null | tr -s "[:space:]" " " | sed "s/^ //;s/ $//")" = {want}'

    def one_pass(fail_var):
        out = []
        for k, v in (settings or {}).items():
            want = ' '.join(str(v).split())
            check = norm.format(k=shlex.quote(str(k)), want=shlex.quote(want))
            # sysctl -w can exit 0 without applying, so verify by reading back.
            out.append(
                'if sysctl -n {k} >/dev/null 2>&1; then [ {check} ] || '
                '{{ sysctl -w {kv} >/dev/null 2>&1; [ {check} ] && c=1 || {f}=1; }}; fi'.format(
                    k=shlex.quote(str(k)), check=check,
                    kv=shlex.quote('%s=%s' % (k, want)), f=fail_var))
        return out
    parts = ['c=0; rc=0; ignore=0'] + one_pass('ignore') + one_pass('rc')
    parts.append('[ "$c" = 0 ] || echo %s; [ "$rc" = 0 ]' % CHANGED_MARKER)
    return '; '.join(parts)


def raw_limits_directives(limits):
    """pam_limits equivalent as raw_set_directives input (one line per domain/type/item)."""
    return [{'regexp': r'^\s*%s\s+%s\s+%s\s' % (re.escape(str(i['domain'])), re.escape(str(i['limit_type'])),
                                                re.escape(str(i['limit_item']))),
             'line': '%s\t%s\t%s\t%s' % (i['domain'], i['limit_type'], i['limit_item'], i['value'])}
            for i in (limits or [])]


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
            'raw_limits_directives': raw_limits_directives,
            'raw_rm_cmd': raw_rm_cmd,
            'raw_yum_cmd': raw_yum_cmd,
            'raw_sysctl_live_cmd': raw_sysctl_live_cmd,
            'raw_sudoers_line': raw_sudoers_line,
            'raw_service_cmd': raw_service_cmd,
            'raw_timezone_cmd': raw_timezone_cmd,
            'raw_selinux_cmd': raw_selinux_cmd,
            'raw_iptables_cmd': raw_iptables_cmd,
            'raw_iptables_absent': raw_iptables_absent,
            'raw_iptables_failed': raw_iptables_failed,
        }
