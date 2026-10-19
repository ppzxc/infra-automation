"""Filters for the FUNA Cluster environment files (funa_env role, #222).

The OpenBao values of the FUNA Cluster are turned into dotenv text that compose
(``env_file:``, ``--env-file``), Caddy/keepalived containers and a login shell
(``. file`` under ``set -a``) all read the same way. Problems are returned as
messages that name the path or key and never contain a value, so the playbook
can print them without hiding the task output behind ``no_log``.
"""

import re

_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
# Written without quotes only when no shell/dotenv metacharacter can change the value.
_BARE = re.compile(r'^[A-Za-z0-9_@%+=:,./-]+$')
HEADER = '# Managed by Ansible (funa_env). Do not edit; values come from OpenBao.\n'


def _scalar(value):
    """str form of a scalar KV value, or None when it cannot be an env value."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _render(mapping, label, errors):
    """dotenv lines for ``mapping``; invalid entries are reported by key name only."""
    lines = []
    for key in sorted(mapping):
        value = _scalar(mapping[key])
        if not _NAME.match(str(key)):
            errors.append("%s: '%s' is not a valid environment variable name" % (label, key))
        elif value is None:
            errors.append("%s: %s is not a single scalar value" % (label, key))
        elif any(c in value for c in '\n\r\0'):
            errors.append("%s: %s contains a line break or NUL" % (label, key))
        elif "'" in value:
            errors.append("%s: %s contains a single quote" % (label, key))
        elif value == '' or _BARE.match(value):
            lines.append('%s=%s\n' % (key, value))
        else:
            lines.append("%s='%s'\n" % (key, value))
    return ''.join(lines)


def _shell_refs(mapping, label, errors):
    """Report values holding ``${`` (a leftover shell reference that would reach Caddy and alerts verbatim); a lone ``$`` is fine."""
    for key in sorted(mapping):
        value = _scalar(mapping[key])
        if value is not None and '${' in value:
            errors.append('%s: %s contains a shell reference' % (label, key))


def _missing(mapping, required, label, errors):
    for key in required:
        value = _scalar(mapping.get(key))
        if value is None or value == '':
            errors.append('%s: required key %s is missing' % (label, key))


def funa_env_kv_by_key(results):
    """{loop key: KV data, or None} from the uri loop results (a 404 has no data)."""
    out = {}
    for r in results or []:
        data = ((r.get('json') or {}).get('data') or {}).get('data') if r.get('status') == 200 else None
        out[r['item']['key']] = data
    return out


def funa_env_resolve(kv, node_keys, required_cluster, required_proxy, required_vrrp,
                     cluster_path, host_path, node_secret_keys=()):
    """Build the three env files from the OpenBao reads.

    ``node_secret_keys`` are per-node secrets read from the host KV and written to the
    proxy file (e.g. a Caddy token that differs per node).
    ``kv`` maps node/cluster/proxy/vrrp to the KV data, or None when the path
    does not exist. Returns ``{'errors': [...], 'cluster': text, 'proxy': text,
    'vrrp': text}``; the texts are empty when there are errors.
    """
    errors = []
    sources = (
        ('node', host_path, list(node_keys) + list(node_secret_keys)),
        ('cluster', cluster_path, required_cluster),
        ('proxy', cluster_path + '/proxy', required_proxy),
        ('vrrp', cluster_path + '/vrrp', required_vrrp),
    )
    data = {}
    for name, path, required in sources:
        value = kv.get(name)
        if value is None:
            errors.append('%s: OpenBao path does not exist' % path)
            value = {}
        elif name in ('proxy', 'vrrp') and not value:
            errors.append('%s: no keys' % path)
        data[name] = value
        if name != 'proxy':
            _missing(value, required, path, errors)

    # Node values only come from the declared keys; hosts/<host> also holds SSH credentials.
    node = {k: data['node'][k] for k in node_keys if k in data['node']}
    node_secrets = {k: data['node'][k] for k in node_secret_keys if k in data['node']}
    _shell_refs(node, host_path, errors)
    _shell_refs(node_secrets, host_path, errors)
    _shell_refs(data['cluster'], cluster_path, errors)
    _shell_refs(data['proxy'], cluster_path + '/proxy', errors)
    _shell_refs(data['vrrp'], cluster_path + '/vrrp', errors)
    cluster = dict(data['cluster'])
    cluster.update(node)
    proxy = dict(data['proxy'])
    proxy.update(node_secrets)
    _missing(proxy, required_proxy, cluster_path + '/proxy', errors)
    for name in ('proxy', 'vrrp'):
        for key in sorted(set(proxy if name == 'proxy' else data[name]) & set(cluster)):
            errors.append('%s: %s is also in the non-secret cluster values' % (cluster_path + '/' + name, key))
    both = sorted(set(proxy) & set(data['vrrp']))
    errors.extend('%s: %s is in both consumer secret files' % (cluster_path, k) for k in both)

    out = {'errors': errors, 'cluster': '', 'proxy': '', 'vrrp': ''}
    rendered = {
        'cluster': _render(cluster, cluster_path, errors),
        'proxy': _render(proxy, cluster_path + '/proxy', errors),
        'vrrp': _render(data['vrrp'], cluster_path + '/vrrp', errors),
    }
    if not errors:
        out.update({k: HEADER + v for k, v in rendered.items()})
    return out


class FilterModule(object):
    def filters(self):
        return {'funa_env_resolve': funa_env_resolve, 'funa_env_kv_by_key': funa_env_kv_by_key}
