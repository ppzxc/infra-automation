"""Filters for the FUNA Cluster environment files (funa_env role, #222, #524).

The OpenBao documents of the FUNA Cluster (snake_case stored keys) are turned into dotenv text that compose
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

ASSET, CLUSTER, PROXY, VRRP, CREDENTIAL = (
    'inventory/assets/+', 'inventory/services/funa', 'secrets/services/funa/proxy',
    'secrets/services/funa/vrrp', 'secrets/assets/+/credentials/+')


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


def funa_env_doc_path(pattern, host, credential):
    """Concrete document path of an index.yml pattern: the first ``+`` is the host, the second the Credential name."""
    for fill in (host, credential):
        pattern = pattern.replace('+', fill, 1)
    return pattern


def _env_values(doc, key_map, path, errors):
    """{ENV_NAME: value} of a document; keys without a table entry are reported by name only."""
    out = {}
    for key in sorted(doc or {}):
        if key in key_map:
            out[key_map[key]] = doc[key]
        else:
            errors.append('%s: %s has no environment variable mapping' % (path, key))
    return out


def funa_env_resolve(docs, key_map, node_required, cloudflare_env, host, credential):
    """Build the three env files from the OpenBao documents.

    ``docs`` maps the index.yml pattern of each document the role reads to its data. ``key_map`` is the
    stored-key -> environment-name table; a key without an entry is an error. The node's own settings are
    the ``funa`` section of its Asset document (``node_required`` must be in it) and its Cloudflare token
    is the Credential ``credential``, written to the proxy file as ``cloudflare_env``.
    Returns ``{'errors': [...], 'cluster': text, 'proxy': text, 'vrrp': text}``; the texts are empty when there are errors.
    """
    errors = []
    path = {p: funa_env_doc_path(p, host, credential) for p in (ASSET, CLUSTER, PROXY, VRRP, CREDENTIAL)}
    section = (docs.get(ASSET) or {}).get('funa')
    if not isinstance(section, dict):
        errors.append('%s: required key funa is missing' % path[ASSET])
        section = {}
    for key in node_required:
        if _scalar(section.get(key)) in (None, ''):
            errors.append('%s: required key funa.%s is missing' % (path[ASSET], key))
    node = _env_values(section, key_map, path[ASSET], errors)
    cluster = _env_values(docs.get(CLUSTER), key_map, path[CLUSTER], errors)
    proxy = _env_values(docs.get(PROXY), key_map, path[PROXY], errors)
    vrrp = _env_values(docs.get(VRRP), key_map, path[VRRP], errors)
    token = (docs.get(CREDENTIAL) or {}).get('token')
    if _scalar(token) in (None, ''):
        errors.append('%s: required key token is missing' % path[CREDENTIAL])
        token = None

    for mapping, label in ((node, path[ASSET]), (cluster, path[CLUSTER]), (proxy, path[PROXY]), (vrrp, path[VRRP])):
        _shell_refs(mapping, label, errors)
    if token is not None:
        _shell_refs({cloudflare_env: token}, path[CREDENTIAL], errors)
        proxy[cloudflare_env] = token
    errors.extend('%s: %s is also set by the service document %s' % (path[ASSET], k, path[CLUSTER])
                  for k in sorted(set(node) & set(cluster)))
    cluster.update(node)
    for secret, label in ((proxy, path[PROXY]), (vrrp, path[VRRP])):
        for key in sorted(set(secret) & set(cluster)):
            errors.append('%s: %s is also in the non-secret cluster values' % (label, key))
    errors.extend('%s: %s is in both consumer secret files' % (path[PROXY], k) for k in sorted(set(proxy) & set(vrrp)))

    out = {'errors': errors, 'cluster': '', 'proxy': '', 'vrrp': ''}
    rendered = {
        'cluster': _render(cluster, path[CLUSTER], errors),
        'proxy': _render(proxy, path[PROXY], errors),
        'vrrp': _render(vrrp, path[VRRP], errors),
    }
    if not errors:
        out.update({k: HEADER + v for k, v in rendered.items()})
    return out


class FilterModule(object):
    def filters(self):
        return {'funa_env_resolve': funa_env_resolve, 'funa_env_doc_path': funa_env_doc_path}
