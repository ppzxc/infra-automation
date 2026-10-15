"""Filters for the common role's node environment (/etc/environment, 98-node-env.sh)."""

# Operational selection/exclusion groups (e.g. host_agents_backup_only,
# host_audit_excluded, firewall_unmanaged, funa_cluster) say which plays touch a host, not what the host is.
SELECTION_GROUP_PREFIXES = ('host_agents_', 'host_audit_', 'firewall_', 'funa_cluster')


def node_role_from_groups(group_names, fallback='server'):
    """First role group of a host for NODE_ROLE, skipping 'all' and selection groups (#150)."""
    for name in group_names or []:
        if name != 'all' and not name.startswith(SELECTION_GROUP_PREFIXES):
            return name
    return fallback


class FilterModule(object):
    def filters(self):
        return {
            'node_role_from_groups': node_role_from_groups,
        }
