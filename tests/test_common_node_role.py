"""NODE_ROLE default (#150): operational selection/exclusion groups
(``host_agents_*``, ``host_audit_*``) never become a host's role."""
import re
import sys
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from node_env import FilterModule, node_role_from_groups  # noqa: E402

TEMPLATES = ROOT_DIR / "roles" / "common" / "templates"


@pytest.mark.parametrize("groups, expected", [
    (["host_agents_backup_only", "servers"], "servers"),
    (["host_audit_excluded", "host_agents_excluded", "servers"], "servers"),
    (["all", "loadbalancers"], "loadbalancers"),
    (["firewall_unmanaged", "funa_cluster", "servers"], "servers"),
    (["host_agents_excluded"], "server"),
    ([], "server"),
])
def test_node_role_skips_selection_groups(groups, expected):
    assert node_role_from_groups(groups) == expected


def _render_node_role(template, **ctx):
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    env.filters.update(FilterModule().filters())
    out = env.get_template(template).render(inventory_hostname="ns0270", ansible_default_ipv4={}, **ctx)
    return re.search(r'NODE_ROLE="([^"]*)"', out).group(1)


@pytest.mark.parametrize("template", ["environment.j2", "node-env.sh.j2"])
def test_templates_render_role_group(template):
    groups = ["host_agents_backup_only", "servers"]
    assert _render_node_role(template, group_names=groups) == "servers"


@pytest.mark.parametrize("template", ["environment.j2", "node-env.sh.j2"])
def test_templates_explicit_node_role_wins(template):
    groups = ["host_agents_backup_only", "servers"]
    assert _render_node_role(template, group_names=groups, node_role="db") == "db"


@pytest.mark.parametrize("template", ["environment.j2", "node-env.sh.j2"])
@pytest.mark.parametrize("ctx", [{}, {"otel_target_endpoint": "10.0.0.1:4317"}])
def test_templates_do_not_export_otlp_endpoint(template, ctx):
    """ADR-0012: no host-shell OTLP endpoint; other variables stay."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    env.filters.update(FilterModule().filters())
    out = env.get_template(template).render(
        inventory_hostname="ns0270", ansible_default_ipv4={}, group_names=["servers"],
        custom_environment_variables={"FOO": "bar"}, **ctx)
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in out
    for name in ("NODE_NAME", "NODE_SSH_PORT", "FOO"):
        assert f"{name}=\"" in out
