"""역할이 읽는 문서 선언과 계열 AppRole 정책의 정적 대조(Spec #511 / Ticket-20, #531).

`<역할>_openbao_required`(역할 vars/main.yml)의 문서 패턴이 그 역할을 돌리는 계열 AppRole의 정책 경로에 모두 들어가고,
선언한 키가 스키마의 required를 덮고 properties 안에 있는지 본다. tofu 바이너리도 서버도 필요 없다.
"""
import ast
import json
import re
import sys

import pytest
import yaml

from test_openbao_policies import ROOT, _role_policies, index_patterns, readable_patterns

sys.path.insert(0, str(ROOT / "lookup_plugins"))
import openbao_connection as oc  # noqa: E402

# 역할 -> 그 역할을 실행하는 Semaphore 템플릿의 AppRole 계열. 새 역할이 선언을 만들면 여기에 한 줄을 더해야 통과한다.
ROLE_FAMILY = {
    "funa_env": "provision",
    "monitoring": "host_agents",
    "backup": "backup_maintenance",
    "openobserve_config": "openobserve_config",
    "host_audit": "host_audit",
    "cisco_backup": "network_backup",
    "fortigate_backup": "network_backup",
    "github_webhook_watch": "github_webhook_watch",
}


# Asset 문서는 여러 역할이 존재·부가 정보만 보려고 읽는다. 스키마 required(description)는 쓰기 검증이 보장하므로
# 역할 선언이 키를 다 나열할 필요는 없다(선언한 키가 스키마 properties 안인지는 그대로 본다).
ASSET_PATTERNS = {"inventory/assets/+"}


def _declared(role):
    data = yaml.safe_load((ROOT / "roles" / role / "vars" / "main.yml").read_text(encoding="utf-8"))
    return data[f"{role}_openbao_required"]


def _schema_for(pattern):
    text = (ROOT / "schemas" / "openbao" / "index.yml").read_text(encoding="utf-8")
    rel = dict(re.findall(r'^"([^"]+)":\s*(\S+)', text, re.M))[pattern]
    return json.loads((ROOT / "schemas" / "openbao" / rel).read_text(encoding="utf-8"))


def test_every_role_with_a_declaration_is_mapped_to_a_family():
    declaring = set()
    for p in (ROOT / "roles").glob("*/vars/main.yml"):
        role = p.parent.parent.name
        if re.search(rf"^{role}_openbao_required:", p.read_text(encoding="utf-8"), re.M):
            declaring.add(role)
    assert declaring == set(ROLE_FAMILY)


@pytest.mark.parametrize("role", sorted(ROLE_FAMILY))
def test_declared_patterns_are_readable_by_the_family_approle(role):
    fam, _ = _role_policies()
    readable = readable_patterns(fam[ROLE_FAMILY[role]])
    declared = _declared(role)
    assert set(declared) <= set(index_patterns()), role
    missing = sorted(set(declared) - readable)
    assert not missing, f"{role}({ROLE_FAMILY[role]}) AppRole 정책이 읽지 못하는 선언: {missing}"


def _fits(schema, keys, check_required):
    """선언한 키가 스키마(또는 oneOf의 한 갈래)의 properties 안이고 required를 덮는가. `type`은 판별 상수라 선언하지 않는다."""
    keys = set(keys)
    for branch in schema.get("oneOf", [schema]):
        if not keys <= set(branch.get("properties", {})):
            continue
        if not check_required or set(branch.get("required", [])) - {"type"} <= keys:
            return True
    return False


@pytest.mark.parametrize("role", sorted(ROLE_FAMILY))
def test_declared_keys_cover_the_schema_required(role):
    for pattern, keys in _declared(role).items():
        assert _fits(_schema_for(pattern), keys, pattern not in ASSET_PATTERNS), f"{role} {pattern}: {keys}"


# ---- lookup 플러그인이 읽는 문서 -------------------------------------------------------------------------------------
# 역할 선언(`<역할>_openbao_required`)에는 공용 읽기 지점이 대신 읽는 문서가 없다. openbao_admin_accounts는 관리 계정의 공개키를
# `inventory/operators/<계정>`에서 읽는데 어느 정책에도 없어 서버 계열이 403으로 멈출 뻔했으므로, 플러그인의 읽기 표를 같이 대조한다.

# lookup을 쓰는 파일 -> 그 파일을 실행하는 계열 AppRole. 새 사용처가 생기면 이 표에도 적어야 통과한다.
LOOKUP_USERS = {
    "playbooks/common/resolve_connection.yml": {"provision", "host_agents", "host_audit"},
    "roles/cisco_backup/tasks/main.yml": {"network_backup"},
    "roles/fortigate_backup/tasks/main.yml": {"network_backup"},
}
# 계열이 쓰는 lookup이 읽는 패턴. 네트워크 장비 계열은 Automation Identity가 없어 IDENTITY_READS와 admin_accounts를 쓰지 않는다.
SERVER_READS = set(oc.CONNECTION_READS) | set(oc.IDENTITY_READS) | set(oc.ADMIN_ACCOUNTS_READS)
FAMILY_LOOKUP_READS = {
    "provision": SERVER_READS, "host_agents": SERVER_READS, "host_audit": SERVER_READS,
    "network_backup": set(oc.CONNECTION_READS),
}


def test_the_lookup_read_table_matches_the_read_calls_in_the_plugin_code():
    tree = ast.parse((ROOT / "lookup_plugins" / "openbao_connection.py").read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "read" and node.args:
            m = re.search(r"['\"]([a-z]+/[^'\"]*)['\"]", ast.unparse(node.args[0]))
            if m:
                found.add(m.group(1).replace("%s", "+"))
    assert found == SERVER_READS, f"플러그인의 read() 경로와 읽기 표가 다르다: {sorted(found ^ SERVER_READS)}"


def test_every_lookup_user_file_is_listed_with_its_families():
    users = set()
    for base in ("roles", "playbooks"):
        for p in (ROOT / base).rglob("*.yml"):
            if re.search(r"lookup\('openbao_(connection|admin_accounts|host_connection)'", p.read_text(encoding="utf-8")):
                users.add(str(p.relative_to(ROOT)))
    assert users == set(LOOKUP_USERS), sorted(users ^ set(LOOKUP_USERS))


@pytest.mark.parametrize("family", sorted(FAMILY_LOOKUP_READS))
def test_lookup_reads_are_readable_by_the_family_approle(family):
    fam, _ = _role_policies()
    missing = sorted(FAMILY_LOOKUP_READS[family] - readable_patterns(fam[family]))
    assert not missing, f"{family} AppRole 정책이 lookup이 읽는 문서를 읽지 못한다: {missing}"


def test_families_in_the_user_table_have_their_lookup_reads_declared():
    assert set().union(*LOOKUP_USERS.values()) == set(FAMILY_LOOKUP_READS)
