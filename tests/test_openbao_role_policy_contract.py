"""역할이 읽는 문서 선언과 계열 AppRole 정책의 정적 대조(Spec #511 / Ticket-20, #531).

`<역할>_openbao_required`(역할 vars/main.yml)의 문서 패턴이 그 역할을 돌리는 계열 AppRole의 정책 경로에 모두 들어가고,
선언한 키가 스키마의 required를 덮고 properties 안에 있는지 본다. tofu 바이너리도 서버도 필요 없다.
"""
import json
import re

import pytest
import yaml

from test_openbao_policies import ROOT, _role_policies, index_patterns, readable_patterns

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
