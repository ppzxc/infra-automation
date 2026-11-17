"""OpenBao 계열별 정책·AppRole의 정적 검사(Spec #511 / Ticket-7, #518).

tofu 바이너리 없이 HCL·tf 파일만 읽는다. 정책 HCL은 `path "..." { capabilities = [...] }` 형태만 정규식으로 읽고
다른 문법(템플릿 변수, `allowed_parameters` 등)이 나오면 실패한다. 계열 x 경로 매트릭스의 원본은 정책 HCL이고,
여기의 EXPECTED_READS는 그 원본이 어긋나지 않게 묶어 두는 회귀 표다(#506 §3).
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOFU = ROOT / "tofu" / "openbao"
POLICIES = TOFU / "policies"
INDEX = ROOT / "schemas" / "openbao" / "index.yml"

KV_MOUNTS = {"inventory", "secrets"}
CAPS = {"create", "read", "update", "delete", "list", "sudo", "deny", "patch"}
# KV 밖(sys/·auth/) 경로를 가질 수 있는 정책.
NON_KV_POLICIES = {"applier", "periodic-check"}
# list 권한을 가질 수 있는 정책(기계는 periodic_check, 에이전트 세션은 metadata 한정).
LIST_POLICIES = {"periodic-check", "operator", "agent-session"}
SERVER_FAMILIES = {"provision", "host_agents", "host_audit"}
ALL_FAMILIES = {
    "provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit", "network_backup",
    "github_webhook_watch", "periodic_check", "agent_session",
}


# ---- HCL 읽기 -------------------------------------------------------------------------------------------------------

_BLOCK = re.compile(r'\s*path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}\s*')


def parse_policy(text):
    """[(path, [capabilities])]. path 블록 외의 문법이 하나라도 있으면 AssertionError."""
    body = re.sub(r"(?m)^\s*#.*$", "", text)
    pos, out = 0, []
    while pos < len(body):
        m = _BLOCK.match(body, pos)
        assert m, f"알 수 없는 HCL 문법: {body[pos:pos + 60]!r}"
        caps = re.findall(r'"([^"]*)"', m.group(2))
        assert re.fullmatch(r'\s*("[^"]*"\s*,?\s*)*', m.group(2)), f"capabilities 형식: {m.group(2)!r}"
        assert caps and set(caps) <= CAPS, f"capabilities 값: {caps}"
        out.append((m.group(1), caps))
        pos = m.end()
    return out


def policy(name):
    return parse_policy((POLICIES / f"{name}.hcl").read_text(encoding="utf-8"))


POLICY_NAMES = sorted(p.stem for p in POLICIES.glob("*.hcl"))


# ---- index.yml 대조 -------------------------------------------------------------------------------------------------

def index_patterns():
    text = INDEX.read_text(encoding="utf-8")
    pats = re.findall(r'^"([^"]+)":', text, re.M)
    assert pats, "index.yml에서 패턴을 못 읽었다"
    return pats


def doc_path(policy_path):
    """KV v2 경로 `<마운트>/data|metadata/<문서>`를 `<마운트>/<문서>`로 바꾼다. 마운트 루트(`data`만)도 허용."""
    parts = policy_path.split("/")
    assert parts[0] in KV_MOUNTS, policy_path
    assert len(parts) >= 2 and parts[1] in {"data", "metadata"}, f"{policy_path}: data/ 또는 metadata/가 필요"
    return [parts[0], *parts[2:]], parts[1]


def _segs(path):
    segs = [s for s in path.split("/") if s != ""]
    for i, s in enumerate(segs):
        assert "*" not in s or (s == "*" and i == len(segs) - 1), f"`*`는 끝자리 한 칸만 쓴다: {path}"
    return segs


def covers(policy_segs, pattern_segs):
    """정책 경로가 index 패턴이 가리키는 모든 문서를 덮는가."""
    for i, p in enumerate(policy_segs):
        if p == "*":
            return True
        if i >= len(pattern_segs):
            return False
        if p != "+" and p != pattern_segs[i]:
            return False
    return len(policy_segs) == len(pattern_segs)


def touches(policy_segs, pattern_segs):
    """정책 경로가 index 패턴 중 문서 하나에라도 맞는가(오타 검출용)."""
    for i, p in enumerate(policy_segs):
        if p == "*":
            return True
        if i >= len(pattern_segs):
            return False
        if p != "+" and pattern_segs[i] != "+" and p != pattern_segs[i]:
            return False
    return len(policy_segs) == len(pattern_segs)


def readable_patterns(policy_names):
    """정책 묶음이 data/ read로 덮는 index 패턴 집합."""
    result = set()
    for name in policy_names:
        for path, caps in policy(name):
            if "read" not in caps or path.split("/")[0] not in KV_MOUNTS:
                continue
            segs, kind = doc_path(path)
            if kind != "data":
                continue
            for pat in index_patterns():
                if covers(segs, _segs(pat)):
                    result.add(pat)
    return result


# ---- AppRole 읽기 ---------------------------------------------------------------------------------------------------

def _role_policies():
    """approles.tf의 locals에서 계열별 token_policies를 읽는다. host_audit은 합집합 식을 따로 검사한다."""
    text = (TOFU / "approles.tf").read_text(encoding="utf-8")
    block = re.search(r"family_policies\s*=\s*\{(.*?)\n  \}", text, re.S)
    assert block, "locals.family_policies가 없다"
    fam = {}
    for m in re.finditer(r"^\s*(\w+)\s*=\s*\[([^\]]*)\]", block.group(1), re.M):
        fam[m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
    ha = re.search(r"host_audit_policies\s*=\s*distinct\(concat\(\s*local\.family_policies\.provision,\s*"
                   r"local\.family_policies\.host_agents,\s*\[([^\]]*)\]\s*\)\)", text)
    assert ha, "host_audit_policies는 provision ∪ host_agents ∪ 자기 경로 식이어야 한다"
    fam["host_audit"] = list(dict.fromkeys(
        fam["provision"] + fam["host_agents"] + re.findall(r'"([^"]+)"', ha.group(1))))
    return fam, text


# ---- 정책 파일 -------------------------------------------------------------------------------------------------------

def test_policy_dir_has_small_policies():
    assert "applier" in POLICY_NAMES
    assert len(POLICY_NAMES) >= 10


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_policy_is_parseable_and_paths_match_index(name):
    entries = policy(name)
    assert entries, name
    pats = [_segs(p) for p in index_patterns()]
    for path, caps in entries:
        _segs(path)  # `*` 위치 검사
        if path.split("/")[0] not in KV_MOUNTS:
            assert name in NON_KV_POLICIES, f"{name}: KV 밖 경로 {path}"
            continue
        segs, kind = doc_path(path)
        assert any(touches(segs, p) for p in pats), f"{name}: index.yml에 없는 문서 경로 {path}"
        if kind == "metadata":
            assert set(caps) <= {"read", "list"} or name == "operator", f"{name}: {path} {caps}"


def test_parser_rejects_unknown_syntax():
    with pytest.raises(AssertionError):
        parse_policy('path "inventory/data/x" {\n  capabilities = ["read"]\n  allowed_parameters = {}\n}')
    with pytest.raises(AssertionError):
        parse_policy('path "{{identity.entity.name}}/x" {\n  capabilities = ["read"]\n}\nfoo')
    with pytest.raises(AssertionError):
        parse_policy('path "inventory/data/x" {\n  capabilities = ["root"]\n}')


def test_service_permission_policies_are_named_after_the_permission():
    for name, doc in {
        "openobserve-ingest": "secrets/services/openobserve/ingest",
        "openobserve-admin": "secrets/services/openobserve/admin",
        "rustfs-maintenance": "secrets/services/rustfs/maintenance",
        "rustfs-audit-reports": "secrets/services/rustfs/audit_reports",
        "alert-notify": "secrets/services/alert/notify",
        "github-org-hooks-read": "secrets/services/github/org_hooks_read",
    }.items():
        assert readable_patterns([name]) == {doc}, name


def test_connect_bundle_is_assets_credentials_automation_identity_and_operator_public_keys():
    assert readable_patterns(["connect"]) == {
        "inventory/assets/+", "inventory/assets/+/endpoints",
        "secrets/assets/+/credentials/+", "secrets/automation/ssh",
        "inventory/operators/+",
    }


def test_connect_bundle_equals_its_small_policies():
    paths = lambda names: {p for n in names for p, _ in policy(n)}  # noqa: E731
    assert paths(["connect"]) == paths(["inventory-assets", "asset-credentials"]) | {
        "secrets/data/automation/ssh", "inventory/data/operators/*"}


def test_no_machine_policy_has_delete_or_sys_outside_applier_and_periodic_check():
    for name in POLICY_NAMES:
        for path, caps in policy(name):
            if name != "applier":
                assert "delete" not in caps and "sudo" not in caps, (name, path)
            if name not in NON_KV_POLICIES:
                assert not path.startswith(("sys/", "auth/")), (name, path)


def test_list_capability_only_in_periodic_check_operator_and_agent_session():
    for name in POLICY_NAMES:
        if name in LIST_POLICIES or name == "applier":
            continue
        for path, caps in policy(name):
            assert "list" not in caps, f"{name}: {path}"


# ---- 계열 x 경로 매트릭스(#506 §3) ------------------------------------------------------------------------------------

COMMON = {
    "inventory/services/openobserve", "inventory/services/rustfs", "inventory/services/github",
    "inventory/services/semaphore", "inventory/services/funa", "inventory/config/common",
}
ASSETS = {"inventory/assets/+", "inventory/assets/+/endpoints"}
CRED = {"secrets/assets/+/credentials/+"}
SSH = {"secrets/automation/ssh"}
OPERATORS = {"inventory/operators/+"}   # connect 묶음: 관리 계정 공개키(lookup openbao_admin_accounts)
AGENTS = {"secrets/assets/+/agents"}
FUNA = {"secrets/services/funa/proxy", "secrets/services/funa/vrrp"}
OO_ING = {"secrets/services/openobserve/ingest"}
PROVISION = COMMON | ASSETS | CRED | SSH | OPERATORS | FUNA
HOST_AGENTS = COMMON | ASSETS | CRED | SSH | OPERATORS | AGENTS | OO_ING | {"secrets/services/alert/notify"}  # 헬스 워치 알림(monitoring)

EXPECTED_READS = {
    "provision": PROVISION,
    "host_agents": HOST_AGENTS,
    "backup_maintenance": COMMON | AGENTS | {"secrets/services/rustfs/maintenance"} | OO_ING,
    "openobserve_config": COMMON | ASSETS | {"secrets/services/openobserve/admin", "secrets/services/alert/notify"}
    | OO_ING | {"inventory/config/openobserve_config"},
    "host_audit": PROVISION | HOST_AGENTS | {"secrets/services/rustfs/audit_reports", "secrets/services/alert/notify",
                                                  "inventory/config/host_audit"},
    "network_backup": COMMON | ASSETS | CRED | {"secrets/services/alert/notify"},
    "github_webhook_watch": COMMON | {"secrets/services/github/org_hooks_read"} | OO_ING
    | {"inventory/config/github_webhook_watch"},
}


def test_there_are_exactly_nine_semaphore_family_approles():
    fam, text = _role_policies()
    roles = set(fam) | {"periodic_check", "agent_session"}
    assert roles == ALL_FAMILIES
    assert "vault_approle_auth_backend_role" in text


@pytest.mark.parametrize("family", sorted(EXPECTED_READS))
def test_family_reads_exactly_the_matrix(family):
    fam, _ = _role_policies()
    assert readable_patterns(fam[family]) == EXPECTED_READS[family], family


def test_family_policies_exist_as_files():
    fam, _ = _role_policies()
    for family, names in fam.items():
        for n in names:
            assert n in POLICY_NAMES, f"{family}: {n}"


def test_every_policy_file_is_used_by_a_role_or_is_applier_or_operator():
    fam, _ = _role_policies()
    used = {n for names in fam.values() for n in names}
    assert set(POLICY_NAMES) - used == {"applier", "operator"}


def test_policy_for_each_is_keyed_by_policy_name_not_file_name():
    _, text = _role_policies()
    assert 'trimsuffix(f, ".hcl") => f' in text  # token_policies가 이름으로 vault_policy.small[...]을 찾는다


def test_automation_identity_only_for_server_families():
    fam, _ = _role_policies()
    for family, names in fam.items():
        if family == "periodic_check":
            continue  # 정기 점검은 #506 §6의 "전체 읽기"라 스키마 대조용으로 예외다(periodic-check.hcl 주석).
        has = bool(readable_patterns(names) & SSH)
        assert has == (family in SERVER_FAMILIES), family
    # 모든 계열이 자기 경로로 일반 정책을 가지므로 network_backup에 connect가 섞이지 않았는지 별도로 본다.
    assert "connect" not in fam["network_backup"] and "automation-ssh" not in fam["network_backup"]


def test_host_audit_union_reason_is_documented_in_policy_comment():
    text = (POLICIES / "config-host-audit.hcl").read_text(encoding="utf-8")
    assert "provision" in text and "host_agents" in text and "드리프트" in text


def test_periodic_check_has_list_and_reads_everything_but_agent_session_cannot_read_secret_values():
    pc = policy("periodic-check")
    kv = {p: c for p, c in pc}
    assert "list" in kv["secrets/metadata/*"] and "list" in kv["inventory/metadata/*"]
    assert {"read"} <= set(kv["secrets/data/*"]) and {"read"} <= set(kv["inventory/data/*"])
    assert not any("create" in c or "update" in c for _, c in pc if _.startswith(("inventory/", "secrets/")))
    ag = dict(policy("agent-session"))
    assert ag["inventory/data/*"] == ["read"]
    assert set(ag["secrets/metadata/*"]) == {"read", "list"}
    assert not any(p.startswith("secrets/data") for p in ag)
    assert readable_patterns(["agent-session"]) == {p for p in index_patterns() if p.startswith("inventory/")}


def test_operator_reads_everything_and_writes_but_never_deletes():
    op = dict(policy("operator"))
    assert set(op["inventory/data/*"]) == {"read", "create", "update"}
    assert set(op["secrets/data/*"]) == {"read", "create", "update"}
    assert set(op["inventory/metadata/*"]) == {"read", "list"}
    assert set(op["secrets/metadata/*"]) == {"read", "list"}
    assert len(op) == 4
    for path, caps in op.items():
        assert not ({"delete", "sudo", "deny"} & set(caps)), path
        assert not path.startswith(("sys/", "auth/")), path
        assert "/delete/" not in path and "/destroy/" not in path and "/undelete/" not in path


def test_periodic_check_machine_only_gets_approle_metadata_and_sys_reads():
    for path, caps in policy("periodic-check"):
        if path.startswith(("sys/", "auth/")):
            assert not ({"delete", "sudo"} & set(caps)), path
            if path.startswith("auth/approle/role/+/secret-id"):
                # secret_id 발급(create/update)은 막는다. accessor 조회만 update.
                assert "lookup" in path or caps == ["list"], path


# ---- AppRole 수명·출발지 ---------------------------------------------------------------------------------------------

def test_semaphore_approles_have_ttls_and_cidr_binding_from_variables():
    _, text = _role_policies()
    assert "secret_id_ttl" in text and "15552000" in text  # 180일
    assert re.search(r"token_ttl\s*=\s*1800", text)
    assert "token_max_ttl" in text
    assert "var.runner_cidrs" in text
    assert "token_bound_cidrs" in text
    assert "var.agent_session_cidrs" in text
    # CIDR 값이 코드에 직접 박히지 않는다.
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?\b", text)


def test_agent_session_secret_id_is_24h():
    _, text = _role_policies()
    assert "86400" in text


def test_operator_policy_is_attached_to_userpass_users():
    assert "operator" in POLICY_NAMES
    assert 'token_policies = ["operator"]' in (TOFU / "auth.tf").read_text(encoding="utf-8")


def test_index_matches_documented_operator_list_decision():
    adr = (ROOT / "docs" / "adr" / "0014-openbao-storage-structure-and-access-policy.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "runbooks" / "openbao-operations.md").read_text(encoding="utf-8")
    assert "list 포함" in adr
    assert "list 포함" in runbook
