"""OpenBao 계열별 정책·AppRole의 정적 검사(Spec #511 / Ticket-7, #518).

서버 없이 HCL·roles.yml 파일만 읽는다. 정책 HCL은 `path "..." { capabilities = [...] }` 형태만 정규식으로 읽고
다른 문법(템플릿 변수, `allowed_parameters` 등)이 나오면 실패한다. 계열 x 경로 매트릭스의 원본은 정책 HCL이고,
여기의 EXPECTED_READS는 그 원본이 어긋나지 않게 묶어 두는 회귀 표다(#506 §3).
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CODE = ROOT / "openbao"
POLICIES = CODE / "policies"
ROLES_YML = CODE / "roles.yml"
INDEX = ROOT / "schemas" / "openbao" / "index.yml"

KV_MOUNTS = {"inventory", "secrets"}
CAPS = {"create", "read", "update", "delete", "list", "sudo", "deny", "patch"}
# KV 밖(sys/·auth/) 경로를 가질 수 있는 정책.
NON_KV_POLICIES = {"applier", "periodic-check"}
# list 권한을 가질 수 있는 정책(기계는 periodic_check, 에이전트 세션은 metadata 한정).
LIST_POLICIES = {"periodic-check", "operator", "agent-session"}
# list 예외: ledger-connect가 이 경로 한 개에 한해 list만 갖는다(Asset 스냅샷이 호스트 이름 목록을 나열, 값은 안 열린다).
# LIST 요청의 ACL 경로는 끝에 /가 붙으므로 정책 경로도 /로 끝난다(periodic-check의 secret-id/와 같은 이유).
LIST_EXCEPTIONS = {("ledger-connect", "inventory/metadata/assets/")}
SERVER_FAMILIES = {"provision", "host_agents", "host_audit", "ledger"}
ALL_FAMILIES = {
    "provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit", "network_backup",
    "ledger", "periodic_check", "agent_session",
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

def _roles_yml():
    return yaml.safe_load(ROLES_YML.read_text(encoding="utf-8"))


def _role_policies():
    """roles.yml의 families에서 계열별 정책 목록을 읽는다. (계열 -> 정책 목록, roles.yml 본문 텍스트)."""
    text = ROLES_YML.read_text(encoding="utf-8")
    fam = {name: list(spec["policies"]) for name, spec in yaml.safe_load(text)["families"].items()}
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
        if (name, path) in LIST_EXCEPTIONS:
            assert caps == ["list"], (name, path, caps)
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
    }.items():
        assert readable_patterns([name]) == {doc}, name


def test_ledger_secrets_reads_only_gws_key_and_bot_token_not_login_or_personal_token():
    # 원장 저장소(Spec #630): GWS 디렉터리 읽기 키와 봇 쓰기 토큰만. 봇 로그인 문서와 개인 읽기 토큰 문서는 스키마 대조용 전체 읽기인 periodic_check와 operator를 제외한 계열이 읽지 못한다.
    assert readable_patterns(["ledger-secrets"]) == {
        "secrets/services/gws/directory_read", "secrets/services/forgejo/idc_access_bot"}
    fam, _ = _role_policies()
    # periodic_check는 스키마 대조용 전체 읽기라 제외한다(periodic-check.hcl 주석).
    readable_by_any = readable_patterns([n for f, names in fam.items() if f != "periodic_check" for n in names])
    forgejo = {p for p in readable_by_any if p.startswith("secrets/services/forgejo/")}
    assert forgejo == {"secrets/services/forgejo/idc_access_bot"}
    assert "connect" not in fam["ledger"]


def test_ledger_connect_is_read_only_key_access_without_login_credentials():
    # Spec #630 / #645: Asset·Endpoint·Automation Identity 키만. 로그인 Credential·operators는 없다. 쓰기도 없고 list는 호스트 목록 한 경로뿐이다.
    assert readable_patterns(["ledger-connect"]) == ASSETS | SSH
    assert all(caps == ["read"] for p, caps in policy("ledger-connect") if p != "inventory/metadata/assets/")
    fam, _ = _role_policies()
    got = readable_patterns(fam["ledger"])
    assert not (got & CRED), "ledger가 secrets/assets credentials를 읽는다"
    assert not (got & OPERATORS)


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
            if (name, path) in LIST_EXCEPTIONS:
                continue
            assert "list" not in caps, f"{name}: {path}"


def test_ledger_connect_list_exception_is_exactly_one_path_and_ledger_lists_nothing_else():
    entries = dict(policy("ledger-connect"))
    assert entries["inventory/metadata/assets/"] == ["list"]
    assert {p for p, c in entries.items() if "list" in c} == {"inventory/metadata/assets/"}
    fam, _ = _role_policies()
    listing = {(n, p) for n in fam["ledger"] for p, c in policy(n) if "list" in c}
    assert listing == LIST_EXCEPTIONS


# ---- 계열 x 경로 매트릭스(#506 §3) ------------------------------------------------------------------------------------

COMMON = {
    "inventory/services/openobserve", "inventory/services/rustfs",
    "inventory/services/semaphore", "inventory/services/funa", "inventory/config/common",
}
ASSETS = {"inventory/assets/+", "inventory/assets/+/endpoints"}
CRED = {"secrets/assets/+/credentials/+"}
SSH = {"secrets/automation/ssh"}
OPERATORS = {"inventory/operators/+"}   # connect 묶음: 관리 계정 공개키(lookup openbao_host_connection)
AGENTS = {"secrets/assets/+/agents", "inventory/assets/+"}   # asset-agents 정책: 에이전트 비밀과 Asset 문서 한 개(버킷 덮어쓰기)
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
                                                  "inventory/config/host_audit",
                                                  "secrets/services/openobserve/readonly",  # Log Review Report 조회(#558)
                                                  "inventory/config/log_review"},  # Log Review 기준 목록(#560)
    "network_backup": COMMON | ASSETS | CRED | {"secrets/services/alert/notify"},
    # 원장 계열(Spec #630): 알림, GWS 키·봇 토큰. 쓰기 권한 없음. 서버 접속은 ledger-connect(로그인 Credential 제외, #645).
    "ledger": COMMON | ASSETS | SSH | {"secrets/services/alert/notify"}
    | {"secrets/services/gws/directory_read", "secrets/services/forgejo/idc_access_bot"},
}


def test_there_are_exactly_the_declared_semaphore_family_approles():
    fam, _ = _role_policies()
    roles = set(fam)
    assert roles == ALL_FAMILIES


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


def test_host_audit_is_union_of_provision_host_agents_and_its_own_paths():
    fam, _ = _role_policies()
    own = {"rustfs-audit-reports", "alert-notify", "config-host-audit", "openobserve-readonly"}
    assert set(fam["host_audit"]) == set(fam["provision"]) | set(fam["host_agents"]) | own
    assert len(fam["host_audit"]) == len(set(fam["host_audit"]))


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
    # 개인정보·Log Review 기준 목록 문서는 deny(#504 단일 원본은 그대로, 읽기만 막는다). 이 둘만 deny이고 나머지는 read다.
    assert ag["inventory/data/config/host_audit"] == ["deny"]
    assert ag["inventory/data/config/log_review"] == ["deny"]
    assert {p for p, c in ag.items() if "deny" in c} == {"inventory/data/config/host_audit", "inventory/data/config/log_review"}
    assert set(ag["secrets/metadata/*"]) == {"read", "list"}
    assert set(ag["inventory/metadata/*"]) == {"read", "list"}      # AGENTS.md: 에이전트 세션은 inventory/를 읽는다(문서 목록 포함)
    assert not any(p.startswith("secrets/data") for p in ag)
    assert not any(p.startswith("inventory/") and ({"create", "update", "delete", "patch"} & set(c)) for p, c in ag.items())
    denied = {"inventory/config/host_audit", "inventory/config/log_review"}
    assert readable_patterns(["agent-session"]) - denied == {p for p in index_patterns() if p.startswith("inventory/")} - denied


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

def test_semaphore_approles_have_ttls_and_cidr_binding_from_environment():
    data = _roles_yml()
    for name, spec in data["families"].items():
        assert spec["token_max_ttl"] >= 3600, name
        assert spec.get("token_ttl", 1800) == 1800, name
        if name != "agent_session":
            assert spec.get("secret_id_ttl", 15552000) == 15552000, name   # 180일
            assert spec.get("cidrs", "runner") == "runner", name
    assert data["families"]["agent_session"]["cidrs"] == "agent_session"
    # CIDR 값은 코드에 직접 박히지 않는다(환경변수로 받는다).
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?\b", ROLES_YML.read_text(encoding="utf-8"))


def test_agent_session_secret_id_is_24h():
    assert _roles_yml()["families"]["agent_session"]["secret_id_ttl"] == 86400


def test_operator_policy_is_attached_to_userpass_users():
    assert "operator" in POLICY_NAMES
    assert _roles_yml()["operator"]["policies"] == ["operator"]


def test_index_matches_documented_operator_list_decision():
    adr = (ROOT / "docs" / "adr" / "0014-openbao-storage-structure-and-access-policy.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "runbooks" / "openbao-operations.md").read_text(encoding="utf-8")
    assert "list 포함" in adr
    assert "list 포함" in runbook


def test_the_applier_policy_says_plainly_that_it_is_effectively_admin_and_the_deny_is_only_a_guardrail():
    text = (POLICIES / "applier.hcl").read_text(encoding="utf-8")
    assert "사실상 관리자" in text and "가드레일" in text and "보안 경계가 아니라" in text
    # 정책을 쓸 수 있는 한 deny는 지울 수 있다: 이 전제가 바뀌면(정책 쓰기를 막으면) 위 문구를 다시 검토한다.
    assert any(p == "sys/policies/acl/*" and "update" in caps for p, caps in policy("applier"))


def test_periodic_check_can_list_secret_id_accessors_with_the_trailing_slash_path():
    """LIST 요청의 ACL 경로는 끝에 /가 붙는다. `.../secret-id`만 있으면 role/*의 read에 걸려 목록이 403이다(실서버 확인)."""
    paths = dict(policy("periodic-check"))
    assert paths.get("auth/approle/role/+/secret-id/") == ["list"]
