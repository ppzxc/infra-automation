"""OpenBao 정책·AppRole 선언(`openbao/roles.yml`, `openbao/policies/*.hcl`) 읽기. openbao_apply.py와 openbao_check.py가 같이 쓴다.

구조를 못 읽으면 `OSError`다(호출자가 "전부 미관리"로 보고하지 않고 명확히 실패하게 한다).
"""
from pathlib import Path

import yaml

DEFAULT_CODE_DIR = Path(__file__).resolve().parent.parent / "openbao"
DEFAULT_SECRET_ID_TTL = 15552000   # 180일
DEFAULT_TOKEN_TTL = 1800
CIDR_SOURCES = ("runner", "agent_session")


def load_code(code_dir=DEFAULT_CODE_DIR):
    """{namespace, mounts, auth_mounts, operator_policies, policies{이름: 본문}, roles{이름: 설정}}.

    roles의 설정은 AppRole 쓰기 키(token_policies, secret_id_ttl, secret_id_num_uses(있을 때), token_ttl, token_max_ttl)와
    CIDR 출처 `cidrs`(runner·agent_session)다. applier도 roles에 들어 있다.
    """
    code_dir = Path(code_dir)
    pol_dir = code_dir / "policies"
    try:
        data = yaml.safe_load((code_dir / "roles.yml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise OSError("roles.yml을 읽을 수 없다") from None
    if not pol_dir.is_dir() or not isinstance(data, dict):
        raise OSError("정책 디렉터리 또는 roles.yml 구조를 읽을 수 없다")
    policies = {p.stem: p.read_text(encoding="utf-8") for p in sorted(pol_dir.glob("*.hcl"))}
    try:
        roles = {"applier": _role(data["applier"])}
        for name, fam in data["families"].items():
            roles[name] = _role(fam)
        mounts = {n: dict(m) for n, m in data["mounts"].items()}
        auth_mounts = {n: dict(m) for n, m in data["auth_mounts"].items()}
        out = {"namespace": str(data["namespace"]), "mounts": mounts, "auth_mounts": auth_mounts,
               "operator_policies": list(data["operator"]["policies"]), "policies": policies, "roles": roles}
    except (KeyError, TypeError, AttributeError, ValueError):
        raise OSError("roles.yml 구조가 바뀌었다") from None
    if not (policies and roles and mounts and auth_mounts):
        raise OSError("정책·role·마운트·인증 이름을 읽지 못했다(구조가 바뀌었다)")
    for name, role in roles.items():
        missing = [p for p in role["token_policies"] + out["operator_policies"] if p not in policies]
        if missing:
            raise OSError("role %s가 없는 정책을 가리킨다: %s" % (name, ", ".join(missing)))
        if role["cidrs"] not in CIDR_SOURCES:
            raise OSError("role %s의 cidrs 값이 올바르지 않다" % name)
    return out


def _role(spec):
    role = {
        "token_policies": list(spec["policies"]),
        "secret_id_ttl": int(spec.get("secret_id_ttl", DEFAULT_SECRET_ID_TTL)),
        "token_ttl": int(spec.get("token_ttl", DEFAULT_TOKEN_TTL)),
        "token_max_ttl": int(spec["token_max_ttl"]),
        "cidrs": spec.get("cidrs", "runner"),
    }
    if "secret_id_num_uses" in spec:
        role["secret_id_num_uses"] = int(spec["secret_id_num_uses"])
    return role
