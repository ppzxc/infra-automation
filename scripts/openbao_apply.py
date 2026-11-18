#!/usr/bin/env python3
"""OpenBao 정책·AppRole·마운트 적용 도구 (Spec #511, #505 변경: OpenTofu 대신 이 스크립트).

선언 원본은 `openbao/roles.yml`과 `openbao/policies/*.hcl`이다. 서버의 현재 상태를 읽어 코드와 비교하고 차이만 다룬다.

하위 명령:
  plan    차이만 보고한다(쓰기 없음). 종료 코드 2면 차이 있음, 0이면 없음.
  apply   차이만 쓴다. 정책·AppRole 설정·인증 마운트·userpass 운영자 사용자·(없을 때만) 마운트.
          secret_id는 만들지 않는다(수동 response-wrapping 런북). 코드에 없는 객체는 지우지 않고 보고만 한다.
          마운트는 없을 때만 만들고 삭제·tune하지 않는다.

접속·입력은 환경변수다(저장소에 쓰지 않는다):
  VAULT_ADDR                          OpenBao 주소(필수). 네임스페이스는 roles.yml의 namespace(infra)다.
  VAULT_ROLE_ID / VAULT_SECRET_ID     applier AppRole 로그인(로그인 토큰을 그대로 쓴다: applier에는 auth/token/create가 없다)
  VAULT_TOKEN                         bootstrap용 토큰(AppRole 변수가 없을 때만)
  OPENBAO_RUNNER_CIDRS                러너 출발지 CIDR 쉼표 목록(필수, 비면 거부)
  OPENBAO_AGENT_SESSION_CIDRS         에이전트 세션 출발지 CIDR 쉼표 목록(필수, 비면 거부)
  OPENBAO_OPERATOR_PASSWORD_HASHES    운영자 이름 -> bcrypt 해시 JSON 맵(선택, 비면 운영자 사용자는 다루지 않는다)

운영자 비밀번호 해시는 서버 값과 비교하지 않는다(서버에서 바꾼 비밀번호를 드리프트로 보지 않는다). 사용자가 없거나 연결 정책이
다를 때, 또는 `apply --rotate-operators`일 때만 해시를 쓴다.

출력은 `종류<TAB>이름<TAB>동작`뿐이다. 값(CIDR·해시·토큰·정책 본문)은 어디에도 내지 않는다.
종료 코드: 0 정상(plan은 차이 없음), 1 서버·실행 오류, 2 plan에 차이 있음 또는 사용법·입력 오류.
"""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "lookup_plugins"))
from openbao_check import BaoError, Client  # noqa: E402
from openbao_code import DEFAULT_CODE_DIR, load_code  # noqa: E402

BCRYPT = re.compile(r"\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}")
BUILTIN_POLICIES = frozenset({"default", "root"})
ROLE_SET_KEYS = ("secret_id_bound_cidrs", "token_bound_cidrs", "token_policies")   # 순서 없는 목록
ROLE_VALUE_KEYS = ("secret_id_ttl", "secret_id_num_uses", "token_ttl", "token_max_ttl")


class InputError(Exception):
    """환경변수 입력 오류. 메시지에 값을 넣지 않는다."""


# ---- 입력 ---------------------------------------------------------------------------------------------------------

def _cidrs(environ, name):
    items = [c.strip() for c in (environ.get(name) or "").split(",") if c.strip()]
    if not items:
        raise InputError("%s가 비어 있다(쉼표로 구분한 CIDR 목록이 필요하다)" % name)
    return items


def read_inputs(environ):
    """({cidr 출처: CIDR 목록}, {운영자: 해시}). 잘못되면 InputError(값은 메시지에 없다)."""
    cidrs = {"runner": _cidrs(environ, "OPENBAO_RUNNER_CIDRS"),
             "agent_session": _cidrs(environ, "OPENBAO_AGENT_SESSION_CIDRS")}
    raw = (environ.get("OPENBAO_OPERATOR_PASSWORD_HASHES") or "").strip()
    hashes = {}
    if raw:
        try:
            hashes = json.loads(raw)
        except ValueError:
            raise InputError("OPENBAO_OPERATOR_PASSWORD_HASHES가 JSON이 아니다") from None
        if not isinstance(hashes, dict) or not all(isinstance(k, str) and k and isinstance(v, str)
                                                   for k, v in hashes.items()):
            raise InputError("OPENBAO_OPERATOR_PASSWORD_HASHES는 {이름: bcrypt 해시} 맵이어야 한다")
        for name, value in hashes.items():
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                raise InputError("운영자 이름에 쓸 수 없는 문자가 있다")
            if not BCRYPT.fullmatch(value):
                raise InputError("운영자 %s의 값이 bcrypt 해시가 아니다(평문 비밀번호를 넣지 않는다)" % name)
    return cidrs, hashes


def desired_roles(code, cidrs):
    """코드의 role 설정을 서버에 쓸 본문으로 바꾼다(CIDR 출처를 환경변수 값으로 풀어서)."""
    out = {}
    for name, role in code["roles"].items():
        body = {k: v for k, v in role.items() if k != "cidrs"}
        body["secret_id_bound_cidrs"] = list(cidrs[role["cidrs"]])
        body["token_bound_cidrs"] = list(cidrs[role["cidrs"]])
        out[name] = body
    return out


# ---- 서버 읽기 ----------------------------------------------------------------------------------------------------

def _get(client, path):
    """데이터 본문. 없으면(404) None. 그 밖의 실패는 BaoError."""
    try:
        return client.request("GET", path).get("data") or {}
    except BaoError as exc:
        if exc.status == 404:
            return None
        raise


def _list(client, path):
    try:
        return list(client.request("LIST", path)["data"]["keys"])
    except BaoError as exc:
        if exc.status == 404:
            return []
        raise
    except (KeyError, TypeError):
        raise BaoError(0) from None


def _cidr(value):
    """CIDR 표기를 하나로 맞춘다. 서버는 token_bound_cidrs의 단일 IP를 접두사 없이 돌려준다(접두사 없는 단일 IP와 /32 표기는 같다)."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def _norm(key, value):
    if key in ("secret_id_bound_cidrs", "token_bound_cidrs"):
        return sorted(_cidr(v) for v in (value or []))
    if key in ROLE_SET_KEYS:
        return sorted(value or [])
    return value


def role_drift(want, have):
    """다른 설정 키 이름 목록(값은 내지 않는다). 서버에 role이 없으면 None이 아니라 호출자가 처리한다."""
    keys = [k for k in (*ROLE_SET_KEYS, *ROLE_VALUE_KEYS) if k in want]
    return [k for k in keys if _norm(k, want[k]) != _norm(k, have.get(k))]


def compute_plan(client, code, roles, hashes):
    """([(종류, 이름, 동작, 쓸 정보)], [(종류, 이름)] 코드에 없는 객체). 읽기만 한다."""
    changes = []
    mounts = client.request("GET", "sys/mounts").get("data") or {}
    for name in code["mounts"]:
        if name + "/" not in mounts:
            changes.append(("mount", name, "create", None))
    auth = client.request("GET", "sys/auth").get("data") or {}
    for name in code["auth_mounts"]:
        if name + "/" not in auth:
            changes.append(("auth", name, "create", None))
    for name, text in code["policies"].items():
        have = _get(client, "sys/policies/acl/" + name)
        if have is None:
            changes.append(("policy", name, "create", None))
        elif (have.get("policy") or "").strip() != text.strip():
            changes.append(("policy", name, "update", None))
    for name, want in roles.items():
        have = _get(client, "auth/approle/role/" + name)
        if have is None:
            changes.append(("approle", name, "create", None))
            continue
        drift = role_drift(want, have)
        if drift:
            changes.append(("approle", name, "update " + ",".join(drift), None))
    for name in hashes:
        have = _get(client, "auth/userpass/users/" + name)
        if have is None:
            changes.append(("operator", name, "create", None))
        elif sorted(have.get("token_policies") or []) != sorted(code["operator_policies"]):
            changes.append(("operator", name, "update token_policies", None))
    extra = [("policy", n) for n in _list(client, "sys/policies/acl")
             if n not in code["policies"] and n not in BUILTIN_POLICIES]
    extra += [("approle", n) for n in _list(client, "auth/approle/role") if n not in roles]
    return changes, extra


# ---- 쓰기 ---------------------------------------------------------------------------------------------------------

def apply_changes(client, code, roles, hashes, changes, rotate_operators=False):
    """계획의 차이만 쓴다. 삭제·tune·secret_id 발급은 하지 않는다. 쓴 (종류, 이름, 동작) 목록."""
    done = []
    for kind, name, action, _ in changes:
        if kind == "mount":
            spec = code["mounts"][name]
            body = {"type": spec["type"], "description": spec.get("description", ""),
                    "options": {"version": str(spec["version"])}}
            client.request("POST", "sys/mounts/" + name, body)
        elif kind == "auth":
            spec = code["auth_mounts"][name]
            client.request("POST", "sys/auth/" + name, {"type": spec["type"], "description": spec.get("description", "")})
        elif kind == "policy":
            client.request("POST", "sys/policies/acl/" + name, {"policy": code["policies"][name]})
        elif kind == "approle":
            client.request("POST", "auth/approle/role/" + name, roles[name])
        elif kind == "operator":
            _write_operator(client, code, name, hashes[name])
        done.append((kind, name, action))
    if rotate_operators:
        written = {n for k, n, _ in done if k == "operator"}
        for name, value in hashes.items():
            if name not in written:
                _write_operator(client, code, name, value)
                done.append(("operator", name, "rotate"))
    return done


def _write_operator(client, code, name, password_hash):
    client.request("POST", "auth/userpass/users/" + name,
                   {"password_hash": password_hash, "token_policies": list(code["operator_policies"])})


# ---- 진입점 -------------------------------------------------------------------------------------------------------

def _login(environ, namespace):
    addr = environ.get("VAULT_ADDR")
    if not addr:
        raise InputError("VAULT_ADDR가 필요하다")
    client = Client(addr, namespace)
    if environ.get("VAULT_ROLE_ID") and environ.get("VAULT_SECRET_ID"):
        client.login_approle(environ["VAULT_ROLE_ID"], environ["VAULT_SECRET_ID"])   # 로그인 토큰을 그대로 쓴다(자식 토큰을 만들지 않는다)
    elif environ.get("VAULT_TOKEN"):
        client.token = environ["VAULT_TOKEN"]
    else:
        raise InputError("VAULT_ROLE_ID와 VAULT_SECRET_ID(또는 bootstrap용 VAULT_TOKEN)가 필요하다")
    return client


def run(command, environ, code_dir=DEFAULT_CODE_DIR, rotate_operators=False, out=None):
    out = out or sys.stdout
    try:
        code = load_code(code_dir)
    except OSError:
        print("선언 코드를 읽을 수 없다: %s" % code_dir, file=sys.stderr)
        return 2
    try:
        cidrs, hashes = read_inputs(environ)
        client = _login(environ, code["namespace"])
        roles = desired_roles(code, cidrs)
        changes, extra = compute_plan(client, code, roles, hashes)
        if command == "apply":
            changes = apply_changes(client, code, roles, hashes, changes, rotate_operators)
            changes = [(k, n, a, None) for k, n, a in changes]
    except InputError as exc:
        print("입력 오류: %s" % exc, file=sys.stderr)
        return 2
    except BaoError as exc:   # 상태 코드만 낸다(응답 본문·토큰은 보관하지 않는다)
        print("OpenBao 호출 실패(HTTP %s)" % (exc.status or "연결 오류"), file=sys.stderr)
        return 1
    except (KeyError, TypeError):
        print("OpenBao 응답을 해석하지 못했다", file=sys.stderr)
        return 1
    verb = "적용" if command == "apply" else "차이"
    for kind, name, action, _ in changes:
        print("%s\t%s\t%s" % (kind, name, action), file=out)
    for kind, name in extra:
        print("%s\t%s\t코드에 없음(삭제하지 않는다)" % (kind, name), file=out)
    print("%s %d건, 코드에 없는 객체 %d건" % (verb, len(changes), len(extra)), file=sys.stderr)
    return 2 if (command == "plan" and changes) else 0


def main(argv=None, environ=None):
    import os
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--code-dir", default=str(DEFAULT_CODE_DIR), help="선언 코드 디렉터리(기본: openbao)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="서버와 코드의 차이만 보고(쓰기 없음)")
    p = sub.add_parser("apply", help="차이만 쓴다(삭제·secret_id 발급 없음)")
    p.add_argument("--rotate-operators", action="store_true", help="운영자 비밀번호 해시를 모든 사용자에게 다시 쓴다")
    args = parser.parse_args(argv)
    return run(args.command, os.environ if environ is None else environ, Path(args.code_dir),
               getattr(args, "rotate_operators", False))


if __name__ == "__main__":
    sys.exit(main())
