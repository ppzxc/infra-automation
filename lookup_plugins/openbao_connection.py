"""접속 해석 (Spec #511 / Ticket-12, #523): Endpoint 선택, 로그인·승격 규칙, via 경유 체인.

결정은 `resolve(read, asset, preference, credential=None)` 순수 함수에 있다. `read(doc, required=True)`는 문서를 돌려주는
함수이고, 이 lookup은 공용 읽기 지점(`openbao_doc.Reader`)을 꽂아 쓴다. 규칙(#502, #504):

* 선호 순서 목록에서 Asset에 등록된 첫 Endpoint를 고른다. 접속 성공 여부는 보지 않는다(실패해도 다른 Endpoint로 넘어가지 않음).
* 로그인: Endpoint에 `identity: automation`이 있고 Credential이 바뀌지 않았으면 Automation Identity 키로 로그인하고
  Credential `password`는 승격에만 쓴다. 아니면 그 Credential 자신의 비밀로 로그인한다.
* `credential=`로 이름을 넘기면(access 절의 admin·bootstrap) Endpoint 기본 Credential 대신 쓰고, 기본과 다르면 자기 비밀로 로그인한다.
* `via: <ns>/<endpoint>`는 여러 단을 따라가며 경유지 Endpoint의 기본 Credential·identity를 쓴다. 순환·없는 참조는 실패다.
* `become.method`는 sudo·su·enable. 비밀번호는 `become.credential`의 비밀번호이고, 없으면 로그인 Credential의 `password`다.
"""
from __future__ import annotations

import os
import sys

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openbao_doc import Reader  # noqa: E402

DOCUMENTATION = r"""
name: openbao_connection
short_description: Asset 접속 해석(Endpoint 선택, 로그인, 승격, via 체인)
description:
  - 결과 맵은 비밀을 담는다. 호출하는 태스크는 no_log여야 한다. 자세한 규칙은 docs/openbao_integration.md 4절.
options:
  _terms:
    description: Asset 관리번호(인벤토리 호스트명).
    required: true
  preference:
    description: Endpoint 이름의 선호 순서 목록.
    type: list
    required: true
  credential:
    description: 기본 대신 쓸 Credential 이름(access 절의 admin·bootstrap).
    type: str
"""


class ConnectionError_(AnsibleError):  # noqa: N801
    pass


# 이 파일의 lookup이 읽는 문서 패턴(schemas/openbao/index.yml의 패턴). 정책 계약 테스트가 계열 AppRole 정책과 대조하고,
# 코드의 read() 호출과 이 표가 같은지도 본다. 새 읽기를 더하면 여기에도 적는다.
CONNECTION_READS = ("inventory/assets/+/endpoints", "secrets/assets/+/credentials/+")
IDENTITY_READS = ("secrets/automation/ssh",)                 # Endpoint가 identity일 때만 읽는다(서버 계열)
ADMIN_ACCOUNTS_READS = ("inventory/assets/+", "inventory/operators/+")


def preference_list(value):
    """선호 순서 입력을 목록으로. 쉼표 문자열(Semaphore 변수)도 받는다."""
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    if not isinstance(value, (list, tuple)):
        raise ConnectionError_("preference는 Endpoint 이름 목록이어야 합니다")
    names = [str(v) for v in value if str(v)]
    if not names:
        raise ConnectionError_("preference(Endpoint 선호 순서 목록)가 비어 있습니다")
    return names


def _need(doc, key, where):
    """문서의 필수 키. 없으면 어느 문서인지 밝히고(값은 밝히지 않고) 실패한다."""
    if doc.get(key) in (None, ""):
        raise ConnectionError_("%s에 %s가 없습니다" % (where, key))
    return doc[key]


def _endpoint_fields(ep, where):
    """Endpoint의 필수 키 묶음(protocol·address·port)."""
    return {k: _need(ep, k, where) for k in ("protocol", "address", "port")}


def _asset_endpoints(read, asset):
    return read("inventory/assets/%s/endpoints" % asset)


def _select_endpoint(endpoints, asset, preference):
    name = next((p for p in preference if p in endpoints), None)
    if name is None:
        raise ConnectionError_("%s에 선호 순서 %s의 Endpoint가 하나도 등록돼 있지 않습니다" % (asset, list(preference)))
    return name, endpoints[name]


def _credential(read, asset, name):
    return read("secrets/assets/%s/credentials/%s" % (asset, name))


def _login(read, asset, endpoint, credential, overridden):
    where = "Credential %s/%s" % (asset, credential)
    doc = _credential(read, asset, credential)
    kind = doc.get("type")
    if endpoint.get("identity") and not overridden:
        username = _need(doc, "username", where)
        key = read("secrets/automation/ssh")
        out = {"mode": "identity", "username": username, "private_key": _need(key, "private_key", "secrets/automation/ssh")}
        if key.get("passphrase"):
            out["passphrase"] = key["passphrase"]
        return out
    if kind == "password":
        out = {"mode": "password", "password": _need(doc, "password", where)}
        if doc.get("username"):
            out["username"] = doc["username"]
    elif kind == "ssh_key":
        out = {"mode": "key", "username": _need(doc, "username", where), "private_key": _need(doc, "private_key", where)}
        if doc.get("passphrase"):
            out["passphrase"] = doc["passphrase"]
    elif kind == "api_token":
        out = {"mode": "token", "token": _need(doc, "token", where)}
    else:
        raise ConnectionError_("%s의 type을 알 수 없습니다" % where)
    if endpoint["protocol"] == "ssh":
        _need(out, "username", where + "(ssh 로그인)")      # 계정 없이 접속하면 컨트롤러 사용자로 시도하게 된다
    return out


def _become(read, asset, endpoint, login_credential):
    spec = endpoint.get("become")
    if not spec:
        return {}
    name = spec.get("credential") or login_credential
    password = _credential(read, asset, name).get("password")
    _need(spec, "method", "%s/%s의 become" % (asset, login_credential))
    if spec["method"] == "su" and not password:
        raise ConnectionError_("su 승격에는 비밀번호가 필요합니다(%s/%s)" % (asset, name))
    return {"method": spec["method"], "password": password}


def _via_chain(read, via):
    hops, seen = [], set()
    while via:
        if via in seen:
            raise ConnectionError_("via 순환입니다: %s" % via)
        seen.add(via)
        asset, _, name = via.partition("/")
        endpoints = read("inventory/assets/%s/endpoints" % asset, True) if asset else {}
        if name not in endpoints:
            raise ConnectionError_("via 대상 Endpoint가 없습니다: %s" % via)
        ep = endpoints[name]
        where = "%s/endpoints의 %s" % (asset, name)
        cred = _need(ep, "credential", where)
        hops.append({"asset": asset, "endpoint": name, **_endpoint_fields(ep, where), "credential": cred,
                     "login": _login(read, asset, ep, cred, False)})
        via = ep.get("via")
    hops.reverse()          # 컨트롤러에서 가까운 경유지가 먼저
    return hops


def resolve(read, asset, preference, credential=None):
    name, ep = _select_endpoint(_asset_endpoints(read, asset), asset, preference)
    where = "%s/endpoints의 %s" % (asset, name)
    default_cred = _need(ep, "credential", where)
    cred = credential or default_cred
    overridden = cred != default_cred
    return {
        "asset": asset, "endpoint": name, **_endpoint_fields(ep, where), "credential": cred,
        "login": _login(read, asset, ep, cred, overridden),
        "become": _become(read, asset, ep, cred),
        "password_auth_exception": ep["protocol"] == "ssh" and not ep.get("identity"),
        "via": _via_chain(read, ep.get("via")),
    }


def admin_accounts(read, asset, preference):
    """`access.admin_credentials`를 common 역할의 `accounts` 항목으로 바꾼다.

    계정 이름은 Credential의 username이다. 공개키는 Endpoint 기본 Credential이 identity를 쓰면 그 계정(자동화 계정)은 Automation
    Identity의 `public_key`, 그 밖의 계정은 `inventory/operators/<username>`의 `public_keys`·`revoked_keys`다.
    """
    access = read("inventory/assets/%s" % asset).get("access") or {}
    _, default = _select_endpoint(_asset_endpoints(read, asset), asset, preference)
    out = []
    for cred_name in access.get("admin_credentials") or []:
        username = _credential(read, asset, cred_name).get("username")
        if not username:
            raise ConnectionError_("관리 계정 Credential %s/%s에 username이 없습니다" % (asset, cred_name))
        if default.get("identity") and default.get("credential") == cred_name:
            key = read("secrets/automation/ssh").get("public_key")
            if not key:
                raise ConnectionError_("자동화 계정에는 secrets/automation/ssh의 public_key가 필요합니다")
            keys, revoked = [key], []
        else:
            op = read("inventory/operators/%s" % username)
            keys, revoked = list(op.get("public_keys") or []), list(op.get("revoked_keys") or [])
        out.append({"name": username, "tier": "admin", "comment": "Administrator provisioned via OpenBao",
                    "shell": "/bin/bash", "keys": keys, "revoked_keys": revoked})
    return out


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        reader = Reader(variables or {}, self._templar)
        preference = kwargs.get("preference")
        if not preference:
            raise ConnectionError_("preference(Endpoint 선호 순서 목록)가 필요합니다")
        return [resolve(reader.read, str(t), preference_list(preference), kwargs.get("credential")) for t in terms]
