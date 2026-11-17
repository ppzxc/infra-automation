"""공용 OpenBao 읽기 지점 (Spec #511 / Ticket-12, #523).

네임스페이스·마운트·인증·우회(`openbao_fixture`)를 정하는 곳은 이 파일 하나다. 역할·플레이북은 경로 접두사나 마운트를
따로 갖지 않고 `lookup('openbao_doc', '<마운트>/<문서 경로>')`만 쓴다.

* 네임스페이스는 `infra`, 마운트는 `inventory`·`secrets` 둘뿐이다. 이를 바꾸는 변수·환경 변수는 없다.
* 문서가 없으면(404) 실패한다. `required=False`를 명시한 호출만 `{}`를 돌려받는다. 403·연결 오류는 항상 실패한다.
* 인증은 AppRole뿐이다. 변수 `_vault_token`(플레이 첫머리에서 `@token`으로 한 번 받아 둔 토큰)이 있으면 그것을 쓰고, 없으면
  `vault_role_id`/`vault_secret_id`(또는 환경 변수 `VAULT_ROLE_ID`/`VAULT_SECRET_ID`)로 로그인한다. `VAULT_TOKEN`·`vault_token`
  같은 평문 토큰 경로는 없다(운영자 토큰은 scripts/ 쪽 도구만 쓴다). 주소는 `vault_addr`/`VAULT_ADDR`.
* https는 인증서를 검증한다. 끄려면 변수 `vault_validate_certs: false`(또는 `VAULT_SKIP_VERIFY=true`), 사설 CA는
  `vault_cacert`/`VAULT_CACERT`(CA 파일 경로)로 준다.
* 로그인은 프로세스 안에서만 캐시한다. Ansible은 호스트·태스크마다 프로세스를 나누므로 `@token`을 한 번 받아 `_vault_token`으로
  넘기지 않는 읽기는 그 호스트·태스크마다 로그인한다. 토큰 TTL은 30분이라 오래 쓸 토큰은 일찍 받아 두지 않는다.
* 특수 용어 `@token`은 위 순서로 얻은 토큰만 돌려준다(플레이당 한 번 로그인해서 변수로 넘길 때 쓴다).
* `openbao_fixture`(키 `<마운트>/<문서 경로>`, 값 문서)가 정의돼 있으면 네트워크 없이 그 안에서만 답한다(molecule용).
  이 변수는 여기서만 처리한다.
* 오류 메시지에는 문서 경로와 상태 코드만 넣는다. 응답 본문은 비밀을 담을 수 있어 넣지 않는다.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

DOCUMENTATION = r"""
name: openbao_doc
short_description: 공용 OpenBao 읽기 지점(KV v2, 네임스페이스 infra)
description:
  - C(<마운트>/<문서 경로>) 문서를 읽어 데이터 맵을 돌려준다. 자세한 규칙은 docs/openbao_integration.md 5·6절.
options:
  _terms:
    description: 문서 경로(C(inventory/assets/ns0001)) 또는 C(@token).
    required: true
"""

NAMESPACE = "infra"
MOUNTS = ("inventory", "secrets")
DEFAULT_ADDR = "http://openbao:8200"
TIMEOUT = 5

_LOGIN_CACHE: dict = {}


class OpenBaoError(AnsibleError):
    pass


class _NotFound(Exception):
    pass


def _first(variables, names, env_names=()):
    for n in names:
        v = variables.get(n)
        if v not in (None, ""):
            return str(v)
    for n in env_names:
        v = os.environ.get(n)
        if v:
            return v
    return ""


class Reader:
    """한 번의 lookup 호출이 쓰는 읽기 객체. `variables`는 lookup이 받은 호스트 변수다."""

    def __init__(self, variables, templar=None):
        self.variables = variables
        fixture = variables.get("openbao_fixture")
        if isinstance(fixture, str) and templar is not None:
            fixture = templar.template(fixture)
        self.fixture = fixture if isinstance(fixture, dict) else None
        self.addr = (_first(variables, ["vault_addr"], ["VAULT_ADDR"]) or DEFAULT_ADDR).rstrip("/")
        validate = variables.get("vault_validate_certs")
        if validate in (None, ""):
            validate = "false" if os.environ.get("VAULT_SKIP_VERIFY", "").lower() in ("true", "1", "yes") else "true"
        self.verify = str(validate).lower() in ("true", "1", "yes")
        self.cacert = _first(variables, ["vault_cacert"], ["VAULT_CACERT"])

    # --- 인증 --------------------------------------------------------------
    def token(self):
        if self.fixture is not None:
            return ""
        v = self.variables
        tok = _first(v, ["_vault_token"])
        if tok:
            return tok
        role = _first(v, ["vault_role_id"], ["VAULT_ROLE_ID"])
        secret = _first(v, ["vault_secret_id"], ["VAULT_SECRET_ID"])
        if role and secret:
            return self._login(role, secret)
        raise OpenBaoError("OpenBao 인증 정보가 없습니다(AppRole: VAULT_ROLE_ID와 VAULT_SECRET_ID)")

    def _login(self, role, secret):
        key = (self.addr, role, secret)
        if key not in _LOGIN_CACHE:
            body = json.dumps({"role_id": role, "secret_id": secret}).encode()
            req = urllib.request.Request(self.addr + "/v1/auth/approle/login", data=body, method="POST",
                                         headers={"X-Vault-Namespace": NAMESPACE, "Content-Type": "application/json"})
            try:
                data = self._send(req, "AppRole 로그인")
            except _NotFound:
                raise OpenBaoError("AppRole 로그인 경로가 없습니다") from None
            tok = (data.get("auth") or {}).get("client_token")
            if not tok:
                raise OpenBaoError("AppRole 로그인 응답에 토큰이 없습니다")
            _LOGIN_CACHE[key] = tok
        return _LOGIN_CACHE[key]

    # --- 읽기 --------------------------------------------------------------
    def read(self, doc, required=True):
        mount, _, rest = doc.partition("/")
        if mount not in MOUNTS or not rest:
            raise OpenBaoError("알 수 없는 문서 경로입니다: %s (마운트는 %s)" % (doc, ", ".join(MOUNTS)))
        if self.fixture is not None:
            if doc in self.fixture:
                return self.fixture[doc]
            return self._missing(doc, required)
        req = urllib.request.Request("%s/v1/%s/data/%s" % (self.addr, mount, rest),
                                     headers={"X-Vault-Token": self.token(), "X-Vault-Namespace": NAMESPACE})
        try:
            data = self._send(req, doc)
        except _NotFound:
            return self._missing(doc, required)
        return (data.get("data") or {}).get("data") or {}

    @staticmethod
    def _missing(doc, required):
        if required:
            raise OpenBaoError("필수 문서가 없습니다: %s" % doc)
        return {}

    def _send(self, req, what):
        ctx = None
        if self.addr.startswith("https"):
            if not self.verify:
                ctx = ssl._create_unverified_context()  # noqa: S323 - 변수·환경 변수로 명시했을 때만
            elif self.cacert:
                ctx = ssl.create_default_context(cafile=self.cacert)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise _NotFound() from None
            raise OpenBaoError("OpenBao 조회 실패: %s (HTTP %s)" % (what, exc.code)) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise OpenBaoError("OpenBao 접속 실패: %s (%s)" % (what, type(exc).__name__)) from None


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        reader = Reader(variables or {}, self._templar)
        required = kwargs.get("required", True)
        out = []
        for term in terms:
            out.append(reader.token() if term == "@token" else reader.read(str(term), required))
        return out
