"""공용 OpenBao 읽기 지점 lookup. 규칙과 구현은 `_openbao_reader.py`(한 모듈을 모든 lookup이 나눠 쓴다)에 있다."""
from __future__ import annotations

import os
import sys

from ansible.plugins.lookup import LookupBase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _openbao_reader as core  # noqa: E402
from _openbao_reader import (  # noqa: E402,F401  (시험과 다른 lookup이 이 이름으로 가져온다)
    DEFAULT_ADDR, MOUNTS, NAMESPACE, TIMEOUT, OpenBaoError, Reader, _LOGIN_CACHE, display)

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


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        core.set_quiet(kwargs.pop("quiet", False))     # errors='ignore'·'warn' 호출자는 quiet=true를 함께 준다
        reader = Reader(variables or {}, self._templar)
        required = kwargs.get("required", True)
        out = []
        try:
            for term in terms:
                out.append(reader.token() if term == "@token" else reader.read(str(term), required))
        finally:
            core.set_quiet(False)
        return out
