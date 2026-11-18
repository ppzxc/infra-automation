"""호스트 하나의 접속 해석 묶음 lookup (Spec #511 / Ticket-12, #523).

Asset 문서, 관리·부트스트랩 연결, 관리 계정 목록을 한 번의 읽기 객체로 만든다(`openbao_connection.host_connections`).
`resolve_connection.yml`이 호스트당 한 번 부른다. 결과에 비밀이 들어 있으니 호출하는 태스크는 no_log여야 한다.
"""
from __future__ import annotations

import os
import sys

from ansible.plugins.lookup import LookupBase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openbao_connection import ConnectionError_, host_connections, preference_list  # noqa: E402
from _openbao_reader import Reader, display  # noqa: E402

DOCUMENTATION = r"""
name: openbao_host_connection
short_description: 호스트의 Asset 문서·관리 연결·부트스트랩 연결·관리 계정 목록
description:
  - 결과 맵(C(asset), C(admin_credential), C(bootstrap_credential), C(admin), C(bootstrap), C(admin_accounts))은 비밀을 담는다.
    호출하는 태스크는 no_log여야 한다. 자세한 규칙은 docs/openbao_integration.md 4절.
options:
  _terms:
    description: Asset 관리번호(인벤토리 호스트명).
    required: true
  preference:
    description: Endpoint 이름의 선호 순서 목록.
    type: list
    required: true
  accounts:
    description: false면 관리 계정 목록(Operator 공개키)을 읽지 않는다(accounts를 쓰지 않는 소비자용).
    type: bool
    default: true
  requires_access:
    description: true면 Asset 문서에 access 절이 없을 때 [ACCESS-MISSING]으로 실패한다(프로비저닝 대상).
    type: bool
    default: false
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        reader = Reader(variables or {}, self._templar)
        preference = kwargs.get("preference")
        if not preference:
            raise ConnectionError_("preference(Endpoint 선호 순서 목록)가 필요합니다")
        requires = bool(kwargs.get("requires_access", False))
        with_accounts = bool(kwargs.get("accounts", True))
        try:
            return [host_connections(reader.read, str(t), preference_list(preference), requires, with_accounts) for t in terms]
        except ConnectionError_ as exc:
            display.error(str(exc))      # no_log 태스크에서도 실패 사유(문서 경로·키 이름, 비밀 없음)가 보인다
            raise
