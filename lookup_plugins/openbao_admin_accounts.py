"""`access.admin_credentials`를 common 역할의 `accounts` 항목 목록으로 바꾸는 lookup (Spec #511 / Ticket-12, #523).

규칙은 `openbao_connection.admin_accounts`에 있다. 결과에 공개키만 있고 개인 비밀은 없다.
"""
from __future__ import annotations

import os
import sys

from ansible.plugins.lookup import LookupBase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from openbao_connection import ConnectionError_, admin_accounts, preference_list  # noqa: E402
from openbao_doc import Reader  # noqa: E402

DOCUMENTATION = r"""
name: openbao_admin_accounts
short_description: Asset 관리 계정 목록(accounts 입력)
description:
  - 자세한 규칙은 docs/openbao_integration.md 4절.
options:
  _terms:
    description: Asset 관리번호.
    required: true
  preference:
    description: Endpoint 이름의 선호 순서 목록(자동화 계정 판별용).
    type: list
    required: true
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        reader = Reader(variables or {}, self._templar)
        preference = kwargs.get("preference")
        if not preference:
            raise ConnectionError_("preference(Endpoint 선호 순서 목록)가 필요합니다")
        return [admin_accounts(reader.read, str(t), preference_list(preference)) for t in terms]
