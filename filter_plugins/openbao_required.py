"""`<역할>_openbao_required` 선언이 읽은 문서에서 채워졌는지 보는 공용 필터 (최종 리뷰 5차 7번).

역할마다 따로 구현돼 있던 "필수 키 충족 검사"(host_agents·openobserve_config·backup·host_audit·github_webhook_watch)를 한 곳으로 모은다.
의미가 실제로 다른 부분은 옵션으로 표현한다:

* `scope`: `required`면 선언을 돌고(읽지 못한 문서도 보고), `docs`면 읽은 문서를 돈다(선언에 없는 문서는 키를 보지 않는다).
* `missing_doc`: 문서가 없을 때 `keys`(그 문서의 필수 키를 모두 보고), `doc`(`<패턴>(문서 없음)` 한 줄), `skip`(건너뜀).
* `blank`: 비었다고 보는 값. `absent`(키가 없을 때만), `none_empty`(None 또는 ''), `blank`(None 또는 공백뿐인 문자열), `falsy`(거짓인 값 전부).
* `skip_plus`: `+`가 든 패턴(호스트마다 읽는 문서)을 건너뛴다. `host`를 주면 `+`를 그 호스트로 바꿔 보고한다.
* `fmt`: 한 줄의 모양. `dot`(`<패턴>.<키>`), `colon`(`<패턴>:<키>`), `colon_space`(`<패턴>: <키>`).

결과에는 문서 경로 패턴과 키 이름만 있고 값은 없다.
"""
from ansible.errors import AnsibleFilterError

_FMT = {"dot": "%s.%s", "colon": "%s:%s", "colon_space": "%s: %s"}


def _is_blank(value, mode):
    if mode == "none_empty":
        return value is None or value == ""
    if mode == "blank":
        return value is None or str(value).strip() == ""
    if mode == "falsy":
        return not value
    raise AnsibleFilterError("알 수 없는 blank 옵션: %s" % mode)


def openbao_required_gaps(docs, required, scope="required", missing_doc="keys", blank="none_empty", skip_plus=False,
                          host=None, fmt="dot"):
    if scope not in ("required", "docs") or missing_doc not in ("keys", "doc", "skip") or fmt not in _FMT \
            or blank not in ("absent", "none_empty", "blank", "falsy"):
        raise AnsibleFilterError("openbao_required_gaps 옵션이 올바르지 않습니다")
    docs, required = docs or {}, required or {}
    patterns = list(required) if scope == "required" else list(docs)
    out = []
    for pattern in patterns:
        if skip_plus and "+" in pattern:
            continue
        shown = pattern.replace("+", host) if host else pattern
        doc = docs.get(pattern)
        if not isinstance(doc, dict):
            if missing_doc == "skip":
                continue
            if missing_doc == "doc":
                out.append("%s(문서 없음)" % shown)
                continue
            out.extend(_FMT[fmt] % (shown, key) for key in required.get(pattern) or [])
            continue
        for key in required.get(pattern) or []:
            gap = key not in doc if blank == "absent" else _is_blank(doc.get(key), blank)
            if gap:
                out.append(_FMT[fmt] % (shown, key))
    return out


class FilterModule:
    def filters(self):
        return {"openbao_required_gaps": openbao_required_gaps}
