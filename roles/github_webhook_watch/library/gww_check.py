#!/usr/bin/python
# -*- coding: utf-8 -*-
"""GitHub 조직 웹훅 전달 점검 (Spec #399 / Ticket-5).

조직 웹훅의 존재·활성·구독 이벤트를 의도값과 비교하고, 재전송 가능 기간 안의 실패한 전달을 재전송한다.
결과는 항상 값(dict)으로 돌려준다: API 실패·자격 없음도 `error` 코드로 담아 호출한 쪽이 하트비트에 남긴 뒤 실패 처리한다.
`error`·`hook_problems`에는 자격, URL, 응답 본문을 넣지 않는다(고정 코드만).
"""
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

DOCUMENTATION = r"""
module: gww_check
short_description: Check an organization webhook and redeliver recently failed deliveries
options:
  api_url: {type: str, default: "https://api.github.com"}
  org: {type: str, required: true}
  token: {type: str, required: true, no_log: true}
  hook_url: {type: str, required: true, no_log: true}
  expected_events: {type: list, elements: str, required: true}
  window_hours: {type: int, default: 72}
  interval_hours: {type: int, default: 6}
  validate_certs: {type: bool, default: true}
  timeout: {type: int, default: 15}
  max_pages: {type: int, default: 10}
"""

_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따라가지 않는다: Authorization 헤더가 다른 출처로 넘어가지 않게 한다."""

    def redirect_request(self, *args, **kwargs):
        return None


class _ApiError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _request(method, url, params, body=None):
    ctx = None
    if url.startswith("https://") and not params["validate_certs"]:
        ctx = ssl._create_unverified_context()  # noqa: S323 - 테스트·사설 CA 환경용 옵션
    req = urllib.request.Request(url, method=method, data=body, headers={
        "Authorization": "Bearer " + params["token"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "infra-automation-webhook-watch",
    })
    try:
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=params["timeout"]) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", "replace")
            status, link = resp.status, resp.headers.get("Link", "")
    except urllib.error.HTTPError as exc:
        return exc.code, None, ""
    except (urllib.error.URLError, OSError):
        raise _ApiError("api_unreachable")
    try:
        return status, (json.loads(raw) if raw.strip() else None), link
    except ValueError:
        raise _ApiError("api_unexpected_response")


def _get(url, params):
    status, data, link = _request("GET", url, params)
    if status != 200:
        raise _ApiError("api_http_%d" % status)
    return data, link


def _parse_time(text):
    # GitHub의 delivered_at은 밀리초를 포함한다(2026-11-04T02:22:21.692Z). 초 단위 형식만 읽으면 None이 되어 실패한 전달이 조용히 건너뛰어진다.
    try:
        return datetime.strptime(re.sub(r"\.\d+Z$", "Z", text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _hook_status(hook, expected):
    problems = []
    if not hook.get("active"):
        problems.append("inactive")
    if sorted(set(hook.get("events") or [])) != sorted(set(expected)):
        problems.append("events_mismatch")
    return problems


def _deliveries(base, params, cutoff):
    """최신순 전달 목록을 cutoff보다 오래된 항목이 나올 때까지 모은다."""
    url = "%s?per_page=100" % base
    origin = _origin(base)
    out = []
    for _ in range(params["max_pages"]):
        page, link = _get(url, params)
        if page is not None and not isinstance(page, list):
            raise ValueError("deliveries")
        out.extend(page or [])
        times = [_parse_time(d.get("delivered_at")) for d in (page or [])]
        if not page or any(t is not None and t < cutoff for t in times):
            return out, False
        m = _NEXT.search(link or "")
        if not m:
            return out, False
        url = m.group(1)
        if _origin(url) != origin:
            return out, True  # 토큰을 다른 출처로 보내지 않는다: 더 있지만 따라가지 않았다
    return out, True  # max_pages에 도달했는데 다음 페이지가 남았다


def _origin(url):
    u = urllib.parse.urlsplit(url)
    return (u.scheme, u.netloc)


def _is_failure(delivery):
    code = delivery.get("status_code")
    return not (isinstance(code, int) and 200 <= code < 400)


def check(params):
    result = {"error": "", "hook_found": False, "hook_status": "unknown", "hook_problems": [],
              "redelivered_count": 0, "would_redeliver_count": 0, "failed_count": 0, "expired_count": 0, "deliveries_truncated": False,
              "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if not params.get("token"):
        result["error"] = "credential_missing"
        return result
    api = params["api_url"].rstrip("/")
    org = urllib.parse.quote(params["org"], safe="")
    try:
        hooks, _ = _get("%s/orgs/%s/hooks?per_page=100" % (api, org), params)
        if hooks is not None and not isinstance(hooks, list):
            raise ValueError("hooks")
        hook = next((h for h in (hooks or []) if (h.get("config") or {}).get("url") == params["hook_url"]), None)
        if hook is None:
            result["hook_status"] = "missing"
            return result
        result["hook_found"] = True
        problems = _hook_status(hook, params["expected_events"])
        result["hook_problems"] = problems
        result["hook_status"] = problems[0] if problems else "ok"

        now = datetime.now(timezone.utc)
        window = now - timedelta(hours=params["window_hours"])
        lookback = window - timedelta(hours=params["interval_hours"])
        hook_base = "%s/orgs/%s/hooks/%s" % (api, org, int(hook["id"]))
        by_guid = {}
        found, result["deliveries_truncated"] = _deliveries(hook_base + "/deliveries", params, lookback)
        for d in found:
            by_guid.setdefault(d.get("guid"), []).append(d)

        for guid, attempts in by_guid.items():
            if any(not _is_failure(a) for a in attempts):
                continue  # 이미 성공(재전송 성공 포함)
            original = min(attempts, key=lambda a: a.get("delivered_at") or "")
            when = _parse_time(original.get("delivered_at"))
            if when is None:
                continue
            if any(a.get("redelivery") for a in attempts):
                result["failed_count"] += 1  # 이미 재전송했는데 아직 실패: 다시 보내지 않는다
            elif when < window:
                if when >= lookback:
                    result["expired_count"] += 1  # 재전송 가능 기간을 막 넘긴 실패(한 번만 센다)
            elif params["check_mode"]:
                result["would_redeliver_count"] += 1
            else:
                status, _, _ = _request("POST", "%s/deliveries/%d/attempts" % (hook_base, int(original["id"])), params, body=b"")
                if status == 202:
                    result["redelivered_count"] += 1
                else:
                    result["failed_count"] += 1
                    if not result["error"]:
                        result["error"] = "api_http_%d" % status
    except _ApiError as exc:
        result["error"] = exc.code
    except (KeyError, ValueError, TypeError, AttributeError):
        result["error"] = "api_unexpected_response"  # 예상 밖 응답 형태: 고정 코드만 남긴다
    return result


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "api_url": {"type": "str", "default": "https://api.github.com"},
            "org": {"type": "str", "required": True},
            "token": {"type": "str", "required": True, "no_log": True},
            "hook_url": {"type": "str", "required": True, "no_log": True},
            "expected_events": {"type": "list", "elements": "str", "required": True},
            "window_hours": {"type": "int", "default": 72},
            "interval_hours": {"type": "int", "default": 6},
            "validate_certs": {"type": "bool", "default": True},
            "timeout": {"type": "int", "default": 15},
            "max_pages": {"type": "int", "default": 10},
        },
        supports_check_mode=True,
    )
    params = dict(module.params)
    params["check_mode"] = module.check_mode
    result = check(params)
    module.exit_json(changed=result["redelivered_count"] > 0, result=result)


if __name__ == "__main__":
    main()
