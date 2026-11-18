"""OpenBao·RustFS HTTP 호출의 공용 보호 (최종 리뷰 5차 3·8번).

`urllib.request.urlopen`은 리다이렉트를 따라가며 `X-Vault-Token`·`Authorization` 헤더와 AppRole 로그인 본문을 다른 호스트로 다시 보낼 수
있다. 이 모듈의 `urlopen`은 리다이렉트를 따르지 않는다(3xx는 HTTPError로 올라온다). 토큰 없는 알림 POST만 `urlopen_following`을 쓴다(알림에 인증 토큰이 있으면 `urlopen`). 공용 읽기 지점(`_openbao_reader.py`)과 운영자
스크립트(`scripts/openbao_check.py`·`openbao_put.py`·`openbao_migrate.py`·`collect-rustfs-policy.py`)가 이 한 곳을 쓴다.

파일 이름이 `_`로 시작해 Ansible이 플러그인으로 읽지 않는다. 스크립트는 `lookup_plugins/`를 sys.path에 넣어 가져온다.
"""
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 30


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따르지 않는다(토큰 헤더가 다른 호스트로 넘어가지 않게)."""

    def redirect_request(self, *args, **kwargs):
        return None


def urlopen(req, timeout=DEFAULT_TIMEOUT, context=None):
    """`urllib.request.urlopen`과 같은 사용법. 리다이렉트를 따르지 않는다. `context`는 https용 ssl 컨텍스트(선택)."""
    handlers = [NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


class _FollowRedirect(urllib.request.HTTPRedirectHandler):
    """표준 핸들러가 따르지 않는 POST의 307·308도 같은 본문으로 따른다(알림 webhook이 게이트웨이 뒤에 있을 때)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code in (307, 308) and req.get_method() == "POST":
            return urllib.request.Request(newurl, data=req.data, headers=dict(req.header_items()), method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def urlopen_following(req, timeout=DEFAULT_TIMEOUT):
    """리다이렉트를 따르는 열기. 토큰·AppRole 본문이 없는 요청(예: 알림 webhook POST) 전용이다. OpenBao·RustFS 호출에는 `urlopen`을 쓴다."""
    return urllib.request.build_opener(_FollowRedirect()).open(req, timeout=timeout)
