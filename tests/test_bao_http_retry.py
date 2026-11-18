"""운영 OpenBao의 요청 제한(HTTP 429)에서 공용 HTTP 호출이 기다렸다 다시 시도하는지 본다(로컬 서버, 외부 접속 없음)."""
import http.server
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lookup_plugins"))
import _bao_http  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.hits += 1
        if self.server.hits <= self.server.fail_times:
            self.send_response(429)
            if self.server.retry_after is not None:
                self.send_header("Retry-After", self.server.retry_after)
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    srv = http.server.HTTPServer(("localhost", 0), _Handler)
    srv.hits, srv.fail_times, srv.retry_after = 0, 0, "0"
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _url(srv):
    return "http://localhost:%d/v1/x" % srv.server_address[1]


def test_429_is_retried_until_success(server, monkeypatch):
    waits = []
    monkeypatch.setattr(_bao_http.time, "sleep", waits.append)
    server.fail_times = 3
    with _bao_http.urlopen(urllib.request.Request(_url(server))) as r:
        assert r.status == 200
    assert server.hits == 4 and len(waits) == 3


def test_retry_wait_follows_retry_after_but_is_capped(server, monkeypatch):
    waits = []
    monkeypatch.setattr(_bao_http.time, "sleep", waits.append)
    server.fail_times, server.retry_after = 1, "999"
    with _bao_http.urlopen(urllib.request.Request(_url(server))):
        pass
    assert waits == [_bao_http.MAX_WAIT_429]


def test_gives_up_after_the_limit_and_raises_the_429(server, monkeypatch):
    monkeypatch.setattr(_bao_http.time, "sleep", lambda s: None)
    server.fail_times = 10 ** 6
    with pytest.raises(urllib.error.HTTPError) as exc:
        _bao_http.urlopen(urllib.request.Request(_url(server)))
    assert exc.value.code == 429 and server.hits == _bao_http.RETRIES_429 + 1


def test_other_errors_are_not_retried(server, monkeypatch):
    monkeypatch.setattr(_bao_http.time, "sleep", lambda s: pytest.fail("재시도하면 안 된다"))
    with pytest.raises(urllib.error.HTTPError) as exc:
        _bao_http.urlopen(urllib.request.Request(_url(server).replace("/v1/x", "/v1/x"), method="DELETE"))
    assert exc.value.code == 501
