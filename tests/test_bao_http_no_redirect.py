"""리다이렉트 응답에 토큰·AppRole 본문이 재전송되지 않는다(최종 리뷰 5차 3번). 공용 모듈 `_bao_http`와 이를 쓰는 모든 호출처를 본다."""
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lookup_plugins"))
sys.path.insert(0, str(ROOT / "scripts"))
import _bao_http  # noqa: E402
import _openbao_reader  # noqa: E402


class _Server:
    def __init__(self, handler):
        self.srv = HTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def redirect_pair():
    """A 서버는 307로 B 서버를 가리킨다. B가 받은 요청(헤더·본문)을 기록한다."""
    seen = []

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _rec(self):
            seen.append({"path": self.path, "token": self.headers.get("X-Vault-Token"),
                         "body": self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = _rec

    b = _Server(Target)

    class Source(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _redir(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(307)
            self.send_header("Location", b.url + self.path)
            self.end_headers()

        do_GET = do_POST = _redir

    a = _Server(Source)
    yield a, seen
    a.close()
    b.close()


def test_the_shared_opener_does_not_follow_a_redirect_so_nothing_is_forwarded(redirect_pair):
    a, seen = redirect_pair
    req = urllib.request.Request(a.url + "/v1/x", headers={"X-Vault-Token": "secret-token"})
    with pytest.raises(urllib.error.HTTPError) as err:
        _bao_http.urlopen(req, timeout=5)
    assert err.value.code == 307 and seen == []


def test_the_reader_login_and_reads_never_forward_the_token_or_the_approle_body(redirect_pair):
    a, seen = redirect_pair
    reader = _openbao_reader.Reader({"vault_addr": a.url, "vault_role_id": "role-xyz", "vault_secret_id": "secret-xyz"})
    with pytest.raises(_openbao_reader.OpenBaoError, match="307"):
        reader.read("inventory/assets/ns0001")          # 로그인(POST 본문에 secret_id)이 먼저 307을 만난다
    with pytest.raises(_openbao_reader.OpenBaoError, match="307"):
        _openbao_reader.Reader({"vault_addr": a.url, "_vault_token": "tok-xyz"}).read("inventory/assets/ns0001")
    assert seen == []


def test_a_redirect_tells_the_operator_to_point_vault_addr_at_the_active_node(redirect_pair):
    a, _ = redirect_pair
    with pytest.raises(_openbao_reader.OpenBaoError, match="활성 노드"):
        _openbao_reader.Reader({"vault_addr": a.url, "_vault_token": "t"}).read("inventory/assets/ns0001")


def test_every_script_http_call_goes_through_the_shared_opener():
    for name in ("openbao_check.py", "openbao_put.py", "openbao_migrate.py", "collect-rustfs-policy.py"):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "urllib.request.urlopen" not in text and "_bao_http.urlopen" in text, name
    assert "urllib.request.urlopen" not in (ROOT / "lookup_plugins" / "_openbao_reader.py").read_text(encoding="utf-8")


def test_the_script_clients_do_not_forward_the_token_on_a_redirect(redirect_pair):
    a, seen = redirect_pair
    import openbao_check
    import openbao_migrate
    import openbao_put
    with pytest.raises(openbao_check.BaoError):
        openbao_check.Client(a.url, "infra", "tok-xyz").request("GET", "sys/health")
    with pytest.raises(openbao_put.HttpError):
        openbao_put.Client(a.url, "tok-xyz", "infra")._call("GET", "inventory/assets/ns0001")
    with pytest.raises(openbao_migrate.ClientError):
        openbao_migrate.Client(a.url, "infra", "tok-xyz")._call("GET", "/v1/inventory/data/assets/ns0001")
    assert seen == []


def test_the_alert_post_has_no_token_so_it_follows_a_redirect_to_the_webhook(redirect_pair):
    """Periodic Check 실패 알림은 토큰이 없는 POST라 리다이렉트를 따른다(최종 리뷰 6차 4번). OpenBao 요청의 비추종은 그대로다."""
    a, seen = redirect_pair
    import openbao_check
    openbao_check.send_alert(a.url + "/hook", "OpenBao Periodic Check 실패 1건\n")
    assert [s["path"] for s in seen] == ["/hook"]
    assert seen[0]["token"] is None and "Periodic Check" in seen[0]["body"]
    with pytest.raises(urllib.error.HTTPError):       # 같은 서버로 OpenBao 호출용 열기는 여전히 따르지 않는다
        _bao_http.urlopen(urllib.request.Request(a.url + "/x", method="POST", data=b"{}"), timeout=5)
    assert len(seen) == 1
