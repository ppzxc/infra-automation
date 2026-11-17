"""공용 가짜 OpenBao HTTP 서버(Spec #511 / Ticket-3).

테스트 파일마다 따로 만들던 가짜 서버를 이 하나로 합친다. KV v2 읽기(`GET /v1/<마운트>/data/<문서 경로>`)와
AppRole 로그인(`POST /v1/auth/approle/login`)만 흉내 낸다.

- 라우트는 URL 문자열이 아니라 `(마운트, 문서 경로) -> 데이터`로 등록한다(`set`·`deny`·`remove`).
  등록하지 않은 문서는 404다. `deny`한 문서는 403이다.
- `namespace`를 주면 `X-Vault-Namespace` 헤더가 그 값과 다른 요청을 403으로 거부한다.
  `token`을 주면 `X-Vault-Token`이 다른 요청을 403으로 거부하고, `approle=True`면 로그인으로 받은 토큰이 있어야 읽는다.
- 받은 요청은 `requests`에 `Request`로 쌓이고, 테스트는 그 기록으로 단언한다(`reads()`·`logins()`).
- `index_patterns`(`<마운트>/<문서 경로>` glob 목록)와 `schema_check`(문서 검증 함수)는 스위치다. 기본은 꺼짐(None)이다.
  켜면 패턴에 맞지 않는 요청은 `violations`에 기록하고, 등록하는 문서는 `schema_check`를 거친다.
  전환 PR에서 `index.yml`·스키마와 연결한다.
"""
import fnmatch
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

APPROLE_TOKEN = "approle-issued"


@dataclass(frozen=True)
class Request:
    method: str
    path: str                 # 요청 경로 그대로(`/v1/...`)
    mount: str | None         # KV 읽기가 아니면 None
    doc: str | None
    token: str | None
    namespace: str | None
    body: dict | None = None  # POST 본문(쓰기·로그인)


class FakeOpenBao:
    def __init__(self, *, namespace=None, token=None, approle=False, index_patterns=None, schema_check=None):
        self.namespace = namespace
        self.token = token
        self.approle = approle
        self.index_patterns = index_patterns
        self.schema_check = schema_check
        self.requests: list[Request] = []
        self.violations: list[tuple[str, str]] = []
        self._docs: dict[tuple[str, str], tuple[int, dict]] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    body = None
                mount, doc = _split(self.path)
                ns = self.headers.get("X-Vault-Namespace")
                outer.requests.append(Request("POST", self.path, mount, doc, self.headers.get("X-Vault-Token"), ns, body))
                if outer.approle and self.path == "/v1/auth/approle/login":
                    return self._reply(200, {"auth": {"client_token": outer.token or APPROLE_TOKEN}})
                if mount is None:
                    return self._reply(404, {})
                want_token = outer.token or (APPROLE_TOKEN if outer.approle else None)
                if (outer.namespace is not None and ns != outer.namespace) or \
                        (want_token is not None and self.headers.get("X-Vault-Token") != want_token):
                    return self._reply(403, {"errors": ["permission denied"]})
                # KV v2 쓰기: options.cas가 현재 버전(없으면 0)과 다르면 400이다.
                status, current = outer._docs.get((mount, doc), (404, None))
                version = current["data"]["metadata"]["version"] if status == 200 else 0
                cas = ((body or {}).get("options") or {}).get("cas")
                if cas is not None and cas != version:
                    return self._reply(400, {"errors": ["check-and-set parameter did not match the current version"]})
                outer._docs[(mount, doc)] = (200, {"data": {"data": (body or {}).get("data"),
                                                            "metadata": {"version": version + 1}}})
                self._reply(200, {"data": {"version": version + 1}})

            def do_GET(self):  # noqa: N802
                mount, doc = _split(self.path)
                req = Request("GET", self.path, mount, doc, self.headers.get("X-Vault-Token"),
                              self.headers.get("X-Vault-Namespace"))
                outer.requests.append(req)
                if mount is not None and outer.index_patterns is not None and \
                        not any(fnmatch.fnmatchcase(f"{mount}/{doc}", p) for p in outer.index_patterns):
                    outer.violations.append((mount, doc))
                want_token = outer.token or (APPROLE_TOKEN if outer.approle else None)
                if (outer.namespace is not None and req.namespace != outer.namespace) or \
                        (want_token is not None and req.token != want_token):
                    return self._reply(403, {"errors": ["permission denied"]})
                status, body = outer._docs.get((mount, doc), (404, {"errors": []}))
                self._reply(status, body)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    # --- 라우트 등록 -------------------------------------------------------
    def set(self, mount, doc, data):
        if self.schema_check is not None:
            self.schema_check(mount, doc, data)
        status, current = self._docs.get((mount, doc), (404, None))
        version = current["data"]["metadata"]["version"] + 1 if status == 200 else 1
        self._docs[(mount, doc)] = (200, {"data": {"data": data, "metadata": {"version": version}}})
        return self

    def get(self, mount, doc):
        """저장된 (데이터, 버전). 없으면 None."""
        status, body = self._docs.get((mount, doc), (404, None))
        return (body["data"]["data"], body["data"]["metadata"]["version"]) if status == 200 else None

    def writes(self):
        return [r for r in self.requests if r.method == "POST" and r.doc is not None]

    def deny(self, mount, doc):
        self._docs[(mount, doc)] = (403, {"errors": ["permission denied"]})
        return self

    def remove(self, mount, doc):
        self._docs.pop((mount, doc), None)
        return self

    # --- 요청 기록 ---------------------------------------------------------
    def reads(self):
        return [r for r in self.requests if r.method == "GET"]

    def logins(self):
        return [r for r in self.requests if r.method == "POST" and r.path == "/v1/auth/approle/login"]

    def env(self, token="bao-test-token"):
        env = {"VAULT_ADDR": self.url, "VAULT_TOKEN": token}
        if self.namespace is not None:
            env["VAULT_NAMESPACE"] = self.namespace
        return env

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _split(path):
    """`/v1/<마운트>/data/<문서 경로>` -> (마운트, 문서 경로). KV 읽기가 아니면 (None, None)."""
    parts = path.split("?")[0].split("/")
    if len(parts) >= 5 and parts[1] == "v1" and parts[3] == "data":
        return parts[2], "/".join(parts[4:])
    return None, None
