"""OpenBao 정기 점검(Periodic Check) 코어 (#519, Spec #511 §7·§8). `openbao_docs.py check`가 쓴다.

OpenBao 전체를 읽어 다음을 대조한다. 위반은 `Violation(문서 경로, JSON 포인터, 규칙 이름)`으로만 다루고 값은 어디에도 내지 않는다.
  1. 모든 문서를 스키마와 대조, 문서 사이 참조 검사(`openbao_validation.validate_store`)
  2. Semaphore 인벤토리와 Asset 목록 대조
       인벤토리에만 있음 -> 실패 `inventory_missing_asset`
       Asset 문서에만 있음 -> 경고(로그만) `orphan_asset`, 수정 없이 30일 넘으면 실패 `orphan_asset_stale`
  3. AppRole secret_id 만료 30일 전 -> 실패 `secret_id_expiring`
  4. 선언 코드(openbao/)에 없는 정책·role·마운트 -> 실패 `not_in_code`
실패하면 `secrets/services/alert/notify` URL로 요약(문서 경로·규칙 이름)을 보낸다.

접속 설정은 환경변수다: VAULT_ADDR, VAULT_NAMESPACE(기본 infra), VAULT_TOKEN 또는 VAULT_ROLE_ID+VAULT_SECRET_ID(AppRole).
"""
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "lookup_plugins"))   # 끝에 붙인다(stdlib·scripts/ 이름을 가리지 않는다)
import _bao_http  # noqa: E402
import openbao_validation as ov  # noqa: E402
from openbao_code import DEFAULT_CODE_DIR, load_code  # noqa: E402

MOUNTS = ("inventory", "secrets")
EXPIRY_WARN = timedelta(days=30)
ORPHAN_LIMIT = timedelta(days=30)
# secret_id를 일부러 짧게(1일·24시간) 쓰는 role은 만료 임박이 정상이라 대상이 아니다(applier: 적용 때마다 발급, agent_session).
SHORT_LIVED_ROLES = frozenset({"applier", "agent_session"})
BUILTIN_POLICIES = frozenset({"default", "root"})
BUILTIN_MOUNTS = frozenset({"sys", "identity", "cubbyhole"})
BUILTIN_AUTH = frozenset({"token"})
ALERT_MAX_LINES = 50
TIMEOUT = 30

Violation = ov.Violation


class BaoError(Exception):
    """HTTP 실패. 내용(응답 본문)은 보관하지 않는다."""

    def __init__(self, status):
        super().__init__(status)
        self.status = status


class Client:
    def __init__(self, addr, namespace, token=None):
        self.addr = addr.rstrip("/")
        self.namespace = namespace
        self.token = token

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        real = "GET" if method == "LIST" else method
        url = self.addr + "/v1/" + urllib.parse.quote(path.strip("/"), safe="/") + \
            ("?list=true" if method == "LIST" else "")
        req = urllib.request.Request(url, data=data, method=real)
        req.add_header("X-Vault-Namespace", self.namespace)
        if self.token:
            req.add_header("X-Vault-Token", self.token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with _bao_http.urlopen(req, timeout=TIMEOUT) as r:
                raw = r.read()
        except urllib.error.HTTPError as exc:
            raise BaoError(exc.code) from None
        except (urllib.error.URLError, OSError):
            raise BaoError(0) from None
        try:
            return json.loads(raw) if raw else {}
        except ValueError:  # 프록시의 HTML 200 응답 등. 본문은 버린다
            raise BaoError(0) from None

    def login_approle(self, role_id, secret_id):
        out = self.request("POST", "auth/approle/login", {"role_id": role_id, "secret_id": secret_id})
        self.token = out["auth"]["client_token"]


# ---- 문서 읽기 ----------------------------------------------------------------------------------------------------

def list_documents(client, mount, prefix="", failed=None):
    """마운트 아래 모든 문서 경로(`<마운트>/<경로>`). 하위 목록이 404면 비어 있다.

    목록 조회가 실패한 접두사는 `failed`에 모으고 나머지는 계속 모은다(읽은 문서는 버리지 않는다).
    마운트 최상위의 404는 마운트가 없거나 비었다는 뜻이라 실패로 본다.
    """
    failed = [] if failed is None else failed
    try:
        keys = client.request("LIST", "%s/metadata/%s" % (mount, prefix))["data"]["keys"]
    except BaoError as exc:
        if exc.status != 404 or not prefix:
            failed.append(prefix)
        return []
    except (KeyError, TypeError):
        failed.append(prefix)
        return []
    docs = []
    for key in keys:
        if key.endswith("/"):
            docs.extend(list_documents(client, mount, prefix + key, failed))
        else:
            docs.append("%s/%s%s" % (mount, prefix, key))
    return docs


def read_store(client):
    """({문서 경로: 데이터}, [Violation], 목록에 있던 문서 경로 집합). 읽지 못한 문서는 store에서 빼고 `read_failed`로 보고한다."""
    store, problems, listed = {}, [], set()
    for mount in MOUNTS:
        failed = []
        docs = list_documents(client, mount, failed=failed)
        problems.extend(Violation("%s/%s" % (mount, p), "#", "list_failed") for p in failed)
        for doc in docs:
            try:
                store[doc] = client.request("GET", "%s/data/%s" % (mount, doc[len(mount) + 1:]))["data"]["data"]
            except BaoError as exc:
                if exc.status == 404:  # 소프트 삭제된 문서도 목록에는 나온다. 없는 문서로 본다
                    continue
                problems.append(Violation(doc, "#", "read_failed"))
            except (KeyError, TypeError):
                problems.append(Violation(doc, "#", "read_failed"))
            listed.add(doc)
    return store, problems, listed


def _is_zero_time(text):
    return isinstance(text, str) and (text == "" or text.startswith("0001-"))


def _parse_time(text):
    """RFC3339(나노초 정밀도·Z 포함)를 시각으로. 읽을 수 없으면 None."""
    if not isinstance(text, str) or not text:
        return None
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", text)
    if not m:
        return None
    if m.group(1).startswith("0001-"):  # secret_id_ttl=0(만료 없음)일 때 OpenBao가 주는 영(0) 시각
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    zone = "+00:00" if m.group(3) == "Z" else m.group(3)
    try:
        return datetime.fromisoformat("%s.%s%s" % (m.group(1), frac, zone))
    except ValueError:
        return None


# ---- Semaphore 인벤토리 -------------------------------------------------------------------------------------------

def _yaml_group_hosts(group, out):
    """Ansible YAML 인벤토리의 그룹 하나: `hosts` 키와 `children` 그룹만 따라간다(vars 등은 보지 않는다)."""
    if not isinstance(group, dict):
        return
    hosts = group.get("hosts")
    if isinstance(hosts, (dict, list)):
        out.update(str(k) for k in hosts)
    children = group.get("children")
    if isinstance(children, dict):
        for child in children.values():
            _yaml_group_hosts(child, out)


def _yaml_hosts(node, out):
    if not isinstance(node, dict):
        return
    if "all" in node:
        _yaml_group_hosts(node["all"], out)
    else:  # `all` 없이 최상위가 그룹인 형식
        for group in node.values():
            _yaml_group_hosts(group, out)


def parse_inventory_hosts(text, kind):
    """정적 인벤토리 본문(YAML 또는 INI)에서 호스트 이름 집합."""
    hosts = set()
    if kind != "static":  # static-yaml, yaml
        try:
            _yaml_hosts(yaml.safe_load(text), hosts)
        except yaml.YAMLError:
            pass
        return hosts
    section = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]")
            continue
        if section is not None and (section.endswith(":vars") or section.endswith(":children")):
            continue
        hosts.add(line.split()[0])
    return hosts


def fetch_semaphore_hosts(base_url, token):
    """Semaphore API(읽기)로 모든 프로젝트의 정적 인벤토리 호스트를 모은다. 실패하면 BaoError(0)."""
    def get(path):
        req = urllib.request.Request(base_url.rstrip("/") + path, headers={"Authorization": "Bearer " + token})
        try:
            with _bao_http.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError):
            raise BaoError(0) from None

    hosts = set()
    try:
        for project in get("/api/projects"):
            for inv in get("/api/project/%s/inventory" % project["id"]):
                if str(inv.get("type", "")).startswith("static") or inv.get("type") == "yaml":
                    hosts |= parse_inventory_hosts(inv.get("inventory") or "", inv["type"])
    except (KeyError, TypeError, AttributeError):  # 예상 밖 응답 모양
        raise BaoError(0) from None
    hosts.discard("localhost")
    return {h for h in hosts if not re.search(r"[\[\]*?]", h)}  # `ns[01:05]` 같은 패턴은 Asset 이름이 아니라 건너뛴다


def compare_inventory(asset_docs, semaphore_hosts, updated_times, now):
    """([실패 Violation], [경고 Violation]). asset_docs: `inventory/assets/<이름>` 문서 경로 집합."""
    failures, warnings = [], []
    assets = {d.rsplit("/", 1)[1]: d for d in asset_docs}
    for name in sorted(semaphore_hosts - set(assets)):
        failures.append(Violation("inventory/assets/" + name, "#", "inventory_missing_asset"))
    for name in sorted(set(assets) - semaphore_hosts):
        warnings.append(Violation(assets[name], "#", "orphan_asset"))
        updated = _parse_time(updated_times.get(assets[name]))
        if updated is None:  # 시각을 못 읽은 것은 30일 넘음과 다르다. 이름을 달리해 알린다
            failures.append(Violation(assets[name], "#", "orphan_metadata_unreadable"))
        elif now - updated > ORPHAN_LIMIT:
            failures.append(Violation(assets[name], "#", "orphan_asset_stale"))
    return failures, warnings


# ---- secret_id 만료 -----------------------------------------------------------------------------------------------

def check_secret_ids(client, roles, now):
    out = []
    for role in sorted(set(roles) - SHORT_LIVED_ROLES):
        doc = "auth/approle/role/" + role
        try:
            accessors = client.request("LIST", doc + "/secret-id")["data"]["keys"]
        except BaoError as exc:
            if exc.status != 404:
                out.append(Violation(doc, "#", "secret_id_lookup_failed"))
            continue
        latest, no_expiry = None, False
        for accessor in accessors:
            try:
                info = client.request("POST", doc + "/secret-id-accessor/lookup", {"secret_id_accessor": accessor})
            except BaoError:
                out.append(Violation(doc, "#", "secret_id_lookup_failed"))
                continue
            expires = _parse_time((info.get("data") or {}).get("expiration_time"))
            if expires is None:
                if _is_zero_time((info.get("data") or {}).get("expiration_time")):
                    no_expiry = True
                else:  # 읽을 수 없는 만료 시각을 "만료 없음"으로 보면 임박한 것을 놓친다
                    out.append(Violation(doc, "#", "secret_id_lookup_failed"))
            elif latest is None or expires > latest:
                latest = expires
        # 교체 중에는 옛 secret_id가 남아 있다. 가장 늦게 만료되는 것이 임박할 때만 알린다.
        if latest is not None and not no_expiry and latest - now <= EXPIRY_WARN:
            out.append(Violation(doc, "#", "secret_id_expiring"))
    return sorted(set(out))


# ---- 선언 코드 밖 객체 --------------------------------------------------------------------------------------------

def expected_from_code(code_dir):
    """선언 코드(`roles.yml`·`policies/*.hcl`)가 만드는 {policies, roles, mounts, auth} 이름 집합."""
    code = load_code(code_dir)   # 구조를 못 읽으면 OSError: "모두 코드 밖"이라는 거짓 경보 대신 읽기 실패로 멈춘다
    return {"policies": set(code["policies"]), "roles": set(code["roles"]), "mounts": set(code["mounts"]),
            "auth": set(code["auth_mounts"])}


def check_unmanaged(client, expected, roles):
    """코드에 없는 정책·role·마운트·인증 마운트. 서버 조회 실패는 `unmanaged_lookup_failed`."""
    out = []

    def keys(method, path):
        try:
            data = client.request(method, path).get("data") or {}
            if method == "LIST":
                return list(data["keys"])
            return [k.rstrip("/") for k, v in data.items() if isinstance(v, dict)]  # 마운트 이름이 keys여도 안전하다
        except BaoError as exc:
            if method == "LIST" and exc.status == 404:  # 비어 있는 목록
                return []
            raise
        except (KeyError, TypeError, AttributeError):
            raise BaoError(0) from None

    plans = (
        ("LIST", "sys/policies/acl", "sys/policies/acl/", expected["policies"] | BUILTIN_POLICIES),
        ("LIST", "auth/approle/role", "auth/approle/role/", expected["roles"]),
        ("GET", "sys/mounts", "sys/mounts/", expected["mounts"] | BUILTIN_MOUNTS),
        ("GET", "sys/auth", "sys/auth/", expected["auth"] | BUILTIN_AUTH),
    )
    for method, path, prefix, allowed in plans:
        try:
            names = roles if path == "auth/approle/role" else keys(method, path)
        except BaoError:
            out.append(Violation(path, "#", "unmanaged_lookup_failed"))
            continue
        out.extend(Violation(prefix + n, "#", "not_in_code") for n in names if n not in allowed)
    return out


def role_names(client):
    """서버의 AppRole role 이름. 비어 있으면 []. 조회·해석에 실패하면 BaoError."""
    try:
        return list(client.request("LIST", "auth/approle/role")["data"]["keys"])
    except BaoError as exc:
        if exc.status == 404:
            return []
        raise
    except (KeyError, TypeError):
        raise BaoError(0) from None


# ---- 알림 ---------------------------------------------------------------------------------------------------------

def build_alert(violations):
    lines = [v.format() for v in violations]
    shown = lines[:ALERT_MAX_LINES]
    if len(lines) > len(shown):
        shown.append("... 외 %d건" % (len(lines) - len(shown)))
    return "OpenBao Periodic Check 실패 %d건\n%s\n" % (len(violations), "\n".join(shown))


DEFAULT_ALERT_AUTH_HEADER = "X-NANOIT-ACCESS"
ALERT_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]+$")


def send_alert(url, text, token=None, auth_header=None):
    """알림 POST. token이 있을 때만 auth_header(기본 X-NANOIT-ACCESS)로 붙인다.

    토큰을 싣는 요청은 리다이렉트를 따르지 않는다(헤더가 다른 호스트로 새지 않게). 토큰이 없는 요청은 새는 비밀이 없어 따른다."""
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    if token:
        name = auth_header or DEFAULT_ALERT_AUTH_HEADER
        if not ALERT_HEADER_NAME.match(name):
            raise ValueError("auth_header")
        headers[name] = token
    req = urllib.request.Request(url, data=text.encode("utf-8"), method="POST", headers=headers)
    opener = _bao_http.urlopen if token else _bao_http.urlopen_following
    opener(req, timeout=TIMEOUT).close()


# ---- 진입점 -------------------------------------------------------------------------------------------------------

def run_check(environ, code_dir=DEFAULT_CODE_DIR, schema_dir=ov.DEFAULT_SCHEMA_DIR, now=None):
    """종료 코드: 0 정상, 1 위반(알림 전송), 2 설정 오류."""
    now = now or datetime.now(timezone.utc)
    addr = environ.get("VAULT_ADDR")
    client = Client(addr or "", environ.get("VAULT_NAMESPACE") or "infra", environ.get("VAULT_TOKEN"))
    try:
        if not addr:
            raise KeyError
        if not client.token:
            client.login_approle(environ["VAULT_ROLE_ID"], environ["VAULT_SECRET_ID"])
        expected = expected_from_code(code_dir)
    except (KeyError, BaoError, OSError, ValueError):  # ValueError: 파일 디코딩
        print("접속 설정 오류: VAULT_ADDR와 VAULT_TOKEN(또는 VAULT_ROLE_ID·VAULT_SECRET_ID)이 필요하고, "
              "선언 코드 디렉터리(openbao/)를 읽을 수 있어야 한다", file=sys.stderr)
        return 2

    store, failures, listed = read_store(client)
    try:
        if failures:  # 읽지 못한 문서가 있으면 참조 검사는 가짜 위반을 내므로 문서별 스키마 검증만 한다
            for doc in sorted(store):
                failures.extend(ov.validate_document(doc, store[doc], schema_dir))
        else:
            failures.extend(ov.validate_store(store, schema_dir))
    except Exception as exc:  # noqa: BLE001 - 스키마·index.yml 문제는 종류만 낸다(값이 섞이지 않게)
        print("스키마 또는 index.yml 오류: %s" % type(exc).__name__, file=sys.stderr)
        return 2

    warnings = []
    unread = {v.doc for v in failures if v.rule == "read_failed"}
    if any(v.rule == "list_failed" for v in failures):  # 목록이 불완전하면 호스트 대조가 가짜 위반을 쏟는다(list_failed로 보고했다)
        unread.add("*")
    failures.extend(_guard("inventory", lambda: _inventory_checks(client, store, listed, unread, now, warnings)))
    try:
        roles = role_names(client)
    except BaoError:
        roles = []
        failures.append(Violation("auth/approle/role", "#", "secret_id_lookup_failed"))
    failures.extend(_guard("auth/approle/role", lambda: check_secret_ids(client, roles, now)))
    failures.extend(_guard("sys", lambda: check_unmanaged(client, expected, roles)))
    failures = sorted(set(failures))

    for w in warnings:
        print("경고\t" + w.format(), file=sys.stderr)
    for v in failures:
        print(v.format())
    print("문서 %d개, 실패 %d건, 경고 %d건" % (len(store), len(failures), len(warnings)), file=sys.stderr)
    if not failures:
        return 0
    _notify(store, failures)
    return 1


def _guard(name, fn):
    """점검 단계 하나. 예상 밖 예외는 트레이스백(값이 섞일 수 있다) 대신 `check_internal_error`로 보고하고 나머지를 계속한다."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return [Violation(name, "#", "check_internal_error")]


def _inventory_checks(client, store, listed, unread, now, warnings):
    if unread & {"*", "inventory/services/semaphore", "secrets/services/semaphore/inventory_read"}:
        return []  # read_failed로 이미 보고했다
    sem_url = (store.get("inventory/services/semaphore") or {}).get("url")
    sem_token = (store.get("secrets/services/semaphore/inventory_read") or {}).get("token")
    if not isinstance(sem_url, str) or not isinstance(sem_token, str):
        return [Violation("inventory/services/semaphore", "#", "semaphore_config_missing")]
    try:
        hosts = fetch_semaphore_hosts(sem_url, sem_token)
    except BaoError:
        return [Violation("inventory/services/semaphore", "#", "semaphore_unreachable")]
    assets = {d for d in listed if len(d.split("/")) == 3 and d.startswith("inventory/assets/")}
    updated = {}
    for doc in assets:
        if doc.rsplit("/", 1)[1] not in hosts:  # 고아 판정에만 수정 시각이 필요하다
            try:
                updated[doc] = client.request("GET", "inventory/metadata/" + doc[len("inventory/"):])["data"]["updated_time"]
            except (BaoError, KeyError, TypeError):
                pass
    failures, found = compare_inventory(assets, hosts, updated, now)
    warnings.extend(found)
    return failures


def _notify(store, failures):
    doc = store.get("secrets/services/alert/notify") or {}
    url = doc.get("url")
    if not isinstance(url, str):
        print("알림 전송 불가: alert/notify 문서를 읽지 못했다", file=sys.stderr)
        return
    try:
        token, header = doc.get("token"), doc.get("auth_header")
        send_alert(url, build_alert(failures), token if isinstance(token, str) else None,
                   header if isinstance(header, str) else None)
    except (urllib.error.URLError, OSError, ValueError) as exc:  # 예외 메시지에 URL이 들어갈 수 있어 종류만 낸다
        print("알림 전송 실패: %s" % type(exc).__name__, file=sys.stderr)
