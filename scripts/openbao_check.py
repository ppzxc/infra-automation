"""OpenBao 정기 점검(Periodic Check) 코어 (#519, Spec #511 §7·§8). `openbao_docs.py check`가 쓴다.

OpenBao 전체를 읽어 다음을 대조한다. 위반은 `Violation(문서 경로, JSON 포인터, 규칙 이름)`으로만 다루고 값은 어디에도 내지 않는다.
  1. 모든 문서를 스키마와 대조, 문서 사이 참조 검사(`openbao_validation.validate_store`)
  2. Semaphore 인벤토리와 Asset 목록 대조
       인벤토리에만 있음 -> 실패 `inventory_missing_asset`
       Asset 문서에만 있음 -> 경고(로그만) `orphan_asset`, 수정 없이 30일 넘으면 실패 `orphan_asset_stale`
  3. AppRole secret_id 만료 30일 전 -> 실패 `secret_id_expiring`
  4. OpenTofu 코드에 없는 정책·role·마운트 -> 실패 `not_in_opentofu`
실패하면 `secrets/services/alert/notify` URL로 요약(문서 경로·규칙 이름)을 보낸다.

접속 설정은 환경변수다: VAULT_ADDR, VAULT_NAMESPACE(기본 infra), VAULT_TOKEN 또는 VAULT_ROLE_ID+VAULT_SECRET_ID(AppRole).
"""
import collections
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
import openbao_validation as ov  # noqa: E402

DEFAULT_TOFU_DIR = Path(__file__).resolve().parent.parent / "tofu" / "openbao"
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
        url = self.addr + "/v1/" + path.strip("/") + ("?list=true" if method == "LIST" else "")
        req = urllib.request.Request(url, data=data, method=real)
        req.add_header("X-Vault-Namespace", self.namespace)
        if self.token:
            req.add_header("X-Vault-Token", self.token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
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

def list_documents(client, mount, prefix=""):
    """마운트 아래 모든 문서 경로(`<마운트>/<경로>`). 목록이 404면 비어 있다."""
    try:
        keys = client.request("LIST", "%s/metadata/%s" % (mount, prefix))["data"]["keys"]
    except BaoError as exc:
        if exc.status == 404:
            return []
        raise
    docs = []
    for key in keys:
        if key.endswith("/"):
            docs.extend(list_documents(client, mount, prefix + key))
        else:
            docs.append("%s/%s%s" % (mount, prefix, key))
    return docs


def read_store(client):
    """({문서 경로: 데이터}, [Violation], 목록에 있던 문서 경로 집합). 읽지 못한 문서는 store에서 빼고 `read_failed`로 보고한다."""
    store, problems, listed = {}, [], set()
    for mount in MOUNTS:
        try:
            docs = list_documents(client, mount)
        except BaoError:
            problems.append(Violation(mount + "/", "#", "list_failed"))
            continue
        listed.update(docs)
        for doc in docs:
            try:
                store[doc] = client.request("GET", "%s/data/%s" % (mount, doc[len(mount) + 1:]))["data"]["data"]
            except (BaoError, KeyError, TypeError):
                problems.append(Violation(doc, "#", "read_failed"))
    return store, problems, listed


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

def _yaml_hosts(node, out):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "hosts" and isinstance(value, dict):
                out.update(str(k) for k in value)
            elif key == "hosts" and isinstance(value, list):
                out.update(str(k) for k in value)
            else:
                _yaml_hosts(value, out)
    elif isinstance(node, list):
        for value in node:
            _yaml_hosts(value, out)


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
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
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
    return hosts


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
        for accessor in accessors:
            try:
                info = client.request("POST", doc + "/secret-id-accessor/lookup", {"secret_id_accessor": accessor})
            except BaoError:
                out.append(Violation(doc, "#", "secret_id_lookup_failed"))
                continue
            expires = _parse_time(info.get("data", {}).get("expiration_time"))
            if expires is not None and expires - now <= EXPIRY_WARN:
                out.append(Violation(doc, "#", "secret_id_expiring"))
    return sorted(set(out))


# ---- OpenTofu 밖 객체 ---------------------------------------------------------------------------------------------

def expected_from_tofu(tofu_dir):
    """OpenTofu 코드가 만드는 {policies, roles, mounts, auth} 이름 집합."""
    tofu_dir = Path(tofu_dir)
    if not (tofu_dir / "policies").is_dir() or not list(tofu_dir.glob("*.tf")):
        raise OSError("tofu 디렉터리를 읽을 수 없다")
    policies = {p.stem for p in (tofu_dir / "policies").glob("*.hcl")}
    roles, mounts, auth = set(), set(), set()
    for tf in sorted(tofu_dir.glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        roles.update(re.findall(r'role_name\s*=\s*"([^"$]+)"', text))
        block = re.search(r"token_max_ttl\s*=\s*\{(.*?)\n\s*\}", text, re.S)  # 계열별 role이 for_each로 만들어진다
        if block:
            roles.update(re.findall(r"^\s*(\w+)\s*=\s*\d+", block.group(1), re.M))
        for kind, bucket in (("vault_mount", mounts), ("vault_auth_backend", auth)):
            for body in re.findall(r'resource\s+"%s"\s+"\w+"\s*\{(.*?)\n\}' % kind, text, re.S):
                bucket.update(re.findall(r'^\s*path\s*=\s*"([^"$]+)"', body, re.M))
    return {"policies": policies, "roles": roles, "mounts": mounts, "auth": auth}


def check_unmanaged(client, expected):
    """코드에 없는 정책·role·마운트·인증 마운트. 서버 조회 실패는 `unmanaged_lookup_failed`."""
    out = []

    def keys(method, path):
        data = client.request(method, path).get("data", {})
        if method == "LIST":
            return list(data["keys"])
        return [k.rstrip("/") for k, v in data.items() if isinstance(v, dict)]  # 마운트 이름이 keys여도 안전하다

    plans = (
        ("LIST", "sys/policies/acl", "sys/policies/acl/", expected["policies"] | BUILTIN_POLICIES),
        ("LIST", "auth/approle/role", "auth/approle/role/", expected["roles"]),
        ("GET", "sys/mounts", "sys/mounts/", expected["mounts"] | BUILTIN_MOUNTS),
        ("GET", "sys/auth", "sys/auth/", expected["auth"] | BUILTIN_AUTH),
    )
    for method, path, prefix, allowed in plans:
        try:
            names = keys(method, path)
        except BaoError:
            out.append(Violation(path, "#", "unmanaged_lookup_failed"))
            continue
        out.extend(Violation(prefix + n, "#", "not_in_opentofu") for n in names if n not in allowed)
    return out


def role_names(client):
    try:
        return client.request("LIST", "auth/approle/role")["data"]["keys"]
    except BaoError:
        return []


# ---- 알림 ---------------------------------------------------------------------------------------------------------

def build_alert(violations):
    lines = [v.format() for v in violations]
    shown = lines[:ALERT_MAX_LINES]
    if len(lines) > len(shown):
        shown.append("... 외 %d건" % (len(lines) - len(shown)))
    return "OpenBao Periodic Check 실패 %d건\n%s\n" % (len(violations), "\n".join(shown))


def send_alert(url, text):
    req = urllib.request.Request(url, data=text.encode("utf-8"), method="POST",
                                 headers={"Content-Type": "text/plain; charset=utf-8"})
    urllib.request.urlopen(req, timeout=TIMEOUT).close()


# ---- 진입점 -------------------------------------------------------------------------------------------------------

def run_check(environ, tofu_dir=DEFAULT_TOFU_DIR, schema_dir=ov.DEFAULT_SCHEMA_DIR, now=None):
    """종료 코드: 0 정상, 1 위반(알림 전송), 2 설정 오류."""
    now = now or datetime.now(timezone.utc)
    addr = environ.get("VAULT_ADDR")
    client = Client(addr or "", environ.get("VAULT_NAMESPACE") or "infra", environ.get("VAULT_TOKEN"))
    try:
        if not addr:
            raise KeyError
        if not client.token:
            client.login_approle(environ["VAULT_ROLE_ID"], environ["VAULT_SECRET_ID"])
        expected = expected_from_tofu(tofu_dir)
    except (KeyError, BaoError, OSError):
        print("접속 설정 오류: VAULT_ADDR와 VAULT_TOKEN(또는 VAULT_ROLE_ID·VAULT_SECRET_ID)이 필요하고, "
              "tofu 디렉터리를 읽을 수 있어야 한다", file=sys.stderr)
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
    failures.extend(_inventory_checks(client, store, listed, unread, now, warnings))
    failures.extend(check_secret_ids(client, role_names(client), now))
    failures.extend(check_unmanaged(client, expected))
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


def _inventory_checks(client, store, listed, unread, now, warnings):
    if unread & {"inventory/services/semaphore", "secrets/services/semaphore/inventory_read"}:
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
    url = (store.get("secrets/services/alert/notify") or {}).get("url")
    if not isinstance(url, str):
        print("알림 전송 불가: alert/notify 문서를 읽지 못했다", file=sys.stderr)
        return
    try:
        send_alert(url, build_alert(failures))
    except (urllib.error.URLError, OSError, ValueError) as exc:  # 예외 메시지에 URL이 들어갈 수 있어 종류만 낸다
        print("알림 전송 실패: %s" % type(exc).__name__, file=sys.stderr)
