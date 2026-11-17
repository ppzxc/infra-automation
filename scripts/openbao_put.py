"""`openbao_docs put` — 검증 후 쓰기 (#516, Spec #511 / Ticket-5).

`openbao_docs.py`는 이 모듈의 `register(sub)`만 부른다(하위 명령 단위 모듈 분리).

  put DOC FILE [--merge]
    DOC   `<마운트>/<문서 경로>`(예: inventory/assets/ns0001, secrets/assets/ns0001/credentials/admin01)
    FILE  입력 YAML. `inventory/`는 문서 전체다. `secrets/`는 비밀 필드를 null로 두면 getpass로 값을 받는다.
          `private_key`만 값이 아니라 개인키 파일 경로다. 비밀 필드에 값을 적으면 거부한다.
    --merge  현재 문서를 읽어 FILE을 위에 덮어 합친 뒤 전체를 검증하고 통째로 쓴다(KV v2 patch는 쓰지 않는다).

접속은 환경변수 VAULT_ADDR·VAULT_TOKEN(없으면 getpass)·VAULT_NAMESPACE(기본 infra)다. 문서의 비밀 값은 명령행 인자나
환경변수로 받지 않는다. 쓰기는 `cas=<현재 버전>`(새 문서는 0)이라 동시 수정이면 실패한다.
출력은 문서 경로·JSON 포인터·규칙 이름뿐이고 값은 내지 않는다(비밀 문서의 변경은 '변경됨'만 낸다).
종료 코드: 0 성공(변경 없음 포함), 1 거부·실패, 2 사용법·접속 설정 오류.
"""
import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import openbao_validation as ov  # noqa: E402

DEFAULT_NAMESPACE = "infra"
_ENDPOINTS_DOC = re.compile(r"^inventory/assets/([^/]+)/endpoints$")
_ASSET_DOC = re.compile(r"^inventory/assets/([^/]+)$")


class HttpError(Exception):
    def __init__(self, status, body=None):
        super().__init__(status)
        self.status = status
        self.body = body if isinstance(body, dict) else {}  # 파싱만 하고 출력하지 않는다(값이 섞일 수 있다)

    @property
    def is_cas_conflict(self):
        return self.status == 400 and any("check-and-set" in str(e) for e in self.body.get("errors") or [])


class Client:
    """KV v2 읽기·쓰기(표준 라이브러리). 응답 본문은 오류에 싣지 않는다(값이 섞일 수 있다)."""

    def __init__(self, addr, token, namespace):
        self.addr = addr.rstrip("/")
        self.headers = {"X-Vault-Token": token, "X-Vault-Namespace": namespace}
        self._cache = {}  # 한 번 실행 안의 읽기 결과(쓰기 전 새 문서·옛 문서 참조 검사가 같은 대상을 다시 읽지 않게 한다)

    def _call(self, method, doc, body=None):
        mount, _, path = doc.partition("/")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request("%s/v1/%s/data/%s" % (self.addr, mount, path), data=data, method=method,
                                     headers=dict(self.headers, **{"Content-Type": "application/json"}))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            try:
                body = json.load(exc)
            except (ValueError, OSError):
                body = None
            raise HttpError(exc.code, body) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise HttpError(0) from None

    def read_for_write(self, doc):
        """(데이터, 버전). 문서가 없으면 데이터 None. 소프트 삭제된 문서는 버전이 남아 있어(404 본문) cas에 그 버전을 써야 한다."""
        try:
            body = self._call("GET", doc)
        except HttpError as exc:
            if exc.status == 404:
                return None, ((exc.body.get("data") or {}).get("metadata") or {}).get("version", 0)
            raise
        inner = body.get("data") or {}
        return inner.get("data"), (inner.get("metadata") or {}).get("version", 0)

    def read(self, doc):
        """(데이터, 버전). 문서가 없으면 None. 같은 실행 안에서는 한 번만 읽는다."""
        if doc not in self._cache:
            data, version = self.read_for_write(doc)
            self._cache[doc] = None if data is None else (data, version)
        return self._cache[doc]

    def write(self, doc, data, cas):
        self._cache.pop(doc, None)
        self._call("POST", doc, {"options": {"cas": cas}, "data": data})


# ---- 입력 ---------------------------------------------------------------------------------------------------------

def _secret_fields(doc):
    """값을 프롬프트로 받는 필드 판별 함수. funa 비밀 문서는 키 전부가 비밀이다. private_key는 경로라 따로 다룬다."""
    if doc.startswith("secrets/services/funa/"):
        return lambda key: True
    return lambda key: key in ov.PROMPTED_KEYS and key != "private_key"


def read_input(doc, text):
    """입력 YAML을 읽는다. (데이터, 위반 목록, 값을 채울 필드 목록). secrets/ 문서의 비밀 자리는 null이어야 한다."""
    try:
        data = ov.yaml.load(text, Loader=ov._UniqueKeyLoader)
    except ov.yaml.YAMLError:
        return None, [ov.Violation(doc, "#", "yaml_parse")], []
    if not isinstance(data, dict):
        return None, [ov.Violation(doc, "#", "not_a_mapping")], []
    if not doc.startswith("secrets/"):
        return data, [], []
    is_secret, bad, prompt = _secret_fields(doc), [], []
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        pointer = ov._pointer([key])
        if key == "private_key":
            if not isinstance(value, str) or not value:
                bad.append(ov.Violation(doc, pointer, "private_key_path_required"))
        elif is_secret(key):
            if value is None:
                prompt.append(key)
            else:
                bad.append(ov.Violation(doc, pointer, "secret_value_in_file"))
    return data, bad, prompt


def _deep_merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        merged = dict(base)
        for key, value in over.items():
            merged[key] = _deep_merge(base.get(key), value) if key in base else value
        return merged
    return over


# ---- 차이 표시 ----------------------------------------------------------------------------------------------------

def _flatten(node, parts=()):
    if isinstance(node, dict) and node:
        for key, value in node.items():
            yield from _flatten(value, parts + (key,))
    else:
        yield ov._pointer(parts), node


def diff_lines(doc, old, new):
    """바뀌는 키 목록. secrets/ 문서는 값을 내지 않고 '변경됨'만 낸다."""
    before, after = dict(_flatten(old or {})), dict(_flatten(new))
    show_values = not doc.startswith("secrets/")
    lines = []
    for pointer in sorted(set(before) | set(after)):
        if pointer in before and pointer in after and before[pointer] == after[pointer]:
            continue
        mark = "+" if pointer not in before else "-" if pointer not in after else "~"
        if show_values:
            old_v = json.dumps(before.get(pointer), ensure_ascii=False)
            new_v = json.dumps(after.get(pointer), ensure_ascii=False)
            lines.append("%s %s: %s" % (mark, pointer, {"+": new_v, "-": old_v, "~": "%s -> %s" % (old_v, new_v)}[mark]))
        else:
            lines.append("%s %s (변경됨)" % (mark, pointer))
    return lines


# ---- 참조 검사 ----------------------------------------------------------------------------------------------------

def _value_at(data, pointer):
    """`#/a/b` 포인터가 가리키는 값(없으면 None)."""
    for part in pointer[2:].split("/") if pointer != "#" else []:
        part = part.replace("~1", "/").replace("~0", "~")
        data = data.get(part) if isinstance(data, dict) else data[int(part)] if isinstance(data, list) and part.isdigit() and int(part) < len(data) else None
    return data


def _names(*values):
    return [v for v in values if isinstance(v, str)]


def reference_violations(client, doc, data):
    """`data`를 `doc`에 썼을 때 그 문서가 가진 참조 위반. 참조 대상은 필요한 만큼만 읽는다(문서 목록을 읽지 않는다)."""
    store = {doc: data}
    m_ep, m_asset = _ENDPOINTS_DOC.match(doc), _ASSET_DOC.match(doc)
    if not (m_ep or m_asset) or not isinstance(data, dict):
        return []
    ns, wanted = (m_ep or m_asset).group(1), []
    if m_ep:
        for ep in data.values():
            if isinstance(ep, dict):
                become = ep.get("become") if isinstance(ep.get("become"), dict) else {}
                wanted += _names(ep.get("credential"), become.get("credential"))
        hops = [ep.get("via") for ep in data.values() if isinstance(ep, dict)]
        seen = set()
        while hops:
            via = hops.pop()
            if not isinstance(via, str) or "/" not in via:
                continue
            target = "inventory/assets/%s/endpoints" % via.split("/", 1)[0]
            if target in store or target in seen:
                continue
            seen.add(target)
            found = client.read(target)
            if found and isinstance(found[0], dict):
                store[target] = found[0]
                hops += [ep.get("via") for ep in found[0].values() if isinstance(ep, dict)]
    else:
        access = data.get("access") if isinstance(data.get("access"), dict) else {}
        wanted = _names(access.get("bootstrap_credential"), *(access.get("admin_credentials") or []))
    for name in set(wanted):
        cred_doc = "secrets/assets/%s/credentials/%s" % (ns, name)
        if client.read(cred_doc) is not None:
            store[cred_doc] = {}
    return [v for v in ov.check_references(store) if v.doc == doc]


# ---- put ----------------------------------------------------------------------------------------------------------

def _fail(message):
    print(message, file=sys.stderr)
    return 1


# 문서 경로 마디: 영숫자·_-와 점(`first.last` 같은 Operator 이름). 점만으로 된 마디(`.`, `..`)는 경로 이동이라 거부한다.
DOC_PATH_RE = re.compile(r"(?!\.+(?:/|$))[A-Za-z0-9_.-]+(/(?!\.+(?:/|$))[A-Za-z0-9_.-]+)+")


def run_put(args):
    addr = os.environ.get("VAULT_ADDR")
    if not addr:
        print("VAULT_ADDR가 필요하다", file=sys.stderr)
        return 2
    doc = args.doc.strip("/")
    if not DOC_PATH_RE.fullmatch(doc) or ov.resolve_schema(doc, args.schemas) is None:
        print(ov.Violation(doc, "#", "no_schema").format())
        return 1
    try:
        text = Path(args.file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return _fail("입력 파일을 읽을 수 없다")
    given, problems, prompt = read_input(doc, text)
    if problems:
        for v in problems:
            print(v.format())
        return 1
    try:
        return _put(args, addr, doc, given, prompt)
    except (EOFError, KeyboardInterrupt):
        return _fail("입력을 받지 못해 취소했다")


def _put(args, addr, doc, given, prompt):
    token = os.environ.get("VAULT_TOKEN") or getpass.getpass("token: ")
    client = Client(addr, token, os.environ.get("VAULT_NAMESPACE") or DEFAULT_NAMESPACE)
    try:
        old, version = client.read_for_write(doc)
        if "private_key" in given and doc.startswith("secrets/"):
            try:
                given["private_key"] = Path(given["private_key"]).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return _fail("private_key 파일을 읽을 수 없다")
        new = _deep_merge(old, given) if args.merge and old is not None else given
        # 값을 입력받기 전에 검증한다(null 자리는 자리표시자로 본다). 입력 실수로 값을 다시 치게 하지 않는다.
        violations = ov.validate_document(doc, new, args.schemas)
        if violations:
            for v in violations:
                print(v.format())
            return 1
        after = set(reference_violations(client, doc, new))
        before = set(reference_violations(client, doc, old)) if old is not None else set()
        # 이미 깨져 있던 참조라도 같은 자리가 다른 값을 가리키게 바뀌었으면 새로 깨뜨린 것으로 본다.
        stale = {v for v in after & before if _value_at(old, v.pointer) == _value_at(new, v.pointer)}
        blocking = sorted(after - stale)
        for v in sorted(stale):
            print("경고(이미 깨져 있음)\t" + v.format(), file=sys.stderr)
        if blocking:
            for v in blocking:
                print(v.format())
            return 1
        for key in prompt:
            value = getpass.getpass("%s: " % key)
            if not value:
                return _fail("빈 값은 쓸 수 없다")
            new[key] = value
        violations = ov.validate_document(doc, new, args.schemas)  # 실제 값으로 다시 검증한다(길이·형식 규칙)
        if violations:
            for v in violations:
                print(v.format())
            return 1
        lines = diff_lines(doc, old, new)
        if not lines:
            print("변경 없음", file=sys.stderr)
            return 0
        print("\n".join(lines))
        try:
            answer = input("%s 문서를 쓸까요? [y/N] " % doc)
        except (EOFError, KeyboardInterrupt):
            return _fail("확인을 받지 못해 취소했다")
        if answer.strip().lower() not in ("y", "yes"):
            return _fail("취소했다")
        try:
            client.write(doc, new, version)
        except HttpError as exc:
            if exc.is_cas_conflict:
                return _fail("conflict: 읽은 뒤 다른 쪽이 문서를 바꿨다(cas). 다시 읽고 시도한다")
            raise
    except HttpError as exc:
        return _fail("OpenBao 요청 실패: HTTP %s" % (exc.status or "연결 불가"))
    print("썼다: %s (버전 %d)" % (doc, version + 1), file=sys.stderr)
    return 0


def register(sub):
    p = sub.add_parser("put", help="검증 후 OpenBao에 쓰기(operator 토큰)")
    p.add_argument("doc", help="<마운트>/<문서 경로>")
    p.add_argument("file", help="입력 YAML 경로")
    p.add_argument("--merge", action="store_true", help="현재 문서에 합친 뒤 전체를 검증해 쓴다")
    p.add_argument("--schemas", default=str(ov.DEFAULT_SCHEMA_DIR), help="스키마 디렉터리(기본: schemas/openbao)")
    p.set_defaults(func=run_put)
