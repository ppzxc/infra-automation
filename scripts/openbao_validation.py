"""OpenBao 문서 검증 코어 (#515, Spec #511).

`openbao_docs.py`의 `validate`와 이후 `put`·`check`, 이전 스크립트가 같이 쓰는 import 가능한 모듈이다.
네트워크를 쓰지 않는다. 문서는 `{문서 경로: 데이터}` 딕셔너리(store)로 다룬다. 문서 경로는 `<마운트>/<경로>`이고
`schemas/openbao/index.yml`의 패턴과 맞춘다(예: `inventory/assets/ns0001/endpoints`).

출력 규칙(Spec #511 §6): 오류는 문서 경로 + JSON 포인터 + 규칙 이름만 낸다. jsonschema의 기본 메시지에는 위반한
값이 들어가므로 쓰지 않는다. 마운트를 가리지 않고 값은 어디에도 내지 않는다.
"""
import collections
import functools
import json
from pathlib import Path

import jsonschema
import yaml

DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "openbao"
PLACEHOLDER = "<prompted>"  # secrets/ YAML에서 값 자리(null)는 getpass로 채워질 값이다.
# null을 값 자리로 인정하는 필드: 비밀 값만이다. 그 밖의 필드(username, type 등)는 null이면 스키마 위반이다.
PROMPTED_KEYS = frozenset({"password", "passphrase", "private_key", "token", "secret_key", "access_key", "url",
                           "ingest_token", "rustfs_access_key", "rustfs_secret_key", "restic_password",
                           "webhook_secret"})


class Violation(collections.namedtuple("Violation", "doc pointer rule")):
    def format(self):
        doc = "".join(c if c.isprintable() else "?" for c in self.doc)  # 제어 문자가 출력 줄 구조를 깨지 않게 한다
        return "%s\t%s\t%s" % (doc, self.pointer, self.rule)


class _UniqueKeyLoader(yaml.SafeLoader):
    """중복 키를 거부하는 로더(마지막 값만 남아 위반이 가려지는 일을 막는다)."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.tag != "tag:yaml.org,2002:merge":
                ident = (key_node.tag, key_node.value)  # 구성한 값이 아니라 표기로 비교한다(1과 true는 서로 다른 키)
                if ident in seen:
                    raise yaml.YAMLError("duplicate key")
                seen.add(ident)
        return super().construct_mapping(node, deep)


class Unparseable:
    """YAML로 읽을 수 없는 파일. 내용은 보관하지 않는다."""


def _pointer(parts):
    return "#" + "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


# ---- index.yml ---------------------------------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _read_index(index_path, mtime_ns):
    data = yaml.load(Path(index_path).read_text(encoding="utf-8"), Loader=_UniqueKeyLoader) or {}
    if not isinstance(data, dict):
        raise ValueError("index.yml은 패턴 -> 스키마 매핑이어야 한다")
    return tuple(data.items())


def load_index(schema_dir=DEFAULT_SCHEMA_DIR):
    """[(경로 패턴, 스키마 상대 경로)] 목록. 파일이 바뀌면(mtime) 다시 읽는다."""
    index = Path(schema_dir) / "index.yml"
    return list(_read_index(str(index), index.stat().st_mtime_ns))


def _matches(pattern, doc_path):
    pat, doc = pattern.split("/"), doc_path.split("/")
    return len(pat) == len(doc) and all(p == "+" and d != "" or p == d for p, d in zip(pat, doc))


def resolve_schema(doc_path, schema_dir=DEFAULT_SCHEMA_DIR):
    """문서 경로에 맞는 스키마 상대 경로. 없으면 None. 패턴 둘 이상에 맞으면 index.yml 오류로 보고 예외."""
    hits = [rel for pattern, rel in load_index(schema_dir) if _matches(pattern, doc_path)]
    if len(hits) > 1:
        raise ValueError("index.yml의 패턴이 겹친다: %s" % doc_path)
    return hits[0] if hits else None


@functools.lru_cache(maxsize=None)
def _build_validator(schema_path, mtime_ns):
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _validator(schema_path):
    return _build_validator(schema_path, Path(schema_path).stat().st_mtime_ns)


# ---- 스키마 검증 ---------------------------------------------------------------------------------------------------

def _fill_placeholders(doc_path, node):
    """secrets/ 문서의 비밀 필드 null(값 자리)을 자리표시자로 바꾼다. funa 비밀 문서는 키 전부가 비밀 값이다."""
    if not isinstance(node, dict):
        return node
    every = doc_path.startswith("secrets/services/funa/")
    return {k: (PLACEHOLDER if v is None and (every or k in PROMPTED_KEYS) else v) for k, v in node.items()}


def _leaf_errors(error):
    """(포인터 조각 목록, 규칙 이름). oneOf 실패는 `type`이 가리키는 가지의 오류로 풀고, 맞는 가지가 없으면 `type` 필드를 짚는다."""
    path = list(error.absolute_path)
    if error.validator == "oneOf" and error.context and isinstance(error.instance, dict):
        want = error.instance.get("type")
        branches = [i for i, b in enumerate(error.validator_value)
                    if b.get("properties", {}).get("type", {}).get("const") == want]
        inner = [e for e in error.context if e.schema_path[0] in branches]
        if inner:
            for e in inner:
                yield from _leaf_errors(e)
            return
        if not branches:
            yield path + ["type"], "oneOf"
            return
    yield path, error.validator


def _non_string_key_paths(node, path):
    """문자열이 아닌 매핑 키(22:, true: 등)를 가진 객체의 포인터 조각 목록. jsonschema가 정규식에서 죽는 입력이다."""
    found = []
    if isinstance(node, dict):
        if any(not isinstance(k, str) for k in node):
            found.append(path)
        for k, v in node.items():
            if isinstance(k, str):
                found.extend(_non_string_key_paths(v, path + [k]))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_non_string_key_paths(v, path + [i]))
    return found


def validate_document(doc_path, data, schema_dir=DEFAULT_SCHEMA_DIR):
    """문서 하나를 스키마로 검증한다. [Violation]."""
    rel = resolve_schema(doc_path, schema_dir)
    if rel is None:
        return [Violation(doc_path, "#", "no_schema")]
    if isinstance(data, Unparseable):
        return [Violation(doc_path, "#", "yaml_parse")]
    if doc_path.startswith("secrets/"):
        data = _fill_placeholders(doc_path, data)
    bad_keys = _non_string_key_paths(data, [])
    if bad_keys:
        return [Violation(doc_path, _pointer(p), "non_string_key") for p in bad_keys]
    out = []
    for error in _validator(str(Path(schema_dir) / rel)).iter_errors(data):
        for parts, rule in _leaf_errors(error):
            out.append(Violation(doc_path, _pointer(parts), rule))
    return sorted(set(out))


# ---- 참조 검사 ----------------------------------------------------------------------------------------------------

def _split(doc_path):
    return doc_path.split("/")


def _credential_names(store):
    names = collections.defaultdict(set)
    for path in store:
        p = _split(path)
        if len(p) == 5 and p[:2] == ["secrets", "assets"] and p[3] == "credentials":
            names[p[2]].add(p[4])
    return names


def check_references(store, skip=()):
    """문서 사이 참조 검사: via 대상 존재·순환, credential·become.credential 존재, access의 Credential 이름 존재.

    스키마 위반 문서(`skip`)의 오류는 스키마 검증이 내므로 여기서는 보고하지 않는다(다른 문서의 via 대상으로는 쓴다). [Violation].
    """
    creds = _credential_names(store)
    endpoints = {}  # (ns, 이름) -> Endpoint dict
    for path, data in store.items():
        p = _split(path)
        if len(p) == 4 and p[:2] == ["inventory", "assets"] and p[3] == "endpoints" and isinstance(data, dict):
            for name, ep in data.items():
                if isinstance(ep, dict):
                    endpoints[(p[2], name)] = ep
    out = []

    def next_hop(ep):
        via = ep.get("via")
        return tuple(via.split("/", 1)) if isinstance(via, str) and "/" in via else None

    for (ns, name), ep in endpoints.items():
        doc = "inventory/assets/%s/endpoints" % ns
        if doc in skip:  # 스키마 위반 문서의 오류는 스키마 검증이 낸다. 다른 문서의 via 대상으로만 쓴다.
            continue
        if ep.get("credential") not in creds[ns]:
            out.append(Violation(doc, _pointer([name, "credential"]), "credential_missing"))
        become_cred = (ep.get("become") or {}).get("credential")
        if become_cred is not None and become_cred not in creds[ns]:
            out.append(Violation(doc, _pointer([name, "become", "credential"]), "become_credential_missing"))
        hop = next_hop(ep)
        if hop is None:
            continue
        if hop not in endpoints:
            out.append(Violation(doc, _pointer([name, "via"]), "via_missing"))
            continue
        seen, cur = set(), hop
        while cur is not None and cur in endpoints and cur not in seen:
            if cur == (ns, name):
                out.append(Violation(doc, _pointer([name, "via"]), "via_cycle"))
                break
            seen.add(cur)
            cur = next_hop(endpoints[cur])

    for path, data in store.items():
        p = _split(path)
        if len(p) == 3 and p[:2] == ["inventory", "assets"] and path not in skip and isinstance(data, dict):
            access = data.get("access") or {}
            for i, name in enumerate(access.get("admin_credentials") or []):
                if name not in creds[p[2]]:
                    out.append(Violation(path, _pointer(["access", "admin_credentials", i]), "access_credential_missing"))
            boot = access.get("bootstrap_credential")
            if boot is not None and boot not in creds[p[2]]:
                out.append(Violation(path, _pointer(["access", "bootstrap_credential"]), "access_credential_missing"))
    return sorted(set(out))


def validate_store(store, schema_dir=DEFAULT_SCHEMA_DIR):
    """스키마 검증 뒤 참조 검사. 스키마를 어긴 문서는 참조 검사에서 뺀다. [Violation]."""
    out, bad = [], set()
    for path in sorted(store):
        found = validate_document(path, store[path], schema_dir)
        if found:
            bad.add(path)
        out.extend(found)
    out.extend(check_references(store, skip=bad))
    return sorted(set(out))


# ---- 로컬 트리 -----------------------------------------------------------------------------------------------------

def load_tree(root):
    """`root` 아래 `<마운트>/<경로>.yml`을 {문서 경로: 데이터}로 읽는다. 읽을 수 없는 파일은 Unparseable."""
    root = Path(root)
    store = {}
    for f in sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml"))):
        doc = f.relative_to(root).with_suffix("").as_posix()
        if f.suffix != ".yml" or doc in store:  # .yaml은 문서로 인정하지 않는다(조용히 건너뛰지 않고 위반으로 낸다)
            store[doc] = Unparseable()
            continue
        try:
            store[doc] = yaml.load(f.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        except (yaml.YAMLError, UnicodeDecodeError, OSError, TypeError):
            store[doc] = Unparseable()
    return store
