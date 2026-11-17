"""OpenBao 문서 검증 코어 (#515, Spec #511).

`openbao_docs.py`의 `validate`와 이후 `put`·`check`, 이전 스크립트가 같이 쓰는 import 가능한 모듈이다.
네트워크를 쓰지 않는다. 문서는 `{문서 경로: 데이터}` 딕셔너리(store)로 다룬다. 문서 경로는 `<마운트>/<경로>`이고
`schemas/openbao/index.yml`의 패턴과 맞춘다(예: `inventory/assets/ns0001/endpoints`).

출력 규칙(Spec #511 §6): 오류는 문서 경로 + JSON 포인터 + 규칙 이름만 낸다. jsonschema의 기본 메시지에는 위반한
값이 들어가므로 쓰지 않는다. 마운트를 가리지 않고 값은 어디에도 내지 않는다.
"""
import collections
import functools
from pathlib import Path

import jsonschema
import yaml

DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "openbao"
PLACEHOLDER = "<prompted>"  # secrets/ YAML에서 값 자리(null)는 getpass로 채워질 값이다.


class Violation(collections.namedtuple("Violation", "doc pointer rule")):
    def format(self):
        return "%s\t%s\t%s" % (self.doc, self.pointer, self.rule)


class Unparseable:
    """YAML로 읽을 수 없는 파일. 내용은 보관하지 않는다."""


def _pointer(parts):
    return "#" + "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


# ---- index.yml ---------------------------------------------------------------------------------------------------

def load_index(schema_dir=DEFAULT_SCHEMA_DIR):
    """[(경로 패턴, 스키마 상대 경로)] 목록."""
    data = yaml.safe_load((Path(schema_dir) / "index.yml").read_text(encoding="utf-8")) or {}
    return list(data.items())


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
def _validator(schema_path):
    import json
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


# ---- 스키마 검증 ---------------------------------------------------------------------------------------------------

def _fill_placeholders(node):
    if isinstance(node, dict):
        return {k: (PLACEHOLDER if v is None else _fill_placeholders(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [PLACEHOLDER if v is None else _fill_placeholders(v) for v in node]
    return node


def _leaf_errors(error, data):
    """oneOf 실패는 `type`이 가리키는 가지의 오류로 풀어, 어느 필드가 문제인지 알려 준다."""
    if error.validator == "oneOf" and error.context and isinstance(error.instance, dict):
        want = error.instance.get("type")
        branches = [i for i, b in enumerate(error.validator_value)
                    if b.get("properties", {}).get("type", {}).get("const") == want]
        inner = [e for e in error.context if e.schema_path[0] in branches]
        if inner:
            for e in inner:
                yield from _leaf_errors(e, data)
            return
    yield error


def validate_document(doc_path, data, schema_dir=DEFAULT_SCHEMA_DIR):
    """문서 하나를 스키마로 검증한다. [Violation]."""
    rel = resolve_schema(doc_path, schema_dir)
    if rel is None:
        return [Violation(doc_path, "#", "no_schema")]
    if isinstance(data, Unparseable):
        return [Violation(doc_path, "#", "yaml_parse")]
    if doc_path.startswith("secrets/"):
        data = _fill_placeholders(data)
    out = []
    for error in _validator(str(Path(schema_dir) / rel)).iter_errors(data):
        for leaf in _leaf_errors(error, data):
            out.append(Violation(doc_path, _pointer(leaf.absolute_path), leaf.validator))
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

    스키마 위반 문서(`skip`)는 모양을 믿을 수 없어 건너뛴다. [Violation].
    """
    creds = _credential_names(store)
    endpoints = {}  # (ns, 이름) -> Endpoint dict
    for path, data in store.items():
        p = _split(path)
        if len(p) == 4 and p[:2] == ["inventory", "assets"] and p[3] == "endpoints" and path not in skip \
                and isinstance(data, dict):
            for name, ep in data.items():
                endpoints[(p[2], name)] = ep
    out = []

    def next_hop(ep):
        via = ep.get("via")
        return tuple(via.split("/", 1)) if via else None

    for (ns, name), ep in endpoints.items():
        doc = "inventory/assets/%s/endpoints" % ns
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
        try:
            store[doc] = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            store[doc] = Unparseable()
    return store
