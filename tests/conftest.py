"""테스트 수집 훅.

1. 자동 slow 표시(#349): `ansible-playbook`을 실제로 실행하는 테스트는 손으로 marker를 달지 않아도 `slow`가 된다.
   모듈 소스를 AST로 읽어 "ansible-playbook" 문자열을 쓰는 함수를 찾고, 그 함수를 (헬퍼·fixture 호출로) 직접·간접
   참조하는 테스트를 표시한다. 커밋 hook은 `pytest -m "not slow"`만 돌린다.
2. CI 샤딩: TEST_SHARD="<번호>/<전체>"(예: "2/4")이면 그 몫의 테스트만 수집한다.
   nodeid의 crc32로 나누므로 xdist 워커마다 따로 수집해도 같은 결과가 나온다. 환경 변수가 없으면 아무것도 하지 않는다.
"""
import ast
import os
import zlib
from functools import lru_cache

import pytest

RUNNER = "ansible-playbook"


@lru_cache(maxsize=None)
def _parse(path):
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read(), path)


def _sibling(path, module):
    """같은 디렉터리의 테스트 모듈 파일 경로(없으면 None)."""
    candidate = os.path.join(os.path.dirname(path), module + ".py")
    return candidate if os.path.exists(candidate) else None


@lru_cache(maxsize=None)
def _slow_functions(path):
    """모듈에서 ansible-playbook을 (간접적으로) 실행하는 최상위 함수 이름 집합.

    같은 디렉터리의 다른 테스트 모듈을 `import x as y`/`from x import f`로 쓰는 경우도 따라간다(순환 import 없음 가정).
    """
    tree = _parse(path)
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    aliases, imported = {}, {}  # 별칭 -> 모듈 경로 / 이름 -> (모듈 경로, 원래 이름)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if (target := _sibling(path, a.name)):
                    aliases[a.asname or a.name] = target
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if (target := _sibling(path, node.module)):
                for a in node.names:
                    imported[a.asname or a.name] = (target, a.name)
    # `_play = el7._play`, `a, b = el7.a, el7.b` 같은 모듈 수준 별칭도 함수처럼 다룬다.
    units = [(fn.name, fn, [a.arg for a in fn.args.args + fn.args.kwonlyargs]) for fn in funcs]
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
            if isinstance(target, ast.Name):
                units.append((target.id, value, []))
            elif isinstance(target, ast.Tuple) and isinstance(value, ast.Tuple) and len(target.elts) == len(value.elts):
                units += [(t.id, v, []) for t, v in zip(target.elts, value.elts) if isinstance(t, ast.Name)]
    direct, refs = set(), {}
    for unit_name, fn, args in units:
        names = set(args)  # fixture 이름은 인자로 들어온다
        external = False
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and node.value == RUNNER:
                direct.add(unit_name)
            elif isinstance(node, ast.Name):
                names.add(node.id)
                if node.id in imported and imported[node.id][1] in _slow_functions(imported[node.id][0]):
                    external = True
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
                if node.attr in _slow_functions(aliases[node.value.id]):
                    external = True
        if external:
            direct.add(unit_name)
        refs[unit_name] = names
    slow = set(direct)
    changed = True
    while changed:
        changed = False
        for name, used in refs.items():
            if name not in slow and used & slow:
                slow.add(name)
                changed = True
    return frozenset(slow)


def _mark_slow(items):
    for item in items:
        func = getattr(item, "function", None)
        if func is None or item.get_closest_marker("slow"):
            continue
        path = str(item.path)
        used = {func.__name__, *getattr(item, "fixturenames", ())}
        if used & _slow_functions(path):
            item.add_marker(pytest.mark.slow)


def pytest_collection_modifyitems(config, items):
    _mark_slow(items)
    spec = os.environ.get("TEST_SHARD")
    if not spec:
        return
    index, total = (int(part) for part in spec.split("/"))
    if not 1 <= index <= total:
        raise SystemExit(f"TEST_SHARD={spec!r}: 번호는 1 이상 전체 이하여야 한다")
    keep = [item for item in items if zlib.crc32(item.nodeid.encode()) % total == index - 1]
    config.hook.pytest_deselected(items=[item for item in items if item not in keep])
    items[:] = keep
