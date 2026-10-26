"""렌더 테스트와 config 테스트가 서로를 import하지 않고 공용 모듈(`o2c_*`)로만 이어지는지 지킨다(#348)."""
import ast
from pathlib import Path

TESTS = Path(__file__).parent


def _imports(name):
    tree = ast.parse((TESTS / name).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_render_tests_do_not_import_the_config_test_module():
    assert "test_openobserve_config" not in _imports("test_openobserve_render.py")


def test_shared_alert_helpers_do_not_import_any_test_module():
    assert not {m for m in _imports("o2c_alert_helpers.py") if m.startswith("test_")}
