"""CI 샤딩: TEST_SHARD="<번호>/<전체>"(예: "2/4")이면 그 몫의 테스트만 수집한다.

nodeid의 crc32로 나누므로 xdist 워커마다 따로 수집해도 같은 결과가 나온다.
환경 변수가 없으면 아무것도 하지 않는다.
"""
import os
import zlib


def pytest_collection_modifyitems(config, items):
    spec = os.environ.get("TEST_SHARD")
    if not spec:
        return
    index, total = (int(part) for part in spec.split("/"))
    if not 1 <= index <= total:
        raise SystemExit(f"TEST_SHARD={spec!r}: 번호는 1 이상 전체 이하여야 한다")
    keep = [item for item in items if zlib.crc32(item.nodeid.encode()) % total == index - 1]
    config.hook.pytest_deselected(items=[item for item in items if item not in keep])
    items[:] = keep
