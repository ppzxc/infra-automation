#!/usr/bin/env bash
# 커밋 hook용 빠른 테스트(#349): ansible-playbook을 실행하는 slow 테스트는 PR의 CI가 돌린다.
# pytest-xdist·pytest-timeout이 없는 환경에서도 인자 오류로 죽지 않게 플러그인을 확인하고 옵션을 붙인다.
# -m은 pytest.ini의 addopts(-m "not heavy_harness")를 덮어쓰므로 heavy_harness 제외를 함께 적는다.
set -euo pipefail
cd "$(dirname "$0")/.."

args=(tests/ -m "not slow and not heavy_harness" -q --durations=10 -p no:cacheprovider)
if python3 -c "import xdist" 2>/dev/null; then
  args+=(-n 4)
else
  echo "[i] pytest-xdist 없음 — 직렬 실행. 'pip install -r requirements-test.txt'로 설치하세요."
fi
if python3 -c "import pytest_timeout" 2>/dev/null; then
  args+=(--timeout=300)
else
  echo "[i] pytest-timeout 없음 — 테스트별 시간 제한 없이 실행합니다."
fi
exec python3 -m pytest "${args[@]}" "$@"
