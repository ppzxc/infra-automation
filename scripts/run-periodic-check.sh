#!/usr/bin/env bash
# Semaphore 템플릿 "[점검] 비밀 저장소 정기 점검 (OpenBao)"의 진입점 (Spec #511 / Ticket-9, #520).
# 저장소 루트에서 `openbao_docs.py check`를 돌리고 종료 코드를 그대로 낸다(0 정상, 1 실패, 2 설정 오류).
# 비0이면 Semaphore 작업이 실패 상태로 끝난다. 접속 값은 periodic_check Environment가 준다(docs/semaphore-setup.md).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 scripts/openbao_docs.py check "$@"
