#!/usr/bin/env bash
# Ansible managed — OpenObserve 생존 확인 (Spec #184 / Ticket-7).
# OpenObserve 헬스 엔드포인트가 실패하면 OpenObserve를 거치지 않고 네이버웍스 webhook으로 직접 P1을 보낸다.
# 같은 장애는 O2_HEALTH_RENOTIFY_MINUTES(기본 60)마다만 다시 통지하고, 복구되면 상태를 지운다(복구 통지 없음).
# 설정은 env 파일(O2_HEALTH_ENV_FILE, 기본 /etc/openobserve-health/env, 0600)에서 읽는다.
# 수동 검증: O2_HEALTH_URL_OVERRIDE=http://127.0.0.1:1/healthz 로 한 번 실행하면 통지가 도착해야 한다.
set -u

ENV_FILE="${O2_HEALTH_ENV_FILE:-/etc/openobserve-health/env}"
# shellcheck disable=SC1090
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

HEALTH_URL="${O2_HEALTH_URL_OVERRIDE:-${O2_HEALTH_URL:-}}"
STATE_DIR="${O2_HEALTH_STATE_DIR:-/var/lib/openobserve-health}"
RENOTIFY_MIN="${O2_HEALTH_RENOTIFY_MINUTES:-60}"
MARKER="$STATE_DIR/notified"

# 설정 누락은 조용히 넘기지 않는다: 어느 값이 없는지 stderr(journal)에 남기고 0이 아닌 종료코드로
# systemd 유닛을 failed로 만든다(생존 확인이 꺼진 채 방치되지 않게).
missing=()
[ -z "$HEALTH_URL" ] && missing+=(O2_HEALTH_URL)
[ -z "${O2_WEBHOOK_URL:-}" ] && missing+=(O2_WEBHOOK_URL)
if [ "${#missing[@]}" -gt 0 ]; then
  echo "openobserve-health: 설정 누락 (${missing[*]}) — $ENV_FILE 를 확인하세요. 생존 확인이 동작하지 않습니다" >&2
  exit 2
fi

CACERT=()
[ -n "${O2_HEALTH_CA_FILE:-}" ] && CACERT=(--cacert "$O2_HEALTH_CA_FILE")

if curl -fsS -o /dev/null --max-time 10 "${CACERT[@]}" "$HEALTH_URL" 2>/dev/null; then
  rm -f "$MARKER"
  exit 0
fi

# 같은 장애의 재통지 억제: 마지막 통지 후 RENOTIFY_MIN분이 지나지 않았으면 조용히 끝낸다.
if [ -e "$MARKER" ]; then
  age=$(( $(date +%s) - $(stat -c %Y "$MARKER") ))
  [ "$age" -lt $(( RENOTIFY_MIN * 60 )) ] && exit 0
fi

host="$(hostname -s 2>/dev/null || echo unknown)"
text="🔴 [P1 긴급] OpenObserve 응답 없음\\n\\n■ 무슨 일: OpenObserve 헬스 확인이 실패했습니다 (검사 호스트 ${host}).\\n■ 왜 중요: OpenObserve가 죽으면 알림 시스템 자체가 동작하지 않아 다른 장애도 통지되지 않습니다.\\n■ 대상: ${HEALTH_URL%%\\?*}\\n■ 조치: ① ns0332에서 OpenObserve 서비스·디스크·메모리 확인 ② 복구 후 Host Agents 수집 재개와 Silent Host 알림 확인\\n\\n▶ 런북: https://github.com/ppzxc/infra-automation/blob/main/docs/runbooks/alerts.md#openobserve-health"
body="{\"content\": {\"type\": \"text\", \"text\": \"${text}\"}}"

# webhook URL·토큰이 프로세스 목록에 보이지 않도록 curl 설정을 stdin으로 넘긴다.
{
  printf 'url = "%s"\n' "$O2_WEBHOOK_URL"
  printf 'header = "Content-Type: application/json"\n'
  [ -n "${O2_WEBHOOK_TOKEN:-}" ] && printf 'header = "%s: %s"\n' "${O2_WEBHOOK_AUTH_HEADER:-Authorization}" "$O2_WEBHOOK_TOKEN"
} | curl -fsS -o /dev/null --max-time 15 -K - --data-binary "$body" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "openobserve-health: webhook 통지 실패 (curl rc=$rc) — 다음 실행에서 재시도합니다" >&2
  exit 1
fi

mkdir -p "$STATE_DIR"
touch "$MARKER"
exit 0
