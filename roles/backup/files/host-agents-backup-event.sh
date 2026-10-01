#!/bin/sh
# Ansible managed — resticprofile 훅이 호출하는 백업 결과 방출기 (ADR-0006 §2.6). POSIX 도구만 사용한다(jq 없음).
#
#   host-agents-backup-event start          run-before: 시작 시각 기록 (duration 계산용)
#   host-agents-backup-event finish <host>  run-finally: backup.jsonl에 한 줄 JSON append
#
# resticprofile이 run-finally 훅에 주는 환경 변수: PROFILE_COMMAND, ERROR(실패 시에만), ERROR_EXIT_CODE.
# 방출 필드(알림 계약, docs/backup.md §6): job, host, command, success, exit_code, duration, error, ts
# 방출 실패가 백업 자체를 실패시키지 않도록 항상 0으로 종료한다.
export LC_ALL=C
LOG="${BACKUP_EVENT_LOG:-/var/log/host-agents/backup.jsonl}"
START_FILE="${BACKUP_EVENT_START_FILE:-/var/lib/host-agents/backup.start}"

# 출력 가능한 ASCII만 남기고 JSON 문자열 이스케이프, 500바이트로 제한한다.
json_str() {
    printf '%s' "$1" | tr -c '\040-\176' ' ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | cut -c1-500
}

case "$1" in
start)
    date +%s > "$START_FILE" 2>/dev/null
    ;;
finish)
    host=$(json_str "${2:-unknown}")
    command=$(json_str "${PROFILE_COMMAND:-backup}")
    now=$(date +%s)
    start=$(cat "$START_FILE" 2>/dev/null)
    case "$start" in ''|*[!0-9]*) start=$now ;; esac
    duration=$((now - start))
    [ "$duration" -ge 0 ] || duration=0
    if [ -z "${ERROR:-}" ]; then
        success=true
        exit_code=0
        error=
    else
        success=false
        exit_code="${ERROR_EXIT_CODE:-1}"
        case "$exit_code" in ''|*[!0-9]*) exit_code=1 ;; esac
        error=$(json_str "$ERROR")
    fi
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '{"job":"backup","host":"%s","command":"%s","success":%s,"exit_code":%s,"duration":%s,"error":"%s","ts":"%s"}\n' \
        "$host" "$command" "$success" "$exit_code" "$duration" "$error" "$ts" >> "$LOG" 2>/dev/null
    rm -f "$START_FILE" 2>/dev/null
    ;;
esac
exit 0
