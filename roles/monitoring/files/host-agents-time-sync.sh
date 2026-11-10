#!/bin/sh
# Ansible managed — 시각 동기 수집기 (Spec #322 / Ticket-14, #336).
#
# cron이 5분마다 root로 실행한다. 읽기 전용이다: 서버에 이미 있는 chronyc → ntpq → timedatectl 중 처음으로 답하는 도구의
# 출력만 읽고, 시각을 맞추거나 서비스를 건드리지 않으며 아무것도 설치하지 않는다.
# 네 번째 도구 rdate는 그 호스트의 cron이 이미 `rdate`로 시각을 맞추는 경우에만 쓴다(ntpd 없이 하루 한 번 맞추는 CentOS 6).
# 이때도 `rdate -p`(조회만, 시계를 바꾸지 않음)로 cron에 적힌 그 서버의 시각을 읽어 편차를 낸다. 정밀도는 1초다.
# 결과는 JSON 한 줄(kind=time_sync)을 time-sync.jsonl에 append하고, otelcol(filelog/host_status_logs)이 읽는다.
#
#   sync_status: synced | unsynced | no_tool | error
#     synced    도구가 시계가 동기됐다고 답함
#     unsynced  동기 안 됐다고 답했거나, 도구는 있는데 데몬이 답하지 않음(message에 이유)
#     no_tool   시각 동기 도구가 하나도 없음
#     error     도구 호출이 제한 시간 안에 끝나지 않음
#   offset_ms: 시스템 시각 − 기준 시각(밀리초, 부호 있음). 도구가 오차를 주지 않거나 동기 안 됐으면 null.
#   synced는 true/false(no_tool·error면 null). 모든 필드는 항상 내보낸다. 어떤 경우에도 종료 코드는 0이다.
#
# POSIX sh + POSIX awk만 쓴다(CentOS 6 gawk 3.1, Ubuntu mawk). timedatectl은 로캘에 따라 라벨이 바뀌므로 C로 고정한다.
export LC_ALL=C
# TIME_SYNC_PATH는 시험용(가짜 도구 디렉터리를 앞에 둔다). 운영 cron은 쓰지 않는다.
PATH="${TIME_SYNC_PATH:+$TIME_SYNC_PATH:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

LOG="${TIME_SYNC_LOG:-/var/log/host-agents/time-sync.jsonl}"
TIMEOUT="${TIME_SYNC_TIMEOUT:-20}"
TOOLS="${TIME_SYNC_TOOLS:-chronyc ntpq timedatectl rdate}"
# rdate 방식 판별에 읽는 cron 파일(시험용으로 바꿀 수 있다). 따옴표 없이 펼쳐 글롭을 허용한다.
CRON_FILES="${TIME_SYNC_CRON_FILES:-/etc/crontab /etc/cron.d/* /var/spool/cron/*}"

ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id="t-$(date +%s)-$$"

# 출력 가능한 ASCII만 남기고 JSON 문자열 이스케이프, 200바이트로 제한한다.
json_str() {
    printf '%s' "$1" | tr -c '\040-\176' ' ' | cut -c1-200 | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# 한 줄 방출: $1=status $2=tool $3=synced(true|false|null) $4=offset_ms(숫자|null) $5=stratum(숫자|null) $6=message
emit() {
    printf '{"ts":"%s","schema":1,"run_id":"%s","kind":"time_sync","family":"timesync","tool":"%s","sync_status":"%s","synced":%s,"offset_ms":%s,"stratum":%s,"message":"%s"}\n' \
        "$ts" "$run_id" "$(json_str "$2")" "$1" "$3" "$4" "$5" "$(json_str "$6")" >> "$LOG" 2>/dev/null
}

# CentOS 6의 coreutils 8.4 timeout에는 -k(TERM 뒤 KILL)가 없다. 지원할 때만 붙인다.
if command -v timeout >/dev/null 2>&1; then
    if timeout -k 1 5 true >/dev/null 2>&1; then
        TIMEOUT_CMD="timeout -k 5 $TIMEOUT"
    else
        TIMEOUT_CMD="timeout $TIMEOUT"
    fi
else
    TIMEOUT_CMD=
fi
run() {
    # shellcheck disable=SC2086 # TIMEOUT_CMD는 의도적으로 단어 분리한다
    $TIMEOUT_CMD "$@"
}

mkdir -p "${LOG%/*}" 2>/dev/null
tmp_out=$(mktemp "${TMPDIR:-/tmp}/time-sync.XXXXXX") || exit 0
trap 'rm -f "$tmp_out"' EXIT

# 프로브는 답을 얻으면 answered=1과 r_synced·r_offset·r_stratum·r_message를 채운다.
# 도구 호출이 시간 초과(종료 코드 124·137)면 timed_out=1로 남긴다.
answered=
timed_out=
r_synced=null; r_offset=null; r_stratum=null; r_message=

probe_chronyc() {
    run chronyc tracking > "$tmp_out" 2>&1
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=1; return; fi
    [ "$rc" -eq 0 ] && grep -q '^Leap status' "$tmp_out" || return
    parsed=$(awk '
        /^Leap status/ { sub(/^Leap status[ \t]*:[ \t]*/, ""); leap = $0 }
        /^Stratum/ { st = $3 }
        /^System time/ { off = $4; dir = $6 }
        END {
            ms = off * 1000
            if (dir == "slow") ms = -ms
            printf "%s|%s|%.3f\n", leap, st, ms
        }' "$tmp_out")
    leap=${parsed%%|*}; rest=${parsed#*|}; st=${rest%%|*}; ms=${rest#*|}
    answered=1
    case "$leap" in
        *[Nn]ot*) r_synced=false; r_message="chronyd reports: $leap" ;;
        *)        r_synced=true; r_offset=$ms
                  case "$st" in ''|*[!0-9]*) ;; *) r_stratum=$st ;; esac ;;
    esac
}

probe_ntpq() {
    run ntpq -pn > "$tmp_out" 2>&1
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=1; return; fi
    # ntpd가 꺼져 있으면 "Connection refused"를 내고도 종료 코드 0일 수 있다. 머리줄(remote)이 있어야 답한 것이다.
    grep -q '^[ ]*remote' "$tmp_out" || return
    parsed=$(awk '
        /^[*o]/ { st = $3; off = $9; found = 1 }
        END { if (found) printf "%s|%s\n", st, off }' "$tmp_out")
    answered=1
    if [ -z "$parsed" ]; then
        r_synced=false; r_message="ntpd has no selected peer"
        return
    fi
    r_synced=true
    st=${parsed%%|*}; off=${parsed#*|}
    case "$st" in ''|*[!0-9]*) ;; *) r_stratum=$st ;; esac
    case "$off" in ''|*[!0-9.+-]*) r_synced=false; r_message="unreadable ntpq offset" ;; *) r_offset=$off ;; esac
}

probe_timedatectl() {
    run timedatectl > "$tmp_out" 2>&1
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=1; return; fi
    [ "$rc" -eq 0 ] || return
    flag=$(awk '/(clock|NTP) synchronized:/ { v = $NF } END { print v }' "$tmp_out")
    case "$flag" in
        yes) answered=1; r_synced=true ;;
        no)  answered=1; r_synced=false ;;
    esac
}

# rdate: cron이 rdate로 맞추는 호스트에서만 쓴다. cron에 적힌 서버를 `rdate -p`로 조회해 시스템 시각과 비교한다(시계는 바꾸지 않는다).
# rdate는 초 단위로만 답하므로 offset_ms는 1000의 배수다(알림 기준 abs(offset_ms) > 1000과 맞물려 1초 이내 오차는 울리지 않는다).
rdate_server() {
    # shellcheck disable=SC2086 # CRON_FILES는 의도적으로 단어 분리·글롭한다
    cat $CRON_FILES 2>/dev/null | grep -v '^[ 	]*#' |
        sed -n 's/.*rdate[ 	][ 	]*\(-[a-z][a-z]*[ 	][ 	]*\)*\([A-Za-z0-9][A-Za-z0-9.-]*\).*/\2/p' | head -n 1
}

probe_rdate() {
    server=$(rdate_server)
    [ -n "$server" ] || return
    run rdate -p "$server" > "$tmp_out" 2>&1
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=1; return; fi
    [ "$rc" -eq 0 ] || return
    # 출력: "rdate: [서버]<탭>Tue Nov 10 13:44:24 2026" — 대괄호 뒤가 로컬 시각이다.
    remote=$(sed -n 's/^rdate: \[[^]]*\][ 	]*\(.*[0-9]\)[ 	]*$/\1/p' "$tmp_out" | head -n 1)
    [ -n "$remote" ] || return
    remote_epoch=$(date -d "$remote" +%s 2>/dev/null)
    case "$remote_epoch" in ''|*[!0-9]*) return ;; esac
    local_epoch=${TIME_SYNC_NOW:-$(date +%s)}
    answered=1
    r_synced=true
    r_offset=$(( (local_epoch - remote_epoch) * 1000 ))
    r_message="rdate -p $server (1s resolution)"
}

first_found=
for t in $TOOLS; do
    command -v "$t" >/dev/null 2>&1 || continue
    # rdate는 이 호스트의 cron이 rdate로 시각을 맞출 때만 후보다(아니면 "도구 없음"으로 센다).
    [ "$t" != rdate ] || [ -n "$(rdate_server)" ] || continue
    [ -n "$first_found" ] || first_found=$t
    case "$t" in
        chronyc) probe_chronyc ;;
        ntpq) probe_ntpq ;;
        timedatectl) probe_timedatectl ;;
        rdate) probe_rdate ;;
    esac
    if [ -n "$answered" ]; then
        if [ "$r_synced" = true ]; then status=synced; else status=unsynced; fi
        emit "$status" "$t" "$r_synced" "$r_offset" "$r_stratum" "$r_message"
        exit 0
    fi
done

if [ -z "$first_found" ]; then
    emit no_tool none null null null ""
elif [ -n "$timed_out" ]; then
    emit error "$first_found" null null null "no answer within ${TIMEOUT}s"
else
    emit unsynced "$first_found" false null null "$first_found not answering (daemon not running?)"
fi
exit 0
