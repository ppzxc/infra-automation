#!/bin/sh
# Ansible managed — HP Smart Array RAID 상태 수집기 (Spec #322 / Ticket-13, #335).
# 근거: docs/research/hardware-raid-metrics-industry-standard.md §6~§8.
#
# cron이 5분마다 root로 실행한다. 읽기 전용이다: `ctrl all show config detail` 한 번만 부르고,
# 설정을 바꾸는 명령은 쓰지 않으며 도구를 설치하지 않는다(없으면 tool_status=no_tool만 남긴다).
# 결과는 정규화한 JSON 줄로 raid.jsonl에 append하고, otelcol(filelog/host_status_logs)이 읽는다.
#
#   레코드 종류(kind): controller, logical_drive, physical_drive, cache_battery, tool_status
#   tool_status는 실행마다 정확히 1줄 남긴다(정상일 때도 status=ok). 어떤 경우에도 종료 코드는 0이다.
#
# POSIX sh + POSIX awk만 쓴다(CentOS 6 gawk 3.1, Ubuntu mawk). jq·python 없음.
export LC_ALL=C
# RAID_STATUS_PATH는 시험용(가짜 도구 디렉터리를 앞에 둔다). 운영 cron은 쓰지 않는다.
PATH="${RAID_STATUS_PATH:+$RAID_STATUS_PATH:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

LOG="${RAID_STATUS_LOG:-/var/log/host-agents/raid.jsonl}"
LOCK="${RAID_STATUS_LOCK:-/var/lib/host-agents/raid-status.lock}"
TIMEOUT="${RAID_STATUS_TIMEOUT:-60}"
TOOLS="${RAID_STATUS_TOOLS:-ssacli hpssacli hpacucli}"

ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start=$(date +%s)
run_id="r-$start-$$"

# 출력 가능한 ASCII만 남기고 JSON 문자열 이스케이프, 200바이트로 제한한다.
json_str() {
    printf '%s' "$1" | tr -c '\040-\176' ' ' | cut -c1-200 | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# tool_status 한 줄: $1=status $2=tool $3=version $4=exit_code $5=message
emit_status() {
    now=$(date +%s)
    dur=$((now - start))
    [ "$dur" -ge 0 ] || dur=0
    printf '{"ts":"%s","schema":1,"run_id":"%s","kind":"tool_status","family":"smartarray","tool":"%s","tool_version":"%s","status":"%s","exit_code":%s,"duration_s":%s,"message":"%s"}\n' \
        "$ts" "$run_id" "$(json_str "$2")" "$(json_str "$3")" "$1" "$4" "$dur" "$(json_str "$5")"
}

# 실행 겹침 방지: 스크립트 전체를 잠금 하나로 감싼다. 잠금을 못 잡으면 locked 한 줄만 남긴다.
# `command exec`: 잠금 파일을 못 열어도 셸이 끝나지 않게 한다(특수 내장 명령의 실패 종료를 막는다).
mkdir -p "${LOCK%/*}" 2>/dev/null
if command -v flock >/dev/null 2>&1 && command exec 9>>"$LOCK"; then
    if ! flock -n 9 2>/dev/null; then
        emit_status locked "" "" 0 "previous run still holds the lock" >> "$LOG" 2>/dev/null
        exit 0
    fi
fi

tool=
for t in $TOOLS; do
    if command -v "$t" >/dev/null 2>&1; then tool=$t; break; fi
done
if [ -z "$tool" ]; then
    emit_status no_tool none "" 0 "" >> "$LOG" 2>/dev/null
    exit 0
fi

tmp_out=$(mktemp "${TMPDIR:-/tmp}/raid-status.XXXXXX") || exit 0
tmp_rec=$(mktemp "${TMPDIR:-/tmp}/raid-status.XXXXXX") || { rm -f "$tmp_out"; exit 0; }
trap 'rm -f "$tmp_out" "$tmp_rec"' EXIT

# CentOS 6의 coreutils 8.4 timeout에는 -k(TERM 뒤 KILL)가 없다. 지원할 때만 붙인다.
if command -v timeout >/dev/null 2>&1; then
    if timeout -k 1 5 true >/dev/null 2>&1; then
        TIMEOUT_CMD="timeout -k 10 $TIMEOUT"
    else
        TIMEOUT_CMD="timeout $TIMEOUT"
    fi
else
    TIMEOUT_CMD=
fi
run() {
    # shellcheck disable=SC2086 # TIMEOUT_CMD는 의도적으로 단어 분리한다
    nice -n 19 $TIMEOUT_CMD "$@"
}

version=$(run "$tool" version 2>/dev/null | sed -n 's/^.*CLI Version: *//p' | head -n 1)
run "$tool" ctrl all show config detail > "$tmp_out" 2>&1
rc=$?
msg=$(grep -v '^[[:space:]]*$' "$tmp_out" | head -n 1)

if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    emit_status timeout "$tool" "$version" "$rc" "no answer within ${TIMEOUT}s" >> "$LOG" 2>/dev/null
    exit 0
fi
if [ "$rc" -ne 0 ]; then
    emit_status error "$tool" "$version" "$rc" "$msg" >> "$LOG" 2>/dev/null
    exit 0
fi
# 컨트롤러 머리줄은 들여쓰기 없는 줄이다. 없으면 컨트롤러가 없다(예: "Error: No controllers detected.").
if ! grep -q '^[^[:space:]]' "$tmp_out" || grep -q '^Error:' "$tmp_out"; then
    emit_status no_controller "$tool" "$version" "$rc" "$msg" >> "$LOG" 2>/dev/null
    exit 0
fi

awk -v ts="$ts" -v run_id="$run_id" -v tool="$tool" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function esc(s) {
    gsub(/[\001-\037\177]/, " ", s)
    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    return s
}
function q(s) { return "\"" esc(s) "\"" }
function num(s) { s = trim(s); if (s ~ /^-?[0-9]+(\.[0-9]+)?$/) return s + 0; return "null" }
function bool(s) { s = tolower(trim(s)); return (s == "true" || s == "enabled" || s == "yes") ? "true" : "false" }
function indent(s) { match(s, /^ */); return RLENGTH }

# 현재 블록의 키·값(원문)을 모은다. raw는 이 블록의 모든 키·값을 JSON으로 만든 문자열이다.
function reset_block() { split("", K); split("", V); nk = 0 }
function put(k, v) { if (!(k in V)) { nk++; K[nk] = k }; V[k] = v }
function get(k) { return (k in V) ? V[k] : "" }
function raw_json(   i, s) {
    s = "{"
    for (i = 1; i <= nk; i++) s = s (i > 1 ? "," : "") q(K[i]) ":" q(V[K[i]])
    return s "}"
}
function head(kind, hw_type, id, parent, name) {
    return "{\"ts\":" q(ts) ",\"schema\":1,\"run_id\":" q(run_id) ",\"kind\":" q(kind) ",\"family\":\"smartarray\",\"tool\":" q(tool) \
           ",\"hw_type\":" q(hw_type) ",\"hw_id\":" q(id) ",\"hw_parent\":" q(parent) ",\"hw_name\":" q(name)
}
function tail(state, raw_state, op, pct) {
    return ",\"hw_state\":" q(state) ",\"raw_state\":" q(raw_state) ",\"operation\":" q(op) ",\"progress_pct\":" pct ",\"raw\":" q(raw_json()) "}"
}

function cache_status(s, present) {
    s = tolower(trim(s))
    if (present == "false") return "none"
    if (s == "ok") return "ok"
    if (s ~ /temporar/) return "temporarily_disabled"
    if (s ~ /permanent/) return "permanently_disabled"
    if (s ~ /not configured/) return "not_configured"
    if (s ~ /fail/) return "failed"
    return "unknown"
}
function battery_state(s) {
    s = tolower(trim(s))
    if (s == "") return "none"
    if (s == "ok") return "ok"
    if (s ~ /fail/) return "failed"
    return "degraded"
}
function battery_op(s) { return (tolower(s) ~ /recharg|charging/) ? "charging" : "none" }

# --- 컨트롤러 -----------------------------------------------------------------
function flush_controller(   present, cst, bcount, bstatus, bsrc, bp, bstate, bop, st, reason, line) {
    if (ctrl_name == "") return
    present = bool(get("Cache Board Present"))
    if (get("Cache Board Present") == "") present = (get("Cache Status") != "") ? "true" : "false"
    cst = cache_status(get("Cache Status"), present)
    bcount = trim(get("Battery/Capacitor Count"))
    bstatus = trim(get("Battery/Capacitor Status"))
    bsrc = tolower(get("Cache Backup Power Source"))
    if (bsrc ~ /batter/) bp = "battery"; else if (bsrc ~ /capacitor/) bp = "capacitor"; else bp = "none"
    if (bstatus != "" && bp == "none") bp = "unknown"
    if (bcount == "0") bp = "none"
    bstate = (bp == "none") ? "none" : battery_state(bstatus)
    bop = battery_op(bstatus)
    st = trim(get("Controller Status"))
    reason = get("Cache Disable Reason")
    if (reason == "") reason = get("Cache Status Details")
    ctrl_cache[ctrl_id] = cst

    line = head("controller", "disk_controller", ctrl_id, "", ctrl_name)
    line = line ",\"hw_model\":" q(ctrl_model) ",\"hw_firmware_version\":" q(get("Firmware Version")) ",\"hw_driver_version\":" q(get("Driver Version"))
    line = line ",\"temperature_c\":" num(get("Controller Temperature (C)")) ",\"cache_temperature_c\":" num(get("Cache Module Temperature (C)"))
    line = line ",\"cache_present\":" present ",\"cache_status\":" q(cst) ",\"cache_reason\":" q(trim(reason)) ",\"cache_size_gb\":" num(get("Total Cache Size"))
    line = line ",\"write_cache_without_battery\":" bool(get("No-Battery Write Cache"))
    line = line ",\"backup_power\":" q(bp) ",\"backup_power_state\":" q(bstate) ",\"backup_power_operation\":" q(bop)
    line = line tail(st == "" ? "unknown" : (tolower(st) == "ok" ? "ok" : "failed"), st, "none", "null")
    print line

    if (bp != "none") {
        bsrc = get("Cache Backup Power Source")
        line = head("cache_battery", "battery", ctrl_id "/battery", ctrl_id, ctrl_name " cache backup power")
        line = line ",\"backup_power\":" q(bp) ",\"present\":true,\"count\":" num(bcount)
        # 배터리 레코드의 raw는 배터리 관련 키만 담는다.
        reset_block(); put("Battery/Capacitor Count", bcount); put("Battery/Capacitor Status", bstatus); put("Cache Backup Power Source", bsrc)
        line = line tail(bstate, bstatus, bop, "null")
        print line
    }
}

# --- 논리 드라이브 --------------------------------------------------------------
function raid_level(ft,   f) {
    f = toupper(trim(ft))
    if (f == "0") return "RAID0"
    if (f == "1") return "RAID1"
    if (f == "1+0") return "RAID10"
    if (f == "5") return "RAID5"
    if (f == "6" || f ~ /ADG/) return "RAID6"
    if (f == "50") return "RAID50"
    if (f == "60") return "RAID60"
    if (f ~ /^1 \(ADM\)/ || f ~ /^1 \(TRIPLE/) return "RAID1ADM"
    if (f ~ /^1\+0 \(ADM\)/ || f ~ /^1\+0 \(TRIPLE/) return "RAID10ADM"
    return f
}
function ld_state(s,   l) {
    l = tolower(s)
    if (l == "ok") return "ok"
    if (l ~ /fail/) return "failed"
    if (l ~ /interim recovery|degraded|recover|rebuild/) return "degraded"
    if (l ~ /expand|transform|queued|initializ/) return "ok"
    return "unknown"
}
function ld_op(s,   l) {
    l = tolower(s)
    if (l ~ /interim/) return "none"
    if (l ~ /recover|rebuild/) return "rebuild"
    if (l ~ /expand|transform|queued/) return "expand"
    if (l ~ /initializ/) return "init"
    return "none"
}
function pct(s) { if (match(s, /[0-9]+(\.[0-9]+)?%/)) return substr(s, RSTART, RLENGTH - 1) + 0; return "null" }
function flush_ld(   st, cfg, eff, cc, line) {
    if (ld_num == "") return
    st = trim(get("Status"))
    cfg = tolower(trim(get("Caching")))
    cfg = (cfg == "enabled") ? "wb" : ((cfg == "disabled") ? "wt" : "unknown")
    cc = ctrl_cache[ctrl_id]
    eff = (cc == "temporarily_disabled" || cc == "permanently_disabled" || cc == "failed" || cc == "none") ? "wt" : cfg
    line = head("logical_drive", "logical_disk", ctrl_id "/ld" ld_num, ctrl_id, "logicaldrive " ld_num)
    line = line ",\"array\":" q(array_name) ",\"raid_level\":" q(raid_level(get("Fault Tolerance"))) ",\"size\":" q(trim(get("Size")))
    line = line ",\"write_cache_configured\":" q(cfg) ",\"write_cache_effective\":" q(eff) ",\"os_device\":" q(trim(get("Disk Name")))
    line = line ",\"unrecoverable_media_errors\":" q(trim(get("Unrecoverable Media Errors")))
    line = line tail(ld_state(st), st, ld_op(st), pct(st))
    print line
    ld_num = ""
}

# --- 물리 드라이브 --------------------------------------------------------------
function pd_state(s,   l) {
    l = tolower(s)
    if (l == "ok") return "ok"
    if (l ~ /predictive/) return "predicted_failure"
    if (l ~ /fail/) return "failed"
    if (l ~ /rebuild/) return "ok"
    return "unknown"
}
function pd_role(s,   l) {
    l = tolower(s)
    if (l ~ /spare/) return "spare"
    if (l ~ /unassigned/) return "unassigned"
    if (l ~ /hba/) return "jbod"
    if (l ~ /data/) return "data"
    return "unknown"
}
function flush_pd(   st, it, model, role, line) {
    if (pd_slot == "") return
    st = trim(get("Status"))
    it = get("Interface Type")
    model = trim(get("Model")); gsub(/  +/, " ", model)
    role = pd_role(get("Drive Type"))
    line = head("physical_drive", "physical_disk", ctrl_id "/pd" pd_slot, ctrl_id, "physicaldrive " pd_slot)
    line = line ",\"slot\":" q(pd_slot) ",\"array\":" q(pd_array) ",\"hw_model\":" q(model) ",\"hw_firmware_version\":" q(trim(get("Firmware Revision")))
    line = line ",\"interface\":" q(trim(it)) ",\"media\":" q((tolower(it) ~ /solid state|ssd/) ? "ssd" : "hdd") ",\"size\":" q(trim(get("Size")))
    line = line ",\"temperature_c\":" num(get("Current Temperature (C)")) ",\"max_temperature_c\":" num(get("Maximum Temperature (C)"))
    line = line ",\"predictive_failure\":" ((tolower(st) ~ /predictive/) ? "true" : "false") ",\"drive_role\":" q(role) ",\"hot_spare\":" ((role == "spare") ? "true" : "false")
    line = line ",\"last_failure_reason\":" q(trim(get("Last Failure Reason")))
    line = line tail(pd_state(st), st, (tolower(st) ~ /rebuild/) ? "rebuild" : "none", "null")
    print line
    pd_slot = ""
}

function flush_all() {
    if (mode == "controller") flush_controller()
    else if (mode == "ld") flush_ld()
    else if (mode == "pd") flush_pd()
    mode = ""
    reset_block()
}

BEGIN { mode = ""; ctrl_name = ""; nctrl = 0; reset_block() }
{
    sub(/\r$/, "")
    line = $0
    if (line ~ /^[ \t]*$/) { flush_all(); next }
    ind = indent(line)
    t = trim(line)

    # 컨트롤러 머리줄: 들여쓰기 없는 줄 ("Smart Array P440 in Slot 2", "HPE Smart Array ... in Slot 0 (Embedded)")
    if (ind == 0) {
        flush_all()
        nctrl++
        ctrl_name = t
        ctrl_model = t; sub(/ in Slot .*$/, "", ctrl_model)
        slot = ""
        if (match(t, / in Slot [^ ]+/)) slot = substr(t, RSTART + 9, RLENGTH - 9)
        ctrl_id = "ssa:slot=" (slot != "" ? slot : "idx" nctrl)
        array_name = ""
        mode = "controller"; reset_block()
        next
    }
    # 하위 블록 시작
    if (ind == 3 && t ~ /^Array: /) { flush_all(); array_name = t; sub(/^Array: /, "", array_name); mode = "array"; next }
    if (ind == 3 && (t == "Unassigned" || t ~ /^HBA Drives/)) { flush_all(); array_name = ""; mode = "array"; next }
    if (ind == 6 && t ~ /^Logical Drive: /) { flush_all(); ld_num = t; sub(/^Logical Drive: /, "", ld_num); mode = "ld"; next }
    if (ind == 6 && t ~ /^physicaldrive [^ ]+$/) { flush_all(); pd_slot = t; sub(/^physicaldrive /, "", pd_slot); pd_array = array_name; mode = "pd"; next }

    # 키: 값 (블록의 바로 아래 단계만. 더 깊은 줄(미러 그룹·파티션 목록)은 버린다)
    if (match(t, /: /) || t ~ /:$/) {
        p = index(t, ":")
        k = trim(substr(t, 1, p - 1)); v = trim(substr(t, p + 1))
        if (mode == "controller" && ind == 3) put(k, v)
        else if ((mode == "ld" || mode == "pd") && ind == 9) put(k, v)
    }
}
END { flush_all() }
' "$tmp_out" > "$tmp_rec" 2>/dev/null
arc=$?

if [ "$arc" -ne 0 ]; then
    emit_status error "$tool" "$version" "$arc" "parser failed" >> "$LOG" 2>/dev/null
    exit 0
fi
emit_status ok "$tool" "$version" 0 "" >> "$tmp_rec"
# 한 실행의 줄을 한 번에 붙인다(filelog가 반쯤 쓴 묶음을 읽지 않게).
cat "$tmp_rec" >> "$LOG" 2>/dev/null
exit 0
