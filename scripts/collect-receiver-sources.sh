#!/usr/bin/env bash
# 로그·트랩 수신기의 실제 출발지와 트랩 인증 문자열 수집기 (#370, Spec #364). 읽기 전용:
# 서버 상태를 바꾸지 않는다. 인증 문자열은 값을 출력하지 않고 길이와 해시 앞 12자로만 남긴다.
#
# 사용법 (운영자 PC에서):
#   scripts/collect-receiver-sources.sh --label ns0266 --ssh user@host [--port N]
#   diff <이전>/receiver-sources.txt <이후>/receiver-sources.txt
#
# 결과는 저장소 밖 비공개 경로(기본 ~/.local/share/infra-automation/sec-review-20261026/
# receiver-sources/<label>/<시각>/receiver-sources.txt, 0600)에만 저장한다. 저장소 안 경로는 거부한다.
#
# 환경변수 (공개 저장소라 값은 실행 때만 넘긴다):
#   BASELINE_SSH_OPTS           ssh에 덧붙일 옵션
#   INFRA_PRIVATE_DIR           결과 저장 기준 경로
#   RECEIVER_SYSLOG_PORT        로그 수신 포트 (기본: 프로토콜 표준)
#   RECEIVER_TRAP_PORT          트랩 수신 포트 (기본: 프로토콜 표준)
#   RECEIVER_SYSLOG_DIR         장비별 로그 보관 디렉터리 (기본 /var/log/remote)
#   RECEIVER_TRAP_LOG_FILES     트랩 수신기 로그 파일 목록 (서버 쪽 경로, 공백 구분)
#   RECEIVER_TRAP_CONTAINERS    트랩 수신기 컨테이너 이름 목록 (docker logs를 읽는다)
#   RECEIVER_LOG_SINCE          컨테이너 로그 조회 범위 (기본 72h)
#   RECEIVER_TRAP_CONF_FILES    트랩 수신기 설정 파일 목록 (인증 지시어만 본다)
set -u
set -o pipefail

DEFAULT_PRIVATE_DIR="$HOME/.local/share/infra-automation/sec-review-20261026"
SECRET_PATTERN='BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY)[A-Za-z_]*[=:] *[^ ]'

# --- 서버 쪽 ------------------------------------------------------------------------
remote_main() {
  local sudo=""
  if [ "$(id -u)" != "0" ]; then
    sudo="sudo -n"
    if ! sudo -n true 2>/dev/null; then
      echo "sudo -n 불가: 수집을 중단합니다." >&2
      return 1
    fi
  fi
  local sport="${RECEIVER_SYSLOG_PORT:-514}" tport="${RECEIVER_TRAP_PORT:-162}"
  local sdir="${RECEIVER_SYSLOG_DIR:-/var/log/remote}" since="${RECEIVER_LOG_SINCE:-72h}"

  section() { printf '\n## %s\n' "$1"; }
  run() {
    local rc name="$*"
    "$@" 2>&1; rc=$?
    name="${name#sudo -n }"
    [ "$rc" -eq 0 ] || echo "(unavailable: ${name} exit=${rc})"
  }

  # 값을 출력하지 않고 "len=N sha256:<12자> [default-string]"만 낸다. 입력은 줄마다 한 값.
  mask_values() {
    local v h flag
    sort -u | while IFS= read -r v; do
      [ -n "$v" ] || continue
      h="$(printf '%s' "$v" | sha256sum | cut -c1-12)"
      flag=""
      case "$(printf '%s' "$v" | tr 'A-Z' 'a-z')" in public|private|community) flag=" default-string" ;; esac
      echo "len=${#v} sha256:${h}${flag}"
    done
  }

  # 로그 줄에서 출발지 주소만 뽑는다. snmptrapd 기본 형식("UDP: [출발지]:포트->[수신]:포트")을 기준으로 한다.
  extract_sources() {
    sed -nE 's/.*(UDP|TCP|UDP6|TCP6)[0-9]*: \[([0-9a-fA-F:.]+)\].*/\2/p' | sort -u
  }
  # 로그 줄에서 인증 문자열만 뽑는다(값은 mask_values가 가린다).
  extract_auth_strings() {
    sed -nE 's/.*snmpTrapCommunity[^"]*STRING: "?([^" ]+).*/\1/p; s/.*[Cc]ommunity[ =:]+"?([^" ,]+).*/\1/p'
  }

  section host
  run hostname

  section receiver-listeners
  # 수신 포트에 열린 소켓. PID·fd는 재시작마다 달라지므로 제거한다.
  run $sudo ss -H -tulnp \
    | grep -E ":(${sport}|${tport})[[:space:]]" \
    | sed -E 's/pid=[0-9]+,?//g; s/fd=[0-9]+//g; s/,\)/)/g; s/[[:space:]]+/ /g' | sort

  section conntrack-sources
  # 커널이 본 원래 출발지(NAT 이전). 수신기가 보는 값과 다를 수 있으므로 아래 절과 대조한다.
  local pair proto port
  for pair in "udp:${sport}" "tcp:${sport}" "udp:${tport}"; do
    proto="${pair%%:*}"; port="${pair##*:}"
    echo "# ${proto} 수신 포트 출발지"
    if command -v conntrack >/dev/null 2>&1; then
      $sudo conntrack -L -p "$proto" --dport "$port" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}' | sort -u
    else
      echo "(unavailable: conntrack)"
    fi
  done

  section syslog-sender-dirs
  # 장비별 보관 디렉터리 이름 = 수신기가 실제로 본 송신 장비.
  run $sudo find "$sdir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort

  # 로그 원문은 파이프로만 흘려 추출기에 넣는다. 디스크에 임시 사본을 만들지 않고 원문은 출력하지 않는다.
  collect_logs() {
    local f c
    for f in ${RECEIVER_TRAP_LOG_FILES:-}; do
      $sudo grep -h '' "$f" 2>/dev/null || echo "(unavailable: ${f##*/})" >&2
    done
    for c in ${RECEIVER_TRAP_CONTAINERS:-}; do
      $sudo docker logs --since "$since" "$c" 2>&1 || echo "(unavailable: container ${c})" >&2
    done
  }

  section trap-sources-from-logs
  collect_logs | extract_sources

  section trap-auth-strings-masked
  # 값은 출력하지 않는다. 같은 값이 설정과 로그 양쪽에서 같은 해시로 보이면 같은 문자열이다.
  collect_logs | extract_auth_strings | mask_values

  section trap-auth-directives
  # 설정 파일의 인증 지시어. 인증 문자열·passphrase는 가리고 허용 출발지와 동작만 싣는다.
  local cf kw rest a1 a2 a3 m
  for cf in ${RECEIVER_TRAP_CONF_FILES:-}; do
    echo "# 설정 파일 ${cf##*/}"
    $sudo sed -nE 's/^[[:space:]]*(authCommunity|authUser|authAccess|createUser|disableAuthorization|authGroup)([[:space:]]+(.*))?$/\1 \3/p' "$cf" 2>&1 \
      | while read -r kw rest; do
          case "$kw" in
            authCommunity)
              # shellcheck disable=SC2086
              set -- $rest; a1="${1:-}"; a2="${2:-}"; a3="${3:-}"
              m="$(printf '%s\n' "$a2" | mask_values)"
              echo "authCommunity actions=${a1} string=[${m}] source=${a3:-(none)}" ;;
            createUser)
              # shellcheck disable=SC2086
              set -- $rest; echo "createUser name=${1:-} (passphrase 가림)" ;;
            *) echo "${kw} ${rest}" ;;
          esac
        done | sort
  done
}

# --- 운영자 쪽 -----------------------------------------------------------------------
check_out_dir() {
  local dir="$1" parent top
  parent="$dir"
  while [ ! -d "$parent" ]; do parent="$(dirname "$parent")"; done
  if top="$(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git -C "$parent" rev-parse --show-toplevel 2>/dev/null)"; then
    echo "거부: 결과 경로가 git 저장소($top) 안입니다. 비공개 경로를 쓰세요." >&2
    return 1
  fi
}

check_no_secrets() {
  if grep -Eiq "$SECRET_PATTERN" "$1"; then
    echo "거부: 수집 결과에 시크릿으로 보이는 패턴이 있습니다(내용은 출력하지 않음)." >&2
    return 1
  fi
}

declare -A OPT=()

collect() {
  local label="${OPT[label]}" dest="${OPT[dest]}" port="${OPT[port]:-}" base="${OPT[base]}" ts out
  check_out_dir "$base" || return 1
  ts="$(date +%Y%m%dT%H%M%S)"
  out="$base/$label/$ts"
  umask 077
  mkdir -p "$base/$label"
  mkdir "$out" || return 1
  local sshargs=(-o BatchMode=yes -o StrictHostKeyChecking=yes)
  [ -n "$port" ] && sshargs+=(-p "$port")
  # shellcheck disable=SC2206
  [ -n "${BASELINE_SSH_OPTS:-}" ] && sshargs+=($BASELINE_SSH_OPTS)
  local remote_env v
  remote_env=""
  for v in RECEIVER_SYSLOG_PORT RECEIVER_TRAP_PORT RECEIVER_SYSLOG_DIR RECEIVER_TRAP_LOG_FILES \
           RECEIVER_TRAP_CONTAINERS RECEIVER_LOG_SINCE RECEIVER_TRAP_CONF_FILES; do
    remote_env+="$(printf '%s=%q ' "$v" "${!v:-}")"
  done
  # shellcheck disable=SC2029  # 클라이언트 쪽 확장이 의도다(%q로 이스케이프함)
  if ! ssh "${sshargs[@]}" "$dest" "env $remote_env bash -s -- --remote" < "$0" > "$out/receiver-sources.txt" 2> "$out/stderr.txt"; then
    echo "수집 실패: $out/stderr.txt 확인" >&2
    return 1
  fi
  if ! check_no_secrets "$out/receiver-sources.txt" || ! check_no_secrets "$out/stderr.txt"; then
    rm -f "$out/receiver-sources.txt" "$out/stderr.txt"
    return 1
  fi
  echo "$out/receiver-sources.txt"
}

main() {
  OPT=([base]="${INFRA_PRIVATE_DIR:-$DEFAULT_PRIVATE_DIR}/receiver-sources")
  while [ $# -gt 0 ]; do
    case "$1" in
      --remote) remote_main; return $? ;;
      --label) OPT[label]="$2"; shift 2 ;;
      --ssh) OPT[dest]="$2"; shift 2 ;;
      --port) OPT[port]="$2"; shift 2 ;;
      --out) OPT[base]="$2"; shift 2 ;;
      *) echo "알 수 없는 인자: $1" >&2; return 2 ;;
    esac
  done
  if [ -z "${OPT[label]:-}" ] || [ -z "${OPT[dest]:-}" ]; then
    echo "사용법: $0 --label <호스트> --ssh <user@host> [--port N] [--out DIR]" >&2
    return 2
  fi
  collect
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main "$@"; fi
