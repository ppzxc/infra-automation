#!/usr/bin/env bash
# 서버 보안 상태 스냅샷 수집기 (#368, Spec #364). 읽기 전용: 서버 상태를 바꾸지 않고
# 시크릿 파일의 내용을 읽지 않는다(권한·소유자만 find -printf로 본다).
#
# 사용법 (운영자 PC에서):
#   scripts/collect-security-baseline.sh --label ns0266 --ssh user@host [--port N]
#   diff -r <결과1>/snapshot.txt <결과2>/snapshot.txt   # 같은 상태면 비어 있다
#
# 결과는 저장소 밖 비공개 경로(기본 ~/.local/share/infra-automation/sec-review-20261026/
# baseline/<label>/<시각>/snapshot.txt)에만 저장한다. 저장소 안 경로는 거부한다.
# 서버에서는 --remote 모드로 같은 파일이 stdin으로 실행된다.
#
# 환경변수:
#   BASELINE_SSH_OPTS    ssh에 덧붙일 옵션 (예: "-i <공개키> -o IdentitiesOnly=yes")
#   BASELINE_FIND_ROOTS  시크릿 후보 파일을 찾을 서버 쪽 경로 (기본 /opt /etc/restic ...)
#   INFRA_PRIVATE_DIR    결과 저장 기준 경로
#   BASELINE_SSHD_MATCH_ADDRS  Match 블록 평가에 쓸 출발지 IP 목록(공백 구분), BASELINE_SSHD_MATCH_USER 사용자(기본 root)
set -u
set -o pipefail

# 결과 기본 저장 기준 경로(저장소 밖). INFRA_PRIVATE_DIR로 바꾼다.
DEFAULT_PRIVATE_DIR="$HOME/.local/share/infra-automation/sec-review-20261026"
# 설정 파일 안 평문 자격 후보. ${VAR} 참조와 빈 값은 제외한다. 파일명만 출력하고 줄은 출력하지 않는다.
PLAINTEXT_CRED_PATTERN='(password|passwd|secret|token|api_?key)[A-Za-z_]*["'"'"']?[ ]*[=:][ ]*["'"'"']?[^$ "'"'"'{#][^ ]*'
SECRET_PATTERN='BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY)[A-Za-z_]*[=:] *[^ ]'

# --- 서버 쪽: 정규화된(시각·카운터·PID 제거) 텍스트를 stdout으로 낸다 ---------------
remote_main() {
  local sudo=""
  if [ "$(id -u)" != "0" ]; then
    sudo="sudo -n"
    # 권한 없이 돌면 모든 구간이 '(unavailable)'로 같아져 빈 diff가 거짓 통과가 된다.
    if ! sudo -n true 2>/dev/null; then
      echo "sudo -n 불가: 수집을 중단합니다." >&2
      return 1
    fi
  fi
  local roots="${BASELINE_FIND_ROOTS:-/opt /srv /etc/restic /etc/ssh /etc/audit /etc/docker /etc/fail2ban /etc/sudoers.d /root /home}"

  section() { printf '\n## %s\n' "$1"; }
  # 출력은 그대로 싣고, 실패하면 sudo를 뺀 실제 명령 이름과 종료코드를 덧붙인다.
  # systemctl is-active/is-enabled의 비정상 종료는 상태값이므로 표시하지 않는다.
  run() {
    local rc name="$*"
    "$@" 2>&1; rc=$?
    name="${name#sudo -n }"
    case "$name" in "systemctl is-"*) return 0 ;; esac
    [ "$rc" -eq 0 ] || echo "(unavailable: ${name} exit=${rc})"
  }

  # grep -l이 일치 없음(1)으로 끝나는 것은 실패가 아니다.
  run_ok1() {
    local rc name="$*"
    "$@" 2>&1; rc=$?
    name="${name#sudo -n }"
    [ "$rc" -le 1 ] || echo "(unavailable: ${name} exit=${rc})"
  }

  section host
  run hostname
  section listen
  # PID·fd는 재시작마다 달라지므로 제거한다.
  run $sudo ss -H -tulnp \
    | sed -E 's/pid=[0-9]+,?//g; s/fd=[0-9]+//g; s/,\)/)/g; s/[[:space:]]+/ /g' | sort
  section published-containers
  run $sudo docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' | sort
  section firewalld
  run $sudo firewall-cmd --get-active-zones
  run $sudo firewall-cmd --list-all-zones
  section nft-ruleset-stateless
  run $sudo nft -s list ruleset
  section iptables-docker-user
  run $sudo iptables -S DOCKER-USER
  section sshd-effective
  run $sudo sshd -T | sort
  section sshd-match-blocks
  # sshd -T는 Match 블록을 평가하지 않으므로 선언 줄과, 지정한 출발지별 달라지는 설정을 따로 본다.
  # shellcheck disable=SC2086
  run_ok1 $sudo grep -rnEi '^[[:space:]]*Match[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d
  local base_cfg addr
  base_cfg="$($sudo sshd -T 2>/dev/null | sort)"
  for addr in ${BASELINE_SSHD_MATCH_ADDRS:-}; do
    echo "# addr=${addr}에서 기본값과 달라지는 줄"
    comm -13 <(printf '%s\n' "$base_cfg") \
      <($sudo sshd -T -C "user=${BASELINE_SSHD_MATCH_USER:-root},host=baseline,addr=${addr}" 2>&1 | sort)
  done
  section fail2ban
  run $sudo systemctl is-active fail2ban
  run $sudo systemctl is-enabled fail2ban
  run $sudo fail2ban-client status
  section auditd
  run $sudo systemctl is-active auditd
  run $sudo systemctl is-enabled auditd
  # 상태 출력의 backlog·lost 같은 카운터는 변동 필드라 enabled·failure·한도만 남긴다.
  run $sudo auditctl -s \
    | grep -E '^(enabled|failure|backlog_limit|rate_limit|loginuid_immutable)|unavailable' | sort
  section audit-rules-loaded
  run $sudo auditctl -l | sort
  section audit-rules-files
  run $sudo find /etc/audit/rules.d -maxdepth 1 -type f -printf '%m %u:%g %p\n'
  section auditd-conf
  run $sudo grep -E '^(max_log_file|max_log_file_action|num_logs|space_left|space_left_action|log_file|write_logs)[[:space:]]*=' \
    /etc/audit/auditd.conf | sort
  section system-log-storage
  run $sudo systemd-analyze cat-config systemd/journald.conf
  run $sudo find /var/log/journal /var/log/audit -maxdepth 0 -printf '%m %u:%g %p\n'
  run $sudo systemctl is-active rsyslog
  section secret-file-metadata
  # 내용은 열지 않는다. 이름 규칙에 맞는 파일의 권한·소유자·경로만 본다.
  # shellcheck disable=SC2086
  run $sudo find $roots -xdev -maxdepth 5 \
    \( -name data -o -name volumes -o -name logs -o -name node_modules -o -name .git \) -prune -o \
    -type f \( -name '.env' -o -name '*.env' -o -name '*secret*' -o -name '*password*' \
      -o -name '*token*' -o -name '*.key' -o -name '*.pem' -o -name 'id_*' \
      -o -name 'ssh_host_*_key' -o -name '.bash_history' -o -name 'authorized_keys' \) \
    -printf '%m %u:%g %p\n' | sort
  section plaintext-credential-files
  # 줄 내용은 출력하지 않는다(grep -l: 파일 경로만). 환경변수 참조(${VAR})·빈 값은 제외한다.
  # shellcheck disable=SC2086
  run_ok1 $sudo find $roots -xdev -maxdepth 5 \
    \( -name data -o -name volumes -o -name logs -o -name node_modules -o -name .git -o -path /etc/fail2ban \) -prune -o \
    -type f -size -1024k \( -name 'docker-compose*' -o -name 'compose*.y*ml' -o -name '*.conf' -o -name '*.ini' \
      -o -name '*.yml' -o -name '*.yaml' -o -name '*.cfg' -o -name '*.properties' \) \
    -exec grep -lEi "$PLAINTEXT_CRED_PATTERN" {} + | sort
  section container-images
  run $sudo docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}' | sort
  section docker-daemon
  run $sudo find /etc/docker -maxdepth 1 -name daemon.json -printf '%m %u:%g %p\n'
}

# --- 운영자 쪽 -------------------------------------------------------------------
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

# 옵션은 OPT 연관 배열(label, dest, port, base)로 받는다.
declare -A OPT=()

collect() {
  local label="${OPT[label]}" dest="${OPT[dest]}" port="${OPT[port]:-}" base="${OPT[base]}" ts out
  check_out_dir "$base" || return 1
  ts="$(date +%Y%m%dT%H%M%S)"
  out="$base/$label/$ts"
  umask 077
  mkdir -p "$base/$label"
  # 같은 초의 다른 실행을 덮어쓰지 않도록 -p 없이 만든다.
  mkdir "$out" || return 1
  local sshargs=(-o BatchMode=yes -o StrictHostKeyChecking=yes)
  [ -n "$port" ] && sshargs+=(-p "$port")
  # shellcheck disable=SC2206
  [ -n "${BASELINE_SSH_OPTS:-}" ] && sshargs+=($BASELINE_SSH_OPTS)
  # 서버 쪽 수집 설정(Match 평가 출발지·사용자)을 환경변수로 넘긴다.
  local remote_env
  remote_env="$(printf 'BASELINE_SSHD_MATCH_ADDRS=%q BASELINE_SSHD_MATCH_USER=%q' \
    "${BASELINE_SSHD_MATCH_ADDRS:-}" "${BASELINE_SSHD_MATCH_USER:-}")"
  # shellcheck disable=SC2029  # 클라이언트 쪽 확장이 의도다(%q로 이스케이프함)
  if ! ssh "${sshargs[@]}" "$dest" "env $remote_env bash -s -- --remote" < "$0" > "$out/snapshot.txt" 2> "$out/stderr.txt"; then
    echo "수집 실패: $out/stderr.txt 확인" >&2
    return 1
  fi
  if ! check_no_secrets "$out/snapshot.txt" || ! check_no_secrets "$out/stderr.txt"; then
    rm -f "$out/snapshot.txt" "$out/stderr.txt"
    return 1
  fi
  echo "$out/snapshot.txt"
}

main() {
  OPT=([base]="${INFRA_PRIVATE_DIR:-$DEFAULT_PRIVATE_DIR}/baseline")
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

# source하면 함수만 불러온다(테스트용). 직접 실행하거나 ssh stdin(bash -s)이면 main을 돈다.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main "$@"; fi
