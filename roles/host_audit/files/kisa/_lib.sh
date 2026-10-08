# KISA-2026 Unix 점검 공통 부분 (ADR-0009, #121). 점검 스크립트(U-NN.sh)보다 먼저 이어 붙는다.
# POSIX sh, 읽기 전용: 파일을 읽고 조회 명령만 실행하며 호스트에 아무것도 쓰지 않는다.
# CentOS 6 ~ Rocky 10, Ubuntu에서 같은 본문이 돈다(bash 전용 문법·Python 없음).
#
# 출력: 표식 사이에 항목마다 한 줄 `U-NN|<GOOD|VULN|NA|MANUAL>|<증적>`.
# 증적은 설정 값·계정 이름·개수만 담는다(비밀번호 해시 등 비밀값은 싣지 않는다).
# 항목 스크립트는 각자 서브셸 `( ... )`에서 돌아 변수가 섞이지 않고, 한 항목이 중간에
# 끝나도 다음 항목은 돈다. 출력이 없는 항목은 보고서에서 점검불가로 표시된다.
# R: 점검할 파일시스템 루트. 운영에서는 비어 있고, pytest는 가짜 루트를 넘긴다.
R="${KISA_ROOT:-}"
LC_ALL=C
export LC_ALL

kisa_emit() {
  printf '%s|%s|%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\n|' ';/')"
}

# 로그인 가능 셸인가. 비어 있으면 /bin/sh로 로그인되므로 로그인 가능으로 본다.
kisa_login_shell() {
  case "$1" in
    */nologin | */false) return 1 ;;
  esac
  return 0
}

# 지정 TCP 포트에서 listening 중인가. ss·netstat이 모두 없으면 모른다(거짓).
kisa_listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p=":$1" 'NR > 1 && substr($4, length($4) - length(p) + 1) == p { f = 1 } END { exit !f }'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p=":$1" '$1 ~ /^tcp/ && substr($4, length($4) - length(p) + 1) == p { f = 1 } END { exit !f }'
  else
    return 1
  fi
}

# 존재하는 PAM 스택 파일 경로 (RHEL 계열 system-auth/password-auth, Debian 계열 common-*).
kisa_pam_files() {
  for f in "$@"; do
    [ -r "$R/etc/pam.d/$f" ] && printf '%s ' "$R/etc/pam.d/$f"
  done
}

# ---- #122: 파일·디렉토리, 서비스, 패치, 로그 관리 항목용 공통 함수 -------------------------

# 파일 모드(8진수 문자열)와 소유자 이름 "MODE OWNER". 없으면 실패.
# KISA_FAKE_ROOT_OWNER는 pytest 가짜 루트(KISA_ROOT) 전용: 그 사용자 소유를 root로 본다.
kisa_stat() {
  _st=$(stat -c '%a %U' "$1" 2>/dev/null) || return 1
  if [ -n "$R" ] && [ -n "${KISA_FAKE_ROOT_OWNER:-}" ] && [ "${_st#* }" = "$KISA_FAKE_ROOT_OWNER" ]; then
    _st="${_st% *} root"
  fi
  printf '%s\n' "$_st"
}

# 모드 $1이 상한 $2 이내인가: 상한에 없는 권한 비트가 하나도 없으면 참 (둘 다 8진수 문자열).
kisa_mode_le() {
  [ $(( 0$1 & ~0$2 & 07777 )) -eq 0 ]
}

# 단일 파일 소유자·권한 판정. kisa_file_check CODE PATH MAXMODE "OWNERS" [파일 없을 때 STATUS]
kisa_file_check() {
  _st=$(kisa_stat "$R$2")
  if [ -z "$_st" ]; then
    kisa_emit "$1" "${5:-NA}" "$2 not found"
    return 0
  fi
  _mode=${_st% *}
  _own=${_st#* }
  _ok=0
  for _o in $4; do
    [ "$_own" = "$_o" ] && _ok=1
  done
  if [ "$_ok" -eq 1 ] && kisa_mode_le "$_mode" "$3"; then
    kisa_emit "$1" GOOD "$2 owner=$_own mode=$_mode"
  else
    kisa_emit "$1" VULN "$2 owner=$_own mode=$_mode (required owner in [$4], mode <= $3)"
  fi
}

# 실행 중인 프로세스(comm) 중 이름이 하나라도 있는가.
kisa_proc() {
  ps -e -o comm= 2>/dev/null | awk -v l=" $* " 'index(l, " " $1 " ") { f = 1 } END { exit !f }'
}

# systemd unit 중 하나라도 active인가 (systemd가 없으면 거짓).
kisa_unit_active() {
  command -v systemctl >/dev/null 2>&1 || return 1
  for _u in "$@"; do
    systemctl is-active --quiet "$_u" 2>/dev/null && return 0
  done
  return 1
}

# xinetd(/etc/xinetd.d/NAME, disable = yes 아님) 또는 inetd.conf(주석 아닌 NAME 줄)로 켜져 있는가.
kisa_inetd_on() {
  for _s in "$@"; do
    _f="$R/etc/xinetd.d/$_s"
    if [ -r "$_f" ] && ! grep -Eiq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$_f"; then
      return 0
    fi
    if [ -r "$R/etc/inetd.conf" ] && grep -Eq "^[[:space:]]*${_s}[[:space:]]" "$R/etc/inetd.conf"; then
      return 0
    fi
  done
  return 1
}

# 서비스 사용 중인가: 프로세스·systemd unit·(x)inetd 중 하나. 이름은 셋에 공통으로 쓴다.
kisa_service_on() {
  kisa_proc "$@" || kisa_unit_active "$@" || kisa_inetd_on "$@"
}

# 표준입력의 줄 목록을 쉼표로 잇되 $1개까지만 싣고 나머지는 개수로 줄인다.
kisa_cap() {
  awk -v n="${1:-20}" 'NF { c++; if (c <= n) printf "%s%s", (c > 1 ? "," : ""), $0 } END { if (c > n) printf ",...(+%d)", c - n }'
}

# find 대상: 루트(/)와 로컬 디스크 파일시스템(ext2/3/4·xfs·btrfs) 디렉터리 마운트 지점. 각자 -xdev로
# 뒤지므로 가상·네트워크 파일시스템은 빠진다. 루트를 늘 넣는 것은 컨테이너처럼 루트가 overlay여도
# 비지 않게 하기 위해서다(빈 목록이면 find가 현재 디렉터리를 뒤진다). 가짜 루트면 그 루트 하나.
kisa_local_mounts() {
  if [ -n "$R" ]; then
    printf '%s/\n' "$R"
    return 0
  fi
  {
    echo /
    awk '$3 ~ /^(ext[234]|xfs|btrfs)$/ { print $2 }' /proc/mounts 2>/dev/null | while read -r _m; do
      [ -d "$_m" ] && printf '%s\n' "$_m"
    done
  } | sort -u
}

# 오래 걸릴 수 있는 find를 시간 제한(기본 120초) 안에서 돌린다. 시간 초과면 종료코드 124.
kisa_find() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${KISA_FIND_TIMEOUT:-120}" find "$@" 2>/dev/null
  else
    find "$@" 2>/dev/null
  fi
}

# 로그인 가능한 계정의 "이름:홈" 목록 (sync·shutdown·halt 같은 관례적 특수 셸 계정 제외).
kisa_login_homes() {
  [ -r "$R/etc/passwd" ] || return 0
  while IFS=: read -r _n _pw _uid _gid _gecos _home _shell; do
    [ -n "$_n" ] || continue
    case "$_n" in sync | shutdown | halt) continue ;; esac
    kisa_login_shell "$_shell" && printf '%s:%s\n' "$_n" "$_home"
  done < "$R/etc/passwd"
}

# 사용 중인 MTA(postfix·sendmail·exim). 없으면 빈 문자열.
kisa_mta() {
  if kisa_service_on master postfix; then
    echo postfix
  elif kisa_service_on sendmail; then
    echo sendmail
  elif kisa_service_on exim exim4; then
    echo exim
  fi
}

# 사용 중인 FTP 데몬(vsftpd·proftpd·pure-ftpd). 없으면 빈 문자열.
kisa_ftpd() {
  if kisa_service_on vsftpd; then
    echo vsftpd
  elif kisa_service_on proftpd; then
    echo proftpd
  elif kisa_service_on pure-ftpd; then
    echo pure-ftpd
  fi
}

# 사용 중인 SNMP 에이전트 설정 파일(snmpd 실행 중일 때만). 없으면 빈 문자열.
kisa_snmpd_conf() {
  kisa_service_on snmpd || return 0
  for _f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do
    [ -r "$R$_f" ] && { printf '%s\n' "$R$_f"; return 0; }
  done
  printf '%s\n' "$R/etc/snmp/snmpd.conf"
}

# 사용 중인 BIND(named)의 설정 본문(주 설정 + include 1단계). named가 없으면 빈 출력·실패.
kisa_named_conf() {
  kisa_service_on named bind9 || return 1
  for _f in /etc/named.conf /etc/bind/named.conf; do
    [ -r "$R$_f" ] || continue
    cat "$R$_f"
    for _inc in $(awk -F'"' '/^[[:space:]]*include[[:space:]]/ { print $2 }' "$R$_f"); do
      [ -r "$R$_inc" ] && cat "$R$_inc"
    done
  done
  return 0
}

echo __HOST_AUDIT_KISA_BEGIN__
