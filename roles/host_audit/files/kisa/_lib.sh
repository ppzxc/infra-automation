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

echo __HOST_AUDIT_KISA_BEGIN__
