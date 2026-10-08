# KISA-2026:U-07 (하) 불필요한 계정 제거
# 양호: 불필요한 계정이 존재하지 않는 경우. "불필요"는 인사·운영 맥락에 달려 자동 판정할 수
# 없으므로 로그인 가능한 계정 목록만 증적으로 내고 점검불가(수동)로 둔다.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-07 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  list=""
  while IFS=: read -r name _pw _uid _gid _gecos _home shell; do
    [ -n "$name" ] || continue
    kisa_login_shell "$shell" && list="$list${list:+,}$name"
  done < "$R/etc/passwd"
  kisa_emit U-07 MANUAL "login-capable accounts: ${list:-none}"
)
