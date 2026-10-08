# KISA-2026:U-32 (중) 홈 디렉토리로 지정한 디렉토리의 존재 관리
# 양호: 홈 디렉터리가 존재하지 않는 (로그인 가능한) 계정이 없는 경우.
# nologin·false 셸 서비스 계정(nobody 등)의 의도적 더미 홈은 보지 않는다.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-32 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  bad=""
  for entry in $(kisa_login_homes | tr ' ' '_'); do
    home=${entry#*:}
    if [ -z "$home" ] || [ ! -d "$R$home" ]; then
      bad="$bad${bad:+ }${entry%%:*}:${home:-empty}"
    fi
  done
  if [ -n "$bad" ]; then
    kisa_emit U-32 VULN "login accounts whose home directory is missing: $bad"
  else
    kisa_emit U-32 GOOD "every login account has an existing home directory"
  fi
)
