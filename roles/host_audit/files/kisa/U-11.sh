# KISA-2026:U-11 (하) 사용자 shell 점검
# 양호: 로그인이 불필요한 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우.
# 대상은 가이드가 나열한 계정이다: daemon bin sys adm listen nobody nobody4 noaccess diag
# operator games gopher (admin 제외). 존재하는 계정만 본다.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-11 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  bad=""
  while IFS=: read -r name _pw _uid _gid _gecos _home shell; do
    case "$name" in
      daemon | bin | sys | adm | listen | nobody | nobody4 | noaccess | diag | operator | games | gopher)
        kisa_login_shell "$shell" && bad="$bad${bad:+,}$name:${shell:-/bin/sh}"
        ;;
    esac
  done < "$R/etc/passwd"
  if [ -z "$bad" ]; then
    kisa_emit U-11 GOOD "listed system accounts have nologin/false shell"
  else
    kisa_emit U-11 VULN "system accounts with login shell: $bad"
  fi
)
