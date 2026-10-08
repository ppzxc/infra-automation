# KISA-2026:U-62 (하) 로그인 시 경고 메시지 설정
# 양호: 서버(콘솔: /etc/motd 또는 /etc/issue)와 사용 중인 원격 서비스(SSH Banner, Telnet: /etc/issue.net,
# FTP·SMTP·DNS 배너)에 로그온 경고 메시지를 설정한 경우. 배포판 기본 /etc/issue처럼 escape(\S \r \n \l \m)나
# OS 이름·릴리스 문구만 있는 줄은 경고 메시지로 보지 않는다. FTP·SMTP·DNS 배너는 U-53·U-45~48·U-49에서 본다.
(
  miss=""
  srv=""
  rel=$(head -n 1 "$R/etc/redhat-release" 2>/dev/null)
  name=$(awk -F= '$1 == "NAME" { gsub(/"/, "", $2); print $2 }' "$R/etc/os-release" 2>/dev/null)
  for f in /etc/motd /etc/issue; do
    [ -s "$R$f" ] || continue
    if grep -Ev '^[[:space:]]*$|\\[SrnlmvsdtOoUu]' "$R$f" | grep -Fv "${rel:-@@none@@}" | grep -Fv "${name:-@@none@@}" \
      | grep -q .; then
      srv="${srv:+$srv,}$f"
    fi
  done
  [ -n "$srv" ] || miss="server(/etc/motd,/etc/issue)"
  ssh=""
  sshd_bin=$(command -v sshd 2>/dev/null)
  [ -z "$sshd_bin" ] && [ -x "$R/usr/sbin/sshd" ] && sshd_bin="$R/usr/sbin/sshd"
  if [ -n "$sshd_bin" ] || [ -r "$R/etc/ssh/sshd_config" ]; then
    b=""
    [ -n "$sshd_bin" ] && b=$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1) == "banner" { print $2; exit }')
    [ -z "$b" ] && b=$(awk 'tolower($1) == "banner" { print $2; exit }' "$R/etc/ssh/sshd_config" 2>/dev/null)
    if [ -n "$b" ] && [ "$b" != none ]; then
      ssh="ssh Banner=$b"
    else
      miss="${miss:+$miss,}ssh Banner"
    fi
  fi
  if kisa_service_on telnet telnetd in.telnetd telnet.socket && [ ! -s "$R/etc/issue.net" ]; then
    miss="${miss:+$miss,}telnet(/etc/issue.net)"
  fi
  if [ -n "$miss" ]; then
    kisa_emit U-62 VULN "warning banner missing: $miss"
  else
    kisa_emit U-62 GOOD "server banner: $srv${ssh:+; $ssh}"
  fi
)
