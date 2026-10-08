# KISA-2026:U-55 (중) FTP 계정 shell 제한
# 양호: ftp 계정에 /bin/false(/sbin/nologin) 셸이 부여된 경우. ftp 계정이 없으면 해당없음.
(
  shell=$(awk -F: '$1 == "ftp" { print $7; found = 1 } END { exit !found }' "$R/etc/passwd" 2>/dev/null) || {
    kisa_emit U-55 NA "no ftp account"
    exit 0
  }
  if kisa_login_shell "$shell"; then
    kisa_emit U-55 VULN "ftp shell=${shell:-empty}"
  else
    kisa_emit U-55 GOOD "ftp shell=$shell"
  fi
)
