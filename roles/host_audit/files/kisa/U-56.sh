# KISA-2026:U-56 (하) FTP 서비스 접근 제어 설정
# 양호: 특정 IP·호스트만 FTP에 접속하도록 접근 제어를 설정한 경우.
# TCP Wrapper(hosts.allow/deny의 FTP 데몬 또는 ALL 항목), vsftpd tcp_wrappers=YES, proftpd <Limit LOGIN>,
# 방화벽 source 규칙은 U-28에서 본다. FTP를 쓰지 않으면 해당없음.
(
  ftpd=$(kisa_ftpd)
  if [ -z "$ftpd" ]; then
    kisa_emit U-56 NA "no FTP service active"
    exit 0
  fi
  how=""
  if grep -Eiq "^[[:space:]]*($ftpd|in.ftpd|ALL)[[:space:]]*:" "$R/etc/hosts.allow" "$R/etc/hosts.deny" 2>/dev/null; then
    how="TCP Wrapper entry for $ftpd"
  fi
  if [ "$ftpd" = proftpd ]; then
    f=$(kisa_first_file /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    [ -n "$f" ] && grep -Eiq '^[[:space:]]*<Limit[[:space:]]+LOGIN' "$f" && how="${how:+$how; }proftpd <Limit LOGIN>"
  fi
  if [ -n "$how" ]; then
    kisa_emit U-56 GOOD "$how"
  else
    kisa_emit U-56 VULN "$ftpd active without host-based access control"
  fi
)
