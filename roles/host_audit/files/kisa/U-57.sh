# KISA-2026:U-57 (중) Ftpusers 파일 설정
# 양호: root 계정의 FTP 접속을 차단한 경우. ftpusers(또는 vsftpd user_list, userlist_deny 기본 YES)에
# root가 있거나, proftpd RootLogin off(기본값)이면 양호. FTP를 쓰지 않으면 해당없음.
(
  ftpd=$(kisa_ftpd)
  if [ -z "$ftpd" ]; then
    kisa_emit U-57 NA "no FTP service active"
    exit 0
  fi
  if [ "$ftpd" = proftpd ]; then
    f=$(kisa_first_file /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    if [ -n "$f" ] && grep -Eiq '^[[:space:]]*RootLogin[[:space:]]+on' "$f"; then
      kisa_emit U-57 VULN "proftpd RootLogin on"
    else
      kisa_emit U-57 GOOD "proftpd RootLogin off"
    fi
    exit 0
  fi
  for f in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list; do
    if [ -r "$R$f" ] && grep -qx 'root' "$R$f"; then
      kisa_emit U-57 GOOD "root listed in $f"
      exit 0
    fi
  done
  kisa_emit U-57 VULN "root not listed in ftpusers/user_list"
)
