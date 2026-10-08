# KISA-2026:U-54 (중) 암호화되지 않는 FTP 서비스 비활성화
# 양호: 암호화되지 않은 FTP를 쓰지 않는 경우. vsftpd가 ssl_enable=YES와 로그인·데이터 SSL 강제
# (force_local_logins_ssl·force_local_data_ssl 기본 YES)이면 암호화된 FTP로 본다. SFTP는 무관하다.
(
  ftpd=$(kisa_ftpd)
  if [ -z "$ftpd" ] && ! kisa_listening 21; then
    kisa_emit U-54 GOOD "no FTP service active"
    exit 0
  fi
  if [ "$ftpd" = vsftpd ]; then
    f=$(kisa_first_file /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf)
    if [ -n "$f" ] && grep -Eiq '^[[:space:]]*ssl_enable[[:space:]]*=[[:space:]]*YES' "$f" \
      && ! grep -Eiq '^[[:space:]]*force_local_(logins|data)_ssl[[:space:]]*=[[:space:]]*NO' "$f"; then
      kisa_emit U-54 GOOD "vsftpd with ssl_enable=YES and forced SSL"
      exit 0
    fi
  fi
  kisa_emit U-54 VULN "unencrypted FTP active: ${ftpd:-21/tcp listening}"
)
