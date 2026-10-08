# KISA-2026:U-53 (하) FTP 서비스 정보 노출 제한
# 양호: FTP 접속 배너에 버전 등 정보가 노출되지 않는 경우.
# vsftpd: ftpd_banner 지정. proftpd: ServerIdent off 또는 직접 지정한 문구. FTP를 쓰지 않으면 해당없음.
(
  case "$(kisa_ftpd)" in
    "")
      kisa_emit U-53 NA "no FTP service active"
      ;;
    vsftpd)
      f=$(kisa_first_file /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf)
      if [ -n "$f" ] && grep -Eq '^[[:space:]]*ftpd_banner[[:space:]]*=' "$f"; then
        kisa_emit U-53 GOOD "vsftpd ftpd_banner set"
      else
        kisa_emit U-53 VULN "vsftpd ftpd_banner not set (default banner shows the version)"
      fi
      ;;
    proftpd)
      f=$(kisa_first_file /etc/proftpd.conf /etc/proftpd/proftpd.conf)
      if [ -n "$f" ] && grep -Eiq '^[[:space:]]*ServerIdent[[:space:]]+(off|on[[:space:]]+")' "$f"; then
        kisa_emit U-53 GOOD "proftpd ServerIdent restricted"
      else
        kisa_emit U-53 VULN "proftpd ServerIdent not restricted"
      fi
      ;;
    *)
      kisa_emit U-53 MANUAL "pure-ftpd banner must be reviewed manually"
      ;;
  esac
)
