# KISA-2026:U-21 (상) /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# 양호: 소유자 root(또는 bin, sys), 권한 640 이하. rsyslog.conf를 먼저 보고 없으면 syslog.conf.
(
  found=0
  for f in /etc/rsyslog.conf /etc/syslog.conf; do
    [ -e "$R$f" ] || continue
    found=1
    kisa_file_check U-21 "$f" 640 "root bin sys"
    break
  done
  [ "$found" -eq 1 ] || kisa_emit U-21 NA "no /etc/rsyslog.conf or /etc/syslog.conf"
)
