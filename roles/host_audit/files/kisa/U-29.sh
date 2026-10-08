# KISA-2026:U-29 (하) hosts.lpd 파일 소유자 및 권한 설정
# 양호: /etc/hosts.lpd가 없거나, 있으면 소유자 root·권한 600 이하.
(
  if [ -e "$R/etc/hosts.lpd" ]; then
    kisa_file_check U-29 /etc/hosts.lpd 600 root
  else
    kisa_emit U-29 GOOD "/etc/hosts.lpd not present"
  fi
)
