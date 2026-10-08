# KISA-2026:U-20 (상) /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# 양호: 소유자 root, 권한 600 이하. (x)inetd가 설치되지 않았으면 해당없음.
(
  found=0
  for f in /etc/xinetd.conf /etc/inetd.conf; do
    [ -e "$R$f" ] || continue
    found=1
    kisa_file_check U-20 "$f" 600 root
    break
  done
  [ "$found" -eq 1 ] || kisa_emit U-20 NA "no /etc/xinetd.conf or /etc/inetd.conf"
)
