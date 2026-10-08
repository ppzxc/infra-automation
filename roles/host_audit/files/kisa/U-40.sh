# KISA-2026:U-40 (상) NFS 접근 통제
# 양호: /etc/exports의 모든 공유에 허용 호스트가 지정되어 있고(*·호스트 없음 아님) 파일 권한이 644 이하.
# NFS 서버가 없으면 해당없음.
(
  if ! kisa_service_on nfsd nfs-server nfs-kernel-server; then
    kisa_emit U-40 NA "NFS server not active"
    exit 0
  fi
  if [ ! -r "$R/etc/exports" ]; then
    kisa_emit U-40 VULN "NFS server active but /etc/exports not readable"
    exit 0
  fi
  open=$(grep -Ev '^[[:space:]]*(#|$)' "$R/etc/exports" | awk 'NF < 2 || $2 ~ /^\*/ || $2 ~ /^\(/ { print $1 }' | kisa_cap 10)
  st=$(kisa_stat "$R/etc/exports")
  why=""
  [ -n "$open" ] && why="exports open to any host: $open"
  if [ "${st#* }" != root ] || ! kisa_mode_le "${st% *}" 644; then
    why="${why:+$why; }/etc/exports owner=${st#* } mode=${st% *}"
  fi
  if [ -n "$why" ]; then
    kisa_emit U-40 VULN "$why"
  else
    kisa_emit U-40 GOOD "every export names its clients; /etc/exports owner=${st#* } mode=${st% *}"
  fi
)
