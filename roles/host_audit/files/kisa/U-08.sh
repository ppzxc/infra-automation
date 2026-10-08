# KISA-2026:U-08 (중) 관리자 그룹에 최소한의 계정 포함
# 양호: 관리자 그룹(root, GID 0)에 불필요한 계정이 없는 경우. "불필요"는 운영 판단이라
# GID 0 그룹 구성원·기본 그룹이 GID 0인 계정, wheel/sudo/admin 구성원을 증적으로 내고
# 점검불가(수동)로 둔다.
(
  if [ ! -r "$R/etc/group" ] || [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-08 MANUAL "/etc/group or /etc/passwd not readable"
    exit 0
  fi
  gid0=$(awk -F: '$3 == "0" { print $1 "=" ($4 == "" ? "-" : $4) }' "$R/etc/group" | tr '\n' ' ' | sed 's/ $//')
  primary=$(awk -F: '$4 == "0" && $1 != "root" { print $1 }' "$R/etc/passwd" | tr '\n' ',' | sed 's/,$//')
  admin=$(awk -F: '$1 == "wheel" || $1 == "sudo" || $1 == "admin" { print $1 "=" ($4 == "" ? "-" : $4) }' "$R/etc/group" | tr '\n' ' ' | sed 's/ $//')
  kisa_emit U-08 MANUAL "GID 0 group: ${gid0:-none}; primary GID 0 (non-root): ${primary:-none}; admin groups: ${admin:-none}"
)
