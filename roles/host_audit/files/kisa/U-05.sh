# KISA-2026:U-05 (상) root 이외의 UID가 '0' 금지
# 양호: root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-05 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  bad=$(awk -F: '$3 == "0" && $1 != "root" { print $1 }' "$R/etc/passwd" | tr '\n' ',' | sed 's/,$//')
  if [ -z "$bad" ]; then
    kisa_emit U-05 GOOD "only root has UID 0"
  else
    kisa_emit U-05 VULN "UID 0 besides root: $bad"
  fi
)
