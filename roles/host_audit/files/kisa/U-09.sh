# KISA-2026:U-09 (하) 계정이 존재하지 않는 GID 금지
# 양호: 불필요한 그룹이 제거된 경우. 가이드의 조치 방법("/etc/group과 /etc/passwd를 비교")에
# 따라, 계정의 기본 GID가 /etc/group에 없는 경우(존재하지 않는 GID)를 취약으로 본다.
(
  if [ ! -r "$R/etc/group" ] || [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-09 MANUAL "/etc/group or /etc/passwd not readable"
    exit 0
  fi
  bad=$(awk -F: 'NR == FNR { g[$3] = 1; next } NF > 3 && !($4 in g) { print $1 "(" $4 ")" }' "$R/etc/group" "$R/etc/passwd" | tr '\n' ',' | sed 's/,$//')
  if [ -z "$bad" ]; then
    kisa_emit U-09 GOOD "every primary GID exists in /etc/group"
  else
    kisa_emit U-09 VULN "primary GID missing from /etc/group: $bad"
  fi
)
