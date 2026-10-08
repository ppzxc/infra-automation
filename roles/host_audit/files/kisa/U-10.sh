# KISA-2026:U-10 (중) 동일한 UID 금지
# 양호: 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-10 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  bad=$(awk -F: 'NF > 2 { n[$3]++; l[$3] = l[$3] (l[$3] == "" ? "" : "+") $1 } END { for (u in n) if (n[u] > 1) print u "=" l[u] }' "$R/etc/passwd" | sort | tr '\n' ' ' | sed 's/ $//')
  if [ -z "$bad" ]; then
    kisa_emit U-10 GOOD "no duplicate UID"
  else
    kisa_emit U-10 VULN "duplicate UID: $bad"
  fi
)
