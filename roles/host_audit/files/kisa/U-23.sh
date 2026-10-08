# KISA-2026:U-23 (상) SUID, SGID, Sticky bit 설정 파일 점검
# 양호: 주요 실행 파일에 불필요한 SUID/SGID가 없는 경우. passwd·su·sudo 등 운영에 필요한
# 표준 바이너리가 늘 있으므로 "있으면 취약"으로 자동 판정하지 않고 목록을 증적으로 낸다(수동).
(
  # shellcheck disable=SC2046
  list=$(kisa_find $(kisa_local_mounts) -xdev -type f \( -perm -4000 -o -perm -2000 \) -print)
  rc=$?
  if [ "$rc" -eq 124 ]; then
    kisa_emit U-23 MANUAL "find timed out after ${KISA_FIND_TIMEOUT:-120}s"
  elif [ -z "$list" ]; then
    kisa_emit U-23 GOOD "no SUID/SGID file on local filesystems"
  else
    kisa_emit U-23 MANUAL "SUID/SGID files ($(printf '%s\n' "$list" | grep -c .)): $(printf '%s\n' "$list" | sed "s|^$R||" | kisa_cap 40)"
  fi
)
