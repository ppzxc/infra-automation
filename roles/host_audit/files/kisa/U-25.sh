# KISA-2026:U-25 (상) world writable 파일 점검
# 양호: world writable 파일이 없거나, 있어도 설정 이유를 인지하고 있는 경우.
# "이유 인지"는 자동 판정할 수 없어 파일이 있으면 목록을 증적으로 내고 수동으로 둔다.
(
  # shellcheck disable=SC2046
  list=$(kisa_find $(kisa_local_mounts) -xdev -type f -perm -0002 -print)
  rc=$?
  if [ "$rc" -eq 124 ]; then
    kisa_emit U-25 MANUAL "find timed out after ${KISA_FIND_TIMEOUT:-120}s"
  elif [ -z "$list" ]; then
    kisa_emit U-25 GOOD "no world-writable regular file on local filesystems"
  else
    kisa_emit U-25 MANUAL "world-writable files: $(printf '%s\n' "$list" | sed "s|^$R||" | kisa_cap 30)"
  fi
)
