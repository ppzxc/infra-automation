# KISA-2026:U-15 (상) 파일 및 디렉터리 소유자 설정
# 양호: 소유자(또는 그룹)가 존재하지 않는 파일 및 디렉터리가 없는 경우.
# 로컬 디스크 파일시스템마다 -xdev로 찾는다(가상·네트워크 파일시스템 제외). 시간 초과면 수동.
(
  # shellcheck disable=SC2046
  list=$(kisa_find $(kisa_local_mounts) -xdev \( -nouser -o -nogroup \) -print)
  rc=$?
  if [ "$rc" -eq 124 ]; then
    kisa_emit U-15 MANUAL "find timed out after ${KISA_FIND_TIMEOUT:-120}s"
  elif [ -z "$list" ]; then
    kisa_emit U-15 GOOD "no file without an existing owner or group on local filesystems"
  else
    kisa_emit U-15 VULN "files without owner/group: $(printf '%s\n' "$list" | sed "s|^$R||" | kisa_cap 20)"
  fi
)
