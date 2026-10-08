# KISA-2026:U-26 (상) /dev에 존재하지 않는 device 파일 점검
# 양호: /dev에 major·minor 번호가 없는 파일(일반 파일)이 없는 경우.
# 공유 메모리·메시지 큐·hugepage 마운트(/dev/shm, /dev/mqueue, /dev/hugepages)는 제외한다.
(
  if [ ! -d "$R/dev" ]; then
    kisa_emit U-26 MANUAL "/dev not readable"
    exit 0
  fi
  list=$(kisa_find "$R/dev" \( -path "$R/dev/shm" -o -path "$R/dev/mqueue" -o -path "$R/dev/hugepages" \) -prune -o -type f -print)
  if [ -z "$list" ]; then
    kisa_emit U-26 GOOD "no regular file under /dev"
  else
    kisa_emit U-26 VULN "regular files under /dev: $(printf '%s\n' "$list" | sed "s|^$R||" | kisa_cap 20)"
  fi
)
