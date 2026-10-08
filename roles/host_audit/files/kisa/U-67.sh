# KISA-2026:U-67 (중) 로그 디렉터리 소유자 및 권한 설정
# 양호: 로그 디렉터리(/var/log) 바로 아래 로그 파일의 소유자가 root이고 권한이 644 이하인 경우.
# 하위 디렉터리는 보지 않는다(가이드 조치 범위와 같다).
(
  if [ ! -d "$R/var/log" ]; then
    kisa_emit U-67 MANUAL "/var/log not readable"
    exit 0
  fi
  bad=""
  n=0
  for f in "$R"/var/log/* "$R"/var/log/.[!.]*; do
    [ -f "$f" ] || continue
    st=$(kisa_stat "$f") || continue
    n=$((n + 1))
    if [ "${st#* }" != root ] || ! kisa_mode_le "${st% *}" 644; then
      bad="$bad${bad:+
}${f##*/}(${st#* },${st% *})"
    fi
  done
  if [ "$n" -eq 0 ]; then
    kisa_emit U-67 GOOD "no log file directly under /var/log"
  elif [ -n "$bad" ]; then
    kisa_emit U-67 VULN "not root-owned or > 644: $(printf '%s\n' "$bad" | kisa_cap 20)"
  else
    kisa_emit U-67 GOOD "$n log files under /var/log root-owned and <= 644"
  fi
)
