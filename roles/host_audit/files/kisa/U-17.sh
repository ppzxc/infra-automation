# KISA-2026:U-17 (상) 시스템 시작 스크립트 권한 설정
# 양호: 시작 스크립트 소유자가 root이고 일반 사용자 쓰기 권한(그룹·기타 쓰기)이 없는 경우.
# SysV(/etc/rc.d/init.d, /etc/init.d)와 systemd 관리자 unit(/etc/systemd/system)의 일반 파일을 본다.
(
  bad=""
  n=0
  for d in /etc/rc.d/init.d /etc/init.d /etc/systemd/system; do
    [ -d "$R$d" ] || continue
    for f in $(kisa_find "$R$d" -type f -print); do
      st=$(kisa_stat "$f") || continue
      n=$((n + 1))
      mode=${st% *}
      own=${st#* }
      if [ "$own" != root ] || ! kisa_mode_le "$mode" 755; then
        bad="$bad${bad:+
}${f#"$R"}($own,$mode)"
      fi
    done
  done
  if [ "$n" -eq 0 ]; then
    kisa_emit U-17 NA "no startup script found"
  elif [ -n "$bad" ]; then
    kisa_emit U-17 VULN "not root-owned or group/other-writable: $(printf '%s\n' "$bad" | kisa_cap 20)"
  else
    kisa_emit U-17 GOOD "$n startup scripts root-owned without group/other write"
  fi
)
