# KISA-2026:U-37 (상) crontab 설정파일 권한 설정 미흡
# 양호: crontab·at 명령 실행 권한이 750 이하이고, cron·at 관련 파일이 소유자 root·권한 640 이하인 경우.
(
  bad=""
  n=0
  for f in /usr/bin/crontab /usr/bin/at; do
    st=$(kisa_stat "$R$f") || continue
    n=$((n + 1))
    kisa_mode_le "${st% *}" 750 || bad="$bad${bad:+ }$f(${st#* },${st% *})"
  done
  for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    st=$(kisa_stat "$R$f") || continue
    n=$((n + 1))
    if [ "${st#* }" != root ] || ! kisa_mode_le "${st% *}" 640; then
      bad="$bad${bad:+ }$f(${st#* },${st% *})"
    fi
  done
  if [ "$n" -eq 0 ]; then
    kisa_emit U-37 NA "cron and at not installed"
  elif [ -n "$bad" ]; then
    kisa_emit U-37 VULN "commands > 750 or files not root/<= 640: $bad"
  else
    kisa_emit U-37 GOOD "$n cron/at commands and files within limits"
  fi
)
