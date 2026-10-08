# KISA-2026:U-12 (하) 세션 종료 시간 설정
# 양호: Session Timeout이 600초(10분) 이하로 설정된 경우.
# sh 계열 전역 프로필(/etc/profile, /etc/profile.d/*.sh, /etc/bashrc, /etc/bash.bashrc)의
# TMOUT을 본다. 여러 곳에 있으면 가장 큰 값(가장 느슨한 값)으로 판정한다. csh는 보지 않는다.
(
  found=""
  max=""
  for f in "$R/etc/profile" "$R"/etc/profile.d/*.sh "$R/etc/bashrc" "$R/etc/bash.bashrc"; do
    [ -r "$f" ] || continue
    for v in $(grep -E '^[[:space:]]*((export|readonly)[[:space:]]+|declare[[:space:]]+-[a-zA-Z]+[[:space:]]+)?TMOUT=[0-9]+' "$f" | sed 's/.*TMOUT=\([0-9][0-9]*\).*/\1/'); do
      found="$found${found:+ }${f#"$R"}=$v"
      if [ -z "$max" ] || [ "$v" -gt "$max" ]; then
        max=$v
      fi
    done
  done
  if [ -z "$max" ]; then
    kisa_emit U-12 VULN "TMOUT not set in global shell profiles"
  elif [ "$max" -ge 1 ] && [ "$max" -le 600 ]; then
    kisa_emit U-12 GOOD "TMOUT: $found"
  else
    kisa_emit U-12 VULN "TMOUT: $found"
  fi
)
