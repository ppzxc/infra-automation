# KISA-2026:U-31 (중) 홈디렉토리 소유자 및 권한 설정
# 양호: 홈 디렉터리 소유자가 해당 계정이고 기타 사용자 쓰기 권한이 없는 경우.
# 로그인 가능한 계정만 보며, 홈이 / 이거나 없는 계정은 U-32가 다룬다. root 홈은 root 소유면 된다.
(
  bad=""
  n=0
  for entry in $(kisa_login_homes | tr ' ' '_'); do
    user=${entry%%:*}
    home=${entry#*:}
    case "$home" in "" | /) continue ;; esac
    [ -d "$R$home" ] || continue
    st=$(kisa_stat "$R$home") || continue
    n=$((n + 1))
    mode=${st% *}
    own=${st#* }
    if [ "$own" != "$user" ] || [ $(( 0$mode & 02 )) -ne 0 ]; then
      bad="$bad${bad:+ }$user:$home($own,$mode)"
    fi
  done
  if [ "$n" -eq 0 ]; then
    kisa_emit U-31 NA "no existing home directory for login accounts"
  elif [ -n "$bad" ]; then
    kisa_emit U-31 VULN "not owned by the account or other-writable: $bad"
  else
    kisa_emit U-31 GOOD "$n home directories owned by their account without other write"
  fi
)
