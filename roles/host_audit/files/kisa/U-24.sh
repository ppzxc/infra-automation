# KISA-2026:U-24 (상) 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# 양호: 홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이고, 그룹·기타 쓰기 권한이 없는 경우.
# 로그인 가능한 계정의 대표 시작 파일만 본다.
(
  bad=""
  n=0
  for entry in $(kisa_login_homes | tr ' ' '_'); do
    user=${entry%%:*}
    home=${entry#*:}
    [ -d "$R$home" ] || continue
    for name in .profile .bashrc .bash_profile .bash_login .bash_logout .kshrc .cshrc .tcshrc .login .exrc .netrc; do
      f="$R$home/$name"
      [ -f "$f" ] || continue
      st=$(kisa_stat "$f") || continue
      n=$((n + 1))
      mode=${st% *}
      own=${st#* }
      if { [ "$own" != root ] && [ "$own" != "$user" ]; } || ! kisa_mode_le "$mode" 755; then
        bad="$bad${bad:+
}$home/$name($own,$mode)"
      fi
    done
  done
  if [ -n "$bad" ]; then
    kisa_emit U-24 VULN "wrong owner or group/other-writable: $(printf '%s\n' "$bad" | kisa_cap 20)"
  elif [ "$n" -eq 0 ]; then
    kisa_emit U-24 GOOD "no environment file in login account homes"
  else
    kisa_emit U-24 GOOD "$n environment files owned by root or the account, no group/other write"
  fi
)
