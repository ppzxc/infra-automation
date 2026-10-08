# KISA-2026:U-27 (상) $HOME/.rhosts, hosts.equiv 사용 금지
# 양호: r-command를 쓰지 않거나, 쓰는 경우 /etc/hosts.equiv·$HOME/.rhosts가 소유자 root(또는 해당 계정),
# 권한 600 이하, "+" 설정 없음을 모두 만족하는 경우.
(
  files=""
  [ -f "$R/etc/hosts.equiv" ] && files="root:/etc/hosts.equiv"
  for entry in $(kisa_login_homes | tr ' ' '_'); do
    home=${entry#*:}
    [ -f "$R$home/.rhosts" ] && files="$files${files:+ }${entry%%:*}:$home/.rhosts"
  done
  rsvc=no
  kisa_service_on rlogin rsh rexec in.rlogind in.rshd in.rexecd rlogind rshd rexecd && rsvc=yes
  if [ -z "$files" ]; then
    kisa_emit U-27 GOOD "no /etc/hosts.equiv or .rhosts; r-services=$rsvc"
    exit 0
  fi
  bad=""
  for e in $files; do
    user=${e%%:*}
    f=${e#*:}
    st=$(kisa_stat "$R$f") || continue
    mode=${st% *}
    own=${st#* }
    why=""
    { [ "$own" = root ] || [ "$own" = "$user" ]; } || why="owner=$own"
    kisa_mode_le "$mode" 600 || why="${why:+$why,}mode=$mode"
    grep -Eq '^[[:space:]]*\+' "$R$f" && why="${why:+$why,}'+' entry"
    [ -n "$why" ] && bad="$bad${bad:+ }$f($why)"
  done
  if [ -n "$bad" ]; then
    kisa_emit U-27 VULN "r-services=$rsvc; $bad"
  else
    kisa_emit U-27 GOOD "r-services=$rsvc; trust files restricted: $files"
  fi
)
