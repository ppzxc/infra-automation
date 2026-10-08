# KISA-2026:U-33 (하) 숨겨진 파일 및 디렉토리 검색 및 제거
# 양호: 의심스러운 숨겨진 파일·디렉터리를 제거한 경우. "의심스러움"은 자동 판정할 수 없으므로
# 로그인 계정 홈(1단계)과 /tmp·/var/tmp·/dev의 숨김 항목 중 통상 항목을 뺀 목록을 증적으로 낸다(수동).
(
  list=""
  dirs="/tmp /var/tmp /dev"
  for entry in $(kisa_login_homes | tr ' ' '_'); do
    home=${entry#*:}
    case "$home" in "" | /) continue ;; esac
    dirs="$dirs $home"
  done
  for d in $dirs; do
    [ -d "$R$d" ] || continue
    for p in "$R$d"/.[!.]* "$R$d"/..?*; do
      [ -e "$p" ] || continue
      case "${p##*/}" in
        .ssh | .cache | .config | .local | .bash_history | .bash_logout | .bash_profile | .bashrc | .profile | \
          .viminfo | .lesshst | .kshrc | .cshrc | .tcshrc | .login | .ansible | .pki | .gnupg | .wget-hsts | \
          .ICE-unix | .X11-unix | .XIM-unix | .font-unix | .Test-unix | .lock | .udev | .mozilla | .zshrc) continue ;;
      esac
      list="$list${list:+
}${p#"$R"}"
    done
  done
  if [ -z "$list" ]; then
    kisa_emit U-33 GOOD "no unusual hidden file in login homes, /tmp, /var/tmp, /dev"
  else
    kisa_emit U-33 MANUAL "hidden entries to review: $(printf '%s\n' "$list" | kisa_cap 30)"
  fi
)
