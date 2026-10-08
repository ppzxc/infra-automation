# KISA-2026:U-06 (상) 사용자 계정 su 기능 제한
# 양호: su 명령어를 특정 그룹(wheel 등)에 속한 사용자만 사용하도록 제한된 경우.
# /etc/pam.d/su에 pam_wheel.so가 required/requisite로 켜져 있거나, su 실행 파일이
# root 외 그룹 소유이면서 other 실행 권한이 없으면 양호다. su가 없으면 해당없음.
(
  if grep -qE '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$R/etc/pam.d/su" 2>/dev/null; then
    kisa_emit U-06 GOOD "pam_wheel.so enabled in /etc/pam.d/su"
    exit 0
  fi
  su_bin=""
  for p in "$R/bin/su" "$R/usr/bin/su"; do
    [ -e "$p" ] && { su_bin="$p"; break; }
  done
  if [ -z "$su_bin" ]; then
    kisa_emit U-06 NA "su not installed"
    exit 0
  fi
  perm=$(ls -lL "$su_bin" 2>/dev/null | awk '{ print $1 " " $4 }')
  mode=${perm%% *}
  group=${perm#* }
  other_x=$(printf '%s' "$mode" | cut -c10)
  ev="pam_wheel.so not enabled in /etc/pam.d/su; su mode=$mode group=$group"
  if [ "$group" != "root" ] && [ "$other_x" != "x" ] && [ "$other_x" != "t" ]; then
    kisa_emit U-06 GOOD "$ev"
  else
    kisa_emit U-06 VULN "$ev"
  fi
)
