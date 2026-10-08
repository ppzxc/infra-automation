# KISA-2026:U-03 (상) 계정 잠금 임계값 설정
# 양호: 계정 잠금 임계값이 10회 이하로 설정된 경우.
# auth 스택의 pam_faillock(RHEL 8+, Ubuntu 22.04+)·pam_tally2(CentOS 6/7)·pam_tally의 deny 값을 본다.
# pam_faillock은 인자에 deny가 없으면 /etc/security/faillock.conf, 그것도 없으면 기본값 3이다.
# 여러 곳에 있으면 가장 큰 값(가장 느슨한 값)으로 판정한다. deny=0은 잠그지 않는다는 뜻이다.
(
  pam=$(kisa_pam_files system-auth password-auth common-auth)
  lines=""
  [ -n "$pam" ] && lines=$(grep -hE '^[[:space:]]*auth[[:space:]].*pam_(faillock|tally2|tally)\.so' $pam 2>/dev/null)
  if [ -z "$lines" ]; then
    kisa_emit U-03 VULN "no pam_faillock/pam_tally2/pam_tally in auth stack"
    exit 0
  fi
  mods=$(printf '%s\n' "$lines" | grep -oE 'pam_(faillock|tally2|tally)\.so' | sort -u | tr '\n' ' ')
  deny=$(printf '%s\n' "$lines" | tr ' \t' '\n\n' | awk -F= '$1 == "deny" { print $2 }' | sort -n | tail -n 1)
  src="pam args"
  if [ -z "$deny" ]; then
    case "$mods" in
      *pam_faillock*)
        deny=$(sed 's/#.*//' "$R/etc/security/faillock.conf" 2>/dev/null | tr -d ' \t' | awk -F= '$1 == "deny" { v = $2 } END { print v }')
        src="/etc/security/faillock.conf"
        if [ -z "$deny" ]; then
          deny=3
          src="pam_faillock default"
        fi
        ;;
    esac
  fi
  ev="modules: ${mods}deny=${deny:-unset} ($src)"
  if [ -n "$deny" ] && [ "$deny" -ge 1 ] 2>/dev/null && [ "$deny" -le 10 ]; then
    kisa_emit U-03 GOOD "$ev"
  else
    kisa_emit U-03 VULN "$ev"
  fi
)
