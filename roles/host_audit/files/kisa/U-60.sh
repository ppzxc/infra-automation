# KISA-2026:U-60 (중) SNMP Community String 복잡성 설정
# 양호: community가 public·private이 아니고, 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상인 경우.
# community 값은 비밀값이라 증적에 싣지 않고 길이·문자 종류만 낸다. v3 전용이면 비밀번호를 확인할 수
# 없어 수동. SNMP를 쓰지 않으면 해당없음.
(
  set -f
  f=$(kisa_snmpd_conf)
  if [ -z "$f" ]; then
    kisa_emit U-60 NA "snmpd not active"
    exit 0
  fi
  comms=$(awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ { print $2 } tolower($1) ~ /^com2sec6?$/ { print $NF }' "$f" 2>/dev/null)
  if [ -z "$comms" ]; then
    kisa_emit U-60 MANUAL "no v1/v2c community; v3 passphrase complexity must be reviewed manually"
    exit 0
  fi
  weak=0
  total=0
  for c in $comms; do
    total=$((total + 1))
    len=${#c}
    alpha=0
    digit=0
    special=0
    printf '%s' "$c" | grep -q '[A-Za-z]' && alpha=1
    printf '%s' "$c" | grep -q '[0-9]' && digit=1
    printf '%s' "$c" | grep -q '[^A-Za-z0-9]' && special=1
    case "$c" in
      public | private) weak=$((weak + 1)); continue ;;
    esac
    if [ "$alpha" -eq 1 ] && [ "$digit" -eq 1 ] && { [ "$len" -ge 10 ] || { [ "$special" -eq 1 ] && [ "$len" -ge 8 ]; }; }; then
      :
    else
      weak=$((weak + 1))
    fi
  done
  if [ "$weak" -gt 0 ]; then
    kisa_emit U-60 VULN "$weak of $total community strings are default or too simple (values not shown)"
  else
    kisa_emit U-60 GOOD "$total community strings meet length/complexity (values not shown)"
  fi
)
