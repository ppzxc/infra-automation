# KISA-2026:U-51 (중) DNS 서비스의 취약한 동적 업데이트 설정 금지
# 양호: 동적 업데이트를 쓰지 않거나(allow-update 없음·none), 쓰면 허용 대상을 제한한 경우 (any 아님).
# DNS 서비스를 쓰지 않으면 해당없음.
(
  conf=$(kisa_named_conf) || { kisa_emit U-51 NA "DNS service (named) not active"; exit 0; }
  au=$(printf '%s\n' "$conf" | grep -E '^[^#/]*allow-update' | tr -s ' \t' ' ' | kisa_cap 5)
  if [ -z "$au" ]; then
    kisa_emit U-51 GOOD "allow-update not set (dynamic update disabled)"
  elif printf '%s' "$au" | grep -Eq '\{[[:space:]]*any[[:space:]]*;'; then
    kisa_emit U-51 VULN "allow-update any: $au"
  else
    kisa_emit U-51 GOOD "$au"
  fi
)
