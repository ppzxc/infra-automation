# KISA-2026:U-50 (상) DNS ZoneTransfer 설정
# 양호: Zone Transfer를 허가된 호스트에만 허용한 경우 (allow-transfer가 있고 any가 아님).
# DNS 서비스를 쓰지 않으면 해당없음.
(
  conf=$(kisa_named_conf) || { kisa_emit U-50 NA "DNS service (named) not active"; exit 0; }
  at=$(printf '%s\n' "$conf" | grep -E '^[^#/]*allow-transfer' | tr -s ' \t' ' ' | kisa_cap 5)
  if [ -z "$at" ]; then
    kisa_emit U-50 VULN "allow-transfer not set (zone transfer allowed to any host by default)"
  elif printf '%s' "$at" | grep -Eq '\{[[:space:]]*any[[:space:]]*;'; then
    kisa_emit U-50 VULN "allow-transfer any: $at"
  else
    kisa_emit U-50 GOOD "$at"
  fi
)
