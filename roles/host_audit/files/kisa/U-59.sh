# KISA-2026:U-59 (상) 안전한 SNMP 버전 사용
# 양호: SNMP v3 이상만 사용하는 경우. snmpd.conf에 v1/v2c community 설정(rocommunity·rwcommunity·
# com2sec)이 있으면 취약. SNMP를 쓰지 않으면 해당없음.
(
  f=$(kisa_snmpd_conf)
  if [ -z "$f" ]; then
    kisa_emit U-59 NA "snmpd not active"
    exit 0
  fi
  v12=$(grep -Eic '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$f" 2>/dev/null)
  v3=$(grep -Eic '^[[:space:]]*(createUser|rouser|rwuser)[[:space:]]' "$f" 2>/dev/null)
  if [ "${v12:-0}" -gt 0 ]; then
    kisa_emit U-59 VULN "v1/v2c community entries=$v12, v3 user entries=${v3:-0}"
  else
    kisa_emit U-59 GOOD "no v1/v2c community; v3 user entries=${v3:-0}"
  fi
)
