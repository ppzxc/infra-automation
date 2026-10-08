# KISA-2026:U-58 (중) 불필요한 SNMP 서비스 구동 점검
# 양호: SNMP 서비스를 사용하지 않는 경우. 필요한 경우는 예외 레지스터로 남긴다.
(
  if kisa_service_on snmpd; then
    kisa_emit U-58 VULN "snmpd active"
  else
    kisa_emit U-58 GOOD "snmpd not active"
  fi
)
