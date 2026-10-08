# KISA-2026:U-65 (중) NTP 및 시각 동기화 설정
# 양호: NTP·시각 동기화가 설정되어 동작하는 경우. chronyd·ntpd가 돌고 설정에 server·pool이 있거나,
# systemd-timesyncd가 active이면 양호.
(
  if kisa_service_on chronyd chrony; then
    f=$(kisa_first_file /etc/chrony.conf /etc/chrony/chrony.conf)
    n=0
    [ -n "$f" ] && n=$(grep -Ec '^[[:space:]]*(server|pool)[[:space:]]' "$f")
    if [ -z "$f" ]; then
      kisa_emit U-65 GOOD "chronyd active"
    elif [ "$n" -gt 0 ]; then
      kisa_emit U-65 GOOD "chronyd active with $n server/pool entries"
    else
      kisa_emit U-65 VULN "chronyd active without server/pool"
    fi
  elif kisa_service_on ntpd ntp; then
    n=$(grep -Ec '^[[:space:]]*(server|pool)[[:space:]]' "$R/etc/ntp.conf" 2>/dev/null)
    if [ "${n:-0}" -gt 0 ]; then
      kisa_emit U-65 GOOD "ntpd active with $n server/pool entries"
    else
      kisa_emit U-65 VULN "ntpd active without server/pool"
    fi
  elif kisa_unit_active systemd-timesyncd; then
    kisa_emit U-65 GOOD "systemd-timesyncd active"
  else
    kisa_emit U-65 VULN "no time synchronization service (chronyd, ntpd, systemd-timesyncd) active"
  fi
)
