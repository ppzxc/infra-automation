# KISA-2026:U-61 (상) SNMP Access Control 설정
# 양호: SNMP 접근 허용 대상(네트워크)을 제한한 경우. rocommunity·rwcommunity의 세 번째 인자(source)나
# com2sec의 source가 default가 아니면 제한으로 본다. v3 전용이면 수동. SNMP를 쓰지 않으면 해당없음.
(
  f=$(kisa_snmpd_conf)
  if [ -z "$f" ]; then
    kisa_emit U-61 NA "snmpd not active"
    exit 0
  fi
  res=$(awk '
    tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ { n++; if (NF < 3 || $3 == "default" || $3 ~ /^-/) open++ }
    tolower($1) ~ /^com2sec6?$/ { n++; src = (NF >= 4 && $2 !~ /^-/) ? $3 : $(NF - 1); if (src == "default" || src == "0.0.0.0/0") open++ }
    END { printf "%d %d", n, open }' "$f" 2>/dev/null)
  n=${res% *}
  open=${res#* }
  if [ "${n:-0}" -eq 0 ]; then
    kisa_emit U-61 MANUAL "no v1/v2c community; v3 access (view/rouser) must be reviewed manually"
  elif [ "${open:-0}" -gt 0 ]; then
    kisa_emit U-61 VULN "$open of $n community entries have no source restriction"
  else
    kisa_emit U-61 GOOD "all $n community entries restrict the source"
  fi
)
