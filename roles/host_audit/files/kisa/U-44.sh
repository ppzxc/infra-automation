# KISA-2026:U-44 (상) tftp, talk 서비스 비활성화
# 양호: tftp·talk·ntalk 서비스가 비활성화된 경우.
(
  on=""
  for s in tftp tftpd in.tftpd tftp.socket tftp-server talk ntalk talkd in.talkd in.ntalkd; do
    kisa_service_on "$s" && on="$on${on:+,}$s"
  done
  if [ -n "$on" ]; then
    kisa_emit U-44 VULN "tftp/talk active: $on"
  else
    kisa_emit U-44 GOOD "tftp, talk, ntalk not active"
  fi
)
