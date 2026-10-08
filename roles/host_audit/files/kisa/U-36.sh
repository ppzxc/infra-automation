# KISA-2026:U-36 (상) r 계열 서비스 비활성화
# 양호: rlogin·rsh·rexec 서비스가 비활성화된 경우 (프로세스·unit·(x)inetd·512~514/tcp).
(
  on=""
  for s in rlogin rsh rexec in.rlogind in.rshd in.rexecd rlogin.socket rsh.socket rexec.socket; do
    kisa_service_on "$s" && on="$on${on:+,}$s"
  done
  for p in 512 513 514; do
    kisa_listening "$p" && on="$on${on:+,}$p/tcp"
  done
  if [ -n "$on" ]; then
    kisa_emit U-36 VULN "r-services active: $on"
  else
    kisa_emit U-36 GOOD "r-services (rlogin, rsh, rexec) not active"
  fi
)
