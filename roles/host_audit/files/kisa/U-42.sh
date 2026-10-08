# KISA-2026:U-42 (상) 불필요한 RPC 서비스 비활성화
# 양호: 가이드가 열거한 불필요한 RPC 서비스가 모두 비활성화된 경우.
# 대상: rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd
#       rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd (프로세스·unit·(x)inetd).
(
  on=""
  for s in rpc.cmsd rpc.ttdbserverd sadmind rusersd rpc.rusersd walld rpc.walld sprayd rpc.sprayd rstatd \
    rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.statd rpc-statd rpc.ypupdated rpc.rquotad rpc-rquotad \
    kcms_server cachefsd; do
    kisa_service_on "$s" && on="$on${on:+,}$s"
  done
  if [ -n "$on" ]; then
    kisa_emit U-42 VULN "RPC services active: $on"
  else
    kisa_emit U-42 GOOD "none of the listed RPC services active"
  fi
)
