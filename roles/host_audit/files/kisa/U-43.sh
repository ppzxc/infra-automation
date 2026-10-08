# KISA-2026:U-43 (상) NIS, NIS+ 점검
# 양호: NIS 서비스가 비활성화된 경우(불가피하면 NIS+). NIS 서버·클라이언트 데몬 실행 여부를 본다.
(
  on=""
  for s in ypserv ypbind ypxfrd rpc.yppasswdd yppasswdd rpc.ypxfrd; do
    kisa_service_on "$s" && on="$on${on:+,}$s"
  done
  if [ -n "$on" ]; then
    kisa_emit U-43 VULN "NIS active: $on"
  else
    kisa_emit U-43 GOOD "NIS not active"
  fi
)
