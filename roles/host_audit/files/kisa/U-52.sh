# KISA-2026:U-52 (중) Telnet 서비스 비활성화
# 양호: Telnet 서비스(telnetd, (x)inetd telnet, telnet.socket, 23/tcp)를 쓰지 않는 경우.
(
  if kisa_service_on telnet telnetd in.telnetd telnet.socket || kisa_listening 23; then
    kisa_emit U-52 VULN "telnet service active"
  else
    kisa_emit U-52 GOOD "telnet service not active"
  fi
)
