# KISA-2026:U-34 (상) Finger 서비스 비활성화
# 양호: Finger 서비스(fingerd, (x)inetd finger, 79/tcp)가 비활성화된 경우.
(
  if kisa_service_on finger fingerd in.fingerd finger.socket || kisa_listening 79; then
    kisa_emit U-34 VULN "finger service active"
  else
    kisa_emit U-34 GOOD "finger service not active"
  fi
)
