# KISA-2026:U-41 (상) 불필요한 automountd 제거
# 양호: automountd(autofs) 서비스가 비활성화된 경우.
(
  if kisa_service_on automount autofs automountd; then
    kisa_emit U-41 VULN "automount (autofs) active"
  else
    kisa_emit U-41 GOOD "automount (autofs) not active"
  fi
)
