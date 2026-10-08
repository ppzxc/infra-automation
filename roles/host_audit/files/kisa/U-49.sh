# KISA-2026:U-49 (상) DNS 보안 버전 패치
# 양호: DNS 서비스를 주기적으로 패치 관리하는 경우. 관리 여부는 운영 절차라 자동 판정할 수 없어
# 사용 중인 BIND 버전을 증적으로 내고 수동으로 둔다(알려진 취약 버전은 Package Vulnerability).
# DNS 서비스를 쓰지 않으면 해당없음.
(
  if kisa_service_on named bind9; then
    ver=$(named -v 2>/dev/null | head -n 1)
    kisa_emit U-49 MANUAL "${ver:-BIND version unknown}; confirm periodic patching and Package Vulnerability"
  else
    kisa_emit U-49 NA "DNS service (named) not active"
  fi
)
