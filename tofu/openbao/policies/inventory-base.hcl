# 모든 계열이 읽는 공통 경로: Service 주소·속성과 회사 공통 설정(domain). 비밀이 아니다.

path "inventory/data/services/*" {
  capabilities = ["read"]
}

path "inventory/data/config/common" {
  capabilities = ["read"]
}
