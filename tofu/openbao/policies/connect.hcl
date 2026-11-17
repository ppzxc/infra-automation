# 접속 해석 공통 묶음(#506 §2): Asset 문서·Endpoint + Credential + Automation Identity. 서버 계열 전용이다.
# 네트워크 장비 계열(network_backup)은 Automation Identity가 없으므로 이 묶음 대신
# inventory-assets + asset-credentials를 쓴다.

path "inventory/data/assets/*" {
  capabilities = ["read"]
}

path "secrets/data/assets/+/credentials/*" {
  capabilities = ["read"]
}

path "secrets/data/automation/ssh" {
  capabilities = ["read"]
}
