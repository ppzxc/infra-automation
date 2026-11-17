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

# 관리 계정 공개키: lookup openbao_admin_accounts가 자동화 계정이 아닌 관리 계정(개인 운영자)의 공개키·폐기 키를 읽는다.
# 공개키라 비밀은 아니지만 inventory 마운트의 문서이므로 서버 계열 정책에 명시한다.
path "inventory/data/operators/*" {
  capabilities = ["read"]
}
