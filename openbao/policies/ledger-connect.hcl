# 원장 계열(Spec #630 / #645) 서버 접속 읽기 전용 묶음. 기존 connect 묶음을 쓰지 않는 이유는 connect가 모든 서버의
# 로그인 Credential(secrets/assets/+/credentials/+)과 관리 계정 공개키(inventory/operators)까지 열기 때문이다.
# 수집기는 SSH 키 접속(Automation Identity)만 지원하고 비밀번호 Credential 자격은 어차피 쓰지 못하므로 넣지 않는다.
# 비밀번호 Credential이 필요해지면 별도 결정으로 따로 더한다. 읽기만 허용하고 list는 없다(수집기는 문서 경로를 이미 안다).

path "inventory/data/assets/+" {
  capabilities = ["read"]
}

path "inventory/data/assets/+/endpoints" {
  capabilities = ["read"]
}

path "secrets/data/automation/ssh" {
  capabilities = ["read"]
}
