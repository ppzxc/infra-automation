# 원장 계열(Spec #630): GWS 디렉터리 읽기 키와 Forgejo 봇 쓰기 토큰. 읽기만 한다.
# 봇 로그인(idc_access_bot_login)과 개인 읽기 토큰 문서는 어느 계열도 읽지 않으므로 여기에 넣지 않는다.

path "secrets/data/services/gws/directory_read" {
  capabilities = ["read"]
}

path "secrets/data/services/forgejo/idc_access_bot" {
  capabilities = ["read"]
}
