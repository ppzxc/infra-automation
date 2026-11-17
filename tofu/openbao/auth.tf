# 사람용 userpass와 기계용 AppRole 마운트.
resource "vault_auth_backend" "userpass" {
  type        = "userpass"
  path        = "userpass"
  description = "운영자 로그인"
}

resource "vault_auth_backend" "approle" {
  type        = "approle"
  path        = "approle"
  description = "Semaphore 작업 계열 로그인"
}

# 운영자 사용자: 이름별 bcrypt 해시와 operator 정책 연결을 선언한다. 평문 비밀번호는 다루지 않는다.
# operator 정책 자체는 후속 티켓(#518)이 만든다. 이름만 참조한다.
# disable_read: 운영자가 직접 바꾼 비밀번호를 드리프트로 보지 않는다. 해시를 바꾸면 다음 apply가 덮어쓴다.
resource "vault_generic_endpoint" "operator_user" {
  for_each = nonsensitive(toset(keys(var.operator_password_hashes)))

  path         = "auth/${vault_auth_backend.userpass.path}/users/${each.key}"
  disable_read = true

  data_json = jsonencode({
    password_hash  = var.operator_password_hashes[each.key]
    token_policies = ["operator"]
  })
}
