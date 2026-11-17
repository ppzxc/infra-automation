# infra 안의 KV v2 마운트 두 개. inventory는 비밀이 아닌 값, secrets는 비밀만(CONTEXT.md, Spec #511 골격).
resource "vault_mount" "inventory" {
  path        = "inventory"
  type        = "kv"
  options     = { version = "2" }
  description = "Asset·Service·Operator·작업 설정(비밀 아님)"
}

resource "vault_mount" "secrets" {
  path        = "secrets"
  type        = "kv"
  options     = { version = "2" }
  description = "Credential·Service 권한 비밀"
}
