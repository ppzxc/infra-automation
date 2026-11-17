# infra 안의 KV v2 마운트 두 개. inventory는 비밀이 아닌 값, secrets는 비밀만(CONTEXT.md, Spec #511 골격).
resource "vault_mount" "inventory" {
  path        = "inventory"
  type        = "kv"
  options     = { version = "2" }
  description = "Asset·Service·Operator·작업 설정(비밀 아님)"

  # 마운트를 지우면 안의 데이터가 모두 사라진다. 교체·삭제가 plan에 뜨면 apply가 실패하게 한다.
  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_mount" "secrets" {
  path        = "secrets"
  type        = "kv"
  options     = { version = "2" }
  description = "Credential·Service 권한 비밀"

  lifecycle {
    prevent_destroy = true
  }
}
