# applier: OpenTofu가 쓰는 AppRole. 사실상 관리자 권한이라 수명을 짧게(secret_id 1일, 1회용), 출발지를 러너로 묶는다.
# 첫 bootstrap(이 정책과 role)만 admin으로 한 번 만들고, 그 뒤에는 이 role이 자기 정의까지 관리한다.
# secret_id는 OpenTofu로 만들지 않는다(state에 남는다). 적용할 때 response-wrapping 수동 런북으로 발급한다.
resource "vault_policy" "applier" {
  name   = "applier"
  policy = file("${path.module}/policies/applier.hcl")
}

resource "vault_approle_auth_backend_role" "applier" {
  backend        = vault_auth_backend.approle.path
  role_name      = "applier"
  token_policies = [vault_policy.applier.name]

  secret_id_ttl         = 86400 # 1일
  secret_id_num_uses    = 1
  secret_id_bound_cidrs = var.runner_cidrs
  token_bound_cidrs     = var.runner_cidrs
  token_ttl             = 1800 # 30분
  token_max_ttl         = 3600 # 1시간
}
