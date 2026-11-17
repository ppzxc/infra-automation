# 작업 계열별 정책과 AppRole(Spec #511 / Ticket-7, #506 §1~§5).
# 정책은 policies/*.hcl의 작은 정책이고 AppRole이 token_policies로 조합한다. 계열 x 경로 매트릭스의 원본은 그 HCL이다.
# applier 정책은 applier.tf가 따로 만든다.
resource "vault_policy" "small" {
  # 키는 정책 이름(파일명에서 .hcl 뺀 것)이다. AppRole이 이름으로 가리킨다.
  for_each = { for f in fileset("${path.module}/policies", "*.hcl") : trimsuffix(f, ".hcl") => f if f != "applier.hcl" }

  name   = each.key
  policy = file("${path.module}/policies/${each.value}")
}

locals {
  # 계열 -> 작은 정책 이름. 모든 계열이 inventory-base(Service·공통 설정)를 읽는다.
  # Automation Identity(connect 묶음에 들어 있다)는 서버 계열 provision·host_agents·host_audit에만 준다.
  # list 권한은 periodic_check(periodic-check)에만 준다.
  family_policies = {
    provision          = ["inventory-base", "connect", "funa-secrets"]
    host_agents        = ["inventory-base", "connect", "asset-agents", "openobserve-ingest", "alert-notify"]
    backup_maintenance = ["inventory-base", "asset-agents", "rustfs-maintenance", "openobserve-ingest"]
    openobserve_config = [
      "inventory-base", "inventory-assets", "openobserve-admin", "openobserve-ingest", "alert-notify",
      "config-openobserve-config",
    ]
    network_backup = ["inventory-base", "inventory-assets", "asset-credentials", "alert-notify"]
    github_webhook_watch = [
      "inventory-base", "github-org-hooks-read", "openobserve-ingest", "config-github-webhook-watch",
    ]
    periodic_check = ["periodic-check"]
    agent_session  = ["agent-session"]
  }

  # host_audit = provision ∪ host_agents ∪ 자기 경로. 드리프트 하위 실행이 같은 AppRole로 site.yml과 Host Agents Config를
  # --check로 렌더링하므로 전체를 읽어야 한다(근거는 policies/config-host-audit.hcl 주석).
  host_audit_policies = distinct(concat(
    local.family_policies.provision,
    local.family_policies.host_agents,
    ["rustfs-audit-reports", "alert-notify", "config-host-audit"]
  ))

  role_policies = merge(local.family_policies, { host_audit = local.host_audit_policies })

  # 이 코드가 만드는 계열 AppRole 이름의 명시 목록. scripts/openbao_check.py(Periodic Check의 OpenTofu 밖 객체 점검)가 이 목록만 읽는다.
  # role_policies의 키와 같아야 하고, 어긋나면 tests/test_openbao_docs_check.py가 실패한다.
  managed_approles = [
    "provision", "host_agents", "backup_maintenance", "openobserve_config", "host_audit",
    "network_backup", "github_webhook_watch", "periodic_check", "agent_session",
  ]

  # 계열별 토큰 최대 TTL(초). 가장 긴 실행보다 길게 잡는다. Host Audit은 드리프트 시간 제한 3600초를 고려한다.
  token_max_ttl = {
    provision            = 7200
    host_agents          = 7200
    backup_maintenance   = 7200
    openobserve_config   = 3600
    host_audit           = 7200
    network_backup       = 3600
    github_webhook_watch = 3600
    periodic_check       = 3600
    agent_session        = 3600
  }
}

resource "vault_approle_auth_backend_role" "family" {
  for_each = local.role_policies

  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  token_policies = [for p in each.value : vault_policy.small[p].name]

  # agent_session은 Semaphore 밖(에이전트 세션)에서 쓰므로 secret_id 24시간, 별도 출발지 CIDR이다.
  secret_id_ttl         = each.key == "agent_session" ? 86400 : 15552000 # 24시간 / 180일
  secret_id_bound_cidrs = each.key == "agent_session" ? var.agent_session_cidrs : var.runner_cidrs
  token_bound_cidrs     = each.key == "agent_session" ? var.agent_session_cidrs : var.runner_cidrs
  token_ttl             = 1800 # 30분
  token_max_ttl         = local.token_max_ttl[each.key]
}
