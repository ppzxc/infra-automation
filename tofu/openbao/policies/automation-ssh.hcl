# Automation Identity(자동화가 내미는 SSH 키 쌍). identity: automation Endpoint를 쓰는 서버 계열
# (provision·host_agents·host_audit)에만 붙인다. network_backup에는 붙이지 않는다.

path "secrets/data/automation/ssh" {
  capabilities = ["read"]
}
