# OpenObserve 조회 전용 용도 계정(Host Audit의 Log Review Report, Spec #544 / Ticket-3 #558).
#
# 읽기만 허용한다. 오픈소스 OpenObserve는 RBAC가 없어 서버가 이 계정을 조회 전용으로 강제하지 못한다(#556).
# 그래서 host_audit 역할은 POST _search 한 경로만 부르고(tests/test_host_audit_log_review_tasks.py), admin 자격은 쓰지 않는다.

path "secrets/data/services/openobserve/readonly" {
  capabilities = ["read"]
}
