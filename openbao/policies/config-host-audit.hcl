# Host Audit 작업의 비공개 설정(메일 수신자 등, Log Review Report 기준 목록).
#
# host_audit AppRole은 provision ∪ host_agents ∪ 자기 경로(rustfs-audit-reports, alert-notify, 이 정책)다(approles.tf).
# alert-notify는 KISA 월간 악화 알림(secrets/services/alert/notify의 url)을 보내려고 더했다(#528).
# openobserve-readonly는 Log Review Report의 OpenObserve 조회(secrets/services/openobserve/readonly, 읽기만)다(#558).
# 이유: 드리프트 하위 실행이 같은 AppRole로 site.yml(FUNA env 포함)과 Host Agents Config를 --check로 렌더링한다.
# 드리프트 점검은 전체를 그대로 렌더링해야 의미가 있다. AppRole 쌍을 따로 두어도 같은 Environment에 들어가
# 노출이 같고, 비밀 역할을 건너뛰면 감지 범위가 줄어서 합집합으로 둔다(#506 §3).

path "inventory/data/config/host_audit" {
  capabilities = ["read"]
}

# Log Review Report 판정 기준 목록(정상 출발지·내부 주소 대응·개인정보처리시스템 표시, Spec #544 / Ticket-5 #560). 읽기만.
path "inventory/data/config/log_review" {
  capabilities = ["read"]
}
