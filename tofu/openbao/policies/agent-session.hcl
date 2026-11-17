# agent_session: 에이전트 세션(Semaphore 밖). inventory/ 전체(문서와 메타데이터)를 읽고 secrets/는 메타데이터(버전·갱신 시각)만 본다.
# secrets/data/*는 일부러 없다. 비밀 값이 필요한 조사는 해당 계열 템플릿을 돌리거나 운영자가 직접 한다.
# list 권한: inventory/metadata/*와 secrets/metadata/*의 list·read(문서 이름·버전만, 값 없음)를 갖는다. 작업 계열 중에는 periodic_check만 list를 갖고,
# 이 에이전트 세션이 사람 쪽(operator)을 뺀 유일한 예외다.
# 주의(사용자 결정 항목): inventory/data/* 전체 읽기에는 개인정보(inventory/config/host_audit의 수신자·발신자)와 웹훅 주소
# (inventory/config/github_webhook_watch의 hook_url)가 들어 있다. #504가 이 값들의 단일 원본을 inventory/config/<작업>으로 정했으므로 옮기지 않았다.

path "inventory/data/*" {
  capabilities = ["read"]
}

# 문서 목록·버전·갱신 시각(조사용). 비밀이 없는 마운트라 secrets/와 달리 data와 같이 연다.
path "inventory/metadata/*" {
  capabilities = ["read", "list"]
}

path "secrets/metadata/*" {
  capabilities = ["read", "list"]
}
