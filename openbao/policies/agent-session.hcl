# agent_session: 에이전트 세션(Semaphore 밖). inventory/ 전체(문서와 메타데이터)를 읽고 secrets/는 메타데이터(버전·갱신 시각)만 본다.
# secrets/data/*는 일부러 없다. 비밀 값이 필요한 조사는 해당 계열 템플릿을 돌리거나 운영자가 직접 한다.
# list 권한: inventory/metadata/*와 secrets/metadata/*의 list·read(문서 이름·버전만, 값 없음)를 갖는다. 작업 계열 중에는 periodic_check만 list를 갖고,
# 이 에이전트 세션이 사람 쪽(operator)을 뺀 유일한 예외다.
# 제외: 개인정보(inventory/config/host_audit의 수신자·발신자)와 웹훅 주소(inventory/config/github_webhook_watch의 hook_url)는
# 읽지 못한다. #504가 단일 원본을 inventory/config/<작업>으로 정했으므로 값은 옮기지 않고 이 경로들만 deny한다(사용자 결정).
# Log Review 기준 목록(inventory/config/log_review, #560)의 출발지·내부 주소·개인정보처리시스템 목록도 deny다.
# 이 문서들의 metadata(이름·버전)는 다른 문서와 같이 보인다.

path "inventory/data/*" {
  capabilities = ["read"]
}

path "inventory/data/config/host_audit" {
  capabilities = ["deny"]
}

path "inventory/data/config/github_webhook_watch" {
  capabilities = ["deny"]
}

# Log Review 기준 목록(정상 출발지·내부 주소·개인정보처리시스템 목록, #560)도 같은 이유로 막는다.
path "inventory/data/config/log_review" {
  capabilities = ["deny"]
}

# 문서 목록·버전·갱신 시각(조사용). 비밀이 없는 마운트라 secrets/와 달리 data와 같이 연다.
path "inventory/metadata/*" {
  capabilities = ["read", "list"]
}

path "secrets/metadata/*" {
  capabilities = ["read", "list"]
}
