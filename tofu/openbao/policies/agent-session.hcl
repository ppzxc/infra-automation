# agent_session: 에이전트 세션(Semaphore 밖). inventory/ 전체를 읽고 secrets/는 메타데이터(버전·갱신 시각)만 본다.
# secrets/data/*는 일부러 없다. 비밀 값이 필요한 조사는 해당 계열 템플릿을 돌리거나 운영자가 직접 한다.

path "inventory/data/*" {
  capabilities = ["read"]
}

path "secrets/metadata/*" {
  capabilities = ["read", "list"]
}
