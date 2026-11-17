# agent_session: 에이전트 세션(Semaphore 밖). inventory/ 전체(문서와 메타데이터)를 읽고 secrets/는 메타데이터(버전·갱신 시각)만 본다.
# secrets/data/*는 일부러 없다. 비밀 값이 필요한 조사는 해당 계열 템플릿을 돌리거나 운영자가 직접 한다.

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
