# 호스트별 에이전트 비밀(수집 토큰·RustFS 키·restic 비밀번호·웹훅 비밀). 설정은 Asset 문서 agents 절에 있다.

path "secrets/data/assets/+/agents" {
  capabilities = ["read"]
}

# Asset 문서 한 개(Endpoint 아님): Repo Maintenance가 호스트별 버킷 덮어쓰기(agents.backup.bucket)를 읽는다. `+`는 한 마디만 맞아
# `inventory/data/assets/<ns>/endpoints`(접속 주소)는 이 정책으로 읽히지 않는다.
path "inventory/data/assets/+" {
  capabilities = ["read"]
}
