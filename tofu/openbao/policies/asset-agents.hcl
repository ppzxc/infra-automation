# 호스트별 에이전트 비밀(수집 토큰·RustFS 키·restic 비밀번호·웹훅 비밀). 설정은 Asset 문서 agents 절에 있다.

path "secrets/data/assets/+/agents" {
  capabilities = ["read"]
}
