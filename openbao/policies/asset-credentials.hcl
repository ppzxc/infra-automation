# Asset별 Credential(비밀번호·SSH 키·API 토큰). 이번 실행 Asset만으로 좁히는 정책 문법은 없어 문서 종류로만 나눈다.

path "secrets/data/assets/+/credentials/*" {
  capabilities = ["read"]
}
