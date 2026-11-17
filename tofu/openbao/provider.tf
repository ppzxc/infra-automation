# 주소와 토큰은 환경변수 VAULT_ADDR, VAULT_TOKEN으로 받는다. 저장소에 쓰지 않는다.
provider "vault" {
  # 관리 대상은 infra 네임스페이스 하나다.
  namespace = var.namespace

  # applier 정책에는 자식 토큰 발급(auth/token/create) 권한이 없다. 자식 토큰을 만들지 않는다.
  skip_child_token = true
}
