# 원장 계열(Spec #630 / #645) 서버 접속 읽기 전용 묶음. 기존 connect 묶음을 쓰지 않는 이유는 connect가 관리 계정 공개키
# (inventory/operators)까지 열기 때문이다.
# 로그인 Credential(secrets/assets/+/credentials/+)은 사용자 결정(2026-11-20)으로 더했다: 전 서버 34/36이 비밀번호 Credential이라
# 수집기가 OpenBao 설정(Endpoint의 credential type)대로 비밀번호·키 접속을 따르게 하기 위해서다. 읽기만 허용한다.
# 예외로 호스트 이름 목록(list) 한 경로만 연다.

path "inventory/data/assets/+" {
  capabilities = ["read"]
}

path "inventory/data/assets/+/endpoints" {
  capabilities = ["read"]
}

path "secrets/data/assets/+/credentials/*" {
  capabilities = ["read"]
}

path "secrets/data/automation/ssh" {
  capabilities = ["read"]
}

# list 예외(원장 계열 한정, 이 경로 하나뿐): 일일 Asset 스냅샷이 호스트 목록을 나열해야 한다. 목록에는 문서 이름만 보이고 값은 열리지 않는다.
# agent_session이 이미 inventory/ 전체를 list하므로 노출이 늘지 않는다. LIST 요청의 ACL 경로는 끝에 /가 붙어 정책 경로도 /로 끝난다.
path "inventory/metadata/assets/" {
  capabilities = ["list"]
}
