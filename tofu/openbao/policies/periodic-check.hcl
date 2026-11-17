# periodic_check: 매일 정기 점검(스키마·참조·Semaphore 인벤토리 대조, secret_id 만료 알림, OpenTofu 밖 객체 탐지).
# 전체 읽기·list와 AppRole 메타데이터 조회만 한다. 쓰기·삭제·secret_id 발급은 없다.
# 스키마 대조에 비밀 문서 값 검사가 필요해 secrets/data/*도 읽는다(#506 §6의 "전체 읽기"). 그래서 Automation Identity
# (secrets/automation/ssh)도 읽는 점이 서버 계열 한정 규칙의 유일한 예외다. list 권한을 가진 유일한 기계 계열이다.

path "inventory/data/*" {
  capabilities = ["read"]
}

path "secrets/data/*" {
  capabilities = ["read"]
}

path "inventory/metadata/*" {
  capabilities = ["read", "list"]
}

path "secrets/metadata/*" {
  capabilities = ["read", "list"]
}

path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "auth/approle/role" {
  capabilities = ["list"]
}

path "auth/approle/role/*" {
  capabilities = ["read"]
}

# role 설정(TTL·정책·CIDR)만 읽는다. role-id는 로그인 입력이라 막는다.
path "auth/approle/role/+/role-id" {
  capabilities = ["deny"]
}

# secret_id 만료 조회: accessor 목록과 accessor 조회만. secret_id 발급(create/update)은 없다.
path "auth/approle/role/+/secret-id" {
  capabilities = ["list"]
}

path "auth/approle/role/+/secret-id-accessor/lookup" {
  capabilities = ["update"]
}
