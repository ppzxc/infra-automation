# applier 정책(infra 네임스페이스 안). 마운트·정책·AppRole·인증 방식만 다룬다.
# KV 데이터 경로(inventory/·secrets/)는 일부러 없다. 이 자격이 새도 비밀 값은 읽지 못한다.

path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/approle/role" {
  capabilities = ["list"]
}

path "auth/approle/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/mounts" {
  capabilities = ["read", "list"]
}

path "sys/mounts/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "sys/auth" {
  capabilities = ["read", "list"]
}

path "sys/auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# 운영자 사용자 선언(auth.tf)에 필요하다. 정책 연결만 쓰고 비밀번호는 다루지 않는다.
path "auth/userpass/users/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
