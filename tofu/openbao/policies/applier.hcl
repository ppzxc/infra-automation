# applier 정책(infra 네임스페이스 안). 마운트·정책·AppRole·인증 방식만 다룬다.
# KV 데이터 경로(inventory/·secrets/)는 일부러 없다. 이 토큰은 KV를 직접 읽지 못한다.
# 단 정책을 쓸 수 있어서 사실상 관리자 권한이다: 자기 정책을 고쳐 deny를 지울 수 있고, AppRole의 bind_secret_id·CIDR을 바꾸거나
# role-id를 읽을 수 있으며(tofu의 AppRole 리소스가 role-id를 읽어 막을 수 없다), userpass 사용자의 비밀번호를 설정할 수 있다.
# 그래서 아래 secret-id deny는 보안 경계가 아니라 실수 방지용 가드레일일 뿐이다. 이 토큰의 노출은 수명·출발지(CIDR) 제한·Auto Approve 끔과
# 적용 내용을 사람이 승인하는 절차로만 줄인다(docs/openbao_opentofu.md, 사용자 결정 항목).

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

# secret_id 발급은 admin 런북으로만 한다(가드레일: 위 설명처럼 정책 수정 권한이 있어 우회할 수 있다). 이 경로를 열어 두면 applier가
# 다른 AppRole의 secret_id를 바로 만들어 로그인해 그 계열의 KV 읽기 권한을 얻을 수 있다.
path "auth/approle/role/+/secret-id" {
  capabilities = ["deny"]
}

path "auth/approle/role/+/secret-id/*" {
  capabilities = ["deny"]
}

path "auth/approle/role/+/custom-secret-id" {
  capabilities = ["deny"]
}

path "auth/approle/role/+/secret-id-accessor/*" {
  capabilities = ["deny"]
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
