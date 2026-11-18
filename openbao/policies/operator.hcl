# operator: 사람 일상용(infra 안 userpass). 전체 읽기(list 포함: 등록 도구의 check와 참조 확인에 필요)와 create/update.
# delete·destroy·undelete·metadata 삭제·sys/는 없다. 삭제는 루트 네임스페이스 admin 런북으로만 한다.
# KV v2에서 문서 쓰기(create/update)는 data/ 경로 하나다. 버전 삭제·영구 삭제는 delete/·destroy/ 경로라 일부러 없다.

path "inventory/data/*" {
  capabilities = ["read", "create", "update"]
}

path "secrets/data/*" {
  capabilities = ["read", "create", "update"]
}

path "inventory/metadata/*" {
  capabilities = ["read", "list"]
}

path "secrets/metadata/*" {
  capabilities = ["read", "list"]
}
