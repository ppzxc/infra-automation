# FUNA 소비 컨테이너별 비밀(proxy·vrrp). provision(site.yml의 FUNA env 렌더링)이 읽는다.

path "secrets/data/services/funa/*" {
  capabilities = ["read"]
}
