# KISA-2026:U-38 (상) DoS 공격에 취약한 서비스 비활성화
# 양호: echo·discard·daytime·chargen 서비스가 비활성화된 경우 ((x)inetd 항목, 7·9·13·19/tcp).
(
  on=""
  for s in echo echo-stream echo-dgram discard discard-stream discard-dgram daytime daytime-stream \
    daytime-dgram chargen chargen-stream chargen-dgram; do
    kisa_inetd_on "$s" && on="$on${on:+,}$s"
  done
  for p in 7 9 13 19; do
    kisa_listening "$p" && on="$on${on:+,}$p/tcp"
  done
  if [ -n "$on" ]; then
    kisa_emit U-38 VULN "DoS-prone services active: $on"
  else
    kisa_emit U-38 GOOD "echo, discard, daytime, chargen not active"
  fi
)
