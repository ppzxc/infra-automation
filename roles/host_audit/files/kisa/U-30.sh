# KISA-2026:U-30 (중) UMASK 설정 관리
# 양호: UMASK 값이 022 이상(그룹·기타 쓰기 비트를 모두 막음)으로 설정된 경우.
# 전역 프로필과 /etc/login.defs의 모든 umask/UMASK 지정을 보고, 하나라도 022 미만이면 취약이다.
(
  found=""
  weak=""
  for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs "$R"/etc/profile.d/*.sh; do
    f=${f#"$R"}
    [ -r "$R$f" ] || continue
    for v in $(grep -Ei '^[[:space:]]*(umask[[:space:]]+[0-7]+|UMASK[[:space:]]+[0-7]+)' "$R$f" | awk '{ print $2 }'); do
      found="$found${found:+ }$f=$v"
      [ $(( 0$v & 022 )) -eq $(( 022 )) ] || weak="$weak${weak:+ }$f=$v"
    done
  done
  if [ -z "$found" ]; then
    kisa_emit U-30 VULN "umask not set in global profiles or /etc/login.defs"
  elif [ -n "$weak" ]; then
    kisa_emit U-30 VULN "umask below 022: $weak (all: $found)"
  else
    kisa_emit U-30 GOOD "umask: $found"
  fi
)
