# KISA-2026:U-04 (상) 비밀번호 파일 보호
# 양호: 쉐도우 비밀번호를 사용하거나 비밀번호를 암호화하여 저장하는 경우.
# /etc/passwd 두 번째 필드가 x(또는 잠금 표시 * ! !!)가 아닌 계정이 있으면 취약이다.
(
  if [ ! -r "$R/etc/passwd" ]; then
    kisa_emit U-04 MANUAL "/etc/passwd not readable"
    exit 0
  fi
  bad=$(awk -F: 'NF > 1 && $2 != "x" && $2 != "*" && $2 != "!" && $2 != "!!" { print $1 }' "$R/etc/passwd" | tr '\n' ',' | sed 's/,$//')
  shadow="present"
  [ -e "$R/etc/shadow" ] || shadow="missing"
  if [ -z "$bad" ] && [ "$shadow" = "present" ]; then
    kisa_emit U-04 GOOD "all /etc/passwd password fields are x; /etc/shadow $shadow"
  else
    kisa_emit U-04 VULN "password field not x: ${bad:-none}; /etc/shadow $shadow"
  fi
)
