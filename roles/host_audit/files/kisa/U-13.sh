# KISA-2026:U-13 (중) 안전한 비밀번호 암호화 알고리즘 사용
# 양호: SHA-2 이상(SHA-256 $5$, SHA-512 $6$, yescrypt $y$)의 안전한 알고리즘을 쓰는 경우.
# 실제 저장된 해시(/etc/shadow, root 필요)에 MD5($1$)·Blowfish($2*$)·DES(13자)가 있거나,
# 설정(/etc/login.defs ENCRYPT_METHOD, pam_unix 인자)이 MD5·DES·Blowfish면 취약이다.
# 증적에는 알고리즘별 개수와 계정 이름만 싣고 해시 값은 싣지 않는다.
(
  method=$(awk '$1 == "ENCRYPT_METHOD" { v = toupper($2) } END { print v }' "$R/etc/login.defs" 2>/dev/null)
  pam=$(kisa_pam_files system-auth password-auth common-password)
  pamalg=""
  [ -n "$pam" ] && pamalg=$(grep -hE '^[[:space:]]*password[[:space:]].*pam_unix\.so' $pam 2>/dev/null | tr ' \t' '\n\n' | grep -xE 'md5|bigcrypt|blowfish|sha256|sha512|yescrypt|gost_yescrypt' | sort -u | tr '\n' ' ' | sed 's/ $//')
  if [ ! -r "$R/etc/shadow" ]; then
    kisa_emit U-13 MANUAL "/etc/shadow not readable; ENCRYPT_METHOD=${method:-unset} pam_unix=${pamalg:-none}"
    exit 0
  fi
  counts=$(awk -F: '
    { h = $2; sub(/^!+/, "", h) }
    h == "" || h == "*" || h == "x" { next }
    h ~ /^\$y\$/ { c["yescrypt"]++; next }
    h ~ /^\$gy\$/ { c["gost-yescrypt"]++; next }
    h ~ /^\$6\$/ { c["sha512"]++; next }
    h ~ /^\$5\$/ { c["sha256"]++; next }
    h ~ /^\$1\$/ { c["md5"]++; next }
    h ~ /^\$2[abxy]?\$/ { c["blowfish"]++; next }
    length(h) == 13 { c["des"]++; next }
    END { for (k in c) printf "%s=%d ", k, c[k] }' "$R/etc/shadow" | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
  weak=$(awk -F: '
    { h = $2; sub(/^!+/, "", h) }
    h ~ /^\$1\$/ || h ~ /^\$2[abxy]?\$/ || (h !~ /^[$*]/ && length(h) == 13) { print $1 }' "$R/etc/shadow" | tr '\n' ',' | sed 's/,$//')
  ev="ENCRYPT_METHOD=${method:-unset} pam_unix=${pamalg:-none} shadow: ${counts:-no password hashes}"
  cfg_weak=0
  case "$method" in
    MD5 | DES | BLOWFISH) cfg_weak=1 ;;
  esac
  case " $pamalg " in
    *" md5 "* | *" bigcrypt "* | *" blowfish "*) cfg_weak=1 ;;
  esac
  if [ -n "$weak" ]; then
    kisa_emit U-13 VULN "$ev; weak hash accounts: $weak"
  elif [ "$cfg_weak" -eq 1 ]; then
    kisa_emit U-13 VULN "$ev; weak algorithm configured"
  else
    kisa_emit U-13 GOOD "$ev"
  fi
)
