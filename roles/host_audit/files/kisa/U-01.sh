# KISA-2026:U-01 (상) root 계정 원격 접속 제한
# 양호: 원격터미널 서비스를 쓰지 않거나, 쓸 때 root 직접 접속을 차단한 경우.
# sshd는 실제 적용값(`sshd -T`, root 필요)을 먼저 보고, 안 되면 sshd_config 첫 지정값을 본다.
# prohibit-password 등은 키로 root 직접 접속이 되므로 취약이다. telnet(23/tcp) listening도 취약.
(
  ev=""
  remote=0
  vuln=0
  if kisa_listening 23; then
    remote=1
    vuln=1
    ev="telnet 23/tcp listening"
  fi
  sshd_bin=$(command -v sshd 2>/dev/null)
  [ -z "$sshd_bin" ] && [ -x "$R/usr/sbin/sshd" ] && sshd_bin="$R/usr/sbin/sshd"
  if [ -n "$sshd_bin" ] || [ -r "$R/etc/ssh/sshd_config" ]; then
    remote=1
    prl=""
    src=""
    if [ -n "$sshd_bin" ]; then
      prl=$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1) == "permitrootlogin" { print tolower($2); exit }')
      src="sshd -T"
    fi
    if [ -z "$prl" ]; then
      prl=$(awk 'tolower($1) == "permitrootlogin" { print tolower($2); exit }' "$R/etc/ssh/sshd_config" 2>/dev/null)
      src="/etc/ssh/sshd_config"
    fi
    [ -z "$prl" ] && prl="unset(default allows root key login)"
    ev="${ev:+$ev; }PermitRootLogin=$prl ($src)"
    [ "$prl" = "no" ] || vuln=1
  fi
  if [ "$remote" -eq 0 ]; then
    kisa_emit U-01 GOOD "no remote terminal service (sshd, telnet)"
  elif [ "$vuln" -eq 1 ]; then
    kisa_emit U-01 VULN "$ev"
  else
    kisa_emit U-01 GOOD "$ev"
  fi
)
