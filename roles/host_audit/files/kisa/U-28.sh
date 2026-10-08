# KISA-2026:U-28 (상) 접속 IP 및 포트 제한
# 양호: 접속을 허용할 특정 호스트에 대한 IP 주소·포트 제한을 설정한 경우.
# firewalld(기본 zone target이 ACCEPT가 아님), ufw(active), nftables(drop 정책·saddr 규칙),
# 레거시 iptables(INPUT DROP·-s 규칙), TCP Wrapper(hosts.deny ALL:ALL) 중 하나라도 있으면 제한으로 본다.
# 읽기 전용: 커널 모듈을 올릴 수 있는 조회는 해당 모듈이 이미 올라와 있을 때만 한다.
# Docker가 도는 호스트는 Docker가 iptables/nftables DOCKER 체인을 직접 관리해 그 구간을
# 위 규칙만으로 판정할 수 없으므로 수동이다(예외 레지스터의 Docker 구간 항목이 이 판정에 적용된다).
(
  how=""
  if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
    zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    target=$(firewall-cmd --zone="$zone" --list-all 2>/dev/null | awk '$1 == "target:" { print $2 }')
    srcs=$(firewall-cmd --list-all-zones 2>/dev/null | grep -Ec '^[[:space:]]*(sources: [^[:space:]]|rule family.*source address)')
    case "$target" in
      ACCEPT) ;;
      *) how="firewalld zone=$zone target=${target:-default} source-rules=$srcs" ;;
    esac
  fi
  if [ -z "$how" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    how="ufw active"
  fi
  if [ -z "$how" ] && [ -d "$R/sys/module/nf_tables" ] && command -v nft >/dev/null 2>&1; then
    rules=$(nft list ruleset 2>/dev/null)
    if printf '%s\n' "$rules" | grep -Eq 'hook input .*policy drop|saddr'; then
      how="nftables input drop policy or source-address rules"
    fi
  fi
  if [ -z "$how" ] && grep -qx filter "$R/proc/net/ip_tables_names" 2>/dev/null && command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)|^-A INPUT .*-s [0-9]'; then
      how="iptables INPUT drop policy or source rules"
    fi
  fi
  if [ -z "$how" ] && [ -r "$R/etc/hosts.deny" ] && grep -Eiq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' "$R/etc/hosts.deny"; then
    how="TCP Wrapper hosts.deny ALL:ALL"
  fi
  docker=no
  if kisa_proc dockerd || [ -d "$R/sys/class/net/docker0" ]; then
    docker=yes
  fi
  if [ -z "$how" ]; then
    kisa_emit U-28 VULN "no IP/port restriction found (firewalld, ufw, nftables, iptables, TCP Wrapper); docker=$docker"
  elif [ "$docker" = yes ]; then
    kisa_emit U-28 MANUAL "$how; Docker manages its own iptables/nftables chains - check published ports manually"
  else
    kisa_emit U-28 GOOD "$how"
  fi
)
