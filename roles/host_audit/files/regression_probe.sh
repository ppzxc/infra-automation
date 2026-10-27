# Host Audit - Security Regression probe (Spec #364 / Ticket-10, #377). POSIX sh, read-only.
# Reads files and runs query commands only (ss, docker ps, sshd -T -C, fail2ban-client status/get, auditctl -l,
# systemctl is-active, stat, find). It writes nothing on the host.
#
# Input is environment variables set by tasks/regression.yml from the host's declared expectations
# (host_audit_regression_expect). A category whose variables are all empty is not declared and prints nothing.
# Output: one line per item between the markers, `EXP-<AREA>-<N>|PASS|FAIL|UNK`. No address, port, path or
# value is ever printed: the result carries item ids and verdicts only.
#   UNK = the tool needed to judge is missing or gave no answer (never counted as PASS).
# HA_REGRESSION_ROOT is for tests only (fake root); empty in production.
R="${HA_REGRESSION_ROOT:-}"
LC_ALL=C
export LC_ALL

emit() { printf '%s|%s\n' "$1" "$2"; }

echo __HOST_AUDIT_REGRESSION_BEGIN__

# 모드 $1이 상한 $2 이내인가 (둘 다 8진수 문자열).
mode_le() { [ $(( 0$1 & ~0$2 & 07777 )) -eq 0 ]; }

# "ADDR PORT" 줄로 TCP listening 소켓을 낸다(ss, 없으면 netstat) + 컨테이너 게시 포트(docker ps).
listeners() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk 'NR > 1 { a = $4; i = match(a, /:[0-9]+$/); if (i) print substr(a, 1, i - 1), substr(a, i + 1) }'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '$1 ~ /^tcp/ { a = $4; i = match(a, /:[0-9]+$/); if (i) print substr(a, 1, i - 1), substr(a, i + 1) }'
  fi
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | awk '/->/ { s = $0; sub(/->.*/, "", s); gsub(/ /, "", s); i = match(s, /:[0-9]+$/); if (i) print substr(s, 1, i - 1), substr(s, i + 1) }'
  fi
}

is_loopback() { case "$1" in 127.* | "[::1]" | "::1") return 0 ;; esac; return 1; }
is_wildcard() { case "$1" in "*" | 0.0.0.0 | "[::]" | "::" | "") return 0 ;; esac; return 1; }
in_list() { for _x in $2; do [ "$_x" = "$1" ] && return 0; done; return 1; }

# --- 관리 웹 접점 (mgmt-web-loopback-bind) -------------------------------------------------
if [ -n "${HA_MGMT_WEB_PORTS}${HA_MGMT_WILDCARD_ALLOWED}${HA_MGMT_REMOVED_PORTS}${HA_MGMT_REMOVED_NAMES}" ]; then
  if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
    emit EXP-MGMT-1 UNK; emit EXP-MGMT-2 UNK; emit EXP-MGMT-3 UNK
  else
    L=$(listeners)
    bad=0
    for p in $HA_MGMT_WEB_PORTS; do
      printf '%s\n' "$L" | while read -r a q; do [ "$q" = "$p" ] && ! is_loopback "$a" && echo x; done | grep -q x && bad=1
    done
    [ "$bad" -eq 0 ] && emit EXP-MGMT-1 PASS || emit EXP-MGMT-1 FAIL
    bad=0
    allowed="$HA_MGMT_WILDCARD_ALLOWED"
    for q in $(printf '%s\n' "$L" | while read -r a q; do is_wildcard "$a" && echo "$q"; done | sort -u); do
      in_list "$q" "$allowed" || bad=1
    done
    [ "$bad" -eq 0 ] && emit EXP-MGMT-2 PASS || emit EXP-MGMT-2 FAIL
    bad=0
    for p in $HA_MGMT_REMOVED_PORTS; do
      printf '%s\n' "$L" | awk -v p="$p" '$2 == p { f = 1 } END { exit !f }' && bad=1
    done
    if [ -n "$HA_MGMT_REMOVED_NAMES" ]; then
      names=""
      command -v docker >/dev/null 2>&1 && names=$(docker ps -a --format '{{.Names}}' 2>/dev/null)
      for n in $HA_MGMT_REMOVED_NAMES; do
        printf '%s\n' "$names" | grep -qx "$n" && bad=1
        command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$n" 2>/dev/null && bad=1
      done
    fi
    [ "$bad" -eq 0 ] && emit EXP-MGMT-3 PASS || emit EXP-MGMT-3 FAIL
  fi
fi

# --- 로그·트랩 수신 접점 (receiver-source-restriction) -------------------------------------
if [ -n "$HA_RECV_SYSLOG_CONF" ]; then
  bad=0
  for f in $HA_RECV_SYSLOG_CONF; do
    c="$R$f"
    if [ -r "$c" ] \
      && grep -Eq '^[[:space:]]*filter[[:space:]]+[A-Za-z0-9_.-]+[[:space:]]*\{' "$c" \
      && grep -Eq '(netmask6?|host)[[:space:]]*\(' "$c" \
      && grep -Eq 'filter[[:space:]]*\([A-Za-z0-9_.-]+\)' "$c"; then :; else bad=1; fi
  done
  [ "$bad" -eq 0 ] && emit EXP-RECV-1 PASS || emit EXP-RECV-1 FAIL
fi
if [ -n "$HA_RECV_TRAP_CONF" ]; then
  noauth=0
  deflt=0
  for f in $HA_RECV_TRAP_CONF; do
    c="$R$f"
    if [ ! -r "$c" ]; then noauth=1; deflt=1; continue; fi
    grep -Eqi '^[[:space:]]*(authCommunity|authUser|authGroup)[[:space:]]' "$c" || noauth=1
    grep -Eqi '^[[:space:]]*disableAuthorization[[:space:]]+(yes|true|1)' "$c" && noauth=1
    awk 'tolower($1) == "authcommunity" { v = tolower($3); gsub(/["'"'"']/, "", v); if (v == "public" || v == "private" || v == "community") f = 1 } END { exit !f }' "$c" && deflt=1
  done
  [ "$noauth" -eq 0 ] && emit EXP-RECV-2 PASS || emit EXP-RECV-2 FAIL
  [ "$deflt" -eq 0 ] && emit EXP-RECV-3 PASS || emit EXP-RECV-3 FAIL
fi

# --- 원격 접속(SSH) 출발지 제한 (ssh-source-restriction) -----------------------------------
if [ -n "$HA_SSH" ]; then
  cfg="$R/etc/ssh/sshd_config"
  if [ -r "$cfg" ] \
    && grep -q 'BEGIN ANSIBLE MANAGED sshd source restriction' "$cfg" \
    && grep -Eq '^[[:space:]]*Match[[:space:]]+Address[[:space:]]' "$cfg" \
    && grep -Eq '^[[:space:]]*DenyUsers[[:space:]]+\*' "$cfg"; then
    emit EXP-SSH-1 PASS
  else
    emit EXP-SSH-1 FAIL
  fi
  # 허용 목록이 비어 있지 않은가: 루프백 말고 제외(!) 항목이 하나 이상.
  n=$(awk '/^[[:space:]]*Match[[:space:]]+Address[[:space:]]/ { s = $3; k = split(s, a, ","); for (i = 1; i <= k; i++) if (a[i] ~ /^!/ && a[i] != "!127.0.0.1" && a[i] != "!::1") c++ } END { print c + 0 }' "$cfg" 2>/dev/null)
  [ "${n:-0}" -ge 1 ] && emit EXP-SSH-4 PASS || emit EXP-SSH-4 FAIL
  sshd_bin=$(command -v sshd 2>/dev/null)
  [ -z "$sshd_bin" ] && [ -x /usr/sbin/sshd ] && sshd_bin=/usr/sbin/sshd
  if [ -z "$sshd_bin" ]; then
    emit EXP-SSH-2 UNK; emit EXP-SSH-3 UNK
  else
    f_opt=""
    [ -n "$R" ] && f_opt="-f $cfg"
    denied() { "$sshd_bin" -T $f_opt -C "user=hostaudit,host=hostaudit,addr=$1" 2>/dev/null | awk 'tolower($1) == "denyusers" { for (i = 2; i <= NF; i++) if ($i == "*") f = 1 } END { exit !f }'; }
    answers() { "$sshd_bin" -T $f_opt -C "user=hostaudit,host=hostaudit,addr=$1" 2>/dev/null | grep -qi '^port '; }
    out_addr="${HA_SSH_DENIED_ADDR:-203.0.113.250}"
    if ! answers "$out_addr"; then
      emit EXP-SSH-2 UNK; emit EXP-SSH-3 UNK
    else
      denied "$out_addr" && emit EXP-SSH-2 PASS || emit EXP-SSH-2 FAIL
      bad=0
      for a in 127.0.0.1 $HA_SSH_ALLOWED_ADDRS; do denied "$a" && bad=1; done
      [ "$bad" -eq 0 ] && emit EXP-SSH-3 PASS || emit EXP-SSH-3 FAIL
    fi
  fi
fi

# --- 탐지·로그 보존 (detection-recovery) ----------------------------------------------------
if [ -n "$HA_DET_JOURNALD" ]; then
  st=$(cat "$R/etc/systemd/journald.conf" "$R"/etc/systemd/journald.conf.d/*.conf 2>/dev/null | awk -F= 'tolower($1) == "storage" { v = tolower($2); gsub(/[[:space:]]/, "", v) } END { print v }')
  if [ "$st" = persistent ] && [ -d "$R/var/log/journal" ]; then emit EXP-DET-1 PASS
  elif [ "$st" = auto ] && [ -d "$R/var/log/journal" ]; then emit EXP-DET-1 PASS
  else emit EXP-DET-1 FAIL; fi
fi
if [ -n "${HA_DET_F2B}${HA_DET_F2B_NOFW}" ]; then
  if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then
    emit EXP-DET-2 PASS
    if [ -n "$HA_DET_F2B_NOFW" ]; then
      acts=$(fail2ban-client get sshd actions 2>/dev/null | grep -vi 'following actions' | awk 'NF { print $1 }')
      if [ -n "$acts" ] && [ -z "$(printf '%s\n' "$acts" | grep -vx dummy)" ]; then emit EXP-DET-3 PASS; else emit EXP-DET-3 FAIL; fi
    fi
  else
    emit EXP-DET-2 FAIL
    [ -n "$HA_DET_F2B_NOFW" ] && emit EXP-DET-3 FAIL
  fi
fi
if [ -n "${HA_DET_AUDIT}${HA_DET_AUDIT_SECRET}" ]; then
  rules=""
  command -v auditctl >/dev/null 2>&1 && rules=$(auditctl -l 2>/dev/null)
  miss=0
  for k in identity auth_config sudo_config sshd_config; do
    printf '%s\n' "$rules" | grep -Eq -- "-k $k( |\$)" || miss=1
  done
  [ "$miss" -eq 0 ] && emit EXP-DET-4 PASS || emit EXP-DET-4 FAIL
  if [ -n "$rules" ] && ! printf '%s\n' "$rules" | grep -q 'execve'; then emit EXP-DET-5 PASS; else emit EXP-DET-5 FAIL; fi
  if [ -n "$HA_DET_AUDIT_SECRET" ]; then
    printf '%s\n' "$rules" | grep -Eq -- '-k secret_access( |$)' && emit EXP-DET-6 PASS || emit EXP-DET-6 FAIL
  fi
fi
if [ -n "$HA_DET_AGENT" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet "$HA_DET_AGENT" 2>/dev/null && emit EXP-DET-7 PASS || emit EXP-DET-7 FAIL
  else
    emit EXP-DET-7 UNK
  fi
fi

# --- 시크릿 파일 권한 (secret-file-permissions) --------------------------------------------
fake_owner() { # stat 결과의 소유자를 테스트 가짜 루트에서만 root로 본다
  if [ -n "$R" ] && [ -n "${HA_FAKE_ROOT_OWNER:-}" ] && [ "$1" = "$HA_FAKE_ROOT_OWNER" ]; then echo root; else echo "$1"; fi
}
if [ -n "$HA_SEC_ROOTS" ]; then
  bad=0
  for d in $HA_SEC_ROOTS; do
    n=$(find "$R$d" -xdev -maxdepth 5 \( -name data -o -name volumes -o -name logs -o -name node_modules -o -name .git \) -prune -o \
      -type f \( -name '.env' -o -name '*.env' -o -name '*secret*' -o -name '*password*' -o -name '*token*' -o -name '*.key' \
        -o -name '*.pem' -o -name 'id_*' -o -name 'ssh_host_*_key' \) \( -perm /022 -o -perm /007 \) -print 2>/dev/null | head -n 1)
    [ -n "$n" ] && bad=1
  done
  [ "$bad" -eq 0 ] && emit EXP-SEC-1 PASS || emit EXP-SEC-1 FAIL
fi
if [ -n "$HA_SEC_FILES" ]; then
  bad=0
  for f in $HA_SEC_FILES; do
    st=$(stat -c '%a %U' "$R$f" 2>/dev/null) || { bad=1; continue; }
    [ "$(fake_owner "${st#* }")" = root ] && mode_le "${st% *}" 600 || bad=1
  done
  [ "$bad" -eq 0 ] && emit EXP-SEC-2 PASS || emit EXP-SEC-2 FAIL
fi
if [ -n "$HA_SEC_ENV_FILES" ]; then
  bad=0
  for f in $HA_SEC_ENV_FILES; do
    st=$(stat -c '%a %U %G' "$R$f" 2>/dev/null) || { bad=1; continue; }
    m=${st%% *}
    rest=${st#* }
    o=$(fake_owner "${rest% *}")
    g=${rest#* }
    [ -n "$R" ] && [ -n "${HA_FAKE_DOCKERMGMT_GROUP:-}" ] && [ "$g" = "$HA_FAKE_DOCKERMGMT_GROUP" ] && g=dockermgmt
    [ "$o" = root ] && [ "$g" = dockermgmt ] && mode_le "$m" 640 || bad=1
  done
  [ "$bad" -eq 0 ] && emit EXP-SEC-3 PASS || emit EXP-SEC-3 FAIL
fi

echo __HOST_AUDIT_REGRESSION_END__
