# Host Audit Asset Inventory probe (ADR-0009, #120). POSIX sh, read-only: it
# only reads files and runs query commands, and writes nothing on the host.
# Runs as root (sudo) on CentOS 6 through Rocky 10 and Ubuntu: no bash-isms,
# no Python. Password hashes never leave the host — /etc/shadow is reduced to a
# status word (set / locked / empty) on the host.
# Output: key=value lines between markers (repeated keys = list items), so
# login banners are ignored.
echo __HOST_AUDIT_INVENTORY_BEGIN__
echo "now_epoch=$(date -u +%s 2>/dev/null)"

# --- 하드웨어 ---------------------------------------------------------------
echo "cpu_count=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
sed -n 's/^model name[[:space:]]*:[[:space:]]*/cpu_model=/p' /proc/cpuinfo 2>/dev/null | head -n 1
sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/mem_total_kb=\1/p' /proc/meminfo 2>/dev/null
for f in sys_vendor product_name product_serial; do
  if [ -r "/sys/class/dmi/id/$f" ]; then
    echo "dmi_$f=$(head -n 1 "/sys/class/dmi/id/$f" 2>/dev/null)"
  fi
done
# 장치 이름·마운트 경로의 공백에 흔들리지 않도록 사용률(NN%) 열을 기준으로 앞뒤를 읽는다.
df -P -T -k 2>/dev/null | awk 'NR > 1 {
  p = 0; for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+%$/) { p = i; break }
  if (p < 5) next
  t = $(p - 4); if (t ~ /^(tmpfs|devtmpfs|overlay|squashfs|proc|sysfs|cgroup2?|nsfs|ramfs|autofs|iso9660|rootfs)$/) next
  m = $(p + 1); for (i = p + 2; i <= NF; i++) m = m " " $i
  print "disk=" m "|" t "|" $(p - 3) "|" $(p - 2) }'

# --- 운영 -------------------------------------------------------------------
echo "uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
if command -v chronyc >/dev/null 2>&1; then
  echo "timesync_tool=chrony"
  chronyc -n tracking 2>/dev/null | sed -n 's/^Leap status[[:space:]]*:[[:space:]]*/timesync_chrony_leap=/p'
fi
if command -v ntpq >/dev/null 2>&1; then
  echo "timesync_tool=ntpd"
  echo "timesync_ntp_peer=$(ntpq -pn 2>/dev/null | grep -c '^\*')"
fi
if command -v timedatectl >/dev/null 2>&1; then
  echo "timesync_tool=timedatectl"
  timedatectl status 2>/dev/null | sed -n 's/^[[:space:]]*\(System clock\|NTP\) synchronized:[[:space:]]*/timesync_timedatectl=/p'
fi

# --- 패키지 (전체 목록은 러너의 호스트별 JSON에만 남는다) -------------------
# rpm opens its database read-write when run as root: on EL9 that alone rewrites
# rpmdb.sqlite-shm (and the Berkeley DB environment on EL6/7). Query it as nobody,
# which can only open it read-only.
rpm_ro() {
  if [ "$(id -u)" != 0 ]; then
    rpm "$@"
  elif command -v setpriv >/dev/null 2>&1; then
    # numeric ids: util-linux 2.23 (EL7) setpriv does not resolve names
    setpriv --reuid="$(id -u nobody)" --regid="$(id -g nobody)" --clear-groups rpm "$@"
  else
    su -s /bin/sh nobody -c 'rpm "$@"' -- rpm_ro "$@"
  fi
}
if command -v rpm >/dev/null 2>&1 && rpm_ro -q rpm >/dev/null 2>&1; then
  echo "pkg_manager=rpm"
  rpm_ro -qa --queryformat 'pkg=%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n' 2>/dev/null
elif command -v dpkg-query >/dev/null 2>&1; then
  echo "pkg_manager=dpkg"
  dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${Architecture}\n' 2>/dev/null \
    | awk -F'|' '$1 ~ /^ii/ { print "pkg=" $2 "|" $3 "|" $4 "|" }'
  echo "pkg_dpkg_status_mtime=$(stat -c %Y /var/lib/dpkg/status 2>/dev/null)"
fi

# --- listening 포트·프로세스 ------------------------------------------------
if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null | sed -n '2,$s/^/listen_tcp=/p'
  ss -ulnp 2>/dev/null | sed -n '2,$s/^/listen_udp=/p'
elif command -v netstat >/dev/null 2>&1; then
  netstat -tlnp 2>/dev/null | sed -n '3,$s/^/netstat=/p'
  netstat -ulnp 2>/dev/null | sed -n '3,$s/^/netstat=/p'
fi

# --- 계정·특수권한 ------------------------------------------------------------
awk -F: '{ print "passwd=" $1 "|" $3 "|" $4 "|" $7 }' /etc/passwd 2>/dev/null
if [ -r /etc/shadow ]; then
  awk -F: '{ s = "set"; if ($2 == "") s = "empty"; else if ($2 ~ /^[!*]/) s = "locked"; print "shadow=" $1 "|" s }' /etc/shadow
else
  echo "shadow_unreadable=1"
fi
awk -F: '$1 == "wheel" || $1 == "sudo" || $1 == "admin" { print "group=" $1 "|" $4 }' /etc/group 2>/dev/null
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -v '^[[:space:]]*Defaults' | grep -v '^[[:space:]]*$' \
    | sed "s|^|sudoers=${f}\||"
done
ll=""
if command -v lastlog >/dev/null 2>&1; then
  ll=lastlog
elif command -v lastlog2 >/dev/null 2>&1; then
  ll=lastlog2
fi
if [ -n "$ll" ]; then
  echo "lastlog_available=1"
  $ll 2>/dev/null | sed -n '2,$s/^/lastlog=/p'
  $ll -t 90 2>/dev/null | awk 'NR > 1 { print "recent_login=" $1 }'
fi

# --- Host Agents ------------------------------------------------------------
for b in otelcol-contrib resticprofile restic; do
  if [ -x "/usr/local/bin/$b" ] || command -v "$b" >/dev/null 2>&1; then
    echo "agent_bin=$b"
  fi
done
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "agent_otelcol_active=$(systemctl is-active otelcol-contrib 2>/dev/null)"
  echo "agent_backup_timer_active=$(systemctl is-active host-agents-backup.timer 2>/dev/null)"
elif [ -x /etc/init.d/otelcol-contrib ]; then
  if service otelcol-contrib status >/dev/null 2>&1; then
    echo "agent_otelcol_active=active"
  else
    echo "agent_otelcol_active=inactive"
  fi
fi
if [ -f /etc/cron.d/host-agents-backup ]; then
  echo "agent_backup_cron=1"
fi
echo __HOST_AUDIT_INVENTORY_END__
