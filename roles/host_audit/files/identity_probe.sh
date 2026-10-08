# Host Audit identity/OS probe (ADR-0009). POSIX sh, read-only: it only reads
# files and runs query commands, and writes nothing on the host. Runs on
# CentOS 6 through Rocky 10 and Ubuntu, so no bash-isms and no Python.
# Output: key=value lines between markers, so login banners are ignored.
echo __HOST_AUDIT_BEGIN__
echo "hostname=$(hostname 2>/dev/null)"
echo "fqdn=$(hostname -f 2>/dev/null)"
echo "account=$(id -un 2>/dev/null)"
echo "kernel=$(uname -r 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
if [ -r /etc/os-release ]; then
  sed -n 's/^\([A-Z_]*\)=/os_release_\1=/p' /etc/os-release
fi
if [ -r /etc/redhat-release ]; then
  echo "redhat_release=$(head -n 1 /etc/redhat-release)"
fi
if command -v ip >/dev/null 2>&1; then
  ip -o addr show 2>/dev/null | awk '$3 == "inet" || $3 == "inet6" { print "ip=" $4 }'
else
  echo "ip=$(hostname -I 2>/dev/null)"
fi
echo __HOST_AUDIT_END__
