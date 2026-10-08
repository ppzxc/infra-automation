# Host Audit — package list probe (POSIX sh, read-only, ADR-0009 §Package Vulnerability).
# Runs through ansible.builtin.raw on every target, CentOS 6 ~ Rocky 10 and Ubuntu/Debian alike:
# no Python, no remote files, nothing installed. Only reads the release files and the
# package database. filter_plugins/host_audit_packages.py parses this output.
# Unlike inventory_probe.sh (#120) it also emits what Trivy needs to match advisories:
# the source package (rpm SOURCERPM, deb source:Package/source:Version) and the EL8+ module label.
echo "===RELEASE==="
if [ -r /etc/os-release ]; then cat /etc/os-release; fi
if [ -r /etc/redhat-release ]; then echo "REDHAT_RELEASE=$(head -n 1 /etc/redhat-release)"; fi
if [ -r /etc/debian_version ]; then echo "DEBIAN_VERSION=$(head -n 1 /etc/debian_version)"; fi
echo "ARCH=$(uname -m)"
# rpm opens its database read-write when run as root: on EL9 that alone rewrites
# rpmdb.sqlite-shm (and the Berkeley DB environment on EL6/7). Query it as nobody,
# which can only open it read-only (same as inventory_probe.sh).
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
if [ -r /etc/redhat-release ] && command -v rpm >/dev/null 2>&1; then
  echo "===PKGS_RPM==="
  # MODULARITYLABEL exists only on rpm >= 4.14 (EL8+); older rpm rejects unknown tags.
  if rpm --querytags 2>/dev/null | grep -qx MODULARITYLABEL; then
    rpm_ro -qa --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{MODULARITYLABEL}\n'
  else
    rpm_ro -qa --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t(none)\n'
  fi
elif command -v dpkg-query >/dev/null 2>&1; then
  echo "===PKGS_DEB==="
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'
else
  echo "===PKGS_NONE==="
fi
echo "===END==="
