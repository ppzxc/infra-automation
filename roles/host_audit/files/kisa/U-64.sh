# KISA-2026:U-64 (상) 주기적 보안 패치 및 벤더 권고사항 적용
# 양호: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하는 경우. 정책·주기는 문서 증적이라 자동
# 판정할 수 없다. 실제 미적용 보안 패치는 같은 보고서의 Package Vulnerability 섹션이 판정하므로,
# 여기서는 OS·커널을 증적으로 내고 수동으로 둔다.
(
  os=$(awk -F= '$1 == "PRETTY_NAME" { gsub(/"/, "", $2); print $2 }' "$R/etc/os-release" 2>/dev/null)
  [ -z "$os" ] && os=$(head -n 1 "$R/etc/redhat-release" 2>/dev/null)
  kisa_emit U-64 MANUAL "${os:-OS unknown}, kernel $(uname -r 2>/dev/null); see Package Vulnerability for unapplied fixes"
)
