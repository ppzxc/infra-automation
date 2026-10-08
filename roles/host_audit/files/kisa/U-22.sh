# KISA-2026:U-22 (상) /etc/services 파일 소유자 및 권한 설정
# 양호: 소유자 root(또는 bin, sys), 권한 644 이하.
(
  kisa_file_check U-22 /etc/services 644 "root bin sys"
)
