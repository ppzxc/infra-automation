# KISA-2026:U-16 (상) /etc/passwd 파일 소유자 및 권한 설정
# 양호: 소유자 root, 권한 644 이하.
(
  kisa_file_check U-16 /etc/passwd 644 root MANUAL
)
