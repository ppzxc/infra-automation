# KISA-2026:U-18 (상) /etc/shadow 파일 소유자 및 권한 설정
# 양호: 소유자 root, 권한 400 이하.
(
  kisa_file_check U-18 /etc/shadow 400 root MANUAL
)
