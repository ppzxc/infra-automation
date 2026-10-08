# KISA-2026:U-63 (중) sudo 명령어 접근 관리
# 양호: /etc/sudoers 소유자 root, 권한 640 이하. sudo를 쓰지 않으면(파일 없음) 해당없음.
# NOPASSWD 여부는 이 항목의 판정 기준이 아니다(특수권한자는 Asset Inventory가 다룬다).
(
  kisa_file_check U-63 /etc/sudoers 640 root NA
)
