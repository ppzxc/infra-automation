# KISA-2026:U-45 (상) 메일 서비스 버전 점검
# 양호: 메일 서비스 버전이 최신인 경우. 최신 여부는 오프라인으로 판정할 수 없어(알려진 취약 버전은
# Package Vulnerability 섹션이 다룬다) 사용 중인 MTA와 버전을 증적으로 내고 수동으로 둔다.
# 메일 서비스를 쓰지 않으면 해당없음.
(
  mta=$(kisa_mta)
  case "$mta" in
    "") kisa_emit U-45 NA "no mail service (postfix, sendmail, exim) active"; exit 0 ;;
    postfix) ver=$(postconf -h mail_version 2>/dev/null) ;;
    # sendmail을 실행하면 큐를 건드릴 수 있어 설정 파일의 버전(DZ)만 읽는다.
    sendmail) ver=$(sed -n 's/^DZ//p' "$R/etc/mail/sendmail.cf" 2>/dev/null | head -n 1) ;;
    exim) ver=$(exim -bV 2>/dev/null | awk 'NR == 1 { print $3 }') ;;
  esac
  kisa_emit U-45 MANUAL "$mta ${ver:-version unknown}; compare with vendor latest and Package Vulnerability"
)
