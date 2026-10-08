# KISA-2026:U-47 (상) 스팸 메일 릴레이 제한
# 양호: 메일 릴레이를 제한한 경우. postfix: smtpd_relay_restrictions·smtpd_recipient_restrictions에
# reject_unauth_destination 또는 defer_unauth_destination. sendmail: promiscuous_relay 미사용.
# exim은 설정 형식이 달라 수동. 메일 서비스를 쓰지 않으면 해당없음.
(
  mta=$(kisa_mta)
  case "$mta" in
    "")
      kisa_emit U-47 NA "no mail service active"
      ;;
    postfix)
      r=$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | tr '\n' ' ')
      if printf '%s' "$r" | grep -Eq '(reject|defer)_unauth_destination'; then
        kisa_emit U-47 GOOD "postfix relay restricted by *_unauth_destination"
      else
        kisa_emit U-47 VULN "postfix relay restrictions lack reject_unauth_destination"
      fi
      ;;
    sendmail)
      if grep -Eiq 'promiscuous_relay' "$R/etc/mail/sendmail.mc" "$R/etc/mail/sendmail.cf" 2>/dev/null; then
        kisa_emit U-47 VULN "sendmail promiscuous_relay enabled"
      else
        kisa_emit U-47 GOOD "sendmail promiscuous_relay not used"
      fi
      ;;
    exim)
      kisa_emit U-47 MANUAL "exim relay ACL must be reviewed manually"
      ;;
  esac
)
