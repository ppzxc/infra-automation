# KISA-2026:U-48 (중) expn, vrfy 명령어 제한
# 양호: SMTP expn·vrfy 명령을 막은 경우. postfix: disable_vrfy_command = yes (postfix는 EXPN 미지원).
# sendmail: PrivacyOptions에 noexpn·novrfy(또는 goaway). 메일 서비스를 쓰지 않으면 해당없음.
(
  mta=$(kisa_mta)
  case "$mta" in
    "")
      kisa_emit U-48 NA "no mail service active"
      ;;
    postfix)
      v=$(postconf -h disable_vrfy_command 2>/dev/null)
      if [ "$v" = yes ]; then
        kisa_emit U-48 GOOD "postfix disable_vrfy_command=yes"
      else
        kisa_emit U-48 VULN "postfix disable_vrfy_command=${v:-unknown}"
      fi
      ;;
    sendmail)
      p=$(grep -Ei '^O[[:space:]]*PrivacyOptions=' "$R/etc/mail/sendmail.cf" 2>/dev/null | head -n 1)
      if printf '%s' "$p" | grep -Eiq 'goaway' || { printf '%s' "$p" | grep -Eiq 'noexpn' && printf '%s' "$p" | grep -Eiq 'novrfy'; }; then
        kisa_emit U-48 GOOD "sendmail ${p#O }"
      else
        kisa_emit U-48 VULN "sendmail PrivacyOptions lacks noexpn/novrfy: ${p:-unset}"
      fi
      ;;
    exim)
      kisa_emit U-48 MANUAL "exim VRFY/EXPN ACL must be reviewed manually"
      ;;
  esac
)
