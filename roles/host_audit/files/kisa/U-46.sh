# KISA-2026:U-46 (상) 일반 사용자의 메일 서비스 실행 방지
# 양호: 일반 사용자가 메일 큐를 조작(q 옵션)하지 못하게 한 경우.
# sendmail: PrivacyOptions에 restrictqrun. postfix: postsuper에 기타 실행 권한 없음. exim: exiqgrep 기타 실행 없음.
(
  mta=$(kisa_mta)
  case "$mta" in
    "")
      kisa_emit U-46 NA "no mail service active"
      ;;
    sendmail)
      if grep -Eiq '^O[[:space:]]*PrivacyOptions=.*restrictqrun' "$R/etc/mail/sendmail.cf" 2>/dev/null; then
        kisa_emit U-46 GOOD "sendmail PrivacyOptions includes restrictqrun"
      else
        kisa_emit U-46 VULN "sendmail PrivacyOptions lacks restrictqrun"
      fi
      ;;
    postfix | exim)
      [ "$mta" = postfix ] && f=/usr/sbin/postsuper || f=/usr/sbin/exiqgrep
      st=$(kisa_stat "$R$f")
      if [ -z "$st" ]; then
        kisa_emit U-46 GOOD "$f not present"
      elif [ $(( 0${st% *} & 01 )) -eq 0 ]; then
        kisa_emit U-46 GOOD "$f mode=${st% *} (no execute for others)"
      else
        kisa_emit U-46 VULN "$f mode=${st% *} (others may execute)"
      fi
      ;;
  esac
)
