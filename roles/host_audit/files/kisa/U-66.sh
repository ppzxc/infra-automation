# KISA-2026:U-66 (중) 정책에 따른 시스템 로깅 설정
# 양호: 로그 기록 정책이 수립되어 있고 정책에 따라 로그를 남기는 경우.
# 이 저장소의 로그 정책은 Host Agents(ADR-0006, ISMS 기준)이고, 호스트 쪽 전제는 syslog 데몬
# (rsyslog·syslog-ng·syslogd)이 돌며 인증(auth·authpriv) 로그 규칙이 있는 것이다. 그 전제를 자동 판정한다.
(
  if kisa_service_on rsyslogd rsyslog; then
    d=rsyslogd
    files="$R/etc/rsyslog.conf $(ls "$R"/etc/rsyslog.d/*.conf 2>/dev/null)"
  elif kisa_service_on syslog-ng; then
    d=syslog-ng
    files="$R/etc/syslog-ng/syslog-ng.conf $(ls "$R"/etc/syslog-ng/conf.d/*.conf 2>/dev/null)"
  elif kisa_service_on syslogd syslog; then
    d=syslogd
    files="$R/etc/syslog.conf"
  else
    kisa_emit U-66 VULN "no syslog daemon (rsyslogd, syslog-ng, syslogd) active"
    exit 0
  fi
  # shellcheck disable=SC2086
  if grep -Eq '^[^#]*(authpriv|auth)[.,]' $files 2>/dev/null || grep -Eq 'facility\((auth|authpriv)' $files 2>/dev/null; then
    kisa_emit U-66 GOOD "$d active with auth/authpriv rule"
  else
    kisa_emit U-66 VULN "$d active but no auth/authpriv logging rule"
  fi
)
