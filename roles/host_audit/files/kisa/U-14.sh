# KISA-2026:U-14 (상) root 홈, 패스 디렉터리 권한 및 패스 설정
# 양호: PATH 환경변수에 "."(또는 빈 항목)이 맨 앞이나 중간에 포함되지 않은 경우. 맨 뒤는 허용.
# 전역 프로필과 root의 셸 시작 파일에서 PATH= 지정을 모두 본다.
(
  bad=""
  seen=0
  for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /root/.profile /root/.bashrc \
    /root/.bash_profile /root/.cshrc /root/.login; do
    [ -r "$R$f" ] || continue
    for v in $(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$R$f" | sed 's/^[^=]*=//; s/["'\'']//g; s/[[:space:]].*$//'); do
      seen=1
      if printf '%s\n' "$v" | awk -F: '{ for (i = 1; i < NF; i++) if ($i == "." || $i == "") { f = 1 } } END { exit !f }'; then
        bad="$bad${bad:+ }$f=$v"
      fi
    done
  done
  if [ -n "$bad" ]; then
    kisa_emit U-14 VULN "'.' or empty entry before the end of PATH: $bad"
  elif [ "$seen" -eq 1 ]; then
    kisa_emit U-14 GOOD "no '.' or empty entry before the end of PATH in profiles"
  else
    kisa_emit U-14 GOOD "PATH not overridden in global or root profiles"
  fi
)
