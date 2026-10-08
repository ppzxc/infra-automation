# KISA-2026:U-02 (상) 비밀번호 관리정책 설정
# 양호: 비밀번호 관리 정책(복잡성·주기)이 설정된 경우. 2026판은 2021판의 복잡성(U-02)·
# 최소 길이(U-46)·최대 사용기간(U-47)·최소 사용기간(U-48)을 합친 항목이라 넷을 모두 본다.
#   최대 사용기간 PASS_MAX_DAYS <= 90, 최소 사용기간 PASS_MIN_DAYS >= 1 (/etc/login.defs)
#   복잡성: 문자 종류 3종 이상 + 8자 이상, 또는 2종 이상 + 10자 이상
#           (pwquality.conf, PAM pam_pwquality/pam_cracklib 인자 — 인자가 파일보다 우선)
(
  max=$(awk '$1 == "PASS_MAX_DAYS" { v = $2 } END { print v }' "$R/etc/login.defs" 2>/dev/null)
  min=$(awk '$1 == "PASS_MIN_DAYS" { v = $2 } END { print v }' "$R/etc/login.defs" 2>/dev/null)
  pam=$(kisa_pam_files system-auth password-auth common-password)
  pamline=""
  [ -n "$pam" ] && pamline=$(grep -hE '^[[:space:]]*password[[:space:]].*pam_(pwquality|cracklib)\.so' $pam 2>/dev/null)
  kv=$(
    {
      for f in "$R/etc/security/pwquality.conf" "$R"/etc/security/pwquality.conf.d/*.conf; do
        [ -r "$f" ] && sed -e 's/#.*//' -e 's/[[:space:]]*=[[:space:]]*/=/' -e 's/^[[:space:]]*//' "$f"
      done
      printf '%s\n' "$pamline" | tr ' \t' '\n\n'
    } 2>/dev/null | grep -E '^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)=-?[0-9]+$'
  )
  get() { printf '%s\n' "$kv" | awk -F= -v k="$1" '$1 == k { v = $2 } END { print v }'; }
  minlen=$(get minlen)
  # 모듈이 스택에 있고 minlen이 없으면 모듈 기본값(pam_pwquality·pam_cracklib 모두 9)이 적용된다.
  [ -z "$minlen" ] && [ -n "$pamline" ] && minlen=9
  classes=$(get minclass)
  [ -z "$classes" ] && classes=0
  neg=0
  for c in dcredit ucredit lcredit ocredit; do
    v=$(get "$c")
    [ -n "$v" ] && [ "$v" -lt 0 ] 2>/dev/null && neg=$((neg + 1))
  done
  [ "$neg" -gt "$classes" ] && classes=$neg
  bad=""
  { [ -n "$max" ] && [ "$max" -le 90 ] 2>/dev/null; } || bad="$bad max_days"
  { [ -n "$min" ] && [ "$min" -ge 1 ] 2>/dev/null; } || bad="$bad min_days"
  cx=0
  if [ -n "$minlen" ]; then
    { [ "$classes" -ge 3 ] && [ "$minlen" -ge 8 ]; } && cx=1
    { [ "$classes" -ge 2 ] && [ "$minlen" -ge 10 ]; } && cx=1
  fi
  [ "$cx" -eq 1 ] || bad="$bad complexity"
  ev="PASS_MAX_DAYS=${max:-unset} PASS_MIN_DAYS=${min:-unset} minlen=${minlen:-unset} classes=$classes"
  [ -n "$pamline" ] || ev="$ev (no pam_pwquality/pam_cracklib in password stack)"
  if [ -z "$bad" ]; then
    kisa_emit U-02 GOOD "$ev"
  else
    kisa_emit U-02 VULN "$ev; not met:$bad"
  fi
)
