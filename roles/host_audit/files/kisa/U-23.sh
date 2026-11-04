# KISA-2026:U-23 (상) SUID, SGID, Sticky bit 설정 파일 점검
# 양호: 주요 실행 파일에 불필요한 SUID/SGID가 없는 경우. passwd·su·sudo 등 운영에 필요한
# 표준 바이너리가 늘 있으므로 "있으면 취약"으로 자동 판정하지 않고 목록을 증적으로 낸다(수동).
# file capability(#432): SUID 밖의 권한 상승 통로라서 같은 증적 줄에 목록을 덧붙인다. 판정은 SUID/SGID만으로
# 정해지며 capability는 판정을 바꾸지 않는다. 배포판 기본(KISA_CAP_DEFAULTS, 역할 변수
# host_audit_kisa_capability_defaults) 밖의 항목만 검토 대상이다. getcap을 쓸 수 없으면 점검불가로 이름만 남긴다.
(
  # shellcheck disable=SC2046
  list=$(kisa_find $(kisa_local_mounts) -xdev -type f \( -perm -4000 -o -perm -2000 \) -print)
  rc=$?

  if ! kisa_getcap_ok; then
    cap="file capability: 점검불가(getcap not found or not executable)"
  else
    # shellcheck disable=SC2046
    capraw=$(kisa_find $(kisa_local_mounts) -xdev -type f -exec getcap {} +)
    caprc=$?
    if [ "$caprc" -eq 124 ]; then
      cap="file capability: 점검불가(timed out after ${KISA_FIND_TIMEOUT:-120}s)"
    else
      all=$(printf '%s\n' "$capraw" | sed "s|^$R||" | kisa_cap_norm)
      defaults=$(printf '%s\n' "${KISA_CAP_DEFAULTS:-}" | kisa_cap_norm)
      review=$(printf '%s\n' "$all" | KISA_CAP_NORM_DEFAULTS="$defaults" awk '
        BEGIN { n = split(ENVIRON["KISA_CAP_NORM_DEFAULTS"], d, "\n"); for (i = 1; i <= n; i++) known[d[i]] = 1 }
        NF && !($0 in known)')
      total=$(printf '%s\n' "$all" | grep -c .)
      nreview=$(printf '%s\n' "$review" | grep -c .)
      if [ "$total" -eq 0 ]; then
        cap="file capability: none"
      elif [ "$nreview" -eq 0 ]; then
        cap="file capability: default only ($total)"
      else
        cap="file capability review ($nreview): $(printf '%s\n' "$review" | kisa_cap 40); default: $((total - nreview))"
      fi
    fi
  fi

  if [ "$rc" -eq 124 ]; then
    kisa_emit U-23 MANUAL "find timed out after ${KISA_FIND_TIMEOUT:-120}s; $cap"
  elif [ -z "$list" ]; then
    kisa_emit U-23 GOOD "no SUID/SGID file on local filesystems; $cap"
  else
    kisa_emit U-23 MANUAL "SUID/SGID files ($(printf '%s\n' "$list" | grep -c .)): $(printf '%s\n' "$list" | sed "s|^$R||" | kisa_cap 40); $cap"
  fi
)
