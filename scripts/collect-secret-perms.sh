#!/usr/bin/env bash
# 시크릿 파일 권한 목록 수집기 (#375, Spec #364). 읽기 전용: 파일 내용을 읽지 않고
# 권한·소유자·경로만 find -printf로 본다. 셸 이력은 시크릿 후보 줄 수와 위치(파일)만 센다.
#
# 서버 쪽 실행(운영자 PC에서 ssh stdin으로, 결과는 저장소 밖 비공개 경로에):
#   ssh <user@host> 'sudo -n bash -s' < scripts/collect-secret-perms.sh > <비공개 경로>/secret-perms-<전|후>.txt
# 같은 명령을 적용 전후에 한 번씩 돌려 diff한다.
#
# 환경변수: SECRET_PERMS_ROOTS  탐색 경로(공백 구분, 기본 /opt /srv /etc/restic /etc/ssh /root /home)
set -u
set -o pipefail

ROOTS="${SECRET_PERMS_ROOTS:-/opt /srv /etc/restic /etc/ssh /root /home}"
# 셸 이력에서 시크릿 후보로 볼 줄 패턴. 일치한 줄은 출력하지 않고 개수만 센다.
HISTORY_PATTERN='(password|passwd|secret|token|api_?key|BEGIN [A-Z ]*PRIVATE KEY)[A-Za-z_]*[=: ]'

section() { printf '\n## %s\n' "$1"; }

section secret-file-permissions
# shellcheck disable=SC2086
find $ROOTS -xdev -maxdepth 5 \
  \( -name data -o -name volumes -o -name logs -o -name node_modules -o -name .git \) -prune -o \
  -type f \( -name '.env' -o -name '*.env' -o -name '*secret*' -o -name '*password*' \
    -o -name '*token*' -o -name '*.key' -o -name '*.pem' -o -name 'id_*' \
    -o -name 'ssh_host_*_key' -o -name 'authorized_keys' \) \
  -printf '%m %u:%g %p\n' 2>/dev/null | sort

section too-open-candidates
# 그룹·기타에 쓰기가 열렸거나 기타(other)에 권한이 열린 파일. 0640 root:dockermgmt 예외도 기타는 0이다.
# shellcheck disable=SC2086
find $ROOTS -xdev -maxdepth 5 \
  \( -name data -o -name volumes -o -name logs -o -name node_modules -o -name .git \) -prune -o \
  -type f \( -name '.env' -o -name '*.env' -o -name '*secret*' -o -name '*password*' \
    -o -name '*token*' -o -name '*.key' -o -name '*.pem' -o -name 'id_*' \
    -o -name 'ssh_host_*_key' \) \
  \( -perm /022 -o -perm /007 \) -printf '%m %u:%g %p\n' 2>/dev/null | sort

section shell-history-candidates
# 줄 내용은 출력하지 않는다. 파일 위치와 후보 줄 수만 싣는다. 교체 여부는 운영자가 정한다.
find /root /home -xdev -maxdepth 3 -type f -name '.*_history' 2>/dev/null | sort | while IFS= read -r f; do
  printf '%s lines=%s candidates=%s\n' "$f" \
    "$(wc -l < "$f" 2>/dev/null || echo '?')" \
    "$(grep -cEi "$HISTORY_PATTERN" "$f" 2>/dev/null || true)"
done

# 일부 경로 접근 거부는 실패가 아니다(빈 결과로 보인다).
exit 0
