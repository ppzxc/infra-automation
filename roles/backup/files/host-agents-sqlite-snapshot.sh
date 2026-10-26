#!/bin/sh
# Ansible managed — 백업 직전 SQLite 스냅샷 (Spec #322 / Ticket-1, #323).
#
#   host-agents-sqlite-snapshot <dest_dir> <db> [<db> ...]
#
# resticprofile의 run-before 훅이 호출한다. 실행 중인 SQLite DB를 파일째 복사하면 쓰는 도중의 찢어진 사본이 되므로,
# sqlite3의 online backup(`.backup`)으로 일관된 사본을 <dest_dir>에 만들고 그 사본을 백업한다.
# 원본에는 쓰지 않는다(읽기와 WAL 공유 메모리 접근뿐이다).
#
# 하나라도 실패하면 0이 아닌 코드로 끝난다. 훅 실패는 resticprofile이 백업을 건너뛰고 run-finally에 ERROR를 주므로,
# 백업 결과(backup.jsonl)가 success=false로 남아 기존 백업 실패·누락 알림에 걸린다.
#
# 오래된 sqlite3 CLI는 점 명령이 실패해도 0을 반환할 수 있으므로 종료 코드만 믿지 않는다:
#   원본 존재 확인(CLI가 없는 파일을 빈 DB로 만들지 않게) → 임시 파일에 .backup → 비어 있지 않은지 → PRAGMA quick_check = ok → rename.
# 스냅샷 파일 이름은 원본의 전체 경로에서 만든다(`/`→`%2F`, `%`→`%25`): 같은 파일 이름이 다른 디렉터리에 있어도 겹치지 않는다.
export LC_ALL=C
SQLITE3="${SQLITE3:-sqlite3}"
TIMEOUT_MS="${SQLITE_SNAPSHOT_TIMEOUT_MS:-60000}"

if [ "$#" -lt 2 ]; then
    echo "usage: host-agents-sqlite-snapshot <dest_dir> <db> [<db> ...]" >&2
    exit 2
fi
dest=$1
shift

umask 077
mkdir -p "$dest" || exit 1
chmod 0700 "$dest" 2>/dev/null
# 지난 실행의 스냅샷과 임시 파일을 먼저 지운다: 입력에서 빠진 DB의 옛 스냅샷이 계속 백업되지 않게 한다.
rm -f "$dest"/*.sqlite-snapshot "$dest"/.*.tmp 2>/dev/null

fail() {
    echo "sqlite snapshot: $1" >&2
    rm -f "$tmp"
    rc=1
}

rc=0
for db in "$@"; do
    name=$(printf '%s' "$db" | sed -e 's|^/||' -e 's|%|%25|g' -e 's|/|%2F|g')
    out="$dest/$name.sqlite-snapshot"
    tmp="$dest/.$name.tmp"

    if [ ! -f "$db" ]; then
        fail "source not found: $db"
        continue
    fi
    if ! "$SQLITE3" -batch "$db" ".timeout $TIMEOUT_MS" ".backup '$tmp'" >&2; then
        fail "backup command failed: $db"
        continue
    fi
    if [ -s "$db" ] && [ ! -s "$tmp" ]; then
        fail "snapshot is empty: $db"
        continue
    fi
    check=$("$SQLITE3" -batch "$tmp" "PRAGMA quick_check;" 2>&1)
    if [ "$check" != "ok" ]; then
        fail "snapshot failed quick_check: $db"
        continue
    fi
    chmod 0600 "$tmp" 2>/dev/null
    if ! mv -f "$tmp" "$out"; then
        fail "cannot move the snapshot into place: $db"
        continue
    fi
done
exit "$rc"
