#!/usr/bin/env bash
# ==============================================================================
# docker-guard.sh <command...>
#
# Runs <command> in its own process group and watches the Docker daemon while it
# runs. If the daemon stops answering for FAILS consecutive probes the whole
# group is killed and the guard exits 125, instead of leaving the caller (a
# pre-push hook) blocked on a `docker exec` that will never return.
#
# Why: Docker Desktop's backend has been observed to freeze under sustained
# `docker exec` load (many tasks x many hosts, as molecule does). Every docker
# call then hangs, including molecule's own cleanup, so a stuck run would hold a
# push for the full RUN_TIMEOUT. No `molecule destroy` is attempted here: it
# would hang the same way. The next `molecule test` starts with a destroy.
#
# Exit: <command>'s own status, 125 = killed because Docker stopped responding,
#       130 = interrupted.
# Env:  GUARD_INTERVAL (s between probes, 5)  GUARD_FAILS (consecutive failures, 3)
#       GUARD_PROBE_TIMEOUT (s per probe, 10) GUARD_GRACE (s TERM -> KILL, 5)
# ==============================================================================
set -uo pipefail

INTERVAL="${GUARD_INTERVAL:-5}"
FAILS="${GUARD_FAILS:-3}"
PROBE_TIMEOUT="${GUARD_PROBE_TIMEOUT:-10}"
GRACE="${GUARD_GRACE:-5}"

[ $# -gt 0 ] || { echo "usage: $0 <command...>" >&2; exit 2; }

# Own session => own process group, so one signal reaches molecule, ansible and
# every child they spawned.
setsid "$@" &
pid=$!

kill_group() {
    kill -TERM -- "-$pid" 2>/dev/null
    sleep "$GRACE"
    kill -KILL -- "-$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}
trap 'kill_group; exit 130' INT TERM

failed=0
while kill -0 "$pid" 2>/dev/null; do
    sleep "$INTERVAL"
    kill -0 "$pid" 2>/dev/null || break
    if timeout "$PROBE_TIMEOUT" docker info >/dev/null 2>&1; then
        failed=0
    else
        failed=$((failed + 1))
    fi
    if [ "$failed" -ge "$FAILS" ]; then
        echo "[✗] Docker daemon stopped responding (${failed} consecutive failed probes); killing the run." >&2
        echo "    Restart Docker Desktop (or run 'wsl --shutdown' from Windows) and retry." >&2
        echo "    Leftover containers are removed by the next run's initial destroy." >&2
        kill_group
        exit 125
    fi
done

wait "$pid"
