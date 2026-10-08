#!/usr/bin/env bash
# ==============================================================================
# Molecule runner (pre-push hook + make test-* targets)
# ==============================================================================
#   run-molecule.sh fast            pre-push tier: Representative Platform (Rocky 9); all three
#                                   platforms in ONE run when roles/security or roles/common changed
#   run-molecule.sh slow            docker_engine + monitoring on every platform
#   run-molecule.sh full            fast + slow on every platform
#   run-molecule.sh role <role>     one role (+ common Base Layer) on Rocky 9
#
# Env: MOLECULE_FORCE=1        run even when nothing molecule-relevant changed
#      MOLECULE_SKIP_IDEMPOTENCE=1   `role` only: dev scenario, no idempotence pass (opt-in)
#      MOLECULE_PLATFORMS      override platform list (space separated, e.g. "rockylinux9")
#
# Guards:
# - Docker daemon must answer, or fail fast instead of hanging the push.
# - Runs are serialized machine-wide (fixed instance names on one daemon).
# - Whole run is bounded so a stuck container cannot hang the push forever.
# - scripts/docker-guard.sh kills the run if the Docker daemon freezes mid-run
#   (observed with Docker Desktop under sustained `docker exec` load).
# ==============================================================================
set -eo pipefail

cd "$(dirname "$0")/.."

TIER="${1:-fast}"
ROLE_ARG="${2:-}"
DOCKER_PROBE_TIMEOUT="${MOLECULE_DOCKER_PROBE_TIMEOUT:-15}"
LOCK_WAIT="${MOLECULE_LOCK_WAIT:-1800}"
RUN_TIMEOUT="${MOLECULE_RUN_TIMEOUT:-1800}"
LOCK_FILE="/tmp/infra-automation-molecule.lock"

RELEVANT_PATHS=(
    roles/common roles/security roles/access_security roles/docker_engine roles/monitoring
    roles/host_audit filter_plugins/host_audit.py filter_plugins/host_audit_inventory.py
    molecule/ ansible.cfg requirements.yml
    scripts/run-molecule.sh scripts/build-test-images.sh lefthook.yml
)
# Changing these can break OS-specific branches the Representative Platform
# (Rocky 9) does not reach, so all platforms run. They run in ONE molecule
# invocation (hosts execute in lockstep, ~240s) rather than one after another
# (~150s each), which is both faster and broader than adding Rocky 8 alone.
WIDE_TRIGGER_PATHS=(roles/security roles/common)

log() { echo "[i] $*"; }

changed_since_base() { # paths... -> non-empty output when any changed
    local base
    base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
    [ -z "$base" ] && { echo "unknown"; return; }
    git diff --name-only "$base" HEAD -- "$@"
    git diff --name-only HEAD -- "$@"
}

echo "================================================================================"
echo " [Molecule] tier=${TIER}${ROLE_ARG:+ role=$ROLE_ARG}"
echo "================================================================================"

if [ "$TIER" = "fast" ] && [ "${MOLECULE_FORCE:-0}" != "1" ]; then
    if [ -z "$(changed_since_base "${RELEVANT_PATHS[@]}")" ]; then
        log "No changes under molecule-relevant paths since origin/main; skipping."
        log "(MOLECULE_FORCE=1 to run anyway)"
        exit 0
    fi
fi

for tool in molecule docker; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[!] Warning: '$tool' is not installed. Skipping molecule."
        exit 0
    fi
done

if ! timeout "$DOCKER_PROBE_TIMEOUT" docker info >/dev/null 2>&1; then
    echo "[✗] Docker daemon did not respond within ${DOCKER_PROBE_TIMEOUT}s."
    echo "    Restart Docker Desktop (or run 'wsl --shutdown' from Windows) and retry."
    exit 1
fi

# --- Static pre-step: cheap failures must not cost a container run ------------
if [ "$TIER" = "fast" ] || [ "$TIER" = "role" ]; then
    log "Static checks (syntax + lint)"
    ansible-playbook --syntax-check playbooks/site.yml >/dev/null \
        || { echo "[✗] ansible-playbook --syntax-check failed"; exit 1; }
    if command -v ansible-lint >/dev/null 2>&1; then
        ansible-lint --offline -q roles/common roles/security roles/access_security \
            || { echo "[✗] ansible-lint failed"; exit 1; }
    else
        echo "[!] ansible-lint not installed; skipping lint (pip install --user ansible-lint)"
    fi
fi

# --- Platform selection --------------------------------------------------------
platforms_for_fast() {
    local diff
    diff="$(changed_since_base "${WIDE_TRIGGER_PATHS[@]}")"
    if [ -n "$diff" ]; then echo "all"; else echo "rockylinux9"; fi
}

case "$TIER" in
    fast) PLATFORMS="${MOLECULE_PLATFORMS:-$(platforms_for_fast)}" ;;
    role) PLATFORMS="${MOLECULE_PLATFORMS:-rockylinux9}" ;;
    slow|full) PLATFORMS="${MOLECULE_PLATFORMS:-all}" ;;
    *) echo "usage: $0 {fast|slow|full|role <role>}"; exit 2 ;;
esac

if [ "$PLATFORMS" = "all" ]; then scripts/build-test-images.sh; else scripts/build-test-images.sh $PLATFORMS; fi

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_WAIT" 9; then
    echo "[✗] Another molecule run held ${LOCK_FILE} for over ${LOCK_WAIT}s; aborting."
    exit 1
fi

run_scenario() { # scenario platforms...
    local scenario="$1"; shift
    for p in "$@"; do
        # "all" targets every platform of the scenario in a single invocation.
        local rc=0 pflag="-p $scenario-$p"
        [ "$p" = "all" ] && pflag=""
        log "molecule test -s $scenario $pflag"
        scripts/docker-guard.sh timeout --kill-after=60 "$RUN_TIMEOUT" molecule test -s "$scenario" $pflag || rc=$?
        if [ "$rc" -ne 0 ]; then
            # 125 = the guard killed the run because the Docker daemon froze; any
            # docker call (including molecule destroy) would hang, so skip cleanup.
            if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
                echo "[✗] exceeded ${RUN_TIMEOUT}s; destroying instances."
                timeout 300 molecule destroy -s "$scenario" || true
            fi
            return "$rc"
        fi
    done
}

case "$TIER" in
    fast) run_scenario fast $PLATFORMS ;;
    slow) run_scenario slow $PLATFORMS ;;
    full) run_scenario fast $PLATFORMS && run_scenario slow $PLATFORMS ;;
    role)
        [ -n "$ROLE_ARG" ] || { echo "usage: $0 role <role>"; exit 2; }
        case "$ROLE_ARG" in
            common|security|access_security) scenario=fast ;;
            docker_engine|monitoring) scenario=slow ;;
            *) echo "unknown role: $ROLE_ARG"; exit 2 ;;
        esac
        # Idempotence stays on by default; skipping it is an explicit opt-in that
        # switches to the dev scenario (Rocky 9 only, no idempotence pass).
        if [ "${MOLECULE_SKIP_IDEMPOTENCE:-0}" = "1" ]; then
            log "MOLECULE_SKIP_IDEMPOTENCE=1: dev scenario, idempotence NOT checked"
            MOLECULE_ROLES="common,$ROLE_ARG" run_scenario dev rockylinux9
        else
            MOLECULE_ROLES="common,$ROLE_ARG" run_scenario "$scenario" $PLATFORMS
        fi
        ;;
esac
