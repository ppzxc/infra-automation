#!/usr/bin/env bash
# ==============================================================================
# Helper: Run Molecule Multi-OS integration tests (pre-push hook)
# ==============================================================================
# - Skips when the pushed commits touch nothing the molecule scenario exercises
#   (e.g. docs-only pushes). Set MOLECULE_FORCE=1 to run regardless.
# - Fails fast when the Docker daemon doesn't answer (hung Docker Desktop)
#   instead of blocking the push indefinitely.
# - Serializes runs machine-wide: every worktree shares the same fixed instance
#   names (test-rockylinux8/9, test-ubuntu2204) on one Docker daemon, so
#   concurrent runs destroy each other's containers.
# - Bounds the whole run so a stuck container can't hang the push forever.
# ==============================================================================
set -eo pipefail

DOCKER_PROBE_TIMEOUT="${MOLECULE_DOCKER_PROBE_TIMEOUT:-15}"
LOCK_WAIT="${MOLECULE_LOCK_WAIT:-1800}"
RUN_TIMEOUT="${MOLECULE_RUN_TIMEOUT:-1800}"
LOCK_FILE="/tmp/infra-automation-molecule.lock"

# Paths the molecule scenario depends on (converge.yml applies these roles).
RELEVANT_PATHS=(
    roles/common roles/security roles/access_security roles/docker_engine roles/monitoring
    molecule/ ansible.cfg requirements.yml
    scripts/run-molecule.sh lefthook.yml
)

echo "================================================================================"
echo " [Pre-Push Hook] Molecule Multi-OS Integration Tests"
echo "================================================================================"

if [ "${MOLECULE_FORCE:-0}" != "1" ]; then
    base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
    if [ -n "$base" ]; then
        if [ -z "$(git diff --name-only "$base" HEAD -- "${RELEVANT_PATHS[@]}")" ]; then
            echo "[i] No changes under molecule-relevant paths since origin/main; skipping."
            echo "    (MOLECULE_FORCE=1 to run anyway)"
            exit 0
        fi
    else
        echo "[i] Could not determine merge-base with origin/main; running molecule."
    fi
fi

if ! command -v molecule >/dev/null 2>&1; then
    echo "[!] Warning: 'molecule' is not installed in the local environment."
    echo "    To run full container integration tests, install:"
    echo "    pip install --user molecule molecule-plugins[docker] ansible-core"
    echo "    Skipping Molecule test for this push."
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Warning: Docker is not available. Skipping Molecule test."
    exit 0
fi

if ! timeout "$DOCKER_PROBE_TIMEOUT" docker info >/dev/null 2>&1; then
    echo "[✗] Docker daemon did not respond within ${DOCKER_PROBE_TIMEOUT}s."
    echo "    Restart Docker Desktop (or run 'wsl --shutdown' from Windows) and push again."
    exit 1
fi

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_WAIT" 9; then
    echo "[✗] Another molecule run held ${LOCK_FILE} for over ${LOCK_WAIT}s; aborting."
    exit 1
fi

echo "[i] Executing 'molecule test' across configured platforms (timeout ${RUN_TIMEOUT}s)..."
rc=0
timeout --kill-after=60 "$RUN_TIMEOUT" molecule test || rc=$?
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "[✗] molecule test exceeded ${RUN_TIMEOUT}s; destroying test instances."
    timeout 300 molecule destroy || true
fi
exit "$rc"
