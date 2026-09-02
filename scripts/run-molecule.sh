#!/usr/bin/env bash
# ==============================================================================
# Helper: Run Molecule Multi-OS integration tests
# ==============================================================================
set -eo pipefail

echo "================================================================================"
echo " [Pre-Push Hook] Running Molecule Multi-OS Integration Tests..."
echo "================================================================================"

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

echo "[i] Executing 'molecule test' across configured platforms..."
molecule test
