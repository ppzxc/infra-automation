#!/usr/bin/env bash
# ==============================================================================
# Helper: Ensure Gitleaks binary is available locally
# Installs to .bin/gitleaks (gitignored) if not found in system PATH.
# ==============================================================================
set -eo pipefail

GITLEAKS_VERSION="8.24.0"
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
LOCAL_BIN="${PROJECT_ROOT}/.bin"
LOCAL_GITLEAKS="${LOCAL_BIN}/gitleaks"

# 1. PATH에 gitleaks가 이미 존재하는 경우
if command -v gitleaks >/dev/null 2>&1; then
    exit 0
fi

# 2. 로컬 .bin/ 디렉터리에 gitleaks가 이미 있는 경우
if [ -x "${LOCAL_GITLEAKS}" ]; then
    exit 0
fi

echo "[i] Gitleaks not found in PATH or .bin/. Downloading Gitleaks v${GITLEAKS_VERSION}..."

mkdir -p "${LOCAL_BIN}"

# OS 및 아키텍처 자동 감지
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64)
        GITLEAKS_ARCH="x64"
        ;;
    aarch64|arm64)
        GITLEAKS_ARCH="arm64"
        ;;
    armv7l)
        GITLEAKS_ARCH="armv7"
        ;;
    *)
        echo "[!] Unsupported architecture for auto-download: ${ARCH}. Falling back to regex scanner."
        exit 0
        ;;
esac

DOWNLOAD_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${GITLEAKS_ARCH}.tar.gz"

if command -v curl >/dev/null 2>&1; then
    curl -sSL "${DOWNLOAD_URL}" | tar -xz -C "${LOCAL_BIN}" gitleaks 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${DOWNLOAD_URL}" | tar -xz -C "${LOCAL_BIN}" gitleaks 2>/dev/null || true
fi

if [ -x "${LOCAL_GITLEAKS}" ]; then
    chmod +x "${LOCAL_GITLEAKS}"
    echo "[✓] Gitleaks v${GITLEAKS_VERSION} downloaded successfully to .bin/gitleaks"
else
    echo "[!] Failed to auto-download Gitleaks. Will fallback to built-in regex scanner."
fi
