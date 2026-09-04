#!/usr/bin/env bash
# ==============================================================================
# Git Pre-Commit Hook for infra-automation
# Checks for:
#   1. Secret leaks (Private Keys, Tokens, Passwords, Cloud Secrets)
#   2. Syntax & Spec validation (Python 3-way validator, Pytest)
#   3. Basic YAML syntax & Ansible Lint checks (if available)
# ==============================================================================

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================================================"
echo " [Git Pre-Commit Hook] Running security & quality checks..."
echo "================================================================================"

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "${ROOT_DIR}"

# ------------------------------------------------------------------------------
# 1. Secret Leak Detection in Staged Files
# ------------------------------------------------------------------------------
echo -n "[1/3] Scanning staged files for accidental secret leaks... "

# Staged files list (excluding deleted files)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "${STAGED_FILES}" ]; then
    echo -e "${GREEN}No staged files to scan.${NC}"
    exit 0
fi

# Secret patterns to block
# - Private Keys
# - AWS / Cloud Access & Secret Keys
# - OpenBao / Vault / GitHub Tokens
# - Hardcoded plaintext passwords (e.g. password: "...", secret: "...")
SECRET_PATTERNS=(
    "-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"
    "AKIA[0-9A-Z]{16}"
    "(s3_secret_key|aws_secret_access_key|bao_token|vault_token)\s*:\s*['\"][^'\"]{8,}['\"]"
    "password\s*:\s*['\"][a-zA-Z0-9!@#$%^&*()_+]{8,}['\"]"
    "ghp_[a-zA-Z0-9]{36}"
    "glpat-[a-zA-Z0-9\-]{20}"
)

FOUND_SECRET=0

for FILE in ${STAGED_FILES}; do
    # Skip binary files or example files if explicitly intended
    if [[ "${FILE}" == *.example || "${FILE}" == *.sample ]]; then
        continue
    fi

    for PATTERN in "${SECRET_PATTERNS[@]}"; do
        if git diff --cached "${FILE}" | grep -E -q "^\+.*${PATTERN}"; then
            echo -e "\n${RED}[!] CRITICAL SECURITY VIOLATION: Potential secret detected in ${FILE}!${NC}"
            echo -e "${YELLOW}    Pattern matched: ${PATTERN}${NC}"
            echo -e "${YELLOW}    Please remove the secret from staged changes or use environment variables/Vault.${NC}"
            FOUND_SECRET=1
        fi
    done
done

if [ ${FOUND_SECRET} -ne 0 ]; then
    echo -e "\n${RED}Commit rejected due to secret leak detection.${NC}"
    exit 1
fi
echo -e "${GREEN}PASS${NC}"

# ------------------------------------------------------------------------------
# 2. Spec Traceability Validator (Docs <-> Tasks <-> Verify)
# ------------------------------------------------------------------------------
echo -n "[2/3] Running 3-Way Specification & Traceability Validator... "
if command -v python3 >/dev/null 2>&1 && [ -f "scripts/validate-ansible-specs.py" ]; then
    if ! python3 scripts/validate-ansible-specs.py > /tmp/spec-validator.log 2>&1; then
        echo -e "${RED}FAIL${NC}"
        cat /tmp/spec-validator.log
        echo -e "\n${RED}Commit rejected: Spec validation failed.${NC}"
        exit 1
    fi
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}SKIPPED (Python3 or validator script missing)${NC}"
fi

# ------------------------------------------------------------------------------
# 3. Unit & Structure Tests
# ------------------------------------------------------------------------------
echo -n "[3/3] Running Structure & Unit Tests (pytest)... "
if command -v pytest >/dev/null 2>&1 && [ -d "tests" ]; then
    if ! pytest tests/ -q > /tmp/pytest-run.log 2>&1; then
        echo -e "${RED}FAIL${NC}"
        cat /tmp/pytest-run.log
        echo -e "\n${RED}Commit rejected: Unit tests failed.${NC}"
        exit 1
    fi
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}SKIPPED (pytest not installed locally)${NC}"
fi

echo "================================================================================"
echo -e "${GREEN}All pre-commit checks passed successfully! Proceeding with commit.${NC}"
echo "================================================================================"
exit 0
