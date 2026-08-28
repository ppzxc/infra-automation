#!/usr/bin/env bash
# ==============================================================================
# Script Name: test_firewalld_docker.sh
# Description: Automated Test Suite for firewalld-docker CLI
#              Tests syntax, CLI help flags, arguments, and mocked firewalld operations
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/firewalld-docker.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED_TESTS=0
TOTAL_TESTS=0

run_test() {
    local test_name="$1"
    shift
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -ne "  - [TEST ${TOTAL_TESTS}] ${test_name} ... "
    if "$@"; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}FAILED${NC}"
    fi
}

echo -e "${CYAN}${BOLD}======================================================${NC}"
echo -e "${CYAN}${BOLD}   Starting firewalld-docker Automated Test Suite     ${NC}"
echo -e "${CYAN}${BOLD}======================================================${NC}"

# 1. Syntax Check
test_syntax() {
    bash -n "${TARGET_SCRIPT}"
}
run_test "Bash syntax validation (bash -n)" test_syntax

# 2. Main Help Flag Tests
test_main_help() {
    "${TARGET_SCRIPT}" --help | grep -q "Docker Firewall Manager"
    "${TARGET_SCRIPT}" -h | grep -q "Available Commands:"
    "${TARGET_SCRIPT}" help | grep -q "Usage:"
}
run_test "Main help flags (--help, -h, help)" test_main_help

# 3. Subcommand Help Tests
test_subcommand_helps() {
    "${TARGET_SCRIPT}" init --help | grep -q "Initialize DOCKER-USER"
    "${TARGET_SCRIPT}" add --help | grep -q "Add an IPv4 host address"
    "${TARGET_SCRIPT}" del --help | grep -q "Remove an IPv4 host address"
    "${TARGET_SCRIPT}" list --help | grep -q "List registered IP"
    "${TARGET_SCRIPT}" status --help | grep -q "Display Firewalld Direct Rules"
    "${TARGET_SCRIPT}" reset --help | grep -q "Emergency reset command"
    "${TARGET_SCRIPT}" help init | grep -q "Initialize DOCKER-USER"
    "${TARGET_SCRIPT}" help add | grep -q "Add an IPv4 host address"
    "${TARGET_SCRIPT}" help del | grep -q "Remove an IPv4 host address"
    "${TARGET_SCRIPT}" help list | grep -q "List registered IP"
    "${TARGET_SCRIPT}" help status | grep -q "Display Firewalld Direct Rules"
    "${TARGET_SCRIPT}" help reset | grep -q "Emergency reset command"
}
run_test "Subcommand help outputs (init, add, del, list, status, reset)" test_subcommand_helps

# 4. Argument Validation Tests (Missing arguments should return non-zero)
test_argument_validation() {
    set +e
    "${TARGET_SCRIPT}" add 2>/dev/null
    local exit_add=$?
    "${TARGET_SCRIPT}" del 2>/dev/null
    local exit_del=$?
    "${TARGET_SCRIPT}" invalid_subcommand 2>/dev/null
    local exit_invalid=$?
    set -e

    [[ $exit_add -ne 0 && $exit_del -ne 0 && $exit_invalid -ne 0 ]]
}
run_test "Argument validation on missing/invalid arguments" test_argument_validation

# 5. Mocked Firewalld & Iptables Execution Tests
test_mocked_operations() {
    local MOCK_DIR
    MOCK_DIR="$(mktemp -d)"
    local MOCK_LOG="${MOCK_DIR}/mock.log"
    local IPSET_DATA_DIR="${MOCK_DIR}/ipsets"
    mkdir -p "${IPSET_DATA_DIR}"

    # Create mock firewall-cmd
    cat << 'MOCK_FIREWALL_CMD' > "${MOCK_DIR}/firewall-cmd"
#!/usr/bin/env bash
LOG_FILE="${MOCK_DIR}/mock.log"
echo "firewall-cmd $*" >> "${LOG_FILE}"

if [[ "$*" =~ --get-ipsets ]]; then
    ls -1 "${MOCK_DIR}/ipsets" 2>/dev/null || true
    exit 0
fi

if [[ "$*" =~ --new-ipset=([^ ]+) ]]; then
    ipset_name="${BASH_REMATCH[1]}"
    touch "${MOCK_DIR}/ipsets/${ipset_name}"
    exit 0
fi

if [[ "$*" =~ --ipset=([^ ]+)\ --add-entry=([^ ]+) ]]; then
    ipset_name="${BASH_REMATCH[1]}"
    ip="${BASH_REMATCH[2]}"
    touch "${MOCK_DIR}/ipsets/${ipset_name}"
    echo "$ip" >> "${MOCK_DIR}/ipsets/${ipset_name}"
    exit 0
fi

if [[ "$*" =~ --ipset=([^ ]+)\ --remove-entry=([^ ]+) ]]; then
    ipset_name="${BASH_REMATCH[1]}"
    ip="${BASH_REMATCH[2]}"
    if [[ -f "${MOCK_DIR}/ipsets/${ipset_name}" ]]; then
        sed -i "/^${ip}$/d" "${MOCK_DIR}/ipsets/${ipset_name}"
    fi
    exit 0
fi

if [[ "$*" =~ --ipset=([^ ]+)\ --get-entries ]]; then
    ipset_name="${BASH_REMATCH[1]}"
    if [[ -f "${MOCK_DIR}/ipsets/${ipset_name}" ]]; then
        cat "${MOCK_DIR}/ipsets/${ipset_name}"
    fi
    exit 0
fi

if [[ "$*" =~ --direct\ --get-all-rules ]]; then
    echo "ipv4 filter DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    echo "ipv4 filter DOCKER-USER 10 -p tcp -m multiport --dports 80,443 -j ACCEPT"
    exit 0
fi

exit 0
MOCK_FIREWALL_CMD
    chmod +x "${MOCK_DIR}/firewall-cmd"

    # Create mock iptables
    cat << 'MOCK_IPTABLES' > "${MOCK_DIR}/iptables"
#!/usr/bin/env bash
echo "iptables $*" >> "${MOCK_DIR}/mock.log"
echo "Chain DOCKER-USER (1 references)"
echo "num   pkts bytes target     prot opt in     out     source               destination"
echo "1        0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED"
exit 0
MOCK_IPTABLES
    chmod +x "${MOCK_DIR}/iptables"

    # Run tests using mock environment (simulate EUID=0 by overriding check_root or executing with mocked path)
    # We can pass MOCK_DIR in PATH
    (
        export PATH="${MOCK_DIR}:${PATH}"
        export MOCK_DIR
        # Run test commands
        # To bypass check_root in non-root test environments, we can mock EUID or use a subshell wrapper
        sed 's/check_root() {/check_root() { return 0; /g' "${TARGET_SCRIPT}" > "${MOCK_DIR}/tested_script.sh"
        chmod +x "${MOCK_DIR}/tested_script.sh"

        # 5.1 Init
        "${MOCK_DIR}/tested_script.sh" init >/dev/null

        # 5.2 Add syslog IP
        "${MOCK_DIR}/tested_script.sh" add syslog 10.10.10.50 >/dev/null
        # 5.3 Add snmp IP
        "${MOCK_DIR}/tested_script.sh" add snmp 10.20.20.0/24 >/dev/null

        # 5.4 List
        local list_syslog
        list_syslog="$("${MOCK_DIR}/tested_script.sh" list syslog)"
        echo "$list_syslog" | grep -q "10.10.10.50"

        local list_snmp
        list_snmp="$("${MOCK_DIR}/tested_script.sh" list snmp)"
        echo "$list_snmp" | grep -q "10.20.20.0/24"

        # 5.5 Delete IP
        "${MOCK_DIR}/tested_script.sh" del syslog 10.10.10.50 >/dev/null
        list_syslog="$("${MOCK_DIR}/tested_script.sh" list syslog)"
        if echo "$list_syslog" | grep -q "10.10.10.50"; then
            exit 1
        fi

        # 5.6 Status
        local status_out
        status_out="$("${MOCK_DIR}/tested_script.sh" status)"
        echo "$status_out" | grep -q "DOCKER-USER"
    )
    local result=$?
    rm -rf "${MOCK_DIR}"
    return $result
}
run_test "Mocked Firewalld & IPSet operations (init, add, del, list, status)" test_mocked_operations

echo -e "\n${BOLD}Test Summary:${NC} ${GREEN}${PASSED_TESTS}${NC} / ${BOLD}${TOTAL_TESTS}${NC} tests passed."

if [[ $PASSED_TESTS -eq $TOTAL_TESTS ]]; then
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED SUCCESSFULLY!${NC}\n"
    exit 0
else
    echo -e "${RED}${BOLD}SOME TESTS FAILED!${NC}\n"
    exit 1
fi
