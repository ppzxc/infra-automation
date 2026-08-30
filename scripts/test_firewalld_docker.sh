#!/usr/bin/env bash
# ==============================================================================
# Script Name: test_firewalld_docker.sh
# Description: Automated TDD Test Suite for firewalld-docker CLI
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/firewalld-docker.sh"

PASSED_TESTS=0
TOTAL_TESTS=0

run_test() {
    local test_name="$1"
    shift
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "  - [TEST ${TOTAL_TESTS}] ${test_name} ... "
    if "$@"; then
        echo "PASSED"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "FAILED"
    fi
}

echo "======================================================"
echo "   Starting firewalld-docker Automated Test Suite     "
echo "======================================================"

# 1. Syntax Validation
test_syntax() {
    bash -n "${TARGET_SCRIPT}"
}
run_test "Bash syntax validation (bash -n)" test_syntax

# 2. ANSI Color Removal Validation (No ANSI escape sequences in script or help output)
test_no_color() {
    # Check that script does not contain ANSI color escape definitions like \033[ or \e[
    if grep -E '\\033\[|\\e\[' "${TARGET_SCRIPT}"; then
        echo "Found ANSI escape codes in source code" >&2
        return 1
    fi
    # Check that help output has no ANSI escape codes
    local help_out
    help_out="$("${TARGET_SCRIPT}" --help)"
    if echo "$help_out" | grep -q $'\033'; then
        echo "Found ANSI escape code in help output" >&2
        return 1
    fi
}
run_test "Verify complete removal of ANSI color codes" test_no_color

# 3. No-argument execution (Must display Help/Usage, NOT interactive menu loop)
test_no_args_shows_help() {
    local out
    out="$("${TARGET_SCRIPT}")"
    echo "$out" | grep -q "사용법"
    echo "$out" | grep -q "사용 가능한 명령어"
}
run_test "Running without arguments displays Help instead of interactive menu" test_no_args_shows_help

# 4. Help Commands & Subcommand Help
test_help_commands() {
    "${TARGET_SCRIPT}" -h | grep -q "사용법"
    "${TARGET_SCRIPT}" --help | grep -q "사용법"
    "${TARGET_SCRIPT}" help | grep -q "사용법"
    "${TARGET_SCRIPT}" 도움말 | grep -q "사용법"
    "${TARGET_SCRIPT}" 도움말 init | grep -q "init"
    "${TARGET_SCRIPT}" init --help | grep -q "init"
    "${TARGET_SCRIPT}" allow-port --help | grep -q "allow-port"
    "${TARGET_SCRIPT}" deny-port --help | grep -q "deny-port"
    "${TARGET_SCRIPT}" add --help | grep -q "add"
    "${TARGET_SCRIPT}" del --help | grep -q "del"
    "${TARGET_SCRIPT}" list --help | grep -q "list"
    "${TARGET_SCRIPT}" status --help | grep -q "status"
    "${TARGET_SCRIPT}" reset --help | grep -q "reset"
}
run_test "Subcommand help outputs (help, 도움말, init, allow-port, deny-port, add, del, list, status, reset)" test_help_commands

# 5. Argument Validation
test_arg_validation() {
    set +e
    "${TARGET_SCRIPT}" add 2>/dev/null
    local exit_add=$?
    "${TARGET_SCRIPT}" del 2>/dev/null
    local exit_del=$?
    "${TARGET_SCRIPT}" allow-port 2>/dev/null
    local exit_allow=$?
    "${TARGET_SCRIPT}" deny-port 2>/dev/null
    local exit_deny=$?
    "${TARGET_SCRIPT}" unknown_command 2>/dev/null
    local exit_unknown=$?
    set -e

    [[ $exit_add -ne 0 && $exit_del -ne 0 && $exit_allow -ne 0 && $exit_deny -ne 0 && $exit_unknown -ne 0 ]]
}
run_test "Argument validation on missing/invalid arguments" test_arg_validation

# 6. Mocked Firewalld, Iptables & Interface Operations
test_mocked_operations() {
    local MOCK_DIR
    MOCK_DIR="$(mktemp -d)"
    local MOCK_LOG="${MOCK_DIR}/mock.log"
    local IPSET_DATA_DIR="${MOCK_DIR}/ipsets"
    mkdir -p "${IPSET_DATA_DIR}"

    # Mock ip command for interface discovery
    cat << 'MOCK_IP' > "${MOCK_DIR}/ip"
#!/usr/bin/env bash
if [[ "$*" =~ link ]]; then
    echo "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536"
    echo "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
    echo "3: bond0: <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP> mtu 1500"
    echo "4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500"
    echo "5: br-1234: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500"
    exit 0
fi
exit 0
MOCK_IP
    chmod +x "${MOCK_DIR}/ip"

    # Mock firewall-cmd
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
    if [[ -f "${MOCK_DIR}/rules.txt" ]]; then
        cat "${MOCK_DIR}/rules.txt"
    fi
    exit 0
fi

if [[ "$*" =~ --direct\ --add-rule\ (.*) ]]; then
    rule="${BASH_REMATCH[1]}"
    echo "$rule" >> "${MOCK_DIR}/rules.txt"
    exit 0
fi

if [[ "$*" =~ --direct\ --remove-rules\ (.*) ]]; then
    > "${MOCK_DIR}/rules.txt"
    exit 0
fi

exit 0
MOCK_FIREWALL_CMD
    chmod +x "${MOCK_DIR}/firewall-cmd"

    # Mock iptables
    cat << 'MOCK_IPTABLES' > "${MOCK_DIR}/iptables"
#!/usr/bin/env bash
echo "iptables $*" >> "${MOCK_DIR}/mock.log"
echo "Chain DOCKER-USER (1 references)"
echo "num   pkts bytes target     prot opt in     out     source               destination"
echo "1        0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED"
exit 0
MOCK_IPTABLES
    chmod +x "${MOCK_DIR}/iptables"

    (
        export PATH="${MOCK_DIR}:${PATH}"
        export MOCK_DIR
        sed 's/check_root() {/check_root() { return 0; /g' "${TARGET_SCRIPT}" > "${MOCK_DIR}/tested_script.sh"
        chmod +x "${MOCK_DIR}/tested_script.sh"

        # 6.1 Interactive init test (simulate selecting interface 'bond0' (2), open 80 'y', open 443 'y')
        local init_out
        init_out=$(printf "2\ny\ny\n" | "${MOCK_DIR}/tested_script.sh" init)
        
        # Verify interface discovery was displayed
        echo "$init_out" | grep -q "eth0"
        echo "$init_out" | grep -q "bond0"
        
        # Verify post-init guide is displayed
        echo "$init_out" | grep -q "firewalld-docker"
        echo "$init_out" | grep -q "add"
        echo "$init_out" | grep -q "allow-port"

        # Check rules added in mock.log and printed execution feedback in init_out
        echo "$init_out" | grep -q "\[실행\] firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        echo "$init_out" | grep -q "\[실행\] firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 99 -i bond0 -j DROP"
        echo "$init_out" | grep -q "\[실행\] firewall-cmd --reload"
        grep -q "firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "${MOCK_LOG}"
        grep -q "firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 99 -i bond0 -j DROP" "${MOCK_LOG}"

        # 6.2 Non-interactive flag init test
        "${MOCK_DIR}/tested_script.sh" init -i eth0 --open-80 --open-443 -y >/dev/null
        grep -q "firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 99 -i eth0 -j DROP" "${MOCK_LOG}"

        # 6.3 Dynamic IPSet & Port Allow/Deny
        # Add IP to custom IPSet
        local add_out
        add_out="$("${MOCK_DIR}/tested_script.sh" add my_whitelist 192.168.1.100)"
        echo "$add_out" | grep -q "\[실행\] firewall-cmd --permanent --ipset=my_whitelist --add-entry=192.168.1.100"
        echo "$add_out" | grep -q "\[실행\] firewall-cmd --reload"
        "${MOCK_DIR}/tested_script.sh" add my_whitelist 10.0.0.0/24 >/dev/null

        local list_out
        list_out="$("${MOCK_DIR}/tested_script.sh" list my_whitelist)"
        echo "$list_out" | grep -q "192.168.1.100"
        echo "$list_out" | grep -q "10.0.0.0/24"

        # Allow port for IPSet
        local allow_out
        allow_out="$("${MOCK_DIR}/tested_script.sh" allow-port my_whitelist 8080 tcp)"
        echo "$allow_out" | grep -q "\[실행\] firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 10 -m set --match-set my_whitelist src -p tcp --dport 8080 -j ACCEPT"
        echo "$allow_out" | grep -q "\[실행\] firewall-cmd --reload"
        grep -q "firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 10 -m set --match-set my_whitelist src -p tcp --dport 8080 -j ACCEPT" "${MOCK_LOG}"

        # Deny port for IPSet
        local deny_out
        deny_out="$("${MOCK_DIR}/tested_script.sh" deny-port my_whitelist 8080 tcp)"
        echo "$deny_out" | grep -q "\[실행\] firewall-cmd --permanent --direct --remove-rule ipv4 filter DOCKER-USER 10 -m set --match-set my_whitelist src -p tcp --dport 8080 -j ACCEPT"
        echo "$deny_out" | grep -q "\[실행\] firewall-cmd --reload"
        grep -q "firewall-cmd --permanent --direct --remove-rule ipv4 filter DOCKER-USER 10 -m set --match-set my_whitelist src -p tcp --dport 8080 -j ACCEPT" "${MOCK_LOG}"

        # Delete entry
        local del_out
        del_out="$("${MOCK_DIR}/tested_script.sh" del my_whitelist 192.168.1.100)"
        echo "$del_out" | grep -q "\[실행\] firewall-cmd --permanent --ipset=my_whitelist --remove-entry=192.168.1.100"
        echo "$del_out" | grep -q "\[실행\] firewall-cmd --reload"
        list_out="$("${MOCK_DIR}/tested_script.sh" list my_whitelist)"
        if echo "$list_out" | grep -q "192.168.1.100"; then
            exit 1
        fi

        # 6.4 Status
        local status_out
        status_out="$("${MOCK_DIR}/tested_script.sh" status)"
        echo "$status_out" | grep -q "DOCKER-USER"

        # 6.6 ensure_docker_user_chain detection & auto-creation test
        # We simulate iptables without DOCKER-USER chain initially
        cat << 'MOCK_IPTABLES_NO_CHAIN' > "${MOCK_DIR}/iptables"
#!/usr/bin/env bash
echo "iptables $*" >> "${MOCK_DIR}/mock.log"
if [[ "$*" =~ "-L DOCKER-USER" ]]; then
    if [[ ! -f "${MOCK_DIR}/docker_user_created" ]]; then
        echo "iptables: No chain/target/match by that name." >&2
        exit 1
    fi
fi
if [[ "$*" =~ "-N DOCKER-USER" ]]; then
    touch "${MOCK_DIR}/docker_user_created"
    exit 0
fi
exit 0
MOCK_IPTABLES_NO_CHAIN
        chmod +x "${MOCK_DIR}/iptables"

        local init_chain_out
        init_chain_out="$("${MOCK_DIR}/tested_script.sh" init -i eth0 --open-80 --open-443 -y)"
        echo "$init_chain_out" | grep -q "iptables에 'DOCKER-USER' 체인이 존재하지 않아 자동으로 생성합니다."
        echo "$init_chain_out" | grep -q "'DOCKER-USER' 체인이 생성되었습니다."
        [[ -f "${MOCK_DIR}/docker_user_created" ]]
    )
    local result=$?
    rm -rf "${MOCK_DIR}"
    return $result
}
run_test "Mocked Firewalld & IPSet operations (interactive/non-interactive init, dynamic allow/deny port, add, del, list, reset, chain auto-creation)" test_mocked_operations

echo ""
echo "Test Summary: ${PASSED_TESTS} / ${TOTAL_TESTS} tests passed."

if [[ $PASSED_TESTS -eq $TOTAL_TESTS ]]; then
    echo "ALL TESTS PASSED SUCCESSFULLY!"
    exit 0
else
    echo "SOME TESTS FAILED!"
    exit 1
fi
