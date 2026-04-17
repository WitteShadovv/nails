#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

AVAILABLE_TESTS=()
SYSTEM="${NAILS_E2E_SYSTEM:-$(nix eval --impure --raw --expr builtins.currentSystem)}"

describe_test() {
    case "$1" in
        basic-workflow) printf '%s' 'Basic activate/deactivate workflow test' ;;
        verify) printf '%s' 'Verify command contract test' ;;
        emergency) printf '%s' 'Functional emergency workflow and cleanup test' ;;
        forensic-clean) printf '%s' 'Forensic cleanliness validation test' ;;
        standard-deactivation-forensic) printf '%s' 'Standard deactivation forensic safety test' ;;
        snapshot-diff) printf '%s' 'Snapshot comparison test' ;;
        config-handling) printf '%s' 'Config edge cases test' ;;
        state-integrity) printf '%s' 'State file integrity test' ;;
        permissions-security) printf '%s' 'Permission and path security test' ;;
        reactivation) printf '%s' 'Re-activation workflow test' ;;
        status-verify) printf '%s' 'Status and verify command coverage test' ;;
        ci) printf '%s' 'CI smoke suite' ;;
        all) printf '%s' 'All tests' ;;
        smoke|config|forensic|lifecycle|security|performance|preflight|nixos|session|shell|notification|overlay|state|contract)
            printf '%s' "Tag suite: $1"
            ;;
        *) printf '%s' 'Auto-discovered E2E target' ;;
    esac
}

load_available_tests() {
    local names_json
    names_json="$({
        cd "$PROJECT_ROOT"
        nix eval --json ".#e2e-tests.$SYSTEM" --apply 'tests: builtins.filter (name: !(builtins.substring 0 1 name == "_")) (builtins.attrNames tests)'
    })"

    mapfile -t AVAILABLE_TESTS < <(
        python3 - <<'PY' "$names_json"
import json
import sys

for name in json.loads(sys.argv[1]):
    print(name)
PY
    )
}

test_exists() {
    local candidate="$1"
    local test_name

    for test_name in "${AVAILABLE_TESTS[@]}"; do
        if [[ "$test_name" == "$candidate" ]]; then
            return 0
        fi
    done

    return 1
}

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  NAILS E2E Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_NAME...]"
    echo ""
    echo "Run NAILS E2E tests locally with colored output."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo "  -i, --interactive   Run interactive test driver for debugging"
    echo "  -l, --list          List available tests"
    echo "  -v, --verbose       More verbose output"
    echo ""
    echo "Arguments:"
    echo "  TEST_NAME           Run specific test(s) or tag groups by name"
    echo ""
    echo "Use --list to see available tests."
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all E2E tests"
    echo "  $0 basic-workflow           # Run one test"
    echo "  $0 smoke security          # Run tag groups"
    echo "  $0 ci                       # Run CI subset"
    echo "  $0 -i basic-workflow        # Interactive one-test run"
    echo ""
}

list_tests() {
    local name

    echo -e "${BOLD}Available E2E Tests:${NC}"
    echo ""

    for name in "${AVAILABLE_TESTS[@]}"; do
        printf "  ${GREEN}%-35s${NC} %s\n" "$name" "$(describe_test "$name")"
    done

    echo ""
}

run_single_test() {
    local test_name="$1"
    local start_time end_time duration target

    if ! test_exists "$test_name"; then
        echo -e "${RED}Unknown E2E target: $test_name${NC}" >&2
        return 1
    fi

    target=".#checks.$SYSTEM.e2e-$test_name"

    echo -e "${YELLOW}Running: $test_name${NC}"
    start_time=$(date +%s)

    local nix_args=(build "$target" --no-link)
    if [ "$VERBOSE" = true ]; then
        nix_args+=(-L)
    fi

    if nix "${nix_args[@]}"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}  PASS${NC} $test_name (${duration}s)"
        return 0
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${RED}  FAIL${NC} $test_name (${duration}s)"
        return 1
    fi
}

run_tests() {
    local tests=("$@")
    local pass=0
    local fail=0
    local failed_tests=()
    local total_start total_end total_duration
    local test_name

    print_header
    echo -e "${YELLOW}Running ${#tests[@]} test(s)...${NC}"
    echo ""

    cd "$PROJECT_ROOT"
    total_start=$(date +%s)

    for test_name in "${tests[@]}"; do
        if run_single_test "$test_name"; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            failed_tests+=("$test_name")
        fi
    done

    total_end=$(date +%s)
    total_duration=$((total_end - total_start))

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Total:  ${#tests[@]}"
    echo -e "  ${GREEN}Passed: $pass${NC}"
    if [ "$fail" -gt 0 ]; then
        echo -e "  ${RED}Failed: $fail${NC}"
        echo -e "  ${RED}Failed tests: ${failed_tests[*]}${NC}"
    else
        echo -e "  Failed: 0"
    fi
    echo -e "  Time:   ${total_duration}s"
    echo ""

    if [ "$fail" -gt 0 ]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        return 0
    fi
}

run_interactive() {
    local test_name="${1:-}"

    print_header
    echo -e "${YELLOW}Launching interactive test driver...${NC}"
    echo -e "${BLUE}Use 'exit' to quit the VM${NC}\n"

    cd "$PROJECT_ROOT"

    if [ -n "$test_name" ]; then
        if ! test_exists "$test_name"; then
            echo -e "${RED}Unknown E2E target: $test_name${NC}" >&2
            exit 1
        fi
        echo "Running interactive test for: $test_name"
        nix run ".#checks.$SYSTEM.e2e-$test_name" --interactive
    else
        echo "Running default interactive test driver"
        nix run ".#apps.$SYSTEM.e2e-test-interactive"
    fi
}

# Parse arguments
TEST_NAMES=()
INTERACTIVE=false
VERBOSE=false

load_available_tests

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -l|--list)
            list_tests
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -i|--interactive)
            INTERACTIVE=true
            shift
            ;;
        -*)
            echo -e "${RED}Error: Unknown option: $1${NC}" >&2
            print_usage
            exit 1
            ;;
        *)
            TEST_NAMES+=("$1")
            shift
            ;;
    esac
done

if [ "$INTERACTIVE" = true ]; then
    run_interactive "${TEST_NAMES[0]:-}"
elif [ "${#TEST_NAMES[@]}" -gt 0 ]; then
    run_tests "${TEST_NAMES[@]}"
else
    run_tests "all"
fi
