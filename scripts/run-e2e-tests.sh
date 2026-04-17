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

# Available tests
AVAILABLE_TESTS=(
    "basic-workflow:Basic activate/deactivate workflow test"
    "verify:Verify command contract test"
    "emergency:Functional emergency workflow and cleanup test"
    "forensic-clean:Forensic cleanliness validation test"
    "standard-deactivation-forensic:Standard deactivation forensic safety test"
    "snapshot-diff:Snapshot comparison test"
    "performance:Performance validation test, including emergency timing"
    "config-handling:Config edge cases test"
    "state-integrity:State file integrity test"
    "permissions-security:Permission and path security test"
    "reactivation:Re-activation workflow test"
    "status-verify:Status and verify command coverage test"
    "ci:CI smoke suite (basic-workflow, verify, emergency, config-handling, status-verify)"
    "all:All tests"
)

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
    echo "  TEST_NAME           Run specific test(s) by name (can specify multiple)"
    echo ""
    echo "Use --list to see available tests."
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all E2E tests"
    echo "  $0 basic-workflow           # Run basic workflow test only"
    echo "  $0 basic-workflow verify    # Run two tests"
    echo "  $0 ci                       # Run CI smoke suite"
    echo "  $0 -l                       # List available tests"
    echo "  $0 -i                       # Launch interactive test driver"
    echo ""
}

list_tests() {
    echo -e "${BOLD}Available E2E Tests:${NC}"
    echo ""
    for entry in "${AVAILABLE_TESTS[@]}"; do
        name="${entry%%:*}"
        desc="${entry#*:}"
        printf "  ${GREEN}%-35s${NC} %s\n" "$name" "$desc"
    done
    echo ""
}

run_single_test() {
    local test_name="$1"
    local start_time end_time duration

    if [ "$test_name" = "ci" ]; then
        target=".#checks.x86_64-linux.e2e-ci"
    elif [ "$test_name" = "all" ]; then
        target=".#checks.x86_64-linux.e2e-all"
    else
        target=".#checks.x86_64-linux.e2e-$test_name"
    fi

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
        echo "Running interactive test for: $test_name"
        nix run ".#checks.x86_64-linux.e2e-$test_name" --interactive
    else
        echo "Running default interactive test driver"
        nix run ".#apps.x86_64-linux.e2e-test-interactive"
    fi
}

# Parse arguments
TEST_NAMES=()
INTERACTIVE=false
VERBOSE=false

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

# Execute
if [ "$INTERACTIVE" = true ]; then
    run_interactive "${TEST_NAMES[0]:-}"
elif [ "${#TEST_NAMES[@]}" -gt 0 ]; then
    run_tests "${TEST_NAMES[@]}"
else
    run_tests "all"
fi
