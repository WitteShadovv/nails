#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  NAILS E2E Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_NAME]"
    echo ""
    echo "Run NAILS E2E tests locally with colored output."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo "  -i, --interactive  Run interactive test driver for debugging"
    echo ""
    echo "Arguments:"
    echo "  TEST_NAME           Run specific test (basic-workflow, verify, emergency, forensic-clean, snapshot-diff, performance, ci)"
    echo ""
    echo "Available tests:"
    echo "  basic-workflow      Basic activate/deactivate workflow test"
    echo "  verify              Verify command contract test"
    echo "  emergency           Emergency deactivation <3s test"
    echo "  forensic-clean      Forensic cleanliness validation test"
    echo "  snapshot-diff       Snapshot comparison test"
    echo "  performance         Performance validation test"
    echo "  ci                  CI smoke suite (basic-workflow, verify, emergency)"
    echo ""
    echo "If no test name is provided, all tests are run."
    echo ""
    echo "Examples:"
    echo "  $0                  # Run all E2E tests"
    echo "  $0 basic-workflow   # Run basic workflow test only"
    echo "  $0 -i              # Launch interactive test driver"
    echo ""
}

run_all_tests() {
    print_header
    echo -e "${YELLOW}Running all E2E tests...${NC}"
    echo ""

    cd "$PROJECT_ROOT"

    if nix build .#checks.x86_64-linux.e2e-all --no-link -L; then
        echo -e "\n${GREEN}✓ All E2E tests PASSED${NC}\n"
        return 0
    else
        echo -e "\n${RED}✗ Some E2E tests FAILED${NC}\n"
        return 1
    fi
}

run_single_test() {
    local test_name="$1"
    print_header
    echo -e "${YELLOW}Running E2E test: $test_name${NC}"
    echo ""

    cd "$PROJECT_ROOT"

    if [ "$test_name" = "ci" ]; then
        target=".#checks.x86_64-linux.e2e-ci"
    else
        target=".#checks.x86_64-linux.e2e-$test_name"
    fi

    if nix build "$target" --no-link -L; then
        echo -e "\n${GREEN}✓ Test '$test_name' PASSED${NC}\n"
        return 0
    else
        echo -e "\n${RED}✗ Test '$test_name' FAILED${NC}\n"
        return 1
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
TEST_NAME=""
INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
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
            TEST_NAME="$1"
            shift
            ;;
    esac
done

# Execute
if [ "$INTERACTIVE" = true ]; then
    run_interactive "$TEST_NAME"
elif [ -n "$TEST_NAME" ]; then
    run_single_test "$TEST_NAME"
else
    run_all_tests
fi
