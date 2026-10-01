#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    printf '%s\n' "This script requires bash 4 or newer." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
E2E_SHARD_DURATION_WEIGHTS_FILE="$PROJECT_ROOT/nix/e2e-tests/shard-durations.json"
E2E_SHARD_WEIGHTS_TOOL="$SCRIPT_DIR/e2e_shard_weights.py"
# The flake builds its VM tests for x86_64-linux only. The full attribute path
# also works from other hosts that have an x86_64-linux builder.
E2E_FLAKE_PREFIX=".#legacyPackages.x86_64-linux"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

AVAILABLE_TARGETS=()
LEAF_TESTS=()
INTERACTIVE=false
VERBOSE=false
DRY_RUN=false
SHARD_INDEX=""
SHARD_COUNT=""
DURATIONS_OUT=""
E2E_METADATA_JSON=""

describe_target() {
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
        ci) printf '%s' 'CI critical regression suite' ;;
        all) printf '%s' 'All tests' ;;
        smoke|config|forensic|lifecycle|init|security|performance|preflight|nixos|session|shell|notification|overlay|state|contract)
            printf '%s' "Tag suite: $1"
            ;;
        *) printf '%s' 'Auto-discovered E2E target' ;;
    esac
}

load_e2e_metadata() {
    local metadata_json

    metadata_json="$({
        cd "$PROJECT_ROOT"
        nix eval --json "$E2E_FLAKE_PREFIX.e2e-metadata"
    })"

    mapfile -t AVAILABLE_TARGETS < <(
        python3 - <<'PY' "$metadata_json"
import json
import sys

payload = json.loads(sys.argv[1])
for name in payload["availableTargets"]:
    print(name)
PY
    )

    mapfile -t LEAF_TESTS < <(
        python3 - <<'PY' "$metadata_json"
import json
import sys

payload = json.loads(sys.argv[1])
for name in payload["leafTests"]:
    print(name)
PY
    )

    E2E_METADATA_JSON="$metadata_json"
}

leaf_test_exists() {
    local candidate="$1"
    local test_name

    for test_name in "${LEAF_TESTS[@]}"; do
        if [[ "$test_name" == "$candidate" ]]; then
            return 0
        fi
    done

    return 1
}

resolve_targets() {
    python3 - <<'PY' "$E2E_METADATA_JSON" "$@"
import json
import sys

payload = json.loads(sys.argv[1])
requested = sys.argv[2:]
leaf_tests = set(payload["leafTests"])
groups = payload["groups"]
seen = set()
resolved = []

for name in requested:
    if name in leaf_tests:
        members = [name]
    elif name in groups:
        members = groups[name]
    else:
        print(f"Unknown E2E target: {name}", file=sys.stderr)
        sys.exit(1)

    for member in members:
        if member not in leaf_tests:
            print(
                f"E2E metadata error: target {name} resolved to unknown leaf test {member}",
                file=sys.stderr,
            )
            sys.exit(1)
        if member not in seen:
            seen.add(member)
            resolved.append(member)

for member in resolved:
    print(member)
PY
}

default_target() {
    if [[ -n "${NAILS_E2E_DEFAULT_TARGET:-}" ]]; then
        printf '%s\n' "$NAILS_E2E_DEFAULT_TARGET"
    elif [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
        printf '%s\n' "ci"
    else
        printf '%s\n' "all"
    fi
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
    echo "  -h, --help              Show this help message and exit"
    echo "  -i, --interactive       Start the interactive driver of one leaf test"
    echo "  -l, --list              List available tests"
    echo "  -v, --verbose           More verbose output"
    echo "      --dry-run           Print final resolved leaf tests without running"
    echo "      --resolve-only      Alias for --dry-run"
    echo "      --shard-index N     Run only shard N (1-based) of the resolved tests"
    echo "      --shard-count N     Total number of deterministic shards"
    echo "      --durations-out FILE"
    echo "                          Write one JSON line per test (test, result,"
    echo "                          seconds) to FILE, replacing its contents"
    echo ""
    echo "Arguments:"
    echo "  TEST_NAME               Run specific test(s), tag groups, or suite targets"
    echo ""
    echo "Default target: override with NAILS_E2E_DEFAULT_TARGET; CI defaults to 'ci', local defaults to 'all'."
    echo "Use --list to see available tests."
    echo ""
    echo "Examples:"
    echo "  $0                          # Run default target"
    echo "  $0 basic-workflow           # Run one test"
    echo "  $0 smoke security          # Expand groups and run sequentially"
    echo "  $0 ci                       # Expand CI suite and run leaf tests"
    echo "  $0 --dry-run all           # Print resolved leaf tests"
    echo "  $0 --shard-index 2 --shard-count 4 all"
    echo "  $0 -i basic-workflow        # Interactive one-test run"
    echo ""
}

option_requires_value() {
    local option_name="$1"
    local option_value="${2:-}"

    if [[ -z "$option_value" || "$option_value" == -* ]]; then
        echo -e "${RED}Error: $option_name requires a value${NC}" >&2
        print_usage
        exit 1
    fi
}

validate_shard_configuration() {
    if [[ -z "$SHARD_INDEX" && -z "$SHARD_COUNT" ]]; then
        return 0
    fi

    if [[ -z "$SHARD_INDEX" || -z "$SHARD_COUNT" ]]; then
        echo -e "${RED}Error: --shard-index and --shard-count must be provided together${NC}" >&2
        exit 1
    fi

    if ! [[ "$SHARD_INDEX" =~ ^[1-9][0-9]*$ ]]; then
        echo -e "${RED}Error: --shard-index must be a positive integer${NC}" >&2
        exit 1
    fi

    if ! [[ "$SHARD_COUNT" =~ ^[1-9][0-9]*$ ]]; then
        echo -e "${RED}Error: --shard-count must be a positive integer${NC}" >&2
        exit 1
    fi

    if (( SHARD_INDEX > SHARD_COUNT )); then
        echo -e "${RED}Error: --shard-index must be less than or equal to --shard-count${NC}" >&2
        exit 1
    fi
}

list_tests() {
    local name

    echo -e "${BOLD}Available E2E Targets:${NC}"
    echo ""

    for name in "${AVAILABLE_TARGETS[@]}"; do
        printf "  ${GREEN}%-35s${NC} %s\n" "$name" "$(describe_target "$name")"
    done

    echo ""
}

print_resolved_tests() {
    local tests=("$@")
    local test_name

    for test_name in "${tests[@]}"; do
        printf '%s\n' "$test_name"
    done
}

select_shard_tests() {
    local tests=("$@")

    if [[ -z "$SHARD_INDEX" || -z "$SHARD_COUNT" ]]; then
        print_resolved_tests "${tests[@]}"
        return 0
    fi

    # The planner refuses weights at or above a test's timeout, so the
    # metadata (which carries the timeouts) is passed in alongside them.
    python3 "$E2E_SHARD_WEIGHTS_TOOL" plan \
        --shard-index "$SHARD_INDEX" \
        --shard-count "$SHARD_COUNT" \
        --weights "$E2E_SHARD_DURATION_WEIGHTS_FILE" \
        --metadata - \
        -- "${tests[@]}" <<<"$E2E_METADATA_JSON"
}

prepare_durations_out() {
    local durations_dir

    [[ -n "$DURATIONS_OUT" ]] || return 0

    durations_dir="$(dirname "$DURATIONS_OUT")"
    mkdir -p "$durations_dir"
    # Absolute, because run_tests changes into the project root.
    DURATIONS_OUT="$(cd "$durations_dir" && pwd)/$(basename "$DURATIONS_OUT")"
    : >"$DURATIONS_OUT"
}

# Written right after each test so the record survives a shard that is
# later killed by its timeout.
record_duration() {
    local test_name="$1"
    local result="$2"
    local seconds="$3"

    [[ -n "$DURATIONS_OUT" ]] || return 0

    python3 -c 'import json, sys; print(json.dumps({"test": sys.argv[1], "result": sys.argv[2], "seconds": int(sys.argv[3])}))' \
        "$test_name" "$result" "$seconds" >>"$DURATIONS_OUT"
}

run_single_test() {
    local test_name="$1"
    local start_time end_time duration target

    if ! leaf_test_exists "$test_name"; then
        echo -e "${RED}Unknown leaf E2E test: $test_name${NC}" >&2
        return 1
    fi

    target="$E2E_FLAKE_PREFIX.e2e.$test_name"

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
        record_duration "$test_name" pass "$duration"
        return 0
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${RED}  FAIL${NC} $test_name (${duration}s)"
        record_duration "$test_name" fail "$duration"
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
    echo -e "${YELLOW}Running ${#tests[@]} resolved leaf test(s)...${NC}"
    if [[ -n "$SHARD_INDEX" && -n "$SHARD_COUNT" ]]; then
        echo -e "${YELLOW}Shard ${SHARD_INDEX}/${SHARD_COUNT} selected deterministically by resolved test order.${NC}"
    fi
    echo ""

    prepare_durations_out
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
    local test_name="$1"
    local members
    local member_list=()

    if ! leaf_test_exists "$test_name"; then
        if members="$(resolve_targets "$test_name" 2>/dev/null)"; then
            if [[ -n "$members" ]]; then
                mapfile -t member_list <<<"$members"
            fi
            echo -e "${RED}Error: $test_name is a group of ${#member_list[@]} tests; --interactive needs one leaf test (list them with --dry-run $test_name)${NC}" >&2
        else
            echo -e "${RED}Unknown leaf E2E test: $test_name${NC}" >&2
        fi
        exit 1
    fi

    print_header
    echo -e "${YELLOW}Launching the interactive driver for $test_name...${NC}"
    echo -e "${BLUE}start_all() boots the VMs, test_script() runs the test, Ctrl-D quits.${NC}\n"

    cd "$PROJECT_ROOT"
    exec nix run "$E2E_FLAKE_PREFIX.e2e.$test_name.driverInteractive"
}

TEST_NAMES=()

load_e2e_metadata

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
        --dry-run|--resolve-only)
            DRY_RUN=true
            shift
            ;;
        --shard-index)
            option_requires_value "$1" "${2:-}"
            SHARD_INDEX="$2"
            shift 2
            ;;
        --shard-count)
            option_requires_value "$1" "${2:-}"
            SHARD_COUNT="$2"
            shift 2
            ;;
        --durations-out)
            option_requires_value "$1" "${2:-}"
            DURATIONS_OUT="$2"
            shift 2
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

validate_shard_configuration

if [ "$INTERACTIVE" = true ]; then
    if [[ -n "$SHARD_INDEX" || -n "$SHARD_COUNT" ]]; then
        echo -e "${RED}Error: sharding is not supported with --interactive${NC}" >&2
        exit 1
    fi
    if [ "${#TEST_NAMES[@]}" -ne 1 ]; then
        echo -e "${RED}Error: --interactive takes exactly one leaf test name${NC}" >&2
        exit 1
    fi
    run_interactive "${TEST_NAMES[0]}"
fi

if [ "${#TEST_NAMES[@]}" -eq 0 ]; then
    TEST_NAMES=("$(default_target)")
fi

mapfile -t RESOLVED_TESTS < <(resolve_targets "${TEST_NAMES[@]}")

if [ "${#RESOLVED_TESTS[@]}" -eq 0 ]; then
    echo -e "${RED}No E2E tests resolved from requested targets: ${TEST_NAMES[*]}${NC}" >&2
    exit 1
fi

# A command substitution, unlike a process substitution, lets a planner
# failure stop the run instead of looking like an empty shard.
if ! shard_selection="$(select_shard_tests "${RESOLVED_TESTS[@]}")"; then
    echo -e "${RED}Error: could not select the tests for this run; see the messages above${NC}" >&2
    exit 1
fi

RESOLVED_TESTS=()
if [[ -n "$shard_selection" ]]; then
    mapfile -t RESOLVED_TESTS <<<"$shard_selection"
fi

if [ "${#RESOLVED_TESTS[@]}" -eq 0 ]; then
    if [[ -n "$SHARD_INDEX" && -n "$SHARD_COUNT" ]]; then
        echo -e "${YELLOW}No tests assigned to shard ${SHARD_INDEX}/${SHARD_COUNT}; nothing to run.${NC}"
        exit 0
    fi

    echo -e "${RED}No E2E tests resolved from requested targets after sharding: ${TEST_NAMES[*]}${NC}" >&2
    exit 1
fi

if [ "$DRY_RUN" = true ]; then
    print_resolved_tests "${RESOLVED_TESTS[@]}"
else
    run_tests "${RESOLVED_TESTS[@]}"
fi
