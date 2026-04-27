#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    printf '%s\n' "This script requires bash 4 or newer." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
E2E_SHARD_DURATION_WEIGHTS_FILE="$PROJECT_ROOT/nix/e2e-tests/shard-durations.json"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

AVAILABLE_TARGETS=()
LEAF_TESTS=()
declare -A LEAF_TEST_NODE_COUNTS=()
SYSTEM="${NAILS_E2E_SYSTEM:-$(nix eval --impure --raw --expr builtins.currentSystem)}"
INTERACTIVE=false
VERBOSE=false
DRY_RUN=false
SHARD_INDEX=""
SHARD_COUNT=""
E2E_METADATA_JSON=""
HOST_CPU_COUNT=""
VM_CPU_PLAN_MODE=""
VM_CPU_PLAN_HOST_CORES=""
VM_CPU_PLAN_TARGET_PERCENT=""
VM_CPU_PLAN_RESERVED_CORES=""
VM_CPU_PLAN_MIN_CORES=""
VM_CPU_PLAN_MAX_CORES=""
VM_CPU_PLAN_NODE_COUNT=""
VM_CPU_PLAN_TOTAL_BUDGET=""
VM_CPU_PLAN_PER_VM_CORES=""

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
    local metadata_entry_name metadata_entry_count

    metadata_json="$({
        cd "$PROJECT_ROOT"
        nix eval --json ".#e2e-test-metadata.$SYSTEM"
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

    LEAF_TEST_NODE_COUNTS=()
    while IFS=$'\t' read -r metadata_entry_name metadata_entry_count; do
        [[ -n "$metadata_entry_name" ]] || continue
        LEAF_TEST_NODE_COUNTS["$metadata_entry_name"]="$metadata_entry_count"
    done < <(
        python3 - <<'PY' "$metadata_json"
import json
import sys

payload = json.loads(sys.argv[1])
for name in payload["leafTests"]:
    print(f"{name}\t{payload['nodeCounts'].get(name, 1)}")
PY
    )

    E2E_METADATA_JSON="$metadata_json"
}

leaf_test_node_count() {
    local candidate="$1"

    if [[ -n "${LEAF_TEST_NODE_COUNTS[$candidate]+x}" ]]; then
        printf '%s\n' "${LEAF_TEST_NODE_COUNTS[$candidate]}"
    else
        printf '%s\n' "1"
    fi
}

warn_invalid_env_default() {
    local env_name="$1"
    local env_value="$2"
    local default_value="$3"

    printf '%s\n' "Warning: ignoring invalid ${env_name}=${env_value@Q}; using ${default_value}." >&2
}

positive_integer_from_env_or_default() {
    local env_name="$1"
    local default_value="$2"
    local env_value="${!env_name:-}"

    if [[ -z "$env_value" ]]; then
        printf '%s\n' "$default_value"
        return 0
    fi

    if [[ "$env_value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$env_value"
        return 0
    fi

    warn_invalid_env_default "$env_name" "$env_value" "$default_value"
    printf '%s\n' "$default_value"
}

percentage_from_env_or_default() {
    local env_name="$1"
    local default_value="$2"
    local env_value="${!env_name:-}"

    if [[ -z "$env_value" ]]; then
        printf '%s\n' "$default_value"
        return 0
    fi

    if [[ "$env_value" =~ ^([1-9][0-9]?|100)$ ]]; then
        printf '%s\n' "$env_value"
        return 0
    fi

    warn_invalid_env_default "$env_name" "$env_value" "$default_value"
    printf '%s\n' "$default_value"
}

detect_host_cpu_count() {
    local detected=""

    if [[ -n "$HOST_CPU_COUNT" ]]; then
        printf '%s\n' "$HOST_CPU_COUNT"
        return 0
    fi

    if [[ -n "${NAILS_E2E_HOST_CPU_COUNT_OVERRIDE:-}" ]]; then
        if [[ "${NAILS_E2E_HOST_CPU_COUNT_OVERRIDE}" =~ ^[1-9][0-9]*$ ]]; then
            HOST_CPU_COUNT="$NAILS_E2E_HOST_CPU_COUNT_OVERRIDE"
            printf '%s\n' "$HOST_CPU_COUNT"
            return 0
        fi

        echo -e "${RED}Error: NAILS_E2E_HOST_CPU_COUNT_OVERRIDE must be a positive integer${NC}" >&2
        exit 1
    fi

    if command -v nproc >/dev/null 2>&1; then
        detected="$(nproc)"
    elif command -v getconf >/dev/null 2>&1; then
        detected="$(getconf _NPROCESSORS_ONLN)"
    fi

    if ! [[ "$detected" =~ ^[1-9][0-9]*$ ]]; then
        detected="4"
    fi

    HOST_CPU_COUNT="$detected"
    printf '%s\n' "$HOST_CPU_COUNT"
}

compute_vm_cpu_plan() {
    local node_count="${1:-1}"
    local explicit_vm_cores="${NAILS_E2E_VM_CORES:-}"
    local host_cores target_percent reserved_cores min_cores max_cores
    local percent_budget reserved_budget total_budget per_vm_cores

    # Auto-sizing defaults intentionally use the full visible runner CPU budget
    # unless an explicit reservation override is configured,
    # then divide that budget across all VMs declared by the selected test.
    # Optional overrides:
    #   NAILS_E2E_VM_CORES                Force a fixed per-VM core count
    #   NAILS_E2E_HOST_CPU_COUNT_OVERRIDE Override detected runner CPU count
    #   NAILS_E2E_VM_CPU_TARGET_PERCENT   Default 100
    #   NAILS_E2E_VM_HOST_RESERVED_CORES  Default 0
    #   NAILS_E2E_VM_MIN_CORES            Default 1
    #   NAILS_E2E_VM_MAX_CORES            Default 16

    if ! [[ "$node_count" =~ ^[1-9][0-9]*$ ]]; then
        node_count="1"
    fi

    host_cores="$(detect_host_cpu_count)"

    if [[ -n "$explicit_vm_cores" ]]; then
        if ! [[ "$explicit_vm_cores" =~ ^[1-9][0-9]*$ ]]; then
            echo -e "${RED}Error: NAILS_E2E_VM_CORES must be a positive integer when set${NC}" >&2
            exit 1
        fi

        VM_CPU_PLAN_MODE="override"
        VM_CPU_PLAN_HOST_CORES="$host_cores"
        VM_CPU_PLAN_TARGET_PERCENT="n/a"
        VM_CPU_PLAN_RESERVED_CORES="n/a"
        VM_CPU_PLAN_MIN_CORES="n/a"
        VM_CPU_PLAN_MAX_CORES="n/a"
        VM_CPU_PLAN_NODE_COUNT="$node_count"
        VM_CPU_PLAN_TOTAL_BUDGET="$((explicit_vm_cores * node_count))"
        VM_CPU_PLAN_PER_VM_CORES="$explicit_vm_cores"
        return 0
    fi

    target_percent="$(percentage_from_env_or_default "NAILS_E2E_VM_CPU_TARGET_PERCENT" "100")"
    reserved_cores="$(positive_integer_from_env_or_default "NAILS_E2E_VM_HOST_RESERVED_CORES" "0")"
    min_cores="$(positive_integer_from_env_or_default "NAILS_E2E_VM_MIN_CORES" "1")"
    max_cores="$(positive_integer_from_env_or_default "NAILS_E2E_VM_MAX_CORES" "16")"

    if (( min_cores > max_cores )); then
        warn_invalid_env_default "NAILS_E2E_VM_MIN_CORES/NAILS_E2E_VM_MAX_CORES" "${min_cores}/${max_cores}" "1/${max_cores}"
        min_cores="1"
    fi

    percent_budget=$(( host_cores * target_percent / 100 ))
    if (( percent_budget < 1 )); then
        percent_budget=1
    fi

    reserved_budget=$(( host_cores - reserved_cores ))
    if (( reserved_budget < 1 )); then
        reserved_budget=1
    fi

    total_budget="$percent_budget"
    if (( reserved_budget < total_budget )); then
        total_budget="$reserved_budget"
    fi

    per_vm_cores=$(( total_budget / node_count ))
    if (( per_vm_cores < 1 )); then
        per_vm_cores=1
    fi

    if (( per_vm_cores < min_cores )); then
        per_vm_cores="$min_cores"
    fi

    if (( per_vm_cores > max_cores )); then
        per_vm_cores="$max_cores"
    fi

    if (( per_vm_cores > host_cores )); then
        per_vm_cores="$host_cores"
    fi

    VM_CPU_PLAN_MODE="auto"
    VM_CPU_PLAN_HOST_CORES="$host_cores"
    VM_CPU_PLAN_TARGET_PERCENT="$target_percent"
    VM_CPU_PLAN_RESERVED_CORES="$reserved_cores"
    VM_CPU_PLAN_MIN_CORES="$min_cores"
    VM_CPU_PLAN_MAX_CORES="$max_cores"
    VM_CPU_PLAN_NODE_COUNT="$node_count"
    VM_CPU_PLAN_TOTAL_BUDGET="$total_budget"
    VM_CPU_PLAN_PER_VM_CORES="$per_vm_cores"
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
    echo "  -i, --interactive       Run interactive test driver for debugging"
    echo "  -l, --list              List available tests"
    echo "  -v, --verbose           More verbose output"
    echo "      --dry-run           Print final resolved leaf tests without running"
    echo "      --resolve-only      Alias for --dry-run"
    echo "      --shard-index N     Run only shard N (1-based) of the resolved tests"
    echo "      --shard-count N     Total number of deterministic shards"
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

    python3 - <<'PY' "$SHARD_INDEX" "$SHARD_COUNT" "$E2E_SHARD_DURATION_WEIGHTS_FILE" "${tests[@]}"
import json
import sys
from pathlib import Path

shard_index = int(sys.argv[1])
shard_count = int(sys.argv[2])
weights_path = Path(sys.argv[3])
tests = sys.argv[4:]

weights = None
if weights_path.is_file():
    weights = json.loads(weights_path.read_text(encoding="utf-8"))

if not weights:
    for index, name in enumerate(tests):
        if (index % shard_count) + 1 == shard_index:
            print(name)
    raise SystemExit(0)

default_weight = 120
shard_loads = [0] * shard_count
shard_members = [[] for _ in range(shard_count)]

weighted_tests = [
    (-int(weights.get(name, default_weight)), original_index, name)
    for original_index, name in enumerate(tests)
]

for negative_weight, original_index, name in sorted(weighted_tests):
    weight = -negative_weight
    target_shard = min(
        range(shard_count),
        key=lambda shard: (shard_loads[shard], len(shard_members[shard]), shard),
    )
    shard_members[target_shard].append((original_index, name))
    shard_loads[target_shard] += weight

for _, name in sorted(shard_members[shard_index - 1]):
    print(name)
PY
}

run_single_test() {
    local test_name="$1"
    local start_time end_time duration target
    local node_count

    if ! leaf_test_exists "$test_name"; then
        echo -e "${RED}Unknown leaf E2E test: $test_name${NC}" >&2
        return 1
    fi

    target=".#checks.$SYSTEM.e2e-$test_name"
    node_count="$(leaf_test_node_count "$test_name")"
    compute_vm_cpu_plan "$node_count"

    echo -e "${YELLOW}Running: $test_name${NC}"
    if [[ "$VM_CPU_PLAN_MODE" == "override" ]]; then
        echo -e "${YELLOW}  VM CPU plan:${NC} override=${VM_CPU_PLAN_PER_VM_CORES} core(s)/VM across ${VM_CPU_PLAN_NODE_COUNT} node(s) on a ${VM_CPU_PLAN_HOST_CORES}-CPU host."
    else
        echo -e "${YELLOW}  VM CPU plan:${NC} host=${VM_CPU_PLAN_HOST_CORES}, target=${VM_CPU_PLAN_TARGET_PERCENT}%, reserve=${VM_CPU_PLAN_RESERVED_CORES}, nodes=${VM_CPU_PLAN_NODE_COUNT}, guest-budget=${VM_CPU_PLAN_TOTAL_BUDGET}, per-vm=${VM_CPU_PLAN_PER_VM_CORES} (bounds ${VM_CPU_PLAN_MIN_CORES}-${VM_CPU_PLAN_MAX_CORES})."
    fi
    start_time=$(date +%s)

    # nix/e2e-tests/lib/vm-config.nix intentionally reads NAILS_E2E_VM_CORES
    # via builtins.getEnv, so the flake check evaluation for the actual test
    # build must be explicitly impure for the computed per-VM core plan to take
    # effect. Scope that impurity to the per-test build only.
    local nix_args=(build "$target" --no-link --impure)
    if [ "$VERBOSE" = true ]; then
        nix_args+=(-L)
    fi

    if NAILS_E2E_VM_CORES="$VM_CPU_PLAN_PER_VM_CORES" nix "${nix_args[@]}"; then
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
    echo -e "${YELLOW}Running ${#tests[@]} resolved leaf test(s)...${NC}"
    if [[ -n "$SHARD_INDEX" && -n "$SHARD_COUNT" ]]; then
        echo -e "${YELLOW}Shard ${SHARD_INDEX}/${SHARD_COUNT} selected deterministically by resolved test order.${NC}"
    fi
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
        if ! leaf_test_exists "$test_name"; then
            echo -e "${RED}Unknown leaf E2E test: $test_name${NC}" >&2
            exit 1
        fi
        echo "Running interactive test for: $test_name"
        nix run ".#checks.$SYSTEM.e2e-$test_name" --interactive
    else
        echo "Running default interactive test driver"
        nix run ".#apps.$SYSTEM.e2e-test-interactive"
    fi
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
    run_interactive "${TEST_NAMES[0]:-}"
    exit 0
fi

if [ "${#TEST_NAMES[@]}" -eq 0 ]; then
    TEST_NAMES=("$(default_target)")
fi

mapfile -t RESOLVED_TESTS < <(resolve_targets "${TEST_NAMES[@]}")

if [ "${#RESOLVED_TESTS[@]}" -eq 0 ]; then
    echo -e "${RED}No E2E tests resolved from requested targets: ${TEST_NAMES[*]}${NC}" >&2
    exit 1
fi

mapfile -t RESOLVED_TESTS < <(select_shard_tests "${RESOLVED_TESTS[@]}")

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
