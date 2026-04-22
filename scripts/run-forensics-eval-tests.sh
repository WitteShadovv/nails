#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    printf '%s\n' "This script requires bash 4 or newer." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUNNER_SCRIPT="$PROJECT_ROOT/scripts/run-forensics-eval.sh"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

AVAILABLE_TARGETS=()
LEAF_TESTS=()
declare -A LEAF_SCENARIOS=()
declare -A LEAF_PROFILES=()
declare -A LEAF_MODES=()
FLAKE_REF="${NAILS_FORENSICS_EVAL_FLAKE_REF:-path:$PROJECT_ROOT}"
SYSTEM="${NAILS_FORENSICS_EVAL_SYSTEM:-$(nix eval --impure --raw --expr builtins.currentSystem)}"
DRY_RUN=false
SHARD_INDEX=""
SHARD_COUNT=""
FORENSICS_METADATA_JSON=""
FORWARD_ARGS=()

leaf_test_exists() {
    local candidate="$1"
    local leaf_id

    for leaf_id in "${LEAF_TESTS[@]}"; do
        if [[ "$leaf_id" == "$candidate" ]]; then
            return 0
        fi
    done

    return 1
}

describe_target() {
    case "$1" in
        ci) printf '%s' 'Ordered CI subset' ;;
        live) printf '%s' 'Built-in live-supported leaves' ;;
        all) printf '%s' 'All supported scenario/profile leaves' ;;
        scenario:*) printf '%s' "Scenario group: ${1#scenario:}" ;;
        profile:*) printf '%s' "Profile group: ${1#profile:}" ;;
        *)
            if leaf_test_exists "$1"; then
                printf '%s' "Leaf: scenario=${LEAF_SCENARIOS[$1]} profile=${LEAF_PROFILES[$1]}"
            else
                printf '%s' 'Auto-discovered forensics target'
            fi
            ;;
    esac
}

load_forensics_metadata() {
    local metadata_json
    local leaf_id scenario_id profile_id recommended_mode

    metadata_json="$({
        cd "$PROJECT_ROOT"
        nix eval --json "${FLAKE_REF}#forensics-eval-metadata.$SYSTEM"
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

    LEAF_SCENARIOS=()
    LEAF_PROFILES=()
    LEAF_MODES=()
    while IFS=$'\t' read -r leaf_id scenario_id profile_id recommended_mode; do
        [[ -n "$leaf_id" ]] || continue
        LEAF_SCENARIOS["$leaf_id"]="$scenario_id"
        LEAF_PROFILES["$leaf_id"]="$profile_id"
        LEAF_MODES["$leaf_id"]="$recommended_mode"
    done < <(
        python3 - <<'PY' "$metadata_json"
import json
import sys

payload = json.loads(sys.argv[1])
for leaf_id in payload["leafTests"]:
    leaf = payload["leaves"][leaf_id]
    print(
        "\t".join(
            [
                leaf_id,
                leaf["scenarioId"],
                leaf["profileId"],
                leaf.get("recommendedMode", ""),
            ]
        )
    )
PY
    )

    FORENSICS_METADATA_JSON="$metadata_json"
}

resolve_targets() {
    python3 - <<'PY' "$FORENSICS_METADATA_JSON" "$@"
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
        print(f"Unknown forensics-eval target: {name}", file=sys.stderr)
        sys.exit(1)

    for member in members:
        if member not in leaf_tests:
            print(
                (
                    f"Forensics metadata error: target {name} resolved to "
                    f"unknown leaf test {member}"
                ),
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
    if [[ -n "${NAILS_FORENSICS_EVAL_DEFAULT_TARGET:-}" ]]; then
        printf '%s\n' "$NAILS_FORENSICS_EVAL_DEFAULT_TARGET"
    else
        printf '%s\n' "ci"
    fi
}

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  NAILS Forensics Eval Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET...] [-- RUNNER_ARGS...]"
    echo ""
    echo "Run NAILS forensics-eval leaves resolved from flake metadata."
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message and exit"
    echo "  -l, --list              List available targets"
    echo "      --dry-run           Print final resolved leaf tests without running"
    echo "      --resolve-only      Alias for --dry-run"
    echo "      --shard-index N     Run only shard N (1-based) of the resolved leaves"
    echo "      --shard-count N     Total number of deterministic shards"
    echo ""
    echo "Arguments:"
    echo "  TARGET                  Leaf id or group from forensics-eval metadata"
    echo ""
    echo "Default target: 'ci' (override with NAILS_FORENSICS_EVAL_DEFAULT_TARGET)."
    echo "Flake ref: default working-tree path; override with NAILS_FORENSICS_EVAL_FLAKE_REF if needed."
    echo "Use -- to pass additional arguments through to scripts/run-forensics-eval.sh."
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 --dry-run all"
    echo "  $0 scenario:direct-baseline"
    echo "  $0 --shard-index 2 --shard-count 3 all -- --fixture-run-dir nix/forensics-eval/fixtures/samples/sample-run"
    echo "  $0 ci -- --dry-run"
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

    echo -e "${BOLD}Available Forensics Eval Targets:${NC}"
    echo ""

    for name in "${AVAILABLE_TARGETS[@]}"; do
        printf "  ${GREEN}%-35s${NC} %s\n" "$name" "$(describe_target "$name")"
    done

    echo ""
}

print_resolved_tests() {
    local tests=("$@")
    local leaf_id

    for leaf_id in "${tests[@]}"; do
        printf '%s\n' "$leaf_id"
    done
}

select_shard_tests() {
    local tests=("$@")
    local selected_tests=()
    local leaf_id
    local index

    if [[ -z "$SHARD_INDEX" || -z "$SHARD_COUNT" ]]; then
        print_resolved_tests "${tests[@]}"
        return 0
    fi

    for index in "${!tests[@]}"; do
        leaf_id="${tests[$index]}"
        if (( (index % SHARD_COUNT) + 1 == SHARD_INDEX )); then
            selected_tests+=("$leaf_id")
        fi
    done

    print_resolved_tests "${selected_tests[@]}"
}

run_single_test() {
    local leaf_id="$1"
    local start_time end_time duration
    local scenario_id profile_id recommended_mode
    local cmd=()

    if ! leaf_test_exists "$leaf_id"; then
        echo -e "${RED}Unknown forensics-eval leaf: $leaf_id${NC}" >&2
        return 1
    fi

    scenario_id="${LEAF_SCENARIOS[$leaf_id]}"
    profile_id="${LEAF_PROFILES[$leaf_id]}"
    recommended_mode="${LEAF_MODES[$leaf_id]}"

    echo -e "${YELLOW}Running:${NC} $leaf_id"
    echo -e "${YELLOW}  Scenario:${NC} $scenario_id"
    echo -e "${YELLOW}  Profile:${NC}  $profile_id"
    if [[ -n "$recommended_mode" && "$recommended_mode" != "builtin-live" ]]; then
        echo -e "${YELLOW}  Note:${NC}     this leaf typically needs --fixture-run-dir or --stage-export-cmd."
    fi

    start_time=$(date +%s)
    cmd=("$RUNNER_SCRIPT" --profile "$profile_id" --scenario "$scenario_id")
    if (( ${#FORWARD_ARGS[@]} > 0 )); then
        cmd+=("${FORWARD_ARGS[@]}")
    fi

    if "${cmd[@]}"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}  PASS${NC} $leaf_id (${duration}s)"
        return 0
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${RED}  FAIL${NC} $leaf_id (${duration}s)"
        return 1
    fi
}

run_tests() {
    local tests=("$@")
    local pass=0
    local fail=0
    local failed_tests=()
    local total_start total_end total_duration
    local leaf_id

    print_header
    echo -e "${YELLOW}Running ${#tests[@]} resolved leaf test(s)...${NC}"
    if [[ -n "$SHARD_INDEX" && -n "$SHARD_COUNT" ]]; then
        echo -e "${YELLOW}Shard ${SHARD_INDEX}/${SHARD_COUNT} selected deterministically by resolved leaf order.${NC}"
    fi
    echo ""

    cd "$PROJECT_ROOT"
    total_start=$(date +%s)

    for leaf_id in "${tests[@]}"; do
        if run_single_test "$leaf_id"; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            failed_tests+=("$leaf_id")
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

TEST_NAMES=()

load_forensics_metadata

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
        --)
            shift
            FORWARD_ARGS=("$@")
            break
            ;;
        -*)
            echo -e "${RED}Error: Unknown option: $1${NC}" >&2
            echo -e "${YELLOW}Hint:${NC} use -- to pass options through to scripts/run-forensics-eval.sh" >&2
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

if [ "${#TEST_NAMES[@]}" -eq 0 ]; then
    TEST_NAMES=("$(default_target)")
fi

mapfile -t RESOLVED_TESTS < <(resolve_targets "${TEST_NAMES[@]}")

if [ "${#RESOLVED_TESTS[@]}" -eq 0 ]; then
    echo -e "${RED}No forensics-eval leaves resolved from requested targets: ${TEST_NAMES[*]}${NC}" >&2
    exit 1
fi

mapfile -t RESOLVED_TESTS < <(select_shard_tests "${RESOLVED_TESTS[@]}")

if [ "${#RESOLVED_TESTS[@]}" -eq 0 ]; then
    if [[ -n "$SHARD_INDEX" && -n "$SHARD_COUNT" ]]; then
        echo -e "${YELLOW}No leaves assigned to shard ${SHARD_INDEX}/${SHARD_COUNT}; nothing to run.${NC}"
        exit 0
    fi

    echo -e "${RED}No forensics-eval leaves resolved from requested targets after sharding: ${TEST_NAMES[*]}${NC}" >&2
    exit 1
fi

if [ "$DRY_RUN" = true ]; then
    print_resolved_tests "${RESOLVED_TESTS[@]}"
else
    run_tests "${RESOLVED_TESTS[@]}"
fi
