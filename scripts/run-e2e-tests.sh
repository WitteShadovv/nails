#!/usr/bin/env bash
# Thin wrapper around the E2E planner and runner. All behaviour lives in the
# importable, tested `ci.e2e` package; this script only locates the repository
# root (so the flake reference `.#...` resolves) and forwards its arguments.
#
#   run-e2e-tests.sh                 # build the default target (the ci group)
#   run-e2e-tests.sh session-lifecycle  # build one test
#   run-e2e-tests.sh run --shard 1/4 all
#   run-e2e-tests.sh -i session-lifecycle   # open the interactive driver
#   run-e2e-tests.sh --help          # usage, with no nix required
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"
exec python3 -m ci.e2e "$@"
