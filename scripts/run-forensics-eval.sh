#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    printf '%s\n' "This script requires bash 4 or newer." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUNNER="$PROJECT_ROOT/nix/forensics-eval/runners/run_forensics_eval.py"
PYTHON_BIN="${PYTHON:-python3}"

if [[ ! -f "$RUNNER" ]]; then
    printf '%s\n' "Forensics eval runner not found: $RUNNER" >&2
    exit 1
fi

exec "$PYTHON_BIN" "$RUNNER" --project-root "$PROJECT_ROOT" "$@"
