#!/usr/bin/env bash
# Run the test suite against a private, empty TMPDIR and fail if any test leaves
# a file behind in it. Temp-dir leaks make the suite order-dependent and, across
# a full CI matrix, slowly fill the runner's disk; this guards against them.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Compile the test binaries first with the ambient TMPDIR so rustc's own build
# temporaries do not land in the probe directory and trip a false positive.
cargo test --workspace --no-run

probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/nails-hermetic.XXXXXX")"
trap 'rm -rf "$probe_dir"' EXIT

TMPDIR="$probe_dir" cargo test --workspace

leftovers="$(find "$probe_dir" -mindepth 1 2>/dev/null || true)"
if [ -n "$leftovers" ]; then
  echo "ERROR: the test suite left files behind in a private TMPDIR:"
  echo ""
  printf '%s\n' "$leftovers" | sed 's/^/  /'
  echo ""
  echo "Tests must clean up their temp files: hold a tempfile::TempDir guard for"
  echo "the lifetime of the test instead of calling .keep() or std::mem::forget."
  exit 1
fi

echo "Test suite is hermetic: the private TMPDIR is empty after the run."
exit 0
