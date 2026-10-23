#!/usr/bin/env bash
# Fail when a fuzz target is not fully wired. Every parser of bytes NAILS does
# not control gets a coverage-guided fuzz target with a seed corpus (see
# docs/testing-strategy.md); this enforces the mechanical half of that rule so a
# target cannot land half-connected:
#
#   - every fuzz/fuzz_targets/<name>.rs has a [[bin]] entry in fuzz/Cargo.toml,
#     and every [[bin]] entry names a file that exists;
#   - no target is still the stub `just new-fuzz-target` writes, which drives
#     nothing: its TODO markers or its body that only discards the input;
#   - every target has a seed corpus in fuzz/seeds/<name>/, which
#     .clusterfuzzlite/build.sh zips for CI (a missing one breaks that build),
#     and at least one of its seeds is not empty, so the scaffold's empty
#     starter seed alone is no corpus;
#   - no seed corpus is left behind for a target that no longer exists.
#
# The review keeps the other half: that a new parser of decoy-controlled bytes
# comes with its target in the first place, and that the target checks it.
#
# It checks the repository it lives in, or the directory given as the only
# argument. The pre-commit hook, `just check` and CI's lint job run it.

set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
TARGETS_DIR="$REPO_ROOT/fuzz/fuzz_targets"
SEEDS_DIR="$REPO_ROOT/fuzz/seeds"
MANIFEST="$REPO_ROOT/fuzz/Cargo.toml"

errors=""
note() { errors="${errors}  $1"$'\n'; }

# The target files present on disk.
mapfile -t target_files < <(
  find "$TARGETS_DIR" -maxdepth 1 -type f -name '*.rs' -printf '%f\n' 2>/dev/null | sort
)
targets=()
for file in "${target_files[@]}"; do
  targets+=("${file%.rs}")
done

# The [[bin]] entries declared in the manifest: name and the path each points
# at. Only entries inside a [[bin]] table are read, never the [package] name.
declare -A bin_path=()
current_name="" in_bin=0
while IFS= read -r line; do
  case "$line" in
    '[[bin]]') in_bin=1; current_name="" ;;
    '['*) in_bin=0 ;;
    *)
      if [ "$in_bin" = 1 ]; then
        if [[ "$line" =~ ^[[:space:]]*name[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
          current_name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*path[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
          if [ -n "$current_name" ]; then
            bin_path["$current_name"]="${BASH_REMATCH[1]}"
          fi
        fi
      fi
      ;;
  esac
done < "$MANIFEST"

# Every target file is wired into the manifest, drives something and has a
# seed corpus with at least one input that is not empty.
for target in "${targets[@]}"; do
  if [ -z "${bin_path[$target]:-}" ]; then
    note "fuzz/fuzz_targets/$target.rs has no [[bin]] entry in fuzz/Cargo.toml."
  fi
  if grep -q -E 'TODO: (the parser this drives|drive the parser with)|^[[:space:]]*let _ = data;' \
    "$TARGETS_DIR/$target.rs"; then
    note "fuzz/fuzz_targets/$target.rs is still the scaffold's stub (drive the parser with the input and check its invariants)."
  fi
  seeds="$SEEDS_DIR/$target"
  if [ ! -d "$seeds" ] || [ -z "$(find "$seeds" -type f -print -quit 2>/dev/null)" ]; then
    note "fuzz target '$target' has no seed corpus (add at least one input under fuzz/seeds/$target/)."
  elif [ -z "$(find "$seeds" -type f ! -empty -print -quit 2>/dev/null)" ]; then
    note "fuzz target '$target' has only empty seeds (add inputs taken from the parser's fixtures and tests under fuzz/seeds/$target/)."
  fi
done

# Every [[bin]] entry points at a file that exists.
for name in "${!bin_path[@]}"; do
  path="${bin_path[$name]}"
  if [ ! -f "$REPO_ROOT/fuzz/$path" ]; then
    note "fuzz/Cargo.toml [[bin]] '$name' points at fuzz/$path, which does not exist."
  fi
done

# No seed corpus is orphaned (its target was removed but the seeds stayed).
if [ -d "$SEEDS_DIR" ]; then
  while IFS= read -r seeds; do
    [ -n "$seeds" ] || continue
    name="$(basename "$seeds")"
    if [ ! -f "$TARGETS_DIR/$name.rs" ]; then
      note "fuzz/seeds/$name/ has no fuzz target fuzz/fuzz_targets/$name.rs (delete the seeds or restore the target)."
    fi
  done < <(find "$SEEDS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
fi

if [ -n "$errors" ]; then
  echo "ERROR: the fuzz targets are not fully wired:"
  echo ""
  printf '%b' "$errors"
  echo ""
  echo "Every parser of bytes NAILS does not control needs a fuzz target and a"
  echo "seed corpus (docs/testing-strategy.md). Use 'just new-fuzz-target <name>'"
  echo "to scaffold one."
  exit 1
fi

echo "All ${#targets[@]} fuzz targets are wired, implemented and seeded."
exit 0
