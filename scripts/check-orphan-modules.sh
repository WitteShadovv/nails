#!/usr/bin/env bash
# Fail when a Rust file of the crates is neither a crate root nor declared as a
# module. An orphan file compiles for nobody: it rots silently (stale code, dead
# tests) and escapes both clippy and the test runner. A file counts as declared
# when some source file resolves to it through a `mod <name>;` declaration or a
# `#[path = "..."]` include, following the same resolution rules rustc uses.
# Every crate directory of the repository (nails-*/), every crate of the side
# workspaces (setup/ and gui/) and the fuzz crate (fuzz/) is checked, so a new
# crate needs no edit here: its src/ tree and the tests/, benches/ and examples/
# trees it has, and the fuzz crate's fuzz_targets/. A crate root is a lib.rs or
# a main.rs, or a file directly in one of those other trees, which Cargo builds
# as a target of its own: an integration test, a benchmark, an example, or a
# fuzz target that fuzz/Cargo.toml lists (check-fuzz-targets.sh checks that it
# does). It checks the repository it lives in, or the directory given as the
# only argument.

set -euo pipefail

# The physical path: realpath resolves a `#[path]` include to one, and it must
# match the paths find reports below.
REPO_ROOT="$(cd "${1:-$(dirname "$0")/..}" && pwd -P)"
SOURCE_ROOTS=("$REPO_ROOT"/nails-*/src "$REPO_ROOT"/setup/*/src "$REPO_ROOT"/gui/*/src "$REPO_ROOT"/fuzz/src)

# A pattern that matches nothing stays as written, and find fails on it inside
# the process substitutions below without failing the script, which would then
# report no orphans; refuse a missing tree instead.
for root in "${SOURCE_ROOTS[@]}"; do
  if [ ! -d "$root" ]; then
    echo "ERROR: no Rust source tree at ${root#"$REPO_ROOT"/}" >&2
    exit 1
  fi
done

# The trees of the other targets. A crate may have none of them, so only those
# that exist are scanned.
TARGET_ROOTS=()
declare -A IS_TARGET_ROOT=()
for root in "$REPO_ROOT"/{nails-*,setup/*,gui/*}/{tests,benches,examples} \
  "$REPO_ROOT"/fuzz/fuzz_targets; do
  if [ -d "$root" ]; then
    TARGET_ROOTS+=("$root")
    IS_TARGET_ROOT["$root"]=1
  fi
done

# Whether `file` is a crate root, which rustc reaches without a `mod`. A crate
# root resolves the modules it declares beside itself, as a mod.rs does.
is_crate_root() {
  local file="$1"
  case "${file##*/}" in
    lib.rs | main.rs) return 0 ;;
  esac
  [ -n "${IS_TARGET_ROOT[${file%/*}]:-}" ]
}

# Resolve a `mod <module_name>;` (optionally carrying a `#[path = "..."]`
# attribute) declared in `current_file` to the concrete file it names, echoing
# the resolved path on success.
resolve_module_file() {
  local current_file="$1"
  local module_name="$2"
  local path_attr="${3:-}"
  local current_dir current_name stem candidate

  current_dir="$(dirname "$current_file")"

  if [ -n "$path_attr" ]; then
    candidate="$(realpath -m "$current_dir/$path_attr")"
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    return 1
  fi

  current_name="$(basename "$current_file")"
  if [ "$current_name" = "mod.rs" ] || is_crate_root "$current_file"; then
    candidate="$current_dir/$module_name.rs"
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    candidate="$current_dir/$module_name/mod.rs"
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    return 1
  fi

  stem="${current_name%.rs}"
  candidate="$current_dir/$stem/$module_name.rs"
  if [ -f "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  candidate="$current_dir/$stem/$module_name/mod.rs"
  if [ -f "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

# Emit every file that `file` references via `mod`/`#[path]` declarations. A
# `#[path = "..."]` attribute on the line(s) before a `mod` applies to it.
emit_referenced_targets() {
  local file="$1"
  local line pending_path="" module_name target
  local -a file_lines=()
  local path_attr_regex='^[[:space:]]*#\[path[[:space:]]*=[[:space:]]*"([^"]+)"\]'
  local module_decl_regex='^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?mod[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;'

  mapfile -t file_lines < "$file"

  for line in "${file_lines[@]}"; do
    if [[ "$line" =~ $path_attr_regex ]]; then
      pending_path="${BASH_REMATCH[1]}"
      continue
    fi
    if [[ "$line" =~ $module_decl_regex ]]; then
      module_name="${BASH_REMATCH[3]}"
      if target="$(resolve_module_file "$file" "$module_name" "$pending_path")"; then
        printf '%s\n' "$target"
      fi
      pending_path=""
      continue
    fi
  done
}

declare -A REFERENCED=()
while IFS= read -r file; do
  [ -n "$file" ] || continue
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    REFERENCED["$target"]=1
  done < <(emit_referenced_targets "$file")
done < <(find "${SOURCE_ROOTS[@]}" "${TARGET_ROOTS[@]}" -type f -name '*.rs')

ORPHANS=""
while IFS= read -r file; do
  [ -n "$file" ] || continue
  # Crate roots are entry points; rustc never reaches them through a `mod`.
  if is_crate_root "$file"; then
    continue
  fi
  if [ -z "${REFERENCED[$file]:-}" ]; then
    ORPHANS="${ORPHANS}  ${file#"$REPO_ROOT"/}\n"
  fi
done < <(find "${SOURCE_ROOTS[@]}" "${TARGET_ROOTS[@]}" -type f -name '*.rs' | sort)

if [ -n "$ORPHANS" ]; then
  echo "ERROR: the following Rust source files are not declared as modules anywhere:"
  echo ""
  printf "%b" "$ORPHANS"
  echo ""
  echo "Declare each file with 'mod <name>;' (or '#[path = \"...\"] mod <name>;') from a"
  echo "reachable module, or delete it if it is dead."
  exit 1
fi

echo "All Rust source files are declared as modules."
exit 0
