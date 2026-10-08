#!/usr/bin/env bash
# Fail when a Rust source file under the crate `src` trees is never declared as a
# module. An orphan file compiles for nobody: it rots silently (stale code, dead
# tests) and escapes both clippy and the test runner. A file counts as declared
# when some source file resolves to it through a `mod <name>;` declaration or a
# `#[path = "..."]` include, following the same resolution rules rustc uses.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_ROOTS=(
  "$REPO_ROOT/nails-base/src"
  "$REPO_ROOT/nails-core/src"
  "$REPO_ROOT/nails-platform/src"
  "$REPO_ROOT/nails-session/src"
  "$REPO_ROOT/nails-cli/src"
  "$REPO_ROOT/nails-teardown/src"
)

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
  if [ "$current_name" = "mod.rs" ] || [ "$current_name" = "lib.rs" ] || [ "$current_name" = "main.rs" ]; then
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
done < <(find "${SOURCE_ROOTS[@]}" -type f -name '*.rs')

ORPHANS=""
while IFS= read -r file; do
  [ -n "$file" ] || continue
  # Crate roots are entry points; rustc never reaches them through a `mod`.
  case "$(basename "$file")" in
    lib.rs | main.rs) continue ;;
  esac
  if [ -z "${REFERENCED[$file]:-}" ]; then
    ORPHANS="${ORPHANS}  ${file#"$REPO_ROOT"/}\n"
  fi
done < <(find "${SOURCE_ROOTS[@]}" -type f -name '*.rs' | sort)

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
