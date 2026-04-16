#!/usr/bin/env bash
# Enforce a 500-line limit on Rust production files only.

set -euo pipefail
shopt -s extglob

MAX_LINES=500
FAILED=0
OFFENDERS=""

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_ROOTS=(
  "$REPO_ROOT/nails-core/src"
  "$REPO_ROOT/nails-cli/src"
)

declare -A RUST_FILES=()
declare -A CFG_TEST_FILES=()
declare -A TEST_ONLY_FILES=()
declare -A VISITED_TEST_ONLY=()

is_excluded_by_path() {
  case "$1" in
    */tests/*|*/benches/*|*/mock/*|*/mock.rs|*/tests.rs) return 0 ;;
  esac

  return 1
}

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

scan_module_targets() {
  local file="$1"
  local test_only_declarations_only="$2"
  local pending_cfg_test=0
  local pending_path=""
  local in_attribute_block=0
  local line module_name target
  local -a file_lines=()
  local cfg_test_regex='^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$'
  local path_attr_regex='^[[:space:]]*#\[path[[:space:]]*=[[:space:]]*"([^"]+)"\][[:space:]]*$'
  local attr_regex='^[[:space:]]*#\[.*\][[:space:]]*$'
  local module_decl_regex='^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;[[:space:]]*$'
  local blank_regex='^[[:space:]]*$'
  local line_comment_regex='^[[:space:]]*//'

  mapfile -t file_lines < "$file"

  for line in "${file_lines[@]}"; do
    if [[ "$line" =~ $cfg_test_regex ]]; then
      pending_cfg_test=1
      in_attribute_block=1
      continue
    fi

    if [[ "$line" =~ $path_attr_regex ]]; then
      pending_path="${BASH_REMATCH[1]}"
      in_attribute_block=1
      continue
    fi

    if [[ "$line" =~ $attr_regex ]]; then
      in_attribute_block=1
      continue
    fi

    if [[ "$line" =~ $module_decl_regex ]]; then
      module_name="${BASH_REMATCH[3]}"

      if [ "$test_only_declarations_only" -eq 0 ] || [ "$pending_cfg_test" -eq 1 ]; then
        if target="$(resolve_module_file "$file" "$module_name" "$pending_path")"; then
          if [ -n "${RUST_FILES[$target]:-}" ]; then
            printf '%s\n' "$target"
          fi
        fi
      fi

      pending_cfg_test=0
      pending_path=""
      in_attribute_block=0
      continue
    fi

    if [[ "$line" =~ $blank_regex ]] || [[ "$line" =~ $line_comment_regex ]]; then
      continue
    fi

    if [ "$in_attribute_block" -eq 1 ]; then
      pending_cfg_test=0
      pending_path=""
      in_attribute_block=0
    fi
  done
}

mark_test_only_files() {
  local file target

  for file in "${!CFG_TEST_FILES[@]}"; do
    while IFS= read -r target; do
      [ -n "$target" ] || continue
      TEST_ONLY_FILES["$target"]=1
    done < <(scan_module_targets "$file" 1)
  done

  while :; do
    local discovered=0

    for file in "${!TEST_ONLY_FILES[@]}"; do
      if [ -n "${VISITED_TEST_ONLY[$file]:-}" ]; then
        continue
      fi

      VISITED_TEST_ONLY["$file"]=1

      while IFS= read -r target; do
        [ -n "$target" ] || continue
        if [ -z "${TEST_ONLY_FILES[$target]:-}" ]; then
          TEST_ONLY_FILES["$target"]=1
          discovered=1
        fi
      done < <(scan_module_targets "$file" 0)
    done

    if [ "$discovered" -eq 0 ]; then
      break
    fi
  done
}

while IFS= read -r file; do
  [ -n "$file" ] || continue
  RUST_FILES["$file"]=1
done < <(find "${SOURCE_ROOTS[@]}" -type f -name '*.rs' 2>/dev/null)

while IFS= read -r file; do
  [ -n "$file" ] || continue
  CFG_TEST_FILES["$file"]=1
done < <(rg -l '#\[cfg\(test\)\]' "${SOURCE_ROOTS[@]}" --glob '*.rs' 2>/dev/null || true)

mark_test_only_files

for file in "${!RUST_FILES[@]}"; do
  if is_excluded_by_path "$file"; then
    continue
  fi

  if [ -n "${TEST_ONLY_FILES[$file]:-}" ]; then
    continue
  fi

  lines=$(wc -l < "$file")
  if [ "$lines" -gt "$MAX_LINES" ]; then
    OFFENDERS="${OFFENDERS}  ${file#"$REPO_ROOT"/}: ${lines} lines\n"
    FAILED=1
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "ERROR: The following Rust production files exceed ${MAX_LINES} lines:"
  echo ""
  printf "%b" "$OFFENDERS"
  echo ""
  echo "Excluded from this check: tests/, benches/, mock/, mock.rs, tests.rs, and modules only compiled via #[cfg(test)]."
  exit 1
fi

echo "All Rust production files are within the ${MAX_LINES}-line limit."
exit 0
