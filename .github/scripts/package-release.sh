#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: package-release.sh --binary PATH --version VERSION --target TARGET --out-dir DIR
EOF
}

binary_path=""
version=""
target=""
out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary_path="$2"
      shift 2
      ;;
    --version)
      version="$2"
      shift 2
      ;;
    --target)
      target="$2"
      shift 2
      ;;
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$binary_path" || -z "$version" || -z "$target" || -z "$out_dir" ]]; then
  usage >&2
  exit 1
fi

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  echo "SOURCE_DATE_EPOCH must be set" >&2
  exit 1
fi

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

repo_root=$(git rev-parse --show-toplevel)
archive_name="nails-${version}-${target}.tar.gz"
package_dir_name="nails-${version}-${target}"
stage_root=$(mktemp -d)
package_dir="${stage_root}/${package_dir_name}"

cleanup() {
  rm -rf "$stage_root"
}
trap cleanup EXIT

mkdir -p "$package_dir" "$out_dir"

install -m 0755 "$binary_path" "${package_dir}/nails"
install -m 0644 "${repo_root}/LICENSE" "${package_dir}/LICENSE"
install -m 0644 "${repo_root}/README.md" "${package_dir}/README.md"

export LC_ALL=C
export TZ=UTC
umask 022

tar --sort=name \
  --mtime="@${SOURCE_DATE_EPOCH}" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -cf - \
  -C "$stage_root" \
  "$package_dir_name" | gzip -n > "${out_dir}/${archive_name}"

(
  cd "$out_dir"
  sha256sum "$archive_name" > SHA256SUMS
)
