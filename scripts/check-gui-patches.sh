#!/usr/bin/env bash
# The copy of Slint's winit backend in gui/patches is the crate crates.io
# publishes plus the project's patch, byte for byte. Given the published
# crate file, this checks it against the checksum in
# gui/patches/i-slint-backend-winit.sha256, unpacks it, applies
# gui/patches/i-slint-backend-winit.patch without fuzz and fails unless the
# result is gui/patches/i-slint-backend-winit file for file. The copy leaves
# out two files of every published crate, Cargo.lock and .cargo_vcs_info.json,
# which cargo reads for neither a build nor a path dependency.
#
# The gui-patches flake check runs it on the crate a fixed-output fetch takes
# by that checksum, and `just vet gui` builds that check.
#
# Usage: scripts/check-gui-patches.sh <crate file>, from the repository root.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <i-slint-backend-winit .crate file>" >&2
  exit 2
fi
crate=$1
patches=gui/patches
name=i-slint-backend-winit

read -r expected file < "$patches/$name.sha256"
actual=$(sha256sum "$crate" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
  echo "check-gui-patches: $crate is not $file: sha256 $actual, not $expected" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$crate" -C "$work"
published=$work/${file%.crate}
rm -f "$published/Cargo.lock" "$published/.cargo_vcs_info.json"
if ! patch --directory="$published" --strip=1 --fuzz=0 --batch --quiet \
  --no-backup-if-mismatch < "$patches/$name.patch"; then
  echo "check-gui-patches: $patches/$name.patch does not apply to $file" >&2
  exit 1
fi
if ! diff -r "$published" "$patches/$name"; then
  echo "check-gui-patches: $patches/$name is not $file with $patches/$name.patch" >&2
  exit 1
fi
echo "check-gui-patches: $patches/$name is $file with $patches/$name.patch"
