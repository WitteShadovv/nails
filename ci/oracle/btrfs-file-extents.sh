#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Show how a btrfs disk image stores some of its files: each file's size, its
# extents as the kernel reports them (filefrag -v, where `inline` is data kept
# in the metadata and `encoded` is compressed data) and the EXTENT_DATA items
# of its inode in its subvolume's tree (btrfs inspect-internal dump-tree:
# inline or regular, and the compression of each). bulk_extractor reads the
# bytes on the disk, so it sees only what is stored uncompressed; this says
# which of a file's bytes those are (see ci/oracle/README.md).
#
#   sudo btrfs-file-extents.sh <image> <path>...
#
# <image> is a bare btrfs filesystem or a whole disk with exactly one btrfs
# partition. A path names a file from the top of the filesystem, the
# subvolume of id 5: on the Fedora decoy /var/log/wtmp, since its /var is the
# subvolume var there. The image is attached read-only and mounted read-only
# without log replay, so nothing is written to it. Needs root, util-linux
# (losetup, blkid), btrfs-progs and e2fsprogs (filefrag).
set -euo pipefail

img=${1:?usage: btrfs-file-extents.sh <image> <path>...}
shift
[ "$#" -gt 0 ] || { echo "btrfs-file-extents: name at least one path" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "btrfs-file-extents: must run as root" >&2; exit 1; }

loop=""
mnt=""
cleanup() {
  if [ -n "$mnt" ]; then
    umount "$mnt" 2>/dev/null || true
    rmdir "$mnt" 2>/dev/null || true
  fi
  if [ -n "$loop" ]; then losetup -d "$loop" 2>/dev/null || true; fi
}
trap cleanup EXIT

loop=$(losetup -r -P --show -f "$img")
udevadm settle 2>/dev/null || true
# The image itself for a bare filesystem, else its partitions, each probed
# through its own superblock.
found=()
for part in "$loop" "$loop"p*; do
  [ -b "$part" ] || continue
  if [ "$(blkid -p -o value -s TYPE "$part" 2>/dev/null || true)" = btrfs ]; then
    found+=("$part")
  fi
done
if [ "${#found[@]}" -ne 1 ]; then
  echo "btrfs-file-extents: $img holds ${#found[@]} btrfs filesystems, not one" >&2
  exit 1
fi
dev=${found[0]}

mnt=$(mktemp -d)
mount -o ro,rescue=nologreplay,subvolid=5 "$dev" "$mnt"

for path in "$@"; do
  file="$mnt/${path#/}"
  echo "== $path"
  if [ ! -f "$file" ] || [ -L "$file" ]; then
    echo "not a regular file in $img"
    continue
  fi
  echo "size: $(stat -c %s "$file") bytes"
  filefrag -v "$file"
  ino=$(stat -c %i "$file")
  # rootid opens a file read-write, which a read-only mount refuses, and a
  # directory read-only: the file's directory is in the same subvolume.
  root=$(btrfs inspect-internal rootid "$(dirname "$file")")
  echo "EXTENT_DATA items of inode $ino in tree $root:"
  # An item line is "<tab>item N key (INO EXTENT_DATA OFFSET) ...", and its
  # fields follow on deeper-indented lines until the next item or leaf.
  btrfs inspect-internal dump-tree -t "$root" "$dev" | awk -v ino="$ino" '
    /^[\t ]*item [0-9]+ key \(/ { keep = ($4 == "(" ino && $5 == "EXTENT_DATA") }
    /^(leaf|node) / { keep = 0 }
    keep { print }'
done
