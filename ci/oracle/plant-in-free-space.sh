#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Plant strings into the free space of an ext2/3/4 filesystem image without
# mounting it: each string, as one line, into its own unallocated block that
# holds nothing but zeros. run-scan.sh plants the positive-control sentinels
# into the working copy of after.raw this way, so the copy differs from the
# captured image in those blocks alone, the way a leaked-then-deleted string
# sits in free space: no file, path, record or filesystem metadata changes, and
# nothing the image held is overwritten. A read-write kernel mount would replay
# or restart the journal, overwriting its oldest blocks, and rewrite the
# superblock, so the image scanned would no longer be the one captured.
#
#   plant-in-free-space.sh <image> <byte-offset> <string>...
#
# <byte-offset> is where the filesystem starts in the image (0 for a bare
# filesystem). With n strings, the k-th goes about k/(n+1) of the way into the
# filesystem, so they sit apart. debugfs finds the free blocks in the block
# bitmap without changing the image, and a free block that is not all zeros
# (old data) is passed over, never overwritten. Exits 0 when every string was
# planted, 1 when the image holds no ext2/3/4 filesystem debugfs can read at
# that offset or no zero-filled free block turns up for a string, and 2 on a
# usage error.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: plant-in-free-space.sh <image> <byte-offset> <string>..." >&2
  exit 2
fi
img=$1
off=$2
shift 2
if [ ! -f "$img" ] || ! [[ "$off" =~ ^[0-9]+$ ]]; then
  echo "plant-in-free-space: need an image file and a byte offset, got '$img' and '$off'" >&2
  exit 2
fi
src=$img
if [ "$off" -gt 0 ]; then src="$img?offset=$off"; fi

# superblock_field <field>: one numeric field of the superblock ("Block size",
# "Block count"), as debugfs's stats print it. awk reads to the end, so debugfs
# never writes into a closed pipe.
superblock_field() {
  debugfs -R "stats -h" "$src" 2>/dev/null |
    awk -F: -v f="$1" '$1 == f && !seen { gsub(/[ \t]/, "", $2); print $2; seen = 1 }'
}

# zero_block <byte-position>: whether the image holds a whole block of zeros
# there. A short read (past the end of the image) is not one.
zero_block() {
  cmp -s -n "$bs" /dev/zero \
    <(dd if="$img" iflag=skip_bytes,count_bytes skip="$1" count="$bs" bs="$bs" status=none)
}

bs=$(superblock_field "Block size") || bs=""
count=$(superblock_field "Block count") || count=""
if ! [[ "$bs" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 2 ]; then
  echo "plant-in-free-space: $img holds no ext2/3/4 filesystem debugfs can read at byte $off" >&2
  exit 1
fi
for string in "$@"; do
  if [ "$((${#string} + 1))" -gt "$bs" ]; then
    echo "plant-in-free-space: '$string' does not fit in one $bs-byte block" >&2
    exit 2
  fi
done

n=$#
k=0
for string in "$@"; do
  k=$((k + 1))
  goal=$((count * k / (n + 1)))
  planted=0
  for blk in $(debugfs -R "ffb 64 $goal" "$src" 2>/dev/null | sed -n 's/^Free blocks found: //p'); do
    pos=$((off + blk * bs))
    if zero_block "$pos"; then
      printf '%s\n' "$string" |
        dd of="$img" oflag=seek_bytes seek="$pos" conv=notrunc status=none
      planted=1
      break
    fi
  done
  if [ "$planted" -ne 1 ]; then
    echo "plant-in-free-space: no zero-filled free block near block $goal of $img for '$string'" >&2
    exit 1
  fi
done
