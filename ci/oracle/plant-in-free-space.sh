#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Plant strings into the free space of an ext2/3/4 or btrfs filesystem image
# without mounting it: each string, as one line, into its own unallocated block
# that holds nothing but zeros. run-scan.sh plants the positive-control sentinels
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
# filesystem, so they sit apart. On ext2/3/4, debugfs finds the free blocks in
# the block bitmap without changing the image. On btrfs, the free blocks are
# the device space no chunk is allocated in: btrfs-progs reads the device
# extents from the device tree, offline, and the first MiB and the superblock
# copies are passed over. btrfs tracks nothing in that space, so the image
# reads the same to every btrfs tool afterwards. A btrfs filesystem on more
# than one device is refused. A free block that is not all zeros (old data) is
# passed over, never overwritten. Exits 0 when every string was planted, 1
# when the image holds no ext2/3/4 or single-device btrfs filesystem the tools
# can read at that offset or no zero-filled free block turns up for a string,
# and 2 on a usage error.
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

# zero_block <byte-position>: whether the image holds a whole block of zeros
# there. A short read (past the end of the image) is not one.
zero_block() {
  cmp -s -n "$bs" /dev/zero \
    <(dd if="$img" iflag=skip_bytes,count_bytes skip="$1" count="$bs" bs="$bs" status=none)
}

# plant_at <byte-position> <string>: write the string, as one line, there.
plant_at() {
  printf '%s\n' "$2" | dd of="$img" oflag=seek_bytes seek="$1" conv=notrunc status=none
}

# fits: every string fits in one $bs-byte block with its newline, or exit 2.
fits() {
  local string
  for string in "$@"; do
    if [ "$((${#string} + 1))" -gt "$bs" ]; then
      echo "plant-in-free-space: '$string' does not fit in one $bs-byte block" >&2
      exit 2
    fi
  done
}

# is_mirror <fs-byte> <block-size>: whether the block of <block-size> bytes at
# filesystem byte <fs-byte> overlaps a btrfs superblock copy (4 KiB at 64 MiB,
# 256 GiB and 1 PiB), which btrfs writes outside its chunks too.
is_mirror() {
  local m
  for m in 67108864 274877906944 1125899906842624; do
    if [ "$1" -lt "$((m + 4096))" ] && [ "$m" -lt "$(($1 + $2))" ]; then return 0; fi
  done
  return 1
}

# --- btrfs: the device space no chunk is allocated in. -----------------------
# The btrfs magic sits 64 bytes into the primary superblock, at 64 KiB.
magic=$(dd if="$img" iflag=skip_bytes,count_bytes skip=$((off + 65536 + 64)) count=8 bs=8 status=none | tr -d '\0') || magic=""
if [ "$magic" = "_BHRfS_M" ]; then
  command -v btrfs >/dev/null || { echo "plant-in-free-space: btrfs-progs is needed to read a btrfs filesystem" >&2; exit 1; }
  dev=$img
  copy=""
  # btrfs-progs reads a file or a device from its start, so a filesystem at an
  # offset is read from a sparse copy of the image from there on; it is only
  # read, and the strings go into the image itself.
  if [ "$off" -gt 0 ]; then
    copy=$(mktemp "${TMPDIR:-/tmp}/plant-btrfs.XXXXXX")
    # shellcheck disable=SC2064  # expand now: the copy's path is fixed
    trap "rm -f '$copy'" EXIT
    dd if="$img" of="$copy" iflag=skip_bytes skip="$off" bs=4M conv=sparse status=none
    dev=$copy
  fi
  super=$(btrfs inspect-internal dump-super "$dev" 2>/dev/null) || super=""
  field() { awk -v f="$1" '$1 == f && !seen { print $2; seen = 1 }' <<<"$super"; }
  bs=$(field sectorsize)
  total=$(field dev_item.total_bytes)
  devid=$(field dev_item.devid)
  ndev=$(field num_devices)
  if ! [[ "$bs" =~ ^[0-9]+$ && "$total" =~ ^[0-9]+$ && "$devid" =~ ^[0-9]+$ ]] || [ "$bs" -lt 512 ]; then
    echo "plant-in-free-space: $img holds no btrfs filesystem btrfs-progs can read at byte $off" >&2
    exit 1
  fi
  if [ "$ndev" != 1 ]; then
    echo "plant-in-free-space: the btrfs filesystem in $img spans ${ndev:-an unknown number of} devices; only a single-device one is planted into" >&2
    exit 1
  fi
  fits "$@"
  # Every device extent as "<devid> <start> <length>": the key line names
  # the device and the start, the item's next lines its length.
  if ! tree=$(btrfs inspect-internal dump-tree -t dev "$dev" 2>/dev/null); then
    echo "plant-in-free-space: btrfs-progs could not read the device tree of $img" >&2
    exit 1
  fi
  extents=$(awk '
    /key \(/ && / DEV_EXTENT / {
      k = $0; sub(/.*key \(/, "", k); sub(/\).*/, "", k); split(k, a, " ")
      if (a[2] == "DEV_EXTENT") { d = a[1]; s = a[3]; want = 1 }
      next
    }
    want && / length / {
      for (i = 1; i < NF; i++) if ($i == "length") { print d, s, $(i + 1); want = 0 }
    }' <<<"$tree")
  # The gaps between them, from the end of the first MiB (which btrfs never
  # allocates and which holds the primary superblock) to the device's end.
  gaps=()
  pos=$((1024 * 1024))
  while read -r d s l; do
    [ -n "$d" ] || continue
    if [ "$d" != "$devid" ]; then
      echo "plant-in-free-space: the device tree of $img names device $d, not its own device $devid" >&2
      exit 1
    fi
    if [ "$s" -gt "$pos" ]; then gaps+=("$pos $s"); fi
    if [ "$((s + l))" -gt "$pos" ]; then pos=$((s + l)); fi
  done < <(sort -n -k2,2 <<<"$extents")
  if [ "$total" -gt "$pos" ]; then gaps+=("$pos $total"); fi
  n=$#
  k=0
  for string in "$@"; do
    k=$((k + 1))
    goal=$((total * k / (n + 1)))
    goal=$((goal - goal % bs))
    planted=0
    # Up to 64 candidate blocks per gap from the goal on, then from the start.
    for from in "$goal" 0; do
      for gap in "${gaps[@]}"; do
        read -r a b <<<"$gap"
        if [ "$b" -le "$from" ]; then continue; fi
        if [ "$a" -lt "$from" ]; then a=$from; fi
        a=$(((a + bs - 1) / bs * bs))
        tries=0
        while [ "$((a + bs))" -le "$b" ] && [ "$tries" -lt 64 ]; do
          if ! is_mirror "$a" "$bs" && zero_block "$((off + a))"; then
            plant_at "$((off + a))" "$string"
            planted=1
            break 3
          fi
          a=$((a + bs))
          tries=$((tries + 1))
        done
      done
    done
    if [ "$planted" -ne 1 ]; then
      echo "plant-in-free-space: no zero-filled unallocated block near byte $goal of the btrfs filesystem in $img for '$string'" >&2
      exit 1
    fi
  done
  exit 0
fi

# --- ext2/3/4: the free blocks of the block bitmap. --------------------------
src=$img
if [ "$off" -gt 0 ]; then src="$img?offset=$off"; fi

# superblock_field <field>: one numeric field of the superblock ("Block size",
# "Block count"), as debugfs's stats print it. awk reads to the end, so debugfs
# never writes into a closed pipe.
superblock_field() {
  debugfs -R "stats -h" "$src" 2>/dev/null |
    awk -F: -v f="$1" '$1 == f && !seen { gsub(/[ \t]/, "", $2); print $2; seen = 1 }'
}

bs=$(superblock_field "Block size") || bs=""
count=$(superblock_field "Block count") || count=""
if ! [[ "$bs" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 2 ]; then
  echo "plant-in-free-space: $img holds no ext2/3/4 or btrfs filesystem the tools can read at byte $off" >&2
  exit 1
fi
fits "$@"

n=$#
k=0
for string in "$@"; do
  k=$((k + 1))
  goal=$((count * k / (n + 1)))
  planted=0
  for blk in $(debugfs -R "ffb 64 $goal" "$src" 2>/dev/null | sed -n 's/^Free blocks found: //p'); do
    pos=$((off + blk * bs))
    if zero_block "$pos"; then
      plant_at "$pos" "$string"
      planted=1
      break
    fi
  done
  if [ "$planted" -ne 1 ]; then
    echo "plant-in-free-space: no zero-filled free block near block $goal of $img for '$string'" >&2
    exit 1
  fi
done
