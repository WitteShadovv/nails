#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# What the partitions of a disk image the forensic oracle scans hold, and how
# the restore channel compares each. ci/oracle/run-scan.sh sources this file,
# and ci/tests runs these functions on disk images it builds, which needs no
# root: they read the image file with mmls (sleuthkit) and blkid (util-linux)
# and never attach or mount it.

# partition_slots <image>: one "<byte-offset> <byte-size>" line per partition
# of any kind in the partition table of a whole-disk image, and nothing for an
# image with no partition table. mmls lists the partitions in the units it
# names, each in a numbered slot, which its meta entries and unallocated gaps
# lack. mawk-safe: %.0f, not %d, for byte counts past 2^31.
partition_slots() {
  local table
  table=$(mmls "$1" 2>/dev/null) || return 0
  awk '
    BEGIN { unit = 512 }
    /^Units are in [0-9]+-byte sectors/ { unit = $4 + 0 }
    $1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+(:[0-9]+)?$/ {
      printf "%.0f %.0f\n", ($3 + 0) * unit, ($5 + 0) * unit
    }' <<<"$table"
}

# fs_partitions <image>: one "<fstype> <byte-offset> <byte-size>" line per
# partition of a whole-disk image that holds a filesystem blkid recognises, and
# nothing for an image with no partition table. mmls's descriptions are only
# the GPT partition names or the MBR type, so blkid probes each partition's own
# superblock for the type (it honours -O and -S only in its low-level mode, -p).
fs_partitions() {
  local img=$1 start size t
  while read -r start size; do
    t=$(blkid -p -o value -s TYPE -O "$start" -S "$size" "$img" 2>/dev/null || true)
    if [ -n "$t" ]; then printf '%s %s %s\n' "$t" "$start" "$size"; fi
  done < <(partition_slots "$img")
}

# detect_fs <image>: print "<fstype> <byte-offset> <byte-size>" for the
# filesystem to carve, or fail with the reason. A bare filesystem image is
# carved whole (offset 0, size 0 for the whole image). A whole-disk image must
# hold exactly one btrfs or ext{2,3,4} partition: with none there is nothing
# this scan can carve, and with several (a separate /boot or /home) the root
# cannot be told apart safely, so the caller scans the root filesystem's own
# image instead.
detect_fs() {
  local img=$1 t parts carvable found
  t=$(blkid -o value -s TYPE "$img" 2>/dev/null || true)
  if [ -n "$t" ]; then
    printf '%s 0 0\n' "$t"
    return 0
  fi
  parts=$(fs_partitions "$img")
  carvable=$(awk '$1 ~ /^(btrfs|ext[234])$/' <<<"$parts")
  found=$(awk 'NF { printf "%s%s at byte %s", (n++ ? ", " : ""), $1, $2 }' <<<"$parts")
  if [ -z "$carvable" ]; then
    echo "run-scan: $img holds no btrfs or ext{2,3,4} filesystem, bare or in a partition (${found:-no filesystem or partition table recognised}); failing closed. Add a carver for its filesystem (see ci/oracle/README.md) or scan a btrfs or ext{2,3,4} image." >&2
    return 1
  fi
  if [ "$(wc -l <<<"$carvable")" -ne 1 ]; then
    echo "run-scan: $img has more than one btrfs or ext{2,3,4} partition ($found), and a /boot or /home cannot be told apart from the root safely; failing closed. Scan the root filesystem's own image instead (for example cut out of the disk with dd)." >&2
    return 1
  fi
  printf '%s\n' "$carvable"
}

# The largest partition holding no filesystem that the restore channel
# compares whole, by its bytes: a BIOS boot partition is 1 MiB.
RAW_PARTITION_MAX=$((64 * 1024 * 1024))

# partition_plan <image> <root-offset>: one "<n> <byte-offset> <byte-size>
# <kind>" line for each partition of a whole-disk image but the root, the
# partition at <root-offset> that detect_fs chose, with n its place in the
# partition table from 1. kind says how the restore channel compares it: vfat,
# a filesystem it carves (an EFI system partition), or raw, a partition holding
# no filesystem blkid recognises (a BIOS boot partition), compared whole by its
# bytes. Any other filesystem, a raw partition larger than RAW_PARTITION_MAX
# and a partition blkid cannot tell (two signatures, say) fail with the
# reason, since the files of a partition the scan does not compare would go
# unseen while the verdict passes. An image with no partition table has no
# line.
partition_plan() {
  local img=$1 root_off=$2 n=0 start size t rc
  while read -r start size; do
    n=$((n + 1))
    if [ "$start" = "$root_off" ]; then continue; fi
    # blkid exits 0 when it finds a signature and 2 when it finds none; with
    # -s TYPE it prints a filesystem's type, and nothing for any other
    # signature, which leaves the partition raw, compared whole.
    rc=0
    t=$(blkid -p -o value -s TYPE -O "$start" -S "$size" "$img" 2>/dev/null) || rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
      echo "run-scan: blkid cannot tell what partition $n of $img holds (exit $rc); failing closed" >&2
      return 1
    fi
    case "$t" in
      vfat) printf '%s %s %s vfat\n' "$n" "$start" "$size" ;;
      "")
        if [ "$size" -gt "$RAW_PARTITION_MAX" ]; then
          echo "run-scan: partition $n of $img holds no filesystem blkid recognises and is $size bytes, more than the $RAW_PARTITION_MAX the restore channel compares whole; failing closed" >&2
          return 1
        fi
        printf '%s %s %s raw\n' "$n" "$start" "$size"
        ;;
      *)
        echo "run-scan: partition $n of $img holds a $t filesystem, and no carver here reads one, so its files would go uncompared; failing closed. Add a carver for it (see ci/oracle/README.md)." >&2
        return 1
        ;;
    esac
  done < <(partition_slots "$img")
}
