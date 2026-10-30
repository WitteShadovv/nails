#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# What a disk image the forensic oracle scans holds, and how the restore
# channel compares each part of it. ci/oracle/run-scan.sh sources this file,
# and ci/tests runs these functions on disk images it builds, which needs no
# root: they read the image file with mmls (sleuthkit), blkid (util-linux),
# debugfs (e2fsprogs) and btrfs-progs, and never attach or mount it.

# table_slots: read mmls's listing of a partition table on stdin and print one
# "<byte-offset> <byte-size>" line per partition in it. mmls lists the
# partitions in the units it names, each in a numbered slot, which its meta
# entries and unallocated gaps lack. It lists the extended partition of a DOS
# table, a container, as a meta entry: the logical partitions in it are slots
# of their own, and the tables between them lie outside every partition.
# awk-safe for byte counts past 2^31 (%.0f, not %d).
table_slots() {
  awk '
    BEGIN { unit = 512 }
    /^Units are in [0-9]+-byte sectors/ { unit = $4 + 0 }
    $1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+(:[0-9]+)?$/ {
      printf "%.0f %.0f\n", ($3 + 0) * unit, ($5 + 0) * unit
    }'
}

# partition_slots <image>: table_slots of the image's partition table, and
# nothing for an image mmls finds no partition table in.
partition_slots() {
  local table
  table=$(mmls "$1" 2>/dev/null) || return 0
  table_slots <<<"$table"
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
# carved whole (offset 0, size 0 for the whole image). An image holding a
# filesystem at byte 0 and a partition table too cannot be told to be either,
# so it stops the run. A whole-disk image must hold exactly one btrfs or
# ext{2,3,4} partition: with none there is nothing this scan can carve, and
# with several (a separate /boot or /home) the root cannot be told apart
# safely, so the caller scans the root filesystem's own image instead.
detect_fs() {
  local img=$1 t parts carvable found
  t=$(blkid -o value -s TYPE "$img" 2>/dev/null || true)
  if [ -n "$t" ]; then
    if [ -n "$(partition_slots "$img")" ]; then
      echo "run-scan: $img holds a $t filesystem at byte 0 and a partition table too, so it cannot be told whether it is a bare filesystem or a whole disk; failing closed" >&2
      return 1
    fi
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
# unseen while the verdict passes. So does a table mmls cannot read, and one
# that does not list the root's partition exactly once.
partition_plan() {
  local img=$1 root_off=$2 n=0 roots=0 plan="" table slots start size t rc
  if ! table=$(mmls "$img" 2>/dev/null); then
    echo "run-scan: mmls cannot read the partition table of $img; failing closed" >&2
    return 1
  fi
  slots=$(table_slots <<<"$table")
  roots=$(awk -v root="$root_off" '$1 == root { n++ } END { print n + 0 }' <<<"$slots")
  if [ "$roots" -ne 1 ]; then
    echo "run-scan: the partition table of $img lists a partition at byte $root_off, the root's, $roots times, not once; failing closed" >&2
    return 1
  fi
  while read -r start size; do
    [ -n "$start" ] || continue
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
      vfat) plan+="$n $start $size vfat"$'\n' ;;
      "")
        if [ "$size" -gt "$RAW_PARTITION_MAX" ]; then
          echo "run-scan: partition $n of $img holds no filesystem blkid recognises and is $size bytes, more than the $RAW_PARTITION_MAX the restore channel compares whole; failing closed" >&2
          return 1
        fi
        plan+="$n $start $size raw"$'\n'
        ;;
      *)
        echo "run-scan: partition $n of $img holds a $t filesystem, and no carver here reads one, so its files would go uncompared; failing closed. Add a carver for it (see ci/oracle/README.md)." >&2
        return 1
        ;;
    esac
  done <<<"$slots"
  printf '%s' "$plan"
}

# outside_partitions <image>: one "<byte-offset> <byte-end>" line, the end
# exclusive, for each stretch of a whole-disk image that no partition in its
# table covers: the protective MBR and the GPT, the gaps before, between and
# after the partitions, the tables of a DOS extended partition and the backup
# GPT at the end. The restore channel compares them by their bytes, so a
# change to the partition table, to boot code outside the partitions or to a
# partition mmls does not list is seen. Overlapping partitions are merged.
outside_partitions() {
  local img=$1 total table
  total=$(stat -c %s "$img")
  if ! table=$(mmls "$img" 2>/dev/null); then
    echo "run-scan: mmls cannot read the partition table of $img; failing closed" >&2
    return 1
  fi
  table_slots <<<"$table" | sort -n -k1,1 | awk -v total="$total" '
    BEGIN { pos = 0 }
    { start = $1 + 0; end = start + $2
      if (start > pos) printf "%.0f %.0f\n", pos, start
      if (end > pos) pos = end }
    END { if (total > pos) printf "%.0f %.0f\n", pos, total }'
}

# le <image> <byte-offset> <length>: the little-endian unsigned number of
# <length> bytes at <byte-offset>.
le() {
  local value=0 shift=0 byte
  for byte in $(od -An -v -t u1 -j "$2" -N "$3" "$1"); do
    value=$((value + (byte << shift)))
    shift=$((shift + 8))
  done
  printf '%s\n' "$value"
}

# vfat_structures_size <image> <byte-offset> <byte-size>: the bytes from the
# start of the vfat filesystem at <byte-offset> to its data area, which hold
# its boot sector (with its label, serial and dirty flag), the rest of its
# reserved sectors, its allocation tables and, on FAT12 and FAT16, its root
# directory, read from the boot sector's BIOS parameter block. The vfat carve
# copies the files alone, so the restore channel compares these bytes too.
# A block whose fields make no sense, or that reaches past the partition,
# fails with the reason.
vfat_structures_size() {
  local img=$1 off=$2 size=$3 bps rsvd nfats rootents fatsz rootsecs bytes=0
  bps=$(le "$img" $((off + 11)) 2)
  rsvd=$(le "$img" $((off + 14)) 2)
  nfats=$(le "$img" $((off + 16)) 1)
  rootents=$(le "$img" $((off + 17)) 2)
  fatsz=$(le "$img" $((off + 22)) 2)
  if [ "$fatsz" -eq 0 ]; then fatsz=$(le "$img" $((off + 36)) 4); fi
  case "$bps" in
    512 | 1024 | 2048 | 4096)
      rootsecs=$(((rootents * 32 + bps - 1) / bps))
      bytes=$(((rsvd + nfats * fatsz + rootsecs) * bps))
      ;;
  esac
  if [ "$bytes" -eq 0 ] || [ "$rsvd" -lt 1 ] || [ "$nfats" -lt 1 ] || [ "$fatsz" -lt 1 ] \
    || [ "$bytes" -gt "$size" ]; then
    echo "run-scan: the vfat filesystem at byte $off of $img has a boot sector this scan cannot read its layout from; failing closed" >&2
    return 1
  fi
  printf '%s\n' "$bytes"
}

# fs_settled <image> <fstype> <byte-offset>: succeed when the filesystem at
# <byte-offset> holds no writes that wait in a journal or log tree, and fail
# with the reason when it does or that cannot be read. Neither carver replays
# one (debugfs rdump and btrfs restore read the filesystem as it lies), so the
# files they recover would be older than the ones the decoy would mount:
# ext{2,3,4} with needs_recovery set, and btrfs with a log tree (log_root
# not 0).
fs_settled() {
  local img=$1 fstype=$2 off=$3 src features log
  case "$fstype" in
    ext2 | ext3 | ext4)
      src=$img
      if [ "$off" -gt 0 ]; then src="$img?offset=$off"; fi
      features=$(debugfs -R "stats -h" "$src" 2>/dev/null \
        | awk -F: '$1 == "Filesystem features" { print $2; exit }') || features=""
      if [ -z "$features" ]; then
        echo "run-scan: debugfs cannot read the features of the $fstype filesystem at byte $off of $img; failing closed" >&2
        return 1
      fi
      if grep -qw needs_recovery <<<"$features"; then
        echo "run-scan: the $fstype filesystem at byte $off of $img holds writes its journal has not replayed (needs_recovery), which the carve would miss; failing closed" >&2
        return 1
      fi
      ;;
    btrfs)
      log=$(btrfs inspect-internal dump-super --bytenr $((off + 65536)) "$img" 2>/dev/null \
        | awk '$1 == "log_root" { print $2; exit }') || log=""
      if ! [[ "$log" =~ ^[0-9]+$ ]]; then
        echo "run-scan: btrfs-progs cannot read the superblock of the btrfs filesystem at byte $off of $img; failing closed" >&2
        return 1
      fi
      if [ "$log" -ne 0 ]; then
        echo "run-scan: the btrfs filesystem at byte $off of $img holds a log tree (log_root $log) that btrfs restore does not replay, which the carve would miss; failing closed" >&2
        return 1
      fi
      ;;
  esac
}
