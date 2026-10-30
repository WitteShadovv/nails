#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the synthetic before/control/after images and run the pinned disk-image
# analysis tools over them into the outputs/ tree the nails-oracle verdict tool
# reads, then render the verdict.
#
# Streaming, so peak disk is one image's worth and not the sum of all three: for
# each label in turn it builds that one image, runs the restore carve (then
# records a SHA-256 of every recovered file, dumps the rows of a recovered Nix
# store database, and empties every file but the login record files, so the
# verdict compares what each file held without the contents taking up disk),
# bulk_extractor and plaso over it, and deletes the image and the bulky plaso
# store before moving to the next label. The small per-tool outputs for
# finished labels stay; nothing bulky accumulates.
#
# A scan that could not look never passes: a carve that recovers nothing or
# reports an error stops the run, a plaso timeline with no event for the
# canary's file drops the plaso channel (plaso still dates an image whose file
# system it cannot open, as one opaque file), and nails-oracle fails a run in
# which any channel reported nothing for an image (channel_missing), so a
# dropped plaso channel fails it too. The run passes only when nails-oracle
# exits 0 and the verdict.json it wrote says clean.
#
# btrfs images are the one exception, by design: plaso cannot open btrfs, so on
# them no timeline runs at all and outputs/plaso/not-run (holding "btrfs") says
# so. nails-oracle then requires the restore carve and bulk_extractor on every
# image as always, and a run that passes everything else is "partial" (exit 3),
# never "clean": its verdict names "timeline: not run, plaso cannot read
# btrfs". This script passes such a run, and only on btrfs images, and says
# loudly that it is not a full run. The three images must then all be btrfs.
#
# plaso reads every image through one fixed in-container path (/data/disk.img),
# so the source path in its timeline is identical across the three images and
# the before/control/after findings collapse as they must.
#
# Image source is pluggable. By default the three synthetic btrfs images are
# built here, one at a time (the proven path). Setting ORACLE_IMAGES_DIR to a
# directory holding before.raw / control.raw / after.raw scans those real decoy
# images instead -- e.g. the raws the e2e disk-forensics harness retains -- and
# the restore channel is carved per detected filesystem (btrfs restore for the
# synthetic btrfs images, debugfs rdump for the ext4 decoy roots). A raw is a
# bare filesystem image, or a whole-disk image with exactly one btrfs or
# ext{2,3,4} partition, the root. The rest of a whole disk is carved too: a
# vfat partition (an EFI system partition) through a read-only mount of a
# read-only loop device, with its boot sector and allocation tables as bytes,
# a small partition holding no filesystem (a BIOS boot partition) as one file
# holding its bytes, and every stretch no partition covers, the partition
# table among them, as files holding their bytes. A partition with any other
# filesystem stops the run, since its files would go uncompared
# (ci/oracle/partitions.sh). The bulk_extractor and plaso channels
# take the image itself and run the same either way, but plaso has to open its
# file system: it cannot open btrfs, so a btrfs image runs no timeline
# (above), and log2timeline, run unattended without --partitions, stops on a
# whole-disk image with more than one partition of any kind, which fails the
# plaso channel (see ci/oracle/README.md).
#
#   sudo run-scan.sh <workdir>
#   sudo env ORACLE_IMAGES_DIR=/path/with/before.raw,control.raw,after.raw run-scan.sh <workdir>
#
# Needs root (loop mounts, and reading the decoy's root-only files), btrfs-progs,
# git + the bulk_extractor build chain, jq (to read the verdict), and docker
# (for the pinned plaso container; without it the verdict fails on the missing
# plaso channel; btrfs images need none); pre-built-image mode also needs sleuthkit (mmls) and
# e2fsprogs (debugfs) plus util-linux (blkid, losetup), and an image that holds
# a Nix store database needs sqlite3 to read its rows. The verdict binary is
# found at $ORACLE_BIN, or target/release/nails-oracle under the repository
# root. No KVM.
set -euo pipefail

# --- Pins (verbatim from the image-analysis feasibility probe). -------------
# plaso (log2timeline), pinned by container digest; the tag is informational.
PLASO_IMAGE="log2timeline/plaso:20260720@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950" # pragma: allowlist secret
# bulk_extractor, built from this exact upstream release commit.
BE_REPO="https://github.com/simsong/bulk_extractor"
BE_TAG="v2.2.0"
BE_COMMIT="9af62917d73e0b631395064aba7ab4de7fbbf696" # pragma: allowlist secret

LABELS=(before control after)

export PATH="/usr/sbin:/sbin:$PATH"
export IMG_SIZE=${IMG_SIZE:-512M}

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/../.." && pwd)
work=${1:?usage: run-scan.sh <workdir>}
mkdir -p "$work"
work=$(cd "$work" && pwd)
images="$work/images"
outputs="$work/outputs"
build="$work/build"
# Pre-create the per-tool output parents, but never the bulk_extractor per-label
# subdirectory: bulk_extractor creates its own output directory and refuses a
# non-empty one.
mkdir -p "$images" "$outputs/restore" "$outputs/nix_db" "$outputs/bulk_extractor" "$outputs/plaso" "$build"

[ "$(id -u)" -eq 0 ] || { echo "run-scan: must run as root (loop mounts)" >&2; exit 1; }
for t in git make btrfs mkfs.btrfs truncate find sort xargs sha256sum jq; do
  command -v "$t" >/dev/null || { echo "run-scan: missing required tool: $t" >&2; exit 1; }
done
have_docker=1
command -v docker >/dev/null || have_docker=0

# --- Image source. ----------------------------------------------------------
# Empty means the default: build the synthetic btrfs images here, one per label.
# Set means scan the caller's pre-built before.raw / control.raw / after.raw;
# those are read-only sources (kept artifacts) and are never deleted, unlike the
# synthetic intermediates.
images_src=${ORACLE_IMAGES_DIR:-}
if [ -n "$images_src" ]; then
  [ -d "$images_src" ] || { echo "run-scan: ORACLE_IMAGES_DIR is not a directory: $images_src" >&2; exit 2; }
  images_src=$(cd "$images_src" && pwd)
  for label in "${LABELS[@]}"; do
    [ -f "$images_src/$label.raw" ] \
      || { echo "run-scan: ORACLE_IMAGES_DIR set but $label.raw is missing in $images_src" >&2; exit 2; }
  done
  for t in blkid debugfs mmls losetup dd cmp mount umount; do
    command -v "$t" >/dev/null \
      || { echo "run-scan: missing required tool for pre-built images: $t" >&2; exit 1; }
  done
  echo "==> scanning pre-built images from $images_src" >&2
fi

# --- Coverage canary and positive-control sentinels. ------------------------
# Synthetic mode: the canary and sentinels are planted into the freshly built
# images by make-sample-images.sh; ORACLE_SEED (or ORACLE_CANARY) rotates the
# canary per run, so a clean canary check proves the scan read THIS run's image,
# and the planted value is pinned in a run-time copy of controls.json, leaving
# the committed file untouched. Real-image mode (ORACLE_IMAGES_DIR): the canary
# was planted into the decoy at e2e time with the committed value and cannot be
# re-planted or rotated on a retained raw, so the committed controls-real.json
# is read verbatim; the positive-control sentinels are injected below into a
# throwaway working copy of after.raw.
canary_default="canary@oracle.example"
if [ -n "${ORACLE_SEED:-}" ]; then
  canary="canary+${ORACLE_SEED}@oracle.example"
elif [ -n "${ORACLE_CANARY:-}" ]; then
  canary="$ORACLE_CANARY"
else
  canary="$canary_default"
fi

# Positive-control sentinels (real-image mode only), the same reserved addresses
# the synthetic controls use so the controls-real.json pins are reusable.
SENTINELS=(unallocated-1@oracle.example unallocated-2@oracle.example unallocated-3@oracle.example)

allowlist="$repo_root/ci/oracle/allowlist.json"
# The on-image file that carries the canary. Every image has it, so a restore
# carve without it did not read the tree, and a plaso timeline with no event for
# it did not read the file system (see the checks below).
if [ -n "$images_src" ]; then
  # The canary is fixed at e2e time and the retained raws cannot be re-planted,
  # so it is never rotated here and controls-real.json is used verbatim.
  if [ -n "${ORACLE_SEED:-}" ] || [ -n "${ORACLE_CANARY:-}" ]; then
    echo "run-scan: ORACLE_SEED/ORACLE_CANARY ignored in ORACLE_IMAGES_DIR mode (the canary is planted at e2e time)" >&2
  fi
  canary="$canary_default"
  canary_file=/var/lib/nails-oracle/canary
  controls_used="$repo_root/ci/oracle/controls-real.json"
else
  canary_file=/var/lib/nails-oracle/canary.txt
  controls_src="$repo_root/ci/oracle/controls.json"
  if [ "$canary" = "$canary_default" ]; then
    controls_used="$controls_src"
  else
    # The default and any rotated canary are [A-Za-z0-9+.@-] only, so the
    # substitution is sed-safe; only the canary value differs from the committed file.
    controls_used="$work/controls.effective.json"
    sed "s|\"$canary_default\"|\"$canary\"|" "$controls_src" >"$controls_used"
  fi
fi
export ORACLE_CANARY="$canary"

# --- Build the pinned bulk_extractor once, with the loud drift guard. -------
echo "==> building pinned bulk_extractor $BE_TAG" >&2
be_src="$build/bulk_extractor"
git clone --quiet --depth 1 --branch "$BE_TAG" "$BE_REPO" "$be_src"
got=$(git -C "$be_src" rev-parse HEAD)
[ "$got" = "$BE_COMMIT" ] || { echo "bulk_extractor commit mismatch: $got != $BE_COMMIT" >&2; exit 1; }
if ! (
  set -e
  cd "$be_src"
  bash bootstrap.sh
  ./configure --disable-libewf --enable-silent-rules
  make -j"$(nproc)"
) >"$build/be-build.log" 2>&1; then
  echo "run-scan: bulk_extractor build failed; see $build/be-build.log" >&2
  tail -n 20 "$build/be-build.log" >&2 || true
  exit 1
fi
be_bin="$be_src/src/bulk_extractor"
[ -x "$be_bin" ] || { echo "run-scan: bulk_extractor binary missing at $be_bin" >&2; exit 1; }

# plaso_label <image> <label>: timeline one image through a fixed in-container
# path and export it to JSON lines. $N and the tool paths expand in the
# container's shell (from -e N=...), not here.
# shellcheck disable=SC2016
plaso_cmd='set -eu
l2t=$(command -v log2timeline.py || command -v log2timeline)
ps=$(command -v psort.py || command -v psort)
"$l2t" --unattended --status-view none --storage-file "/out/$N.plaso" /data/disk.img
"$ps" -o json_line -w "/out/$N.jsonl" "/out/$N.plaso"
rm -f "/out/$N.plaso"'

plaso_failed=0
plaso_label() {
  local img=$1 label=$2
  chmod a+r "$img"
  chmod -R a+rwX "$outputs/plaso"
  timeout 1200 docker run --rm \
    -e N="$label" \
    -v "$img":/data/disk.img:ro \
    -v "$outputs/plaso":/out \
    --entrypoint bash "$PLASO_IMAGE" -c "$plaso_cmd" </dev/null >&2
}

# --- Restore-channel carving (pluggable per filesystem). --------------------
# The restore channel recovers the file tree into outputs/restore/<label>/ so
# that each recovered entry stands for its absolute on-image path (the verdict
# keys a restore finding on that path, with the entry's kind as its field: a
# file, a directory or a symlink). btrfs and ext4 land the same shape there;
# only the carving tool differs.

# partition_slots, fs_partitions, detect_fs and partition_plan: what the
# partitions of a whole-disk image hold, and which of them is the root.
# shellcheck source=ci/oracle/partitions.sh
. "$here/partitions.sh"

# The read-only loop device a btrfs partition is carved through, detached by
# the EXIT trap if the carve stops the run.
carve_loop=""

# carve_restore <image> <dest> <fstype> <byte-offset> <byte-size>: recover the
# file tree into the empty <dest>, so <dest>/var/log/x stands for an on-image
# /var/log/x. btrfs uses `btrfs restore` with snapshots (-s) and symlinks (-S),
# through a read-only loop device for a partition; ext{2,3,4} uses `debugfs
# rdump /`, reading a partition through e2fsprogs' "<image>?offset=<bytes>"
# device form (debugfs has no offset option). Neither may pass over what it
# cannot read: btrfs restore runs without -i, so a file it cannot recover fails
# it, and since debugfs exits 0 even when it cannot open the image or a dump
# fails, any line on its stderr but its version banner fails the run. A
# filesystem with no carver here fails the run closed rather than leaving the
# channel empty: see the `*)` arm.
carve_restore() {
  local img=$1 dest=$2 fstype=$3 off=$4 size=$5 src=$1 log rc=0
  case "$fstype" in
    btrfs)
      if [ "$off" -gt 0 ]; then
        carve_loop=$(losetup -r -o "$off" --sizelimit "$size" --show -f "$img")
        src=$carve_loop
      fi
      btrfs restore -s -S "$src" "$dest" </dev/null >/dev/null
      if [ -n "$carve_loop" ]; then
        losetup -d "$carve_loop"
        carve_loop=""
      fi
      ;;
    ext2 | ext3 | ext4)
      if [ "$off" -gt 0 ]; then src="$img?offset=$off"; fi
      log="$work/debugfs.log"
      # debugfs splits its request on blanks; a double-quoted argument keeps a
      # destination with a space whole, with any quote in it doubled.
      debugfs -R "rdump / \"${dest//\"/\"\"}\"" "$src" >/dev/null 2>"$log" || rc=$?
      if [ "$rc" -ne 0 ] || grep -qvE '^r?debugfs [0-9]' "$log"; then
        echo "run-scan: debugfs could not carve $img (exit $rc); failing closed:" >&2
        cat "$log" >&2
        exit 1
      fi
      ;;
    *)
      # Fail closed. The restore channel recovers every on-image path and
      # what each file holds -- a new leftover file whose bytes are not
      # distinctively carvable, a file rewritten in place, an empty
      # directory, a symlink -- and no other channel compares those. A
      # filesystem it cannot carve is therefore a hard error with its reason,
      # not a skipped channel; the verdict would fail an empty channel too.
      # Add a carver for it (see README.md) or scan a btrfs or ext{2,3,4}
      # image.
      echo "run-scan: no restore carver for filesystem '$fstype' on $img; failing closed, since the scan cannot look at its files. Add a carver for '$fstype' (see ci/oracle/README.md) or scan a btrfs or ext{2,3,4} image." >&2
      exit 1
      ;;
  esac
}

# The read-only loop device and the mount point a vfat partition is carved
# through, undone by the EXIT trap if the carve stops the run.
vfat_loop=""
vfat_mnt=""

# carve_vfat <image> <byte-offset> <byte-size> <dest>: copy every directory and
# file of the vfat filesystem at <byte-offset> into the new <dest>. No carver
# here reads vfat offline, so it is mounted read-only from a read-only loop
# device, through which the kernel cannot write to the image. vfat keeps no
# owner, mode or link of its own, so the copy holds what the restore channel
# compares: the names, the directories and what each file holds.
carve_vfat() {
  local img=$1 off=$2 size=$3 dest=$4
  vfat_loop=$(losetup -r -o "$off" --sizelimit "$size" --show -f "$img")
  vfat_mnt=$(mktemp -d)
  mount -t vfat -o ro,nosuid,nodev,noexec,utf8 "$vfat_loop" "$vfat_mnt"
  mkdir "$dest"
  cp -a "$vfat_mnt/." "$dest/"
  umount "$vfat_mnt"
  rmdir "$vfat_mnt"
  vfat_mnt=""
  losetup -d "$vfat_loop"
  vfat_loop=""
}

# copy_bytes <image> <byte-offset> <byte-count> <file>: copy that stretch of
# the image into the new <file>, keeping runs of zeros as holes.
copy_bytes() {
  dd if="$1" of="$4" iflag=skip_bytes,count_bytes skip="$2" count="$3" bs=1M \
    conv=sparse status=none
  truncate -s "$3" "$4"
}

# claim_name <dest> <name> <what>: stop the run when the root filesystem's
# carve already holds <name>, where <what> would go.
claim_name() {
  if [ -e "$1/$2" ] || [ -L "$1/$2" ]; then
    echo "run-scan: the root filesystem holds /$2, where $3 would be carved; failing closed" >&2
    exit 1
  fi
}

# carve_other_partitions <image> <dest> <root-offset>: carve every part of a
# whole-disk image but the root at <root-offset> into <dest> as well, each at
# a top-level name of its own, so that the restore channel compares every
# byte of the disk outside the root filesystem's: each partition, from its
# place n in the partition table (partition_plan), a vfat partition's files
# into the directory partition-<n>-vfat and its boot sector, allocation
# tables and root directory into the file partition-<n>-vfat-structures, a
# partition holding no filesystem into the file partition-<n> with its bytes,
# and each stretch no partition covers (outside_partitions), the partition
# table among them, into outside-partitions/<offset>-<end>. A partition no
# carver reads stops the run (partition_plan says why), as does a root that
# already holds one of these names.
carve_other_partitions() {
  local img=$1 dest=$2 root_off=$3 plan gaps n start size kind bytes end
  plan=$(partition_plan "$img" "$root_off") || exit 1
  gaps=$(outside_partitions "$img") || exit 1
  while read -r n start size kind; do
    [ -n "$n" ] || continue
    case "$kind" in
      vfat)
        claim_name "$dest" "partition-$n-vfat" "partition $n"
        claim_name "$dest" "partition-$n-vfat-structures" "partition $n"
        bytes=$(vfat_structures_size "$img" "$start" "$size") || exit 1
        copy_bytes "$img" "$start" "$bytes" "$dest/partition-$n-vfat-structures"
        carve_vfat "$img" "$start" "$size" "$dest/partition-$n-vfat"
        ;;
      raw)
        claim_name "$dest" "partition-$n" "partition $n"
        copy_bytes "$img" "$start" "$size" "$dest/partition-$n"
        ;;
    esac
  done <<<"$plan"
  claim_name "$dest" outside-partitions "what lies outside the partitions"
  mkdir "$dest/outside-partitions"
  while read -r start end; do
    [ -n "$start" ] || continue
    copy_bytes "$img" "$start" $((end - start)) "$dest/outside-partitions/$start-$end"
  done <<<"$gaps"
}

# --- The Nix store database's rows. -----------------------------------------
# The oracle's decoy VMs register their store paths at every start (the QEMU
# test module's register-nix-paths), which rewrites pages of the store
# database, so its digest differs on every image and the verdict can only call
# the file noise. Its rows do not change with such a start: dump every one of
# them, so that a store path the session registered or removed, a reference or
# the raised sequence of a path it registered and collected again is a change
# of its own (the verdict's nix_db channel; see ci/oracle/README.md).
nix_db=/nix/var/nix/db/db.sqlite

# The SQL that writes, for the schema (sqlite_master) and for each table of a
# database, one query that prints every row of it as one JSON object a line:
# {"table": <its name>, "row": {<column>: <value>, ...}}. sqlite3 writes them
# from the schema itself, so a table a Nix version adds is read as well, and
# json_object names every column, so a row reads the same whatever order its
# columns come in. A name is quoted with its quotes doubled.
nix_db_queries=$(cat <<'SQL'
SELECT 'SELECT json_object(''table'', ' || quote(t.name) || ', ''row'', json_object('
       || group_concat(quote(c.name) || ', "' || replace(c.name, '"', '""') || '"', ', ')
       || ')) FROM "' || replace(t.name, '"', '""') || '";'
FROM (SELECT 'sqlite_master' AS name
      UNION ALL SELECT name FROM sqlite_master WHERE type = 'table') AS t
JOIN pragma_table_info(t.name) AS c
GROUP BY t.name
ORDER BY t.name;
SQL
)

# dump_nix_db <restored-tree> <dest>: write every row of the store database in
# the restored tree to <dest>, one JSON object a line (see nix_db_queries).
# sqlite3 reads a copy, with the write-ahead log beside it so rows not yet
# checkpointed into the database are read too, and never the restored files
# themselves, which are already hashed. A database it cannot read stops the
# run: its rows are the only view of that file.
dump_nix_db() {
  local tree=$1 dest=$2 copy="$work/nix-db" queries
  command -v sqlite3 >/dev/null \
    || { echo "run-scan: $tree holds the Nix store database $nix_db, and reading its rows needs sqlite3; failing closed" >&2; exit 1; }
  rm -rf "$copy"
  mkdir -p "$copy"
  cp "$tree$nix_db" "$copy/db.sqlite"
  if [ -f "$tree$nix_db-wal" ]; then cp "$tree$nix_db-wal" "$copy/db.sqlite-wal"; fi
  if ! queries=$(sqlite3 -bail "$copy/db.sqlite" "$nix_db_queries") \
    || ! sqlite3 -bail "$copy/db.sqlite" "$queries" >"$dest"; then
    echo "run-scan: sqlite3 could not read the rows of the Nix store database in $tree; failing closed" >&2
    exit 1
  fi
  rm -rf "$copy"
}

# --- Positive-control injection (real-image mode only). ---------------------
# Before scanning the 'after' image, copy after.raw to a sparse WORKING COPY and
# write each positive-control sentinel into its own zero-filled free block of
# the copy's filesystem, byte by byte and with no mount
# (plant-in-free-space.sh). The copy then differs from the captured image in
# those blocks alone, the way a leaked-then-deleted string sits in free space:
# no file, path or record changes, and nothing after.raw holds is overwritten.
# A read-write kernel mount would replay or restart the ext4 journal and
# rewrite the superblock, so the scanned 'after' would no longer be the
# captured image, nor read the way before and control are, which are never
# mounted. Only bulk_extractor reads free space, so only it sees the
# sentinels; the restore carve and plaso read the copy as they would read
# after.raw. before.raw, control.raw and the retained after.raw are never
# touched. The EXIT trap detaches a carve's loop device and unmounts a vfat
# carve; no global `losetup -D` is ever run.
# shellcheck disable=SC2329  # invoked indirectly by the EXIT trap below
cleanup() {
  if [ -n "$carve_loop" ]; then losetup -d "$carve_loop" 2>/dev/null || true; fi
  if [ -n "$vfat_mnt" ]; then
    umount "$vfat_mnt" 2>/dev/null || true
    rmdir "$vfat_mnt" 2>/dev/null || true
  fi
  if [ -n "$vfat_loop" ]; then losetup -d "$vfat_loop" 2>/dev/null || true; fi
}
trap cleanup EXIT

# inject_after_sentinels <working-image> <fstype> <byte-offset>: plant the
# sentinels into the working copy's ext{2,3,4} filesystem (its free blocks) or
# btrfs filesystem (the device space no chunk is allocated in). Any other
# filesystem stops the run: planting into it would need the mount this avoids.
inject_after_sentinels() {
  local img=$1 fstype=$2 off=$3 sentinel lines=()
  case "$fstype" in
    ext2 | ext3 | ext4 | btrfs) ;;
    *)
      echo "run-scan: cannot plant the positive controls in a $fstype image without mounting it read-write, which would change the image under test; failing closed. Scan an ext{2,3,4} or btrfs image (see ci/oracle/README.md)." >&2
      exit 1
      ;;
  esac
  for sentinel in "${SENTINELS[@]}"; do
    lines+=("nails-oracle positive control: $sentinel")
  done
  if ! "$here/plant-in-free-space.sh" "$img" "$off" "${lines[@]}"; then
    echo "run-scan: could not plant the positive controls in $img without overwriting anything; failing closed" >&2
    exit 1
  fi
}

# --- Whether the timeline runs: never on btrfs. ------------------------------
# plaso cannot open a btrfs file system, so on btrfs images no timeline runs
# and the scan says so (outputs/plaso/not-run). The before, control and after
# images are one host's disk, so they hold one file system: either all three
# are btrfs, or none is, and anything else stops the run, since a timeline of
# only some images would raise phantom residue.
if [ -n "$images_src" ]; then
  nbtrfs=0
  for label in "${LABELS[@]}"; do
    # detect_fs prints why when it fails.
    fs=$(detect_fs "$images_src/$label.raw") || exit 1
    read -r fstype _ _ <<<"$fs"
    if [ "$fstype" = btrfs ]; then nbtrfs=$((nbtrfs + 1)); fi
  done
else
  # The synthetic images are always bare btrfs.
  nbtrfs=${#LABELS[@]}
fi
case "$nbtrfs" in
  0) timeline=run ;;
  "${#LABELS[@]}") timeline=btrfs ;;
  *)
    echo "run-scan: $nbtrfs of the ${#LABELS[@]} images are btrfs and the others are not, but before, control and after are one disk; failing closed" >&2
    exit 1
    ;;
esac
# A rerun into the same workdir starts from no timeline and no marker.
rm -f "$outputs/plaso"/*.jsonl "$outputs/plaso"/*.plaso "$outputs/plaso/not-run" 2>/dev/null || true

# --- Pull the pinned plaso container once (not for btrfs images). ----------
plaso_ok=0
if [ "$timeline" = btrfs ]; then
  echo "==> btrfs images: plaso cannot read btrfs, so no timeline runs; the verdict can be partial at best, never a full run" >&2
elif [ "$have_docker" -ne 1 ]; then
  echo "run-scan: docker absent; the plaso channel cannot run, so the verdict will fail" >&2
else
  echo "==> pulling pinned plaso $PLASO_IMAGE" >&2
  if docker pull -q "$PLASO_IMAGE" >&2; then
    plaso_ok=1
  else
    echo "run-scan: plaso pull failed; the plaso channel cannot run, so the verdict will fail" >&2
  fi
fi

# --- Stream the three labels. -----------------------------------------------
for label in "${LABELS[@]}"; do
  echo "==> label $label" >&2

  # Image source: a caller-supplied pre-built raw, or a freshly built synthetic
  # btrfs image. In synthetic mode the filesystem is always our bare btrfs, so
  # the restore below is byte-for-byte the proven synthetic `btrfs restore`.
  if [ -n "$images_src" ]; then
    img="$images_src/$label.raw"
    # detect_fs prints why when it fails.
    fs=$(detect_fs "$img") || exit 1
    read -r fstype off size <<<"$fs"
    # The partitions of any kind on a whole-disk image (0 for a bare
    # filesystem): plaso stops on more than one, and its failure says so below.
    nparts=$(partition_slots "$img" | wc -l)
    if [ "$label" = after ]; then
      # Inject the positive controls into a sparse working copy; the retained
      # source raw is left untouched and is never scanned directly for 'after'.
      # The filesystem detected on the source applies to the copy (same bytes).
      injected="$work/after.injected.raw"
      rm -f "$injected"
      cp --sparse=always "$img" "$injected"
      inject_after_sentinels "$injected" "$fstype" "$off"
      img="$injected"
    fi
  else
    img="$images/$label.img"
    "$here/make-sample-images.sh" "$images" "$label"
    fstype=btrfs
    off=0
    size=0
    nparts=0
  fi

  # File-level restore into an empty tree, so a carve that recovers nothing
  # cannot pass on an earlier run's files.
  dest="$outputs/restore/$label"
  rm -rf "$dest" "$dest.sha256"
  mkdir -p "$dest"
  carve_restore "$img" "$dest" "$fstype" "$off" "$size"
  # A root in a partition: the disk's other partitions are carved too.
  if [ "$off" -gt 0 ]; then carve_other_partitions "$img" "$dest" "$off"; fi
  # A carver's exit status does not prove it read the tree, so check the carve
  # itself: every image carries the canary's file.
  if [ ! -f "$dest$canary_file" ]; then
    echo "run-scan: the restore carve of $img recovered no $canary_file, which every image carries; failing closed. The carver read nothing, or not the root filesystem." >&2
    exit 1
  fi
  # The verdict keys a recovered file on its path and its content, so record a
  # SHA-256 of every file before dropping the contents to free the disk for the
  # next tool. sha256sum --zero ends each record with a NUL and leaves the name
  # unescaped, so any file name survives. A file it cannot read fails the run
  # here, and nails-oracle stops on a file the manifest has no digest for.
  if ! (cd "$dest" && find . -type f -print0 | LC_ALL=C sort -z |
    xargs -0 -r sha256sum --zero --) >"$dest.sha256"; then
    echo "run-scan: could not hash the files the restore carve of $img recovered; failing closed" >&2
    exit 1
  fi
  # The rows of the store database go to outputs/nix_db/<label>.jsonl, exactly
  # when the tree holds the database as a file; nails-oracle stops on one
  # without the other.
  rm -f "$outputs/nix_db/$label.jsonl"
  if [ -f "$dest$nix_db" ] && [ ! -L "$dest$nix_db" ]; then
    dump_nix_db "$dest" "$outputs/nix_db/$label.jsonl"
  fi
  # The login record files (wtmp, btmp and their rotations) stay whole:
  # nails-oracle reads the records of the control image's, which on a
  # compressing filesystem bulk_extractor cannot carve (see
  # ci/oracle/README.md). These patterns keep at least every file it reads.
  find "$dest" -type f ! \( -name wtmp -o -name btmp -o -name 'wtmp[.-][0-9]*' -o -name 'btmp[.-][0-9]*' \) \
    -exec truncate -s 0 {} +

  # bulk_extractor creates outputs/bulk_extractor/<label> itself.
  "$be_bin" -j "$(nproc)" -o "$outputs/bulk_extractor/$label" "$img" >/dev/null

  # A timeline counts only when plaso read the image's file system: plaso dates
  # an image it cannot open as one opaque file, at the same path on every image,
  # so the timeline must have an event for the canary's file. On btrfs images
  # no timeline runs (see above).
  if [ "$timeline" = run ] && [ "$plaso_ok" -eq 1 ]; then
    if ! plaso_label "$img" "$label"; then
      echo "run-scan: plaso failed on $label" >&2
      if [ "$nparts" -gt 1 ]; then
        echo "run-scan: the $label image is a whole-disk image with $nparts partitions, and plaso, run unattended, stops rather than choose among them, so such an image fails the plaso channel. Scan the root filesystem's own image instead (see ci/oracle/README.md)." >&2
      fi
      plaso_failed=1
    elif ! "$here/timeline-has-file.sh" "$outputs/plaso/$label.jsonl" "$canary_file"; then
      echo "run-scan: plaso's timeline of $label has no event for $canary_file, which every image carries, so plaso did not read the image's $fstype file system (see ci/oracle/README.md)" >&2
      plaso_failed=1
    fi
  fi

  # Delete this label's synthetic image before building the next (bounded peak
  # disk). A caller-supplied pre-built image is a retained source; never delete
  # it.
  if [ -z "$images_src" ]; then rm -f "$img"; fi
done

# plaso is all-or-nothing: a partial timeline would make one image's events look
# new in another and raise phantom residue, so drop the channel whole if any
# label's timeline failed or did not read its image. A dropped channel never
# reads as clean: the restore channel leaves the rotating journal files to
# plaso, and nails-oracle fails a run in which any channel reported nothing for
# an image (channel_missing). The verdict is still rendered, so the other
# channels' findings can be read.
if [ "$timeline" = btrfs ]; then
  # Left out by design, never dropped: the marker says why, and nails-oracle
  # refuses it next to any timeline.
  printf 'btrfs\n' >"$outputs/plaso/not-run"
elif [ "$plaso_ok" -ne 1 ] || [ "$plaso_failed" -ne 0 ]; then
  echo "run-scan: dropping the plaso channel (a timeline is missing or did not read its image); the verdict will fail on it" >&2
  rm -f "$outputs/plaso"/*.jsonl "$outputs/plaso"/*.plaso 2>/dev/null || true
fi

# --- Render the verdict. ----------------------------------------------------
bin=${ORACLE_BIN:-$repo_root/target/release/nails-oracle}
[ -x "$bin" ] || { echo "run-scan: verdict binary not found at $bin" >&2; exit 2; }
echo "==> verdict" >&2
status=0
"$bin" "$outputs" --allowlist "$allowlist" --controls "$controls_used" \
  >"$work/verdict.json" || status=$?
cat "$work/verdict.json" || true
# The exit status alone does not pass a run: the verdict it wrote must say
# clean too, so a binary that exits 0 on anything else still fails here.
if [ "$status" -eq 0 ] && ! jq -e '.status == "clean"' "$work/verdict.json" >/dev/null; then
  echo "run-scan: nails-oracle exited 0, but $work/verdict.json does not say clean; failing closed" >&2
  status=1
fi
# A partial verdict (exit 3) passes only a scan of btrfs images that ran no
# timeline by design, and only when the verdict says partial and names exactly
# that. It is never reported as clean.
if [ "$status" -eq 3 ]; then
  partial='.status == "partial" and .not_run == [{"tool": "plaso", "channel": "timeline", "reason": "plaso cannot read btrfs"}]'
  if [ "$timeline" = btrfs ] && jq -e "$partial" "$work/verdict.json" >/dev/null; then
    note="PARTIAL verdict, not a full run: timeline: not run, plaso cannot read btrfs. The restore carve, the record diff and bulk_extractor ran and found nothing unexplained."
    echo "run-scan: $note" >&2
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning title=Partial oracle verdict::$note"; fi
    status=0
  else
    echo "run-scan: nails-oracle says partial, but this scan ran every channel or $work/verdict.json does not name the timeline of btrfs images as the one channel left out; failing closed" >&2
    status=1
  fi
fi
exit "$status"
