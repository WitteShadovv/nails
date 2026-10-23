#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the synthetic before/control/after images and run the pinned disk-image
# analysis tools over them into the outputs/ tree the nails-oracle verdict tool
# reads, then render the verdict.
#
# Streaming, so peak disk is one image's worth and not the sum of all three: for
# each label in turn it builds that one image, runs btrfs restore (then
# truncates the recovered file contents to zero, keeping only the recovered
# paths the verdict keys on), bulk_extractor and plaso over it, and deletes the
# image and the bulky plaso store before moving to the next label. The small
# per-tool outputs for finished labels stay; nothing bulky accumulates.
#
# A scan that could not look never passes: a carve that recovers nothing or
# reports an error stops the run, and nails-oracle fails a run in which any
# channel reported nothing for an image (channel_missing), so a dropped plaso
# channel fails it too.
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
# ext{2,3,4} partition. The bulk_extractor and plaso channels read the image
# bytes directly and are identical either way.
#
#   sudo run-scan.sh <workdir>
#   sudo env ORACLE_IMAGES_DIR=/path/with/before.raw,control.raw,after.raw run-scan.sh <workdir>
#
# Needs root (loop mounts), btrfs-progs, git + the bulk_extractor build chain,
# and docker (for the pinned plaso container; without it the verdict fails on
# the missing plaso channel); pre-built-image mode also needs sleuthkit (mmls)
# and e2fsprogs (debugfs) plus util-linux (blkid, losetup). The verdict binary
# is found at $ORACLE_BIN, or target/release/nails-oracle under the repository
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
mkdir -p "$images" "$outputs/restore" "$outputs/bulk_extractor" "$outputs/plaso" "$build"

[ "$(id -u)" -eq 0 ] || { echo "run-scan: must run as root (loop mounts)" >&2; exit 1; }
for t in git make btrfs mkfs.btrfs truncate find; do
  command -v "$t" >/dev/null || { echo "run-scan: missing required tool: $t" >&2; exit 1; }
done
have_docker=1
command -v docker >/dev/null || { echo "run-scan: docker absent; the plaso channel cannot run, so the verdict will fail" >&2; have_docker=0; }

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
  for t in blkid debugfs mmls losetup; do
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
WTMP_SENTINEL=${ORACLE_WTMP_SENTINEL:-wtmpdb-boot@oracle.example}
LASTLOG_SENTINEL=${ORACLE_LASTLOG_SENTINEL:-lastlog2@oracle.example}
PKG_SENTINEL=${ORACLE_PKG_SENTINEL:-pkg-history@oracle.example}

allowlist="$repo_root/ci/oracle/allowlist.json"
# The on-image file that carries the canary. Every image has it, so a restore
# carve without it did not read the tree (see the carve check below).
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

# --- Pull the pinned plaso container once. ----------------------------------
plaso_ok=0
if [ "$have_docker" -eq 1 ]; then
  echo "==> pulling pinned plaso $PLASO_IMAGE" >&2
  if docker pull -q "$PLASO_IMAGE" >&2; then
    plaso_ok=1
  else
    echo "run-scan: plaso pull failed; the plaso channel cannot run, so the verdict will fail" >&2
  fi
fi

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

# fs_partitions <image>: one "<fstype> <byte-offset> <byte-size>" line per
# partition of a whole-disk image that holds a filesystem blkid recognises, and
# nothing for an image with no partition table. mmls lists the partitions in
# the units it names; its descriptions are only the GPT partition names or the
# MBR type, so blkid probes each partition's own superblock for the type (it
# honours -O and -S only in its low-level mode, -p). mawk-safe: %.0f, not %d,
# for byte counts past 2^31.
fs_partitions() {
  local img=$1 table start size t
  table=$(mmls "$img" 2>/dev/null) || return 0
  while read -r start size; do
    t=$(blkid -p -o value -s TYPE -O "$start" -S "$size" "$img" 2>/dev/null || true)
    if [ -n "$t" ]; then printf '%s %s %s\n' "$t" "$start" "$size"; fi
  done < <(awk '
    BEGIN { unit = 512 }
    /^Units are in [0-9]+-byte sectors/ { unit = $4 + 0 }
    $1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+(:[0-9]+)?$/ {
      printf "%.0f %.0f\n", ($3 + 0) * unit, ($5 + 0) * unit
    }' <<<"$table")
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
      # Fail closed. The restore channel recovers every on-image path -- a
      # new leftover file whose bytes are not distinctively carvable, an empty
      # directory, a symlink -- and nails-oracle leans on it (it drops
      # bulk_extractor's carved recorders on the premise that restore recovers
      # every real file by its path). A filesystem it cannot carve is
      # therefore a hard error with its reason, not a skipped channel; the
      # verdict would fail an empty channel too. Add a carver for it (see
      # README.md) or scan a btrfs or ext{2,3,4} image.
      echo "run-scan: no restore carver for filesystem '$fstype' on $img; failing closed, since the scan cannot look at its files. Add a carver for '$fstype' (see ci/oracle/README.md) or scan a btrfs or ext{2,3,4} image." >&2
      exit 1
      ;;
  esac
}

# --- Positive-control injection (real-image mode only). ---------------------
# Before scanning the 'after' image, copy after.raw to a sparse WORKING COPY and
# append the positive-control sentinels in place to the baseline carrier files
# the decoy already carries, so only the new @oracle address differs and no new
# on-image path appears (the carriers already exist on before/control, so the
# restore channel's after - before - control set difference keeps subtracting
# their paths; only the carved address is new). before.raw, control.raw and the
# retained after.raw are never touched. The working copy is loop-mounted
# read-write at the filesystem's byte offset (from detect_fs) and is unmounted
# under a cleanup trap, which also detaches a carve's loop device; no global
# `losetup -D` is ever run.
inject_mnt=""
# shellcheck disable=SC2329  # invoked indirectly by the EXIT trap below
cleanup() {
  if [ -n "$inject_mnt" ] && mountpoint -q "$inject_mnt" 2>/dev/null; then
    umount "$inject_mnt" 2>/dev/null || umount -l "$inject_mnt" 2>/dev/null || true
  fi
  if [ -n "$carve_loop" ]; then losetup -d "$carve_loop" 2>/dev/null || true; fi
}
trap cleanup EXIT

# inject_after_sentinels <working-image> <byte-offset> <byte-size>: mount the
# working copy read-write and append the three sentinels in place,
# byte-for-byte as make-sample-images.sh's apply_after_changes does, so plaso
# and the restore channel behave exactly as on the proven synthetic path.
inject_after_sentinels() {
  local img=$1 off=$2 size=$3 opts
  opts="loop,rw,offset=$off"
  if [ "$size" -gt 0 ]; then opts="$opts,sizelimit=$size"; fi
  inject_mnt="$work/inject.mnt"
  mkdir -p "$inject_mnt"
  mount -o "$opts" "$img" "$inject_mnt"
  printf 'login\tnails-oracle\tpts/9\t%s\t2026-01-01T00:05:00+00:00\n' \
    "$WTMP_SENTINEL" >>"$inject_mnt/var/log/wtmp.db"
  printf 'nails-oracle\tpts/9\t%s\t2026-01-01T00:05:00+00:00\n' \
    "$LASTLOG_SENTINEL" >>"$inject_mnt/var/lib/lastlog/lastlog2.db"
  printf '[2026-01-01T00:05:00+0000] [ALPM] installed nails-oracle-marker (%s)\n' \
    "$PKG_SENTINEL" >>"$inject_mnt/var/log/pacman.log"
  sync
  umount "$inject_mnt"
  inject_mnt=""
}

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
    if [ "$label" = after ]; then
      # Inject the positive controls into a sparse working copy; the retained
      # source raw is left untouched and is never scanned directly for 'after'.
      # The filesystem detected on the source applies to the copy (same bytes).
      injected="$work/after.injected.raw"
      rm -f "$injected"
      cp --sparse=always "$img" "$injected"
      inject_after_sentinels "$injected" "$off" "$size"
      img="$injected"
    fi
  else
    img="$images/$label.img"
    "$here/make-sample-images.sh" "$images" "$label"
    fstype=btrfs
    off=0
    size=0
  fi

  # File-level restore into an empty tree, so a carve that recovers nothing
  # cannot pass on an earlier run's files. Then keep only the recovered paths:
  # the verdict keys a restore finding on the path alone, so the contents are
  # dropped to free the bulk of the disk before the next tool.
  dest="$outputs/restore/$label"
  rm -rf "$dest"
  mkdir -p "$dest"
  carve_restore "$img" "$dest" "$fstype" "$off" "$size"
  # A carver's exit status does not prove it read the tree, so check the carve
  # itself: every image carries the canary's file.
  if [ ! -f "$dest$canary_file" ]; then
    echo "run-scan: the restore carve of $img recovered no $canary_file, which every image carries; failing closed. The carver read nothing, or not the root filesystem." >&2
    exit 1
  fi
  find "$dest" -type f -exec truncate -s 0 {} +

  # bulk_extractor creates outputs/bulk_extractor/<label> itself.
  "$be_bin" -j "$(nproc)" -o "$outputs/bulk_extractor/$label" "$img" >/dev/null

  if [ "$plaso_ok" -eq 1 ]; then
    plaso_label "$img" "$label" || { echo "run-scan: plaso failed on $label" >&2; plaso_failed=1; }
  fi

  # Delete this label's synthetic image before building the next (bounded peak
  # disk). A caller-supplied pre-built image is a retained source; never delete
  # it.
  if [ -z "$images_src" ]; then rm -f "$img"; fi
done

# plaso is all-or-nothing: a partial timeline would make one image's events look
# new in another and raise phantom residue, so drop the channel whole if any
# label's timeline failed. A dropped channel never reads as clean: the restore
# channel leaves the rotating journal files to plaso, and nails-oracle fails a
# run in which any channel reported nothing for an image (channel_missing). The
# verdict is still rendered, so the other channels' findings can be read.
if [ "$plaso_ok" -ne 1 ] || [ "$plaso_failed" -ne 0 ]; then
  echo "run-scan: dropping the plaso channel (incomplete across labels); the verdict will fail on it" >&2
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
exit "$status"
