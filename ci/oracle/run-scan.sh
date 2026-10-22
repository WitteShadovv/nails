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
# plaso reads every image through one fixed in-container path (/data/disk.img),
# so the source path in its timeline is identical across the three images and
# the before/control/after findings collapse as they must.
#
# Image source is pluggable. By default the three synthetic btrfs images are
# built here, one at a time (the proven path). Setting ORACLE_IMAGES_DIR to a
# directory holding before.raw / control.raw / after.raw scans those real decoy
# images instead -- e.g. the raws the e2e disk-forensics harness retains -- and
# the restore channel is carved per detected filesystem (btrfs restore for the
# synthetic btrfs images, debugfs rdump for the ext4 decoy roots). The
# bulk_extractor and plaso channels read the image bytes directly and are
# identical either way.
#
#   sudo run-scan.sh <workdir>
#   sudo env ORACLE_IMAGES_DIR=/path/with/before.raw,control.raw,after.raw run-scan.sh <workdir>
#
# Needs root (loop mounts), btrfs-progs, git + the bulk_extractor build chain,
# and docker (for the pinned plaso container); pre-built-image mode also needs
# sleuthkit (mmls) and e2fsprogs (debugfs) plus util-linux (blkid). The verdict
# binary is found at $ORACLE_BIN, or target/release/nails-oracle under the
# repository root. No KVM.
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
command -v docker >/dev/null || { echo "run-scan: docker absent; the plaso channel is skipped" >&2; have_docker=0; }

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
  for t in blkid debugfs mmls; do
    command -v "$t" >/dev/null \
      || { echo "run-scan: missing required tool for pre-built images: $t" >&2; exit 1; }
  done
  echo "==> scanning pre-built images from $images_src" >&2
fi

# --- Coverage canary. -------------------------------------------------------
# By default the fixed committed canary is planted and the verdict reads the
# committed ci/oracle/controls.json verbatim. Setting ORACLE_SEED (or
# ORACLE_CANARY) rotates the canary per run, so a clean canary check proves the
# scan read THIS run's freshly built image rather than a stale output; the
# planted value is then pinned in a run-time copy of the controls file that the
# verdict reads instead, leaving the committed file untouched.
canary_default="canary@oracle.example"
if [ -n "${ORACLE_SEED:-}" ]; then
  canary="canary+${ORACLE_SEED}@oracle.example"
elif [ -n "${ORACLE_CANARY:-}" ]; then
  canary="$ORACLE_CANARY"
else
  canary="$canary_default"
fi
export ORACLE_CANARY="$canary"

controls_src="$repo_root/ci/oracle/controls.json"
allowlist="$repo_root/ci/oracle/allowlist.json"
if [ "$canary" = "$canary_default" ]; then
  controls_used="$controls_src"
else
  # The default and any rotated canary are [A-Za-z0-9+.@-] only, so the
  # substitution is sed-safe; only the canary value differs from the committed file.
  controls_used="$work/controls.effective.json"
  sed "s|\"$canary_default\"|\"$canary\"|" "$controls_src" >"$controls_used"
fi

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
    echo "run-scan: plaso pull failed; the plaso channel is skipped" >&2
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
# that each recovered regular file stands for its absolute on-image path (the
# verdict keys a restore finding on that path alone, with an empty field). btrfs
# and ext4 land the same shape there; only the carving tool differs.

# partition_offset <image>: the 512-byte sector start of the Linux filesystem
# partition on a whole-disk image, or 0 for a bare (unpartitioned) filesystem.
# Mirrors disk_forensics.partition_offset: pick the Linux/ext partition with the
# greatest start. mawk-safe (no gawk match() captures).
partition_offset() {
  local img=$1
  command -v mmls >/dev/null 2>&1 || { echo 0; return; }
  mmls "$img" 2>/dev/null | awk '
    /^[0-9]+:/ {
      start = $3; desc = "";
      for (i = 6; i <= NF; i++) desc = desc " " $i;
      dl = tolower(desc);
      if (dl ~ /linux/ || dl ~ /ext/) { if (start + 0 > best + 0) best = start + 0 }
    }
    END { print best + 0 }'
}

# detect_fs <image>: print "<fstype> <sector-offset>". A bare filesystem probes
# at offset 0; otherwise the Linux partition of a whole-disk image is probed at
# its own offset. An unrecognised image prints an empty fstype.
detect_fs() {
  local img=$1 t off=0
  t=$(blkid -o value -s TYPE "$img" 2>/dev/null || true)
  if [ -n "$t" ]; then
    printf '%s 0\n' "$t"
    return
  fi
  off=$(partition_offset "$img")
  if [ "$off" -gt 0 ]; then
    t=$(blkid -o value -s TYPE -O "$((off * 512))" "$img" 2>/dev/null || true)
  fi
  # A non-empty placeholder keeps the two fields aligned for `read`.
  printf '%s %s\n' "${t:-unknown}" "$off"
}

# carve_restore <image> <dest> <fstype> <sector-offset>: recover the file tree
# into <dest>. btrfs uses `btrfs restore` (the synthetic path, bare image,
# offset 0); ext{2,3,4} uses `debugfs rdump /` at the partition's byte offset,
# exactly as disk_forensics._rdump lifts a tree out of an ext4 image. Both leave
# <dest>/var/log/x for an on-image /var/log/x.
carve_restore() {
  local img=$1 dest=$2 fstype=$3 off=$4
  case "$fstype" in
    btrfs)
      btrfs restore -i "$img" "$dest" >/dev/null
      ;;
    ext2 | ext3 | ext4)
      if [ "$off" -gt 0 ]; then
        debugfs -o "$((off * 512))" -R "rdump / $dest" "$img" >/dev/null 2>&1
      else
        debugfs -R "rdump / $dest" "$img" >/dev/null 2>&1
      fi
      ;;
    *)
      echo "run-scan: unrecognised filesystem '$fstype' on $img; restore channel skipped" >&2
      ;;
  esac
}

# --- Stream the three labels. -----------------------------------------------
for label in "${LABELS[@]}"; do
  echo "==> label $label" >&2

  # Image source: a caller-supplied pre-built raw, or a freshly built synthetic
  # btrfs image. In synthetic mode the filesystem is always our bare btrfs, so
  # the restore below is byte-for-byte the proven synthetic `btrfs restore`.
  if [ -n "$images_src" ]; then
    img="$images_src/$label.raw"
    read -r fstype off < <(detect_fs "$img")
    off=${off:-0}
  else
    img="$images/$label.img"
    "$here/make-sample-images.sh" "$images" "$label"
    fstype=btrfs
    off=0
  fi

  # File-level restore, then keep only the recovered paths: the verdict keys a
  # restore finding on the path alone, so the contents are dropped to free the
  # bulk of the disk before the next tool.
  mkdir -p "$outputs/restore/$label"
  carve_restore "$img" "$outputs/restore/$label" "$fstype" "$off"
  find "$outputs/restore/$label" -type f -exec truncate -s 0 {} +

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
# label's timeline failed. A missing plaso subtree is non-fatal for the verdict.
if [ "$plaso_ok" -ne 1 ] || [ "$plaso_failed" -ne 0 ]; then
  echo "run-scan: dropping the plaso channel (incomplete across labels)" >&2
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
