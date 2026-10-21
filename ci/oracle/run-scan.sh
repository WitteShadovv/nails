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
#   sudo run-scan.sh <workdir>
#
# Needs root (loop mounts), btrfs-progs, git + the bulk_extractor build chain,
# and docker (for the pinned plaso container). The verdict binary is found at
# $ORACLE_BIN, or target/release/nails-oracle under the repository root. No KVM.
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

# --- Stream the three labels. -----------------------------------------------
for label in "${LABELS[@]}"; do
  img="$images/$label.img"
  echo "==> label $label" >&2
  "$here/make-sample-images.sh" "$images" "$label"

  # btrfs file-level restore, then keep only the recovered paths: the verdict
  # keys a restore finding on the path alone, so the contents are dropped to
  # free the bulk of the disk before the next tool.
  mkdir -p "$outputs/restore/$label"
  btrfs restore -i "$img" "$outputs/restore/$label" >/dev/null
  find "$outputs/restore/$label" -type f -exec truncate -s 0 {} +

  # bulk_extractor creates outputs/bulk_extractor/<label> itself.
  "$be_bin" -j "$(nproc)" -o "$outputs/bulk_extractor/$label" "$img" >/dev/null

  if [ "$plaso_ok" -eq 1 ]; then
    plaso_label "$img" "$label" || { echo "run-scan: plaso failed on $label" >&2; plaso_failed=1; }
  fi

  # Delete this label's image before building the next (bounded peak disk).
  rm -f "$img"
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
