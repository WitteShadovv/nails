#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the forensic oracle's synthetic btrfs images. It writes, into the given
# directory, one small btrfs image per label:
#   before.img   a clean, representative decoy baseline
#   control.img  a content-identical rebuild of before (the noise baseline)
#   after.img    before plus the planted self-checks (the image under test)
#
# The three share one filesystem UUID and label and differ only by the few
# sentinel bytes the 'after' image adds, so the oracle's after - before -
# control set difference is exact: every finding that is not a planted
# self-check collapses across the images and subtracts away.
#
# What 'after' adds, and nothing else:
#   - one e-mail-shaped sentinel appended in place to each of three baseline
#     carriers (a wtmpdb login row, a lastlog2 row, a pacman history line), each
#     carrying a unique reserved @oracle.example address. bulk_extractor carves
#     the address from the raw image bytes with no format-aware parser, so each
#     surfaces as an exact (bulk_extractor, email, <address>) finding that the
#     ci/oracle/controls.json positive controls pin. The carrier files already
#     exist on before/control with baseline content, so only the address is new
#     and the file paths are unchanged.
# A coverage canary (a reserved @oracle.example address, rotatable per run via
# ORACLE_CANARY) is planted on every image at an otherwise-uncovered path, so
# finding it proves the scan read the image.
#
# The content is deterministic -- fixed text, fixed timestamps, a fixed UUID --
# so a rerun builds the same thing. btrfs records internal generation counters,
# so the image files are not guaranteed byte-identical across runs, but their
# contents are, which is what the analysis tools read.
#
#   sudo make-sample-images.sh <output-dir> [before|control|after]
#
# With a label, only that one image is built (the streaming scan builds them one
# at a time); with no label, all three are built. Needs root (loop mount) plus
# btrfs-progs. No network, no KVM.
set -euo pipefail

export PATH="/usr/sbin:/sbin:$PATH"

out=${1:?usage: make-sample-images.sh <output-dir> [before|control|after]}
only_label=${2:-}
mkdir -p "$out"
out=$(cd "$out" && pwd)
mnt="$out/.mnt"

# Deterministic knobs; every default is overridable so the scan can rotate the
# canary and the sentinels per run without editing this script.
IMG_SIZE=${IMG_SIZE:-512M}
CONTACTS=${ORACLE_CONTACTS:-300}
LOGLINES=${ORACLE_LOGLINES:-500}
CANARY=${ORACLE_CANARY:-canary@oracle.example}
WTMP_SENTINEL=${ORACLE_WTMP_SENTINEL:-wtmpdb-boot@oracle.example}
LASTLOG_SENTINEL=${ORACLE_LASTLOG_SENTINEL:-lastlog2@oracle.example}
PKG_SENTINEL=${ORACLE_PKG_SENTINEL:-pkg-history@oracle.example}
FS_UUID=${ORACLE_FS_UUID:-0a0a0a0a-0b0b-0c0c-0d0d-0e0e0e0e0e0e}
FS_LABEL=${ORACLE_FS_LABEL:-decoy}
STAMP="${ORACLE_STAMP:-2026-01-01 00:00:00 +0000}"

[ "$(id -u)" -eq 0 ] || { echo "make-sample-images: must run as root (loop mount)" >&2; exit 1; }
command -v mkfs.btrfs >/dev/null || { echo "make-sample-images: btrfs-progs required" >&2; exit 1; }
modprobe btrfs loop 2>/dev/null || true

cleanup() {
  set +e
  if mountpoint -q "$mnt"; then umount "$mnt"; fi
  rmdir "$mnt" 2>/dev/null
}
trap cleanup EXIT
mkdir -p "$mnt"

# populate_base <root>: the baseline present on every image.
populate_base() {
  local r=$1 i
  mkdir -p \
    "$r/etc" "$r/home/user/docs" "$r/var/log" "$r/var/lib/lastlog" \
    "$r/var/lib/nixos" "$r/var/lib/systemd/timesync" "$r/var/lib/systemd/timers" \
    "$r/var/lib/nails-oracle"

  printf 'decoy-host\n' >"$r/etc/hostname"
  cat >"$r/etc/os-release" <<'EOF'
NAME="Synthetic Decoy"
ID=decoy
VERSION_ID="1"
PRETTY_NAME="Synthetic Decoy Linux"
EOF
  printf 'id=42\nname=sample\nmode=baseline\n' >"$r/etc/app.conf"

  # Reserved-example features so a feature scan has e-mails and URLs to carve;
  # identical on every image, so they subtract away and never count as residue.
  : >"$r/home/user/docs/contacts.txt"
  for ((i = 1; i <= CONTACTS; i++)); do
    printf 'contact %d: user%d@example.com, admin%d@example.org\n' "$i" "$i" "$i"
    printf 'see https://example.com/item/%d and https://example.net/r/%d\n' "$i" "$i"
  done >>"$r/home/user/docs/contacts.txt"

  # A syslog-shaped text log for the timeliner to parse.
  : >"$r/var/log/app.log"
  for ((i = 1; i <= LOGLINES; i++)); do
    printf 'Jan 01 00:%02d:%02d decoy-host service[%d]: event %d processed\n' \
      "$(((i / 60) % 60))" "$((i % 60))" "$((1000 + i % 97))" "$i"
  done >>"$r/var/log/app.log"

  # Representative decoy residue paths. Identical on every image, so the control
  # subtraction removes them; on a real image they are what the cited allowlist
  # entries (var-lib-nixos, timesync-clock, timer-stamps) vouch for.
  printf 'user:1000\n' >"$r/var/lib/nixos/declarative-users"
  printf '1000 1000\n' >"$r/var/lib/nixos/uid-map"
  printf 'clock\n' >"$r/var/lib/systemd/timesync/clock"
  printf 'stamp\n' >"$r/var/lib/systemd/timers/stamp-logrotate.timer"

  # Baseline login/boot and package carriers, with no reserved oracle address.
  # On 'after', apply_after_changes appends one sentinel line to each in place.
  cat >"$r/var/log/wtmp.db" <<'EOF'
# synthetic wtmpdb login/boot carrier
boot	~	localhost	2026-01-01T00:00:00+00:00
login	root	localhost	2026-01-01T00:01:00+00:00
login	user	localhost	2026-01-01T00:02:00+00:00
EOF
  cat >"$r/var/lib/lastlog/lastlog2.db" <<'EOF'
# synthetic lastlog2 last-login carrier
root	pts/0	localhost	2026-01-01T00:01:00+00:00
user	tty1	localhost	2026-01-01T00:02:00+00:00
EOF
  cat >"$r/var/log/pacman.log" <<'EOF'
[2026-01-01T00:00:00+0000] [PACMAN] Running 'pacman -Syu'
[2026-01-01T00:00:01+0000] [ALPM] installed base (3.0-1)
[2026-01-01T00:00:02+0000] [ALPM] installed coreutils (9.5-1)
EOF

  # Coverage canary on every image (rotatable via ORACLE_CANARY).
  printf '# NAILS forensic-oracle coverage canary (synthetic)\ncanary address: %s\n' \
    "$CANARY" >"$r/var/lib/nails-oracle/canary.txt"
}

# apply_after_changes <root>: the only differences the 'after' image carries.
# Each sentinel is a reserved @oracle.example address in a text field, appended
# in place so the carrier's path is unchanged and only the address is new.
apply_after_changes() {
  local r=$1
  printf 'login\tnails-oracle\tpts/9\t%s\t2026-01-01T00:05:00+00:00\n' \
    "$WTMP_SENTINEL" >>"$r/var/log/wtmp.db"
  printf 'nails-oracle\tpts/9\t%s\t2026-01-01T00:05:00+00:00\n' \
    "$LASTLOG_SENTINEL" >>"$r/var/lib/lastlog/lastlog2.db"
  printf '[2026-01-01T00:05:00+0000] [ALPM] installed nails-oracle-marker (%s)\n' \
    "$PKG_SENTINEL" >>"$r/var/log/pacman.log"
}

# make_one_image <image-path> <label>
make_one_image() {
  local img=$1 label=$2
  rm -f "$img"
  truncate -s "$IMG_SIZE" "$img"
  mkfs.btrfs -f -m single -d single -U "$FS_UUID" -L "$FS_LABEL" "$img" >/dev/null
  mount -o loop "$img" "$mnt"
  populate_base "$mnt"
  if [ "$label" = after ]; then apply_after_changes "$mnt"; fi
  # Fixed mtimes so the tree is deterministic regardless of build order.
  find "$mnt" -depth -exec touch -h -d "$STAMP" {} +
  sync
  umount "$mnt"
  printf '  built %-8s -> %s\n' "$label" "$img" >&2
}

if [ -n "$only_label" ]; then
  case "$only_label" in
    before | control | after) make_one_image "$out/$only_label.img" "$only_label" ;;
    *) echo "make-sample-images: unknown label '$only_label' (want before|control|after)" >&2; exit 1 ;;
  esac
else
  for l in before control after; do make_one_image "$out/$l.img" "$l"; done
fi
