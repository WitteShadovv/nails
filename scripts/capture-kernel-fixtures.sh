#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Capture real kernel and systemd output as parser test fixtures, so the parser
# tests run against what the kernel and the tools actually print instead of
# hand-written strings. The output lands in nails-base/tests/fixtures/kernel/.
#
#   capture-kernel-fixtures.sh userns OUTDIR
#       Unprivileged. Builds an overlay scene inside a fresh user + mount
#       namespace (unshare -Urm) and captures its mountinfo, a hidden-root
#       scene (a tmpfs named after a mapper device, an overlay with its upper
#       on it and a shadowed overlay pair), the stat and status of a setsid
#       child with an awkward comm, and /proc/swaps with its file names
#       neutralised. The scratch prefix is rewritten to /fixture, so no host
#       path is recorded.
#
#   capture-kernel-fixtures.sh vm OUTDIR
#       Run as root inside a NixOS test VM, in the hidden root of an active
#       NAILS session (the decoy-journal-leak test, right after `nails
#       activate`). Captures the session's mountinfo, /proc/swaps, journald's
#       stat, status and cgroup, and the systemd version in exactly the two
#       invocations the code uses.
#
#   capture-kernel-fixtures.sh blockdev OUTDIR
#       Run as root on a throwaway machine with cryptsetup and lvm2 (the
#       research-blockdev-fixtures VM test). Builds an ext4 logical volume on
#       a LUKS2 mapping of a GPT partition of a loop device over a file in a
#       tmpfs, records the sysfs attributes the block-device walk reads for
#       every device of that stack, and tears the stack down again. The
#       scratch path is rewritten to /fixture.
#
# Re-run only when a kernel, systemd or NAILS change alters these formats, and
# review the diff before committing: the VM capture is synthetic, but check it
# anyway for anything that should not be published.
set -euo pipefail

usage() {
  echo "usage: $0 {userns|vm|blockdev} OUTDIR" >&2
  exit 2
}

[ $# -eq 2 ] || usage
mode=$1
out=$2
mkdir -p "$out"
out=$(cd "$out" && pwd)

capture_userns() {
  # Re-enter this script inside the namespace; the inner half does the work.
  unshare -Urm --propagation private "$0" userns-inner "$out"
}

# Inside the namespace: tmpfs scratch, a base /var-like tmpfs and an overlay on
# top of it with awkward layer names.
capture_userns_inner() {
  local scratch
  scratch=$(mktemp -d)
  mount -t tmpfs -o mode=0755 scratch "$scratch"
  mkdir -p "$scratch/var" "$scratch/lower, with:colon" \
    "$scratch/upper\\dir" "$scratch/work dir"
  mount -t tmpfs -o mode=0755 basevar "$scratch/var"
  # The production overlay options, escaped as escape_overlay_path does.
  mount -t overlay overlay -o nosuid,nodev \
    -o "lowerdir=$scratch/lower\\, with\\:colon,upperdir=$scratch/upper\\\\dir,workdir=$scratch/work dir,index=off,metacopy=off,redirect_dir=nofollow" \
    "$scratch/var"

  # Only the scene's own mounts, with the random scratch path made stable.
  grep -F " $scratch" /proc/self/mountinfo | sed "s|$scratch|/fixture|g" \
    >"$out/mountinfo-overlay-scene.txt"
  uname -sr >"$out/kernel.txt"

  capture_hidden_root_scene
  capture_odd_process
  capture_swaps
}

# A hidden-volume stand-in: a tmpfs whose source names a mapper device mounted
# at a root with a space in it, a /home overlay whose upper lives on it, and a
# /nix/store overlay shadowed by a later /nix overlay (the shape NAILS leaves
# when it overlays /nix). Only the mount table is recorded.
capture_hidden_root_scene() {
  local scene hidden opts
  scene=$(mktemp -d)
  mount -t tmpfs -o mode=0755 scene "$scene"
  hidden="$scene/mnt/hidden root"
  mkdir -p "$hidden" "$scene/home" "$scene/nix/store"
  mount -t tmpfs -o mode=0700 /dev/mapper/vault "$hidden"
  mkdir -p "$hidden/overlays/home/upper" "$hidden/overlays/home/work" \
    "$hidden/overlays/store/upper" "$hidden/overlays/store/work" \
    "$hidden/overlays/nix/upper" "$hidden/overlays/nix/work"
  opts=index=off,metacopy=off,redirect_dir=nofollow
  mount -t overlay overlay -o nosuid,nodev \
    -o "lowerdir=$scene/home,upperdir=$hidden/overlays/home/upper,workdir=$hidden/overlays/home/work,$opts" \
    "$scene/home"
  mount -t overlay overlay -o nosuid,nodev \
    -o "lowerdir=$scene/nix/store,upperdir=$hidden/overlays/store/upper,workdir=$hidden/overlays/store/work,$opts" \
    "$scene/nix/store"
  mount -t overlay overlay -o nosuid,nodev \
    -o "lowerdir=$scene/nix,upperdir=$hidden/overlays/nix/upper,workdir=$hidden/overlays/nix/work,$opts" \
    "$scene/nix"
  grep -F " $scene" /proc/self/mountinfo | sed "s|$scene|/fixture|g" \
    >"$out/mountinfo-hidden-root.txt"
}

# A child in its own session and process group whose comm holds ") (" and
# spaces, the case a naive /proc/<pid>/stat split gets wrong.
capture_odd_process() {
  local pid tries=0
  # The shell renames itself through /proc/self/comm, then waits on a child
  # (the trailing exit keeps bash from exec'ing its last command).
  # shellcheck disable=SC2016 # expanded by the inner shell
  setsid bash -c 'printf "x) (y z" >/proc/self/comm; sleep 30; exit' &
  pid=$!
  until [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "x) (y z" ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 500 ] || { echo "the odd-comm child never started" >&2; exit 1; }
    sleep 0.01
  done
  cat "/proc/$pid/stat" >"$out/proc-stat-setsid-odd-comm.txt"
  cat "/proc/$pid/status" >"$out/proc-status-setsid-odd-comm.txt"
  kill -- "-$pid" # the whole process group: the shell and its sleep
}

# /proc/swaps is not namespaced: this is the host's. Each file name becomes
# /fixture/swapN, re-padded the way the kernel pads it (to column 40, at least
# one space), so the layout stays the kernel's and no host path is recorded.
capture_swaps() {
  awk 'NR == 1 { print; next }
    { name = "/fixture/swap" (NR - 1); pad = 40 - length(name); if (pad < 1) pad = 1
      rest = $0; sub(/^[^ \t]+ +/, "", rest)
      printf "%s%*s%s\n", name, pad, "", rest }' /proc/swaps >"$out/proc-swaps.txt"
}

capture_vm() {
  local pid
  uname -sr >"$out/kernel.txt"
  # The two invocations session/systemd.rs reads the version through.
  systemctl --version | head -1 >"$out/systemd-version.txt"
  systemctl show -p Version --value >"$out/systemd-show-version.txt"
  cat /proc/self/mountinfo >"$out/mountinfo-host.txt"
  cat /proc/swaps >"$out/proc-swaps.txt"

  pid=$(pgrep -x systemd-journal | head -1)
  cat "/proc/$pid/stat" >"$out/proc-stat-journald.txt"
  cat "/proc/$pid/status" >"$out/proc-status-journald.txt"
  cat "/proc/$pid/cgroup" >"$out/proc-cgroup-journald.txt"
}

# An ext4 logical volume on a LUKS2 mapping of the first GPT partition of a
# loop device over a file in a tmpfs. Nothing of it touches a disk: the
# volume group skips LVM's metadata backups, the passphrase is a fixed word
# and the LUKS uuid a fixed value, so the capture holds nothing of the host.
capture_blockdev() {
  local scene loop mnt dev
  scene=$(mktemp -d /run/nails-blockdev.XXXXXX)
  mount -t tmpfs -o size=96m,mode=0700 scene "$scene"
  truncate -s 64M "$scene/disk.img"
  loop=$(losetup --find --show --partscan "$scene/disk.img")
  printf 'label: gpt\nsize=56MiB, name=scene\n' | sfdisk --quiet "$loop"
  udevadm settle
  printf scene | cryptsetup luksFormat --batch-mode --type luks2 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --uuid 6e61696c-7300-4000-8000-000000000001 --key-file - "${loop}p1"
  printf scene | cryptsetup open --key-file - "${loop}p1" scenecrypt
  pvcreate --quiet /dev/mapper/scenecrypt
  vgcreate --quiet --autobackup n scenevg /dev/mapper/scenecrypt
  lvcreate --quiet --yes --autobackup n --name data --extents 100%FREE scenevg
  mkfs.ext4 -q /dev/scenevg/data
  mnt=$scene/mnt
  mkdir "$mnt"
  mount /dev/scenevg/data "$mnt"

  dev=$(mountpoint --fs-devno "$mnt")
  {
    echo "# capture-kernel-fixtures.sh blockdev on $(uname -sr)"
    grep -F " $mnt " /proc/self/mountinfo | sed "s|$scene|/fixture|g; s|^|mount\t|"
    record_link "/sys/dev/block/$dev"
    record_stack "$(readlink -f "/sys/dev/block/$dev")"
  } >"$out/blockdev-lvm-on-luks.txt"

  umount "$mnt"
  vgchange --quiet --activate n scenevg
  cryptsetup close scenecrypt
  losetup --detach "$loop"
  umount "$scene"
  rmdir "$scene"
}

# A symlink as a `link` record, with its target resolved.
record_link() {
  printf 'link\t%s\t%s\n' "$1" "$(readlink -f "$1")"
}

# A one-line `file` record: backslashes doubled, newlines written as \n.
record_file() {
  [ -r "$1" ] || return 0
  printf 'file\t%s\t%s\n' "$1" "$(sed 's/\\/\\\\/g' "$1" | awk '{ printf "%s\\n", $0 }')"
}

# The attributes the walk reads for the device whose sysfs directory is $1, the
# entries of its slaves/ and holders/, the disk of a partition, and the same
# for every device below it.
record_stack() {
  local dir=$1 attribute sub entry
  for attribute in dev uevent ro size partition start dm/name dm/uuid \
    queue/discard_max_bytes loop/backing_file loop/offset loop/sizelimit \
    loop/autoclear; do
    record_file "$dir/$attribute"
  done
  for sub in slaves holders; do
    [ -d "$dir/$sub" ] || continue # a partition has no slaves/
    printf 'dir\t%s\t%s\n' "$dir/$sub" \
      "$(find "$dir/$sub" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ' | sed 's/ $//')"
  done
  if [ -r "$dir/partition" ]; then
    record_file "${dir%/*}/dev"
    record_file "${dir%/*}/uevent"
  fi
  for entry in "$dir"/slaves/*; do
    [ -e "$entry" ] || continue
    record_link "$entry"
    record_stack "$(readlink -f "$entry")"
  done
}

case $mode in
userns) capture_userns && echo "fixtures written to $out" ;;
userns-inner) capture_userns_inner ;;
vm) capture_vm && echo "fixtures written to $out" ;;
blockdev) capture_blockdev && echo "fixtures written to $out" ;;
*) usage ;;
esac
