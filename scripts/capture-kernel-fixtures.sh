#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Capture real kernel and systemd output as parser test fixtures, so the parser
# tests run against what the kernel and the tools actually print instead of
# hand-written strings. The output lands in nails-core/tests/fixtures/kernel/.
#
#   capture-kernel-fixtures.sh userns OUTDIR
#       Unprivileged. Builds an overlay scene inside a fresh user + mount
#       namespace (unshare -Urm) and captures its mountinfo and fdinfo, a
#       hidden-root scene (a tmpfs named after a mapper device, an overlay with
#       its upper on it and a shadowed overlay pair), the stat and status of a
#       setsid child with an awkward comm, and /proc/swaps with its file names
#       neutralised. The scratch prefix is rewritten to /fixture, so no host
#       path is recorded.
#
#   capture-kernel-fixtures.sh vm OUTDIR
#       Run as root inside a NixOS test VM with an active NAILS session that
#       overlays /var (for example the decoy-journal-leak test, right after
#       `nails activate`). Captures the host's mountinfo, journald's mountinfo,
#       its journal fds and fdinfo, logind's session records, and the systemctl
#       and loginctl output the parsers consume, in exactly the invocations the
#       code uses.
#
# Re-run only when a kernel, systemd or NAILS change alters these formats, and
# review the diff before committing: the VM capture is synthetic, but check it
# anyway for anything that should not be published.
set -euo pipefail

usage() {
  echo "usage: $0 {userns|vm} OUTDIR" >&2
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

# Inside the namespace: tmpfs scratch, a base /var-like tmpfs with an fd held on
# it, an overlay on top with awkward layer names, and an fd through the overlay.
capture_userns_inner() {
  local scratch fd_dir
  scratch=$(mktemp -d)
  mount -t tmpfs -o mode=0755 scratch "$scratch"
  mkdir -p "$scratch/var/log/journal/m" "$scratch/lower, with:colon" \
    "$scratch/upper\\dir" "$scratch/work dir"
  mount -t tmpfs -o mode=0755 basevar "$scratch/var"
  mkdir -p "$scratch/var/log/journal/m"
  exec 7>>"$scratch/var/log/journal/m/system.journal" # stale fd, base /var
  # The production overlay options, escaped as escape_overlay_path does.
  mount -t overlay overlay -o nosuid,nodev \
    -o "lowerdir=$scratch/lower\\, with\\:colon,upperdir=$scratch/upper\\\\dir,workdir=$scratch/work dir,index=off,metacopy=off,redirect_dir=nofollow" \
    "$scratch/var"
  mkdir -p "$scratch/var/log/journal/m"
  exec 8>>"$scratch/var/log/journal/m/system.journal" # re-homed fd, overlay
  exec 9<"$scratch/var/log/journal/m/system.journal"  # read-only fd, overlay

  # Only the scene's own mounts, with the random scratch path made stable.
  grep -F " $scratch" /proc/self/mountinfo | sed "s|$scratch|/fixture|g" \
    >"$out/mountinfo-overlay-scene.txt"
  fd_dir=/proc/self/fdinfo
  cat "$fd_dir/7" >"$out/fdinfo-append-base.txt"
  cat "$fd_dir/8" >"$out/fdinfo-append-overlay.txt"
  cat "$fd_dir/9" >"$out/fdinfo-readonly-overlay.txt"
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
  local pid fd target name
  uname -sr >"$out/kernel.txt"
  systemctl --version | head -1 >"$out/systemd-version.txt"
  cat /proc/self/mountinfo >"$out/mountinfo-host.txt"
  cat /proc/swaps >"$out/proc-swaps.txt"

  pid=$(pgrep -x systemd-journal | head -1)
  cat "/proc/$pid/mountinfo" >"$out/mountinfo-journald.txt"
  cat "/proc/$pid/stat" >"$out/proc-stat-journald.txt"
  cat "/proc/$pid/status" >"$out/proc-status-journald.txt"
  cat "/proc/$pid/cgroup" >"$out/proc-cgroup-journald.txt"
  : >"$out/journald-fds.txt"
  for fd in "/proc/$pid/fd/"*; do
    target=$(readlink "$fd") || continue
    case $target in
    /var/log/journal/* | /run/log/journal/*)
      name=$(basename "$fd")
      printf '%s %s\n' "$name" "$target" >>"$out/journald-fds.txt"
      cat "/proc/$pid/fdinfo/$name" >"$out/fdinfo-journald-$name.txt"
      ;;
    esac
  done

  # The exact invocations in manager/helpers/service_controller.rs,
  # overlay_mount/journald_fd.rs and target_user.rs.
  systemctl list-units --type=service --all --no-legend --plain --no-pager \
    >"$out/systemctl-list-units-all.txt"
  systemctl list-units --type=service --state=active --no-legend --plain --no-pager \
    >"$out/systemctl-list-units-active.txt"
  systemctl is-active systemd-journald.service nails-absent.service \
    >"$out/systemctl-is-active.txt" || true
  systemctl show -p MainPID --value systemd-journald.service \
    >"$out/systemctl-show-journald-mainpid.txt"
  local session
  session=$(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null) || true
  printf '%s\n' "$session" >"$out/loginctl-seat0-active-session.txt"
  if [ -n "$session" ]; then
    loginctl show-session "$session" -p User --value \
      >"$out/loginctl-show-session-user.txt" || true
    # The cgroup of a process of that session, which the emergency kill spares.
    local leader
    leader=$(loginctl show-session "$session" -p Leader --value) || leader=
    [ -z "$leader" ] || cat "/proc/$leader/cgroup" >"$out/proc-cgroup-session-leader.txt"
  fi

  # logind's own session records, which nails-teardown/src/session.rs reads
  # (the .ref FIFOs are skipped).
  mkdir -p "$out/logind-sessions"
  local record
  for record in /run/systemd/sessions/*; do
    [ -f "$record" ] || continue
    cp "$record" "$out/logind-sessions/"
  done
}

case $mode in
userns) capture_userns && echo "fixtures written to $out" ;;
userns-inner) capture_userns_inner ;;
vm) capture_vm && echo "fixtures written to $out" ;;
*) usage ;;
esac
