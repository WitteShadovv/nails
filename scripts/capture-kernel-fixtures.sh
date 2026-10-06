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
#       namespace (unshare -Urm) and captures its mountinfo and fdinfo. The
#       scratch prefix is rewritten to /fixture, so no host path is recorded.
#
#   capture-kernel-fixtures.sh vm OUTDIR
#       Run as root inside a NixOS test VM with an active NAILS session that
#       overlays /var (for example the decoy-journal-leak test, right after
#       `nails activate`). Captures the host's mountinfo, journald's mountinfo,
#       its journal fds and fdinfo, and the systemctl and loginctl output the
#       parsers consume, in exactly the invocations the code uses.
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

  # The exact invocations in manager/helpers/service_controller.rs and
  # manager/deactivation/session_guard.rs.
  systemctl list-units --type=service --all --no-legend --plain --no-pager \
    >"$out/systemctl-list-units-all.txt"
  systemctl list-units --type=service --state=active --no-legend --plain --no-pager \
    >"$out/systemctl-list-units-active.txt"
  systemctl is-active systemd-journald.service nails-absent.service \
    >"$out/systemctl-is-active.txt" || true
  systemctl show systemd-journald.service -p ActiveState -p SubState -p MainPID \
    >"$out/systemctl-show-journald.txt"
  loginctl list-sessions --no-legend >"$out/loginctl-list-sessions.txt" || true
  local id
  while read -r id _; do
    [ -n "$id" ] || continue
    loginctl show-session "$id" -p Class -p Type -p Name -p State -p Remote \
      >"$out/loginctl-show-session-$id.txt" || true
  done <"$out/loginctl-list-sessions.txt"
}

case $mode in
userns) capture_userns && echo "fixtures written to $out" ;;
userns-inner) capture_userns_inner ;;
vm) capture_vm && echo "fixtures written to $out" ;;
*) usage ;;
esac
