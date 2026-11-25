#!/usr/bin/env bash
# The install that runs inside the Arch live ISO (see build.sh).
#
# The ISO's own automated-script hook runs this on tty1: build.sh boots the
# ISO's kernel with `script=<url of this file>`, and the live system fetches
# and runs it once root is logged in there. It installs Arch with archinstall,
# from the package snapshot the mirrorlist names, onto the first SATA disk, and
# writes what it did to the output disk (label NAILSOUT): `status` ("ok" or the
# failure), the logs, the package list and the layout. Then it powers off,
# which ends QEMU and hands control back to build.sh.
set -Eeuo pipefail

out=/run/nails-out
target=/dev/sda
exec > >(tee /dev/ttyS0) 2>&1

finish() {
  local status=$1
  if mountpoint -q "$out"; then
    cp /var/log/archinstall/install.log "$out/archinstall.log" 2>/dev/null || true
    journalctl -b --no-pager >"$out/live-journal.txt" 2>/dev/null || true
    printf '%s\n' "$status" >"$out/status"
    sync
    umount "$out" || true
  fi
  echo "nails-arch-install: $status"
  systemctl poweroff
  exit 0
}
trap 'finish "failed at line $LINENO"' ERR

# The directory this script was fetched from, which serves the other files.
base=
for param in $(</proc/cmdline); do
  case "$param" in
    script=*) base=${param#script=} ;;
  esac
done
base=${base%/*}
[ -n "$base" ] || finish "no script= on the kernel command line"

mkdir -p "$out"
for _ in $(seq 60); do
  [ -e /dev/disk/by-label/NAILSOUT ] && break
  sleep 1
done
mount /dev/disk/by-label/NAILSOUT "$out"

# The automated script starts while boot services still run (pacman-init,
# which sets up the live keyring, and reflector, which rewrites the
# mirrorlist). Wait for them, then pin the mirrorlist to the snapshot: pacstrap
# copies it into the target, so the installed system uses it too.
timeout 900 systemctl is-system-running --wait || true
systemctl stop reflector.service reflector.timer || true
curl -fsS --retry 5 "$base/mirrorlist" -o /etc/pacman.d/mirrorlist
cat /etc/pacman.d/mirrorlist

work=/root/nails-install
mkdir -p "$work"
for file in disk_layout.py user_configuration.json user_credentials.json; do
  curl -fsS --retry 5 "$base/$file" -o "$work/$file"
done

pacman -Q archinstall >"$out/archinstall-version.txt"
python3 "$work/disk_layout.py" "$target" >"$work/disk_config.json"
python3 - "$work" <<'PY'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])
config = json.loads((work / "user_configuration.json").read_text())
config["disk_config"] = json.loads((work / "disk_config.json").read_text())
(work / "config.json").write_text(json.dumps(config, indent=2))
PY
cp "$work/config.json" "$out/config.json"

# --skip-ntp: the live clock comes from the host's RTC, and an NTP sync over
# QEMU's user network may never finish. --skip-wkd: the keyring is the ISO's,
# from the same day as the snapshot.
archinstall \
  --config "$work/config.json" \
  --creds "$work/user_credentials.json" \
  --silent \
  --skip-ntp \
  --skip-wkd \
  --skip-version-check \
  --skip-wifi-check
grep -q 'Installation completed without any errors' /var/log/archinstall/install.log

# archinstall leaves the target mounted at /mnt.
mountpoint -q /mnt

# What the test harness needs beyond archinstall's own result: the kernel
# console on the serial line the test driver reads, as nix-vm-test sets it
# for arch-boxes.
sed -i 's/^options .*/& console=tty0 console=ttyS0/' /mnt/boot/loader/entries/*.conf

# The image ships without the downloaded packages: every test VM would fetch
# them only to keep them in the cache.
find /mnt/var/cache/pacman/pkg -mindepth 1 -delete

{
  echo "== findmnt"
  findmnt -R /mnt
  echo "== btrfs subvolumes"
  btrfs subvolume list /mnt
  echo "== /etc/fstab"
  cat /mnt/etc/fstab
  echo "== loader.conf"
  cat /mnt/boot/loader/loader.conf
  for entry in /mnt/boot/loader/entries/*.conf; do
    echo "== $entry"
    cat "$entry"
  done
  echo "== ESP"
  find /mnt/boot -maxdepth 3
  echo "== zram"
  cat /mnt/etc/systemd/zram-generator.conf
  echo "== users"
  grep -E '^(root|arch):' /mnt/etc/passwd
  grep -E '^wheel:' /mnt/etc/group
} >"$out/layout.txt"
pacman --root /mnt --dbpath /mnt/var/lib/pacman -Q >"$out/packages.txt"

# The checks that a test needs these to hold, so a change of archinstall's
# defaults fails the build rather than a test later.
test -f /mnt/boot/EFI/BOOT/BOOTX64.EFI
ls /mnt/boot/loader/entries/*.conf
grep -Eq '[[:space:]]/[[:space:]]+btrfs[[:space:]].*subvol=/@([,[:space:]]|$)' /mnt/etc/fstab
grep -Eq '[[:space:]]/home[[:space:]]+btrfs[[:space:]].*subvol=/@home' /mnt/etc/fstab
grep -Eq '[[:space:]]/boot[[:space:]]+vfat[[:space:]]' /mnt/etc/fstab
grep -q '^arch:' /mnt/etc/passwd
test -f /mnt/etc/systemd/zram-generator.conf

# Free the blocks the package cache held, so the image does not carry them.
fstrim -v /mnt || true
fstrim -v /mnt/boot || true
sync
umount -R /mnt

finish ok
