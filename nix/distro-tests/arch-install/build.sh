# shellcheck shell=bash
# Build the archinstall test image (see default.nix, which wraps this script and
# sets ISO, GUEST, INPUTS, OVMF_CODE, OVMF_VARS and OVMF_FD).
#
#   build-arch-install-image <out-dir> <asset-name>
#
# It boots the pinned Arch ISO's own kernel in QEMU under UEFI (OVMF) with a
# blank disk, and the ISO's automated-script hook runs install.sh there, which
# installs Arch with archinstall from the pinned package snapshot. Then it
# boots the installed disk once under UEFI as the test harness does and waits
# for its login prompt on the serial line, and writes into <out-dir>:
#
#   <asset-name>          the image, a compressed qcow2 under 2 GiB
#   <asset-name>.sha256   its SHA-256 in sha256sum's format
#   <asset-name>.json     the manifest: the hash in Nix's SRI form, the size,
#                         the pinned inputs and the installed packages
#   logs/                 both serial logs and what install.sh wrote
#
# Needs /dev/kvm. Nothing here reads a secret.
set -euo pipefail

die() {
  echo "build-arch-install-image: $*" >&2
  exit 1
}

[ "$#" -eq 2 ] || die "usage: build-arch-install-image <out-dir> <asset-name>"
asset=$2
case "$asset" in
  arch-install-*.qcow2) ;;
  *) die "the asset name must be arch-install-<something>.qcow2, not '$asset'" ;;
esac
case "$asset" in
  */* | *[[:space:]]*) die "the asset name must be a plain file name" ;;
esac
if ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; then
  die "/dev/kvm is not usable"
fi

mkdir -p "$1/logs"
out=$(realpath "$1")
logs=$out/logs
work=$(mktemp -d "${TMPDIR:-/tmp}/arch-install.XXXXXX")
http_pid=
boot_pid=
install_pid=
cleanup() {
  [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
  [ -z "$install_pid" ] || kill "$install_pid" 2>/dev/null || true
  [ -z "$boot_pid" ] || kill "$boot_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
export MTOOLS_SKIP_CHECK=1

# The live system's kernel and initramfs, booted directly so that the kernel
# command line can carry `script=`. archiso finds its root by the ISO's volume
# UUID, which is the build time of the ISO.
mkdir "$work/iso"
bsdtar -xf "$ISO" -C "$work/iso" arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img
iso_uuid=$(blkid -o value -s UUID "$ISO")
[ -n "$iso_uuid" ] || die "the ISO has no volume UUID"
live_options="archisobasedir=arch archisosearchuuid=$iso_uuid"

# What the live system fetches: install.sh and its files, and a mirrorlist
# that names the snapshot alone.
mkdir "$work/serve"
cp "$GUEST"/* "$work/serve/"
printf 'Server = %s\n' "$(jq -er .packages.server "$INPUTS")" >"$work/serve/mirrorlist"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -m http.server --bind 127.0.0.1 --directory "$work/serve" "$port" >"$logs/http.log" 2>&1 &
http_pid=$!

qemu-img create -q -f qcow2 "$work/disk.qcow2" "$(jq -er .disk.size "$INPUTS")"
truncate -s 64M "$work/out.img"
mkfs.vfat -n NAILSOUT "$work/out.img" >/dev/null
install -m 0644 "$OVMF_VARS" "$work/vars.fd"

# The machine the harness boots (nix-vm-test): the default i440fx machine, the
# root disk on IDE, so that the initramfs archinstall builds for this machine
# holds the drivers the test VMs need.
common=(
  -machine "pc,accel=kvm"
  -cpu max
  -m 4096
  -smp "$(nproc)"
  -device virtio-rng-pci
  -netdev "user,id=net0"
  -device "virtio-net-pci,netdev=net0"
  -display none
  -monitor none
  -no-reboot
)

echo "Installing from $(basename "$ISO") (live system $iso_uuid)"
# The ISO goes on a virtio-scsi CD drive, as archiso's own run_archiso attaches
# it: the live initramfs finds no IDE CD drive.
qemu-system-x86_64 "${common[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$work/vars.fd" \
  -kernel "$work/iso/arch/boot/x86_64/vmlinuz-linux" \
  -initrd "$work/iso/arch/boot/x86_64/initramfs-linux.img" \
  -append "$live_options console=tty0 console=ttyS0,115200 script=http://10.0.2.2:$port/install.sh" \
  -device virtio-scsi-pci,id=scsi0 \
  -device scsi-cd,bus=scsi0.0,drive=cdrom0 \
  -drive id=cdrom0,if=none,format=raw,media=cdrom,readonly=on,file="$ISO" \
  -drive file="$work/disk.qcow2",format=qcow2,if=ide,discard=unmap \
  -drive file="$work/out.img",format=raw,if=virtio \
  -serial file:"$logs/install-serial.log" &
install_pid=$!

# Watch the install: stop at once when the live system cannot start (the
# initramfs drops to its rescue shell, or the kernel panics), and after 90
# minutes in any case, rather than wait out the job's timeout.
for _ in $(seq 5400); do
  kill -0 "$install_pid" 2>/dev/null || break
  if grep -q -e 'ERROR: Device' -e 'Kernel panic' -e "can't access tty" "$logs/install-serial.log" 2>/dev/null; then
    kill "$install_pid" 2>/dev/null || true
    wait "$install_pid" 2>/dev/null || true
    tail -n 40 "$logs/install-serial.log" >&2 || true
    die "the live system did not start (see logs/install-serial.log)"
  fi
  sleep 1
done
if kill -0 "$install_pid" 2>/dev/null; then
  kill "$install_pid" 2>/dev/null || true
  wait "$install_pid" 2>/dev/null || true
  tail -n 80 "$logs/install-serial.log" >&2 || true
  die "the install VM did not finish within 90 minutes (see logs/install-serial.log)"
fi
wait "$install_pid" || die "the install VM failed (see logs/install-serial.log)"

mcopy -s -n -i "$work/out.img" '::*' "$logs/" || true
status=$(cat "$logs/status" 2>/dev/null || echo "no status written")
[ "$status" = ok ] || {
  tail -n 80 "$logs/install-serial.log" >&2 || true
  die "the install did not finish: $status"
}

# One boot of the result under UEFI, the way the harness boots it: OVMF with
# no saved boot entries, so systemd-boot starts from the ESP's fallback path.
echo "Booting the installed image"
qemu-system-x86_64 "${common[@]}" \
  -bios "$OVMF_FD" \
  -drive file="$work/disk.qcow2",format=qcow2,if=ide,snapshot=on \
  -serial file:"$logs/boot-serial.log" &
boot_pid=$!
booted=
for _ in $(seq 300); do
  if grep -q 'login:' "$logs/boot-serial.log" 2>/dev/null; then
    booted=yes
    break
  fi
  kill -0 "$boot_pid" 2>/dev/null || break
  sleep 1
done
kill "$boot_pid" 2>/dev/null || true
wait "$boot_pid" 2>/dev/null || true
boot_pid=
[ -n "$booted" ] || {
  tail -n 80 "$logs/boot-serial.log" >&2 || true
  die "the installed image did not reach a login prompt (see logs/boot-serial.log)"
}

echo "Compressing"
qemu-img convert -c -O qcow2 "$work/disk.qcow2" "$out/$asset"
size=$(stat -c %s "$out/$asset")
limit=$((2 * 1024 * 1024 * 1024))
[ "$size" -lt "$limit" ] || die "$asset is $size bytes, not under the 2 GiB release-asset limit"

hex=$(sha256sum "$out/$asset" | cut -d' ' -f1)
printf '%s  %s\n' "$hex" "$asset" >"$out/$asset.sha256"
sri=$(python3 -c 'import base64, sys; print("sha256-" + base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' "$hex")
jq -n \
  --arg asset "$asset" \
  --arg sha256 "$sri" \
  --arg sha256Hex "$hex" \
  --argjson size "$size" \
  --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg archinstall "$(cat "$logs/archinstall-version.txt")" \
  --slurpfile inputs "$INPUTS" \
  --rawfile packages "$logs/packages.txt" \
  '{
    asset: $asset,
    sha256: $sha256,
    sha256Hex: $sha256Hex,
    size: $size,
    built: $built,
    iso: $inputs[0].iso,
    packages: $inputs[0].packages,
    archinstall: $archinstall,
    installed: ($packages | split("\n") | map(select(. != "")))
  }' >"$out/$asset.json"

echo "Built $asset: $size bytes, sha256 $hex ($sri)"
