# Hidden-root setup for the distribution smoke VMs.
#
# The NixOS suite backs the hidden root with a LUKS volume on a second disk
# (nix/e2e-tests/lib/hidden-volume.nix). A stock Debian/Ubuntu cloud image has
# no second disk and may not ship cryptsetup, so the distro tier backs the
# hidden root with a loop-mounted ext4 image file instead, and uses LUKS only
# when cryptsetup is present. Either way the on-disk directory layout is the one
# nix/e2e-tests/lib/backends.nix lays down, so one overlay-only activation drives
# any backend.
#
# Every on-disk name is neutral ("data"): the loop device, the device-mapper
# name, the ext4 label and the mount point must never hint at hidden storage,
# because they survive in /dev, /dev/mapper, /proc/mounts and the kernel log.
{
  # Shell that creates and mounts the hidden root at /mnt/data. `cryptsetup`
  # gates the LUKS branch: when it is missing the root is plain ext4, which is a
  # supported fallback, not a weaker test -- the overlay and leak assertions are
  # identical either way.
  setupHiddenRoot = ''
    set -eu

    backing=/var/tmp/data.img
    mountpoint=/mnt/data

    # A 1 GiB sparse backing file is ample for the smoke canaries and keeps the
    # decoy image small. truncate leaves it sparse until written.
    truncate -s 1G "$backing"

    if command -v cryptsetup >/dev/null 2>&1; then
      echo 'cryptsetup present: backing the hidden root with LUKS'
      # --iter-time 1 keeps formatting fast; acceptable for a test passphrase.
      echo -n 'test-passphrase' | cryptsetup luksFormat -q --iter-time 1 "$backing" -
      echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - "$backing" data
      mkfs.ext4 -q -L data /dev/mapper/data
      mkdir -p "$mountpoint"
      mount /dev/mapper/data "$mountpoint"
    else
      echo 'cryptsetup absent: backing the hidden root with plain ext4 on loop'
      loop=$(losetup --show -f "$backing")
      mkfs.ext4 -q -L data "$loop"
      mkdir -p "$mountpoint"
      mount "$loop" "$mountpoint"
    fi

    # The overlay upper/work layout NAILS expects, mirroring
    # nix/e2e-tests/lib/backends.nix nailsDirStructure.
    mkdir -p "$mountpoint"/home "$mountpoint"/etc "$mountpoint"/var "$mountpoint"/nix
    mkdir -p "$mountpoint"/.work/home "$mountpoint"/.work/etc \
      "$mountpoint"/.work/var "$mountpoint"/.work/nix
    mkdir -p "$mountpoint"/config "$mountpoint"/config/nixos "$mountpoint"/nixos
    # The FHS backend overlays more trees than the NixOS one; give each an upper.
    mkdir -p "$mountpoint"/srv "$mountpoint"/opt "$mountpoint"/tmp
    mkdir -p "$mountpoint"/.work/srv "$mountpoint"/.work/opt "$mountpoint"/.work/tmp

    echo 'Hidden root ready at '"$mountpoint"
  '';

  # Switch journald to volatile storage so the decoy-persistence preflight
  # passes. A stock cloud image keeps a persistent journal, which the preflight
  # refuses by design; the smoke test exercises both the refusal and this fix.
  makeJournalVolatile = ''
    set -eu
    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nStorage=volatile\n' \
      > /etc/systemd/journald.conf.d/00-nails-volatile.conf
    systemctl restart systemd-journald
  '';
}
