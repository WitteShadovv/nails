# Hidden-root and decoy-posture setup for the distribution smoke VMs.
#
# The NixOS suite backs the hidden root with a LUKS volume on a second disk
# (nix/e2e-tests/lib/hidden-volume.nix). nix-vm-test boots a stock Debian/Ubuntu
# cloud image with a single disk, and that disk is the decoy the forensic check
# images, so the hidden root must not live on it: a plain ext4 image file there
# would carry the hidden-session canaries in clear text straight into the scan.
# The backing file therefore sits on a dedicated tmpfs, which never reaches the
# decoy disk (the cloud images have no swap) and is gone after a reboot -- the
# amnesic property a real hidden volume gets from being detached. LUKS is used
# on top when cryptsetup ships (Ubuntu), plain ext4 on a loop device otherwise
# (Debian's generic cloud image has no cryptsetup); the overlay and leak
# assertions are identical either way.
#
# The backing file's tmpfs is mounted below /run, which a soft-reboot does not
# carry (only /run itself moves): after the switch the file is reachable only
# through the open loop device, and once the session ends and the mapping
# closes, it is gone.
#
# Every name is neutral ("data", "blk"): the loop device, the device-mapper name,
# the ext4 label and the mount points must never hint at hidden storage, because
# they survive in /dev, /dev/mapper, /proc/mounts and the kernel log.
{
  # Shell that creates and mounts the hidden root at /mnt/data. Idempotent: when
  # the root is still mounted it is reused as is, never re-formatted; after a
  # session it is gone and a fresh one is made.
  setupHiddenRoot = ''
    set -eu

    mountpoint=/mnt/data
    store=/run/blk
    backing="$store/data.img"

    if mountpoint -q "$mountpoint"; then
      echo "Hidden root already mounted at $mountpoint"
    else
      # A RAM-backed home for the backing file. The cap only bounds growth: the
      # 1 GiB image is sparse, so only what is written consumes memory.
      mkdir -p "$store"
      if ! mountpoint -q "$store"; then
        mount -t tmpfs -o size=1200m,mode=0700 tmpfs "$store"
      fi
      truncate -s 1G "$backing"

      if command -v cryptsetup >/dev/null 2>&1; then
        echo 'cryptsetup present: backing the hidden root with LUKS'
        # PBKDF2 with --iter-time 1 keeps formatting fast and avoids Argon2's
        # memory cost in a small VM; acceptable for a test passphrase.
        echo -n 'test-passphrase' | cryptsetup luksFormat -q --type luks2 \
          --pbkdf pbkdf2 --iter-time 1 "$backing" -
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
    fi

    # The whole-root layout: the root overlay's work directory (its upper is
    # created at activation with the decoy root's mode and owner) and the
    # configuration directory.
    mkdir -p "$mountpoint"/root/work "$mountpoint"/config

    echo 'Hidden root ready at '"$mountpoint"
  '';

  # Make the decoy amnesic so the decoy-persistence preflight passes: journald
  # to volatile storage, and any active disk log sink (rsyslog on Ubuntu)
  # stopped. A stock cloud image keeps a persistent journal, which the preflight
  # refuses by design; the smoke test exercises both the refusal and this fix.
  #
  # NAILS reads `Storage=` from the main /etc/systemd/journald.conf only, so the
  # setting is appended there (the last assignment wins); the drop-in keeps
  # journald itself volatile even if a vendor drop-in would override the main
  # file. The names are neutral: these files stay on the decoy disk.
  makeDecoyAmnesic = ''
    set -eu
    printf '\n[Journal]\nStorage=volatile\n' >> /etc/systemd/journald.conf
    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nStorage=volatile\n' > /etc/systemd/journald.conf.d/zz-volatile.conf
    systemctl restart systemd-journald

    # rsyslog is socket-activated through syslog.socket on Ubuntu, so both are
    # masked: a masked service cannot be re-activated by the socket.
    if systemctl is-active --quiet rsyslog.service; then
      systemctl mask --now rsyslog.service syslog.socket
    fi
    for unit in syslog-ng.service auditd.service; do
      if systemctl is-active --quiet "$unit"; then
        systemctl mask --now "$unit"
      fi
    done
  '';
}
