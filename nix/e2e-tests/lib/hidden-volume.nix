# Hidden Volume Simulation for E2E Tests
# Provides LUKS-based hidden volume simulation using secondary disk.
#
# Every on-disk name here is neutral ("data"): the device-mapper name, the ext4
# label and the mount point must never hint at hidden storage, because they
# survive in /dev/mapper, /dev/disk/by-label, generated mount unit names and the
# kernel/journal. The Nix identifiers below are internal to the test harness and
# never reach the guest's disk.

let
  # Shared diagnostics for a backend that will not close. A LUKS backend that
  # stays open keeps its master key in RAM, which is exactly the leak the threat
  # model forbids, so a close failure must fail the test loudly and name the
  # holders rather than being masked as a "known limitation". The usual cause is
  # an overlay that was only lazily detached and is still referenced by a live
  # process, so the hidden superblock cannot be released.
  reportBackendHolders = ''
    echo 'Holders of /mnt/data:'
    fuser -vm /mnt/data 2>&1 || true
    echo 'Holders of the backing device-mapper node:'
    fuser -vm /dev/mapper/data 2>&1 || true
    echo 'Device-mapper state:'
    dmsetup info data 2>&1 || true
    echo 'Open file descriptors pointing into /mnt/data:'
    for fd in /proc/[0-9]*/fd/*; do
      target=$(readlink "$fd" 2>/dev/null) || continue
      case "$target" in
        /mnt/data*) echo "  $fd -> $target" ;;
      esac
    done
    echo 'Overlay and data mounts still live:'
    grep -E 'overlay|/mnt/data' /proc/mounts || true
  '';

  # Strict teardown of the hidden backend: a plain unmount followed by a real
  # cryptsetup close, with NO lazy-unmount fallback and NO ignored close failure.
  # On any failure it prints the holders and exits non-zero so the test fails.
  unmountHiddenVolumeStrict = ''
    echo 'Strict unmount of data volume...'

    if [ ! -e /dev/mapper/data ]; then
      echo 'Device /dev/mapper/data does not exist - nothing to do'
      exit 0
    fi

    if mountpoint -q /mnt/data; then
      if ! umount /mnt/data; then
        echo 'ERROR: could not unmount /mnt/data; something still holds it.'
        ${reportBackendHolders}
        exit 1
      fi
    fi

    if ! cryptsetup close data; then
      echo 'ERROR: cryptsetup close failed; the hidden backend is still open and'
      echo 'its master key is still resident in RAM. This is a real leak, not a'
      echo 'test-infrastructure artefact: a lazily detached overlay is almost'
      echo 'certainly still holding the hidden superblock.'
      ${reportBackendHolders}
      exit 1
    fi

    echo 'Data volume unmounted and backend closed.'
  '';

  # Open the existing LUKS backend and mount it again, without reformatting. Used
  # after a crash/reboot to read back the state file and upper dirs that survive
  # on the hidden filesystem, so a crash test actually exercises recovery instead
  # of reading a missing state file that defaults to Inactive.
  reopenHiddenVolume = ''
    echo 'Reopening data volume...'

    echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - /dev/disk/by-id/virtio-data data
    mkdir -p /mnt/data
    mount /dev/mapper/data /mnt/data

    echo 'Data volume reopened at: /mnt/data'
  '';
in
{
  inherit unmountHiddenVolumeStrict reopenHiddenVolume;

  # Setup script - creates LUKS volume and prepares directory structure
  # Note: Use single quotes in echo to avoid breaking Python string interpolation
  setupHiddenVolume = ''
    echo 'Setting up data volume on /dev/disk/by-id/virtio-data...'

    # Format the data disk with LUKS using test passphrase
    # --iter-time=1 makes this fast for testing (less secure but acceptable for tests)
    echo -n 'test-passphrase' | cryptsetup luksFormat -q --iter-time=1 /dev/disk/by-id/virtio-data -

    # Open LUKS volume as the neutral "data" device
    echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - /dev/disk/by-id/virtio-data data

    # Create ext4 filesystem with the neutral label "data"
    mkfs.ext4 -L data /dev/mapper/data

    # Mount the volume
    mkdir -p /mnt/data
    mount /dev/mapper/data /mnt/data

    # The whole-root layout NAILS expects: the root overlay's work directory
    # (its upper is created at the first activation, with the decoy root's own
    # mode and owner) and the configuration directory.
    mkdir -p /mnt/data/root/work
    mkdir -p /mnt/data/config/nixos

    echo 'Data volume setup complete!'
    echo 'Volume mounted at: /mnt/data'
    echo 'Directory structure created for NAILS'
  '';

  # Unmount hidden volume (cryptsetup close). This is the strict teardown: it
  # never falls back to a lazy unmount and never ignores a close failure, because
  # either one would leave the master key in RAM.
  unmountHiddenVolume = unmountHiddenVolumeStrict;

  # Mount hidden volume (cryptsetup open + mount). Alias of reopenHiddenVolume.
  mountHiddenVolume = reopenHiddenVolume;
}
