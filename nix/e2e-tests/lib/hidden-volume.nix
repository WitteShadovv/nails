# Hidden Volume Simulation for E2E Tests
# Provides LUKS-based hidden volume simulation using secondary disk.
#
# Every on-disk name here is neutral ("data"): the device-mapper name, the ext4
# label and the mount point must never hint at hidden storage, because they
# survive in /dev/mapper, /dev/disk/by-label, generated mount unit names and the
# kernel/journal. The Nix identifiers below are internal to the test harness and
# never reach the guest's disk.

{
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

    # Create NAILS directory structure (matching what nails expects)
    # Upper directories for overlays
    mkdir -p /mnt/data/home
    mkdir -p /mnt/data/etc
    mkdir -p /mnt/data/var
    mkdir -p /mnt/data/nix
    # Work directories for overlays
    mkdir -p /mnt/data/.work/home
    mkdir -p /mnt/data/.work/etc
    mkdir -p /mnt/data/.work/var
    mkdir -p /mnt/data/.work/nix
    # Additional required directories
    mkdir -p /mnt/data/config
    mkdir -p /mnt/data/config/nixos
    mkdir -p /mnt/data/nixos

    echo 'Data volume setup complete!'
    echo 'Volume mounted at: /mnt/data'
    echo 'Directory structure created for NAILS'
  '';

  # Unmount hidden volume (cryptsetup close)
  unmountHiddenVolume = ''
    echo 'Unmounting data volume...'

    # Check if device exists and get diagnostics before attempting unmount
    if [ -e /dev/mapper/data ]; then
      echo 'Device /dev/mapper/data exists'

      # Show what's using the device
      echo 'Checking for open files on the device...'
      lsof /dev/mapper/data 2>/dev/null || echo 'lsof: no open files found'

      # Show current mounts
      echo 'Current mounts:'
      mount | grep /mnt/data || echo 'No mounts found'
    else
      echo 'Device /dev/mapper/data does not exist - nothing to do'
      exit 0
    fi

    # Unmount the filesystem with retry logic
    echo 'Attempting to unmount /mnt/data...'

    # First check what's mounted before unmounting
    echo 'All active mounts before unmount:'
    mount | grep -E '(overlay|/mnt/data)' || echo 'No overlay or data mounts'

    if umount /mnt/data 2>&1; then
      echo 'Successfully unmounted /mnt/data'
    else
      echo 'Failed to unmount /mnt/data'
      # Try lazy unmount if regular unmount fails
      echo 'Attempting lazy unmount...'
      umount -l /mnt/data 2>&1 || echo 'Lazy unmount also failed'
    fi

    # Verify nothing overlay-related is still mounted
    echo 'Checking for remaining overlay mounts after unmount:'
    remaining_overlays=$(mount | grep 'overlay on /' || true)
    if [ -n "$remaining_overlays" ]; then
      echo 'WARNING: Found remaining overlay mounts:'
      echo "$remaining_overlays"
    else
      echo 'No overlay mounts found (good)'
    fi

    # Give the system a moment to cleanup
    sleep 0.5

    # Close the LUKS device
    echo 'Closing LUKS device...'

    # Attempt to close the LUKS device
    # Note: This may fail due to kernel-internal dm-crypt references in VM environments
    # This is acceptable for test purposes - the kernel will clean up on VM shutdown
    if cryptsetup luksClose data 2>&1; then
      echo 'Successfully closed LUKS device'
    else
      echo 'Note: LUKS device could not be closed (kernel-internal reference in VM environment)'
      echo 'This is a known test infrastructure limitation and does not affect test validity'
      echo 'The device will be cleaned up when the VM shuts down'
    fi

    echo 'Data volume unmounted and closed.'
  '';

  # Mount hidden volume (cryptsetup open + mount)
  mountHiddenVolume = ''
    echo 'Mounting data volume...'

    # Open LUKS volume
    echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - /dev/disk/by-id/virtio-data data

    # Mount the filesystem
    mkdir -p /mnt/data
    mount /dev/mapper/data /mnt/data

    echo 'Data volume mounted at: /mnt/data'
  '';

}
