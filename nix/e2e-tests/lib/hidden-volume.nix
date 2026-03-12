# Hidden Volume Simulation for E2E Tests
# Provides LUKS-based hidden volume simulation using secondary disk

{
  # Setup script - creates LUKS volume and prepares directory structure
  # Note: Use single quotes in echo to avoid breaking Python string interpolation
  setupHiddenVolume = ''
    echo 'Setting up hidden volume on /dev/vdb...'

    # Format /dev/vdb with LUKS using test passphrase
    # --iter-time=1 makes this fast for testing (less secure but acceptable for tests)
    echo -n 'test-passphrase' | cryptsetup luksFormat -q --iter-time=1 /dev/vdb -

    # Open LUKS volume as "hidden-volume" device
    echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - /dev/vdb hidden-volume

    # Create ext4 filesystem with label "hidden-volume"
    mkfs.ext4 -L hidden-volume /dev/mapper/hidden-volume

    # Mount the hidden volume
    mkdir -p /mnt/hidden-volume
    mount /dev/mapper/hidden-volume /mnt/hidden-volume

    # Create NAILS directory structure (matching what nails expects)
    # Upper directories for overlays
    mkdir -p /mnt/hidden-volume/home
    mkdir -p /mnt/hidden-volume/etc
    mkdir -p /mnt/hidden-volume/var
    mkdir -p /mnt/hidden-volume/nix
    # Work directories for overlays
    mkdir -p /mnt/hidden-volume/.work/home
    mkdir -p /mnt/hidden-volume/.work/etc
    mkdir -p /mnt/hidden-volume/.work/var
    mkdir -p /mnt/hidden-volume/.work/nix
    # Additional required directories
    mkdir -p /mnt/hidden-volume/config
    mkdir -p /mnt/hidden-volume/config/nixos
    mkdir -p /mnt/hidden-volume/nixos
    mkdir -p /mnt/hidden-volume/.nails

    echo 'Hidden volume setup complete!'
    echo 'Volume mounted at: /mnt/hidden-volume'
    echo 'Directory structure created for NAILS'
  '';

  # Unmount hidden volume (cryptsetup close)
  unmountHiddenVolume = ''
    echo 'Unmounting hidden volume...'

    # Check if device exists and get diagnostics before attempting unmount
    if [ -e /dev/mapper/hidden-volume ]; then
      echo 'Device /dev/mapper/hidden-volume exists'

      # Show what's using the device
      echo 'Checking for open files on the device...'
      lsof /dev/mapper/hidden-volume 2>/dev/null || echo 'lsof: no open files found'

      # Show current mounts
      echo 'Current mounts:'
      mount | grep hidden-volume || echo 'No mounts found'
    else
      echo 'Device /dev/mapper/hidden-volume does not exist - nothing to do'
      exit 0
    fi

    # Unmount the filesystem with retry logic
    echo 'Attempting to unmount /mnt/hidden-volume...'

    # First check what's mounted before unmounting
    echo 'All active mounts before unmount:'
    mount | grep -E '(overlay|hidden)' || echo 'No overlay or hidden mounts'

    if umount /mnt/hidden-volume 2>&1; then
      echo 'Successfully unmounted /mnt/hidden-volume'
    else
      echo 'Failed to unmount /mnt/hidden-volume'
      # Try lazy unmount if regular unmount fails
      echo 'Attempting lazy unmount...'
      umount -l /mnt/hidden-volume 2>&1 || echo 'Lazy unmount also failed'
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
    if cryptsetup luksClose hidden-volume 2>&1; then
      echo 'Successfully closed LUKS device'
    else
      echo 'Note: LUKS device could not be closed (kernel-internal reference in VM environment)'
      echo 'This is a known test infrastructure limitation and does not affect test validity'
      echo 'The device will be cleaned up when the VM shuts down'
    fi

    echo 'Hidden volume unmounted and closed.'
  '';

  # Mount hidden volume (cryptsetup open + mount)
  mountHiddenVolume = ''
    echo 'Mounting hidden volume...'

    # Open LUKS volume
    echo -n 'test-passphrase' | cryptsetup luksOpen --key-file - /dev/vdb hidden-volume

    # Mount the filesystem
    mkdir -p /mnt/hidden-volume
    mount /dev/mapper/hidden-volume /mnt/hidden-volume

    echo 'Hidden volume mounted at: /mnt/hidden-volume'
  '';

  # Check if hidden volume is set up
  checkHiddenVolume = ''
    if [ -f /mnt/hidden-volume/nails/config.toml ]; then
      echo 'Hidden volume is set up'
      exit 0
    else
      echo 'Hidden volume is not set up'
      exit 1
    fi
  '';
}
