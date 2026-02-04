# Hidden Volume Simulation for E2E Tests
# Provides LUKS-based hidden volume simulation using secondary disk

{
  # Setup script - creates LUKS volume and prepares directory structure
  setupHiddenVolume = ''
    echo "Setting up hidden volume on /dev/vdb..."

    # Format /dev/vdb with LUKS using test passphrase
    # --iter-time=1 makes this fast for testing (less secure but acceptable for tests)
    echo -n "test-passphrase" | cryptsetup luksFormat -q --iter-time=1 /dev/vdb -

    # Open LUKS volume as "hidden-volume" device
    echo -n "test-passphrase" | cryptsetup luksOpen --key-file - /dev/vdb hidden-volume

    # Create ext4 filesystem with label "hidden-volume"
    mkfs.ext4 -L hidden-volume /dev/mapper/hidden-volume

    # Mount the hidden volume
    mkdir -p /mnt/hidden-volume
    mount /dev/mapper/hidden-volume /mnt/hidden-volume

    # Create NAILS directory structure
    mkdir -p /mnt/hidden-volume/nails/{bin,config,logs}
    mkdir -p /mnt/hidden-volume/nails/overlay/home/{upper,work}
    mkdir -p /mnt/hidden-volume/nails/overlay/etc/{upper,work}

    # Copy NAILS binary to hidden volume
    cp /run/current-system/sw/bin/nails /mnt/hidden-volume/nails/bin/nails
    chmod +x /mnt/hidden-volume/nails/bin/nails

    # Generate config.toml with proper paths
    cat > /mnt/hidden-volume/nails/config.toml <<'EOF'
[general]
hidden_volume_root = "/mnt/hidden-volume"
overlay_targets = ["/home", "/etc"]

[overlay.home]
upper_dir = "/mnt/hidden-volume/nails/overlay/home/upper"
work_dir = "/mnt/hidden-volume/nails/overlay/home/work"

[overlay.etc]
upper_dir = "/mnt/hidden-volume/nails/overlay/etc/upper"
work_dir = "/mnt/hidden-volume/nails/overlay/etc/work"
EOF

    echo "Hidden volume setup complete!"
    echo "Volume mounted at: /mnt/hidden-volume"
    echo "NAILS binary: /mnt/hidden-volume/nails/bin/nails"
    echo "Config file: /mnt/hidden-volume/nails/config.toml"
  '';

  # Unmount hidden volume (cryptsetup close)
  unmountHiddenVolume = ''
    echo "Unmounting hidden volume..."

    # Unmount the filesystem
    umount /mnt/hidden-volume 2>/dev/null || echo "Warning: /mnt/hidden-volume not mounted"

    # Close the LUKS device
    cryptsetup luksClose hidden-volume 2>/dev/null || echo "Warning: hidden-volume not open"

    echo "Hidden volume unmounted and closed."
  '';

  # Mount hidden volume (cryptsetup open + mount)
  mountHiddenVolume = ''
    echo "Mounting hidden volume..."

    # Open LUKS volume
    echo -n "test-passphrase" | cryptsetup luksOpen --key-file - /dev/vdb hidden-volume

    # Mount the filesystem
    mkdir -p /mnt/hidden-volume
    mount /dev/mapper/hidden-volume /mnt/hidden-volume

    echo "Hidden volume mounted at: /mnt/hidden-volume"
  '';

  # Check if hidden volume is set up
  checkHiddenVolume = ''
    if [ -f /mnt/hidden-volume/nails/config.toml ]; then
      echo "Hidden volume is set up"
      exit 0
    else
      echo "Hidden volume is not set up"
      exit 1
    fi
  '';
}
