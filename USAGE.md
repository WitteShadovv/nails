# NAILS Usage Guide

## Quick Start

### 1. Setup VeraCrypt Hidden Volume
```bash
# Create a VeraCrypt volume with hidden partition
# Mount the hidden volume to a directory, e.g., /media/hidden

cd /media/hidden
git clone <nails-repo> .
chmod +x setup-hidden-volume.sh
./setup-hidden-volume.sh
```

### 2. Configure Hidden Environment
```bash
# Edit your hidden system configuration
vim config/configuration.nix

# Test the configuration
./nails-helper.sh test-hidden

# Build and populate the hidden nix store
./nails-helper.sh populate-store
```

### 3. Activate Hidden Environment
```bash
# Activate overlay (requires root)
sudo ./nails-overlay.py activate

# Rebuild system with hidden config
sudo nixos-rebuild switch

# Your system now has access to hidden packages and configuration
```

### 4. Deactivate and Clean Up
```bash
# Switch back to decoy system
sudo nixos-rebuild switch  # Uses backed up decoy config

# Remove overlay
sudo ./nails-overlay.py deactivate

# Unmount VeraCrypt hidden volume
# System returns to original decoy state
```

## Advanced Usage

### Environment Status
```bash
# Check current status
./nails-overlay.py status

# View detailed overlay information
./nails-helper.sh status
```

### Package Management
```bash
# Add packages to hidden environment
vim config/configuration.nix  # Add to environment.systemPackages

# Rebuild hidden store
./nails-helper.sh populate-store

# Apply changes
sudo ./nails-overlay.py activate
sudo nixos-rebuild switch
```

### Emergency Operations
```bash
# Emergency cleanup (removes all traces)
sudo ./nails-overlay.py emergency-clean

# Force deactivation if something goes wrong
sudo umount -f /nix
sudo ./nails-overlay.py deactivate
```

## Security Best Practices

### VeraCrypt Configuration
- Use AES-256 encryption with strongest available hash
- Use a strong passphrase for the hidden volume
- Ensure the outer volume contains believable decoy data
- Never mount both volumes simultaneously

### System Hygiene
- Always deactivate before shutting down or unmounting
- Regularly clean /tmp and system logs
- Use UTC timezone to avoid fingerprinting
- Disable swap or encrypt it separately

### Operational Security
- Test your setup thoroughly before relying on it
- Have a backup plan for emergency situations
- Consider using Tails or similar for maximum security
- Be aware of memory artifacts and cold boot attacks

## File Structure

```
Hidden Volume Root/
├── nails-overlay.py         # Main overlay script
├── nails-helper.sh          # Helper utilities
├── setup-hidden-volume.sh  # Initial setup script
├── config/                  # Hidden system configuration
│   ├── configuration.nix
│   └── hardware-configuration.nix
├── nix/                     # Hidden Nix store
│   ├── store/              # Packages and derivations
│   └── var/nix/            # Nix database
├── data/                    # User data and applications
├── backups/                 # System configuration backups
└── .nails-state            # Runtime state tracking
```

## Troubleshooting

### Overlay Won't Mount
- Check if you have root privileges
- Ensure /nix is not already mounted as overlay
- Verify hidden volume is properly mounted and writable

### System Won't Build
- Check configuration.nix syntax with `nixos-rebuild dry-build`
- Ensure hardware-configuration.nix is present and valid
- Verify all referenced packages exist

### Can't Switch Back to Decoy
- Check if backup configuration exists in backups/
- Manually restore /etc/nixos/ from backup
- Use `nixos-rebuild switch --rollback` if needed

### Emergency Recovery
```bash
# If overlay is stuck
sudo umount -f /nix
sudo systemctl daemon-reload

# If system won't boot
# Boot from NixOS installer
# Mount system drive
# Restore /etc/nixos from backup
# Run nixos-rebuild switch
```

## Performance Considerations

### Storage Overhead
- Hidden store requires space for packages
- Overlay has minimal performance impact
- Consider using compression in VeraCrypt

### Memory Usage
- Overlay metadata uses some RAM
- Hidden packages loaded on demand
- Monitor system resources during operation

### Boot Time
- Activation adds ~10-30 seconds depending on system
- Can be automated with systemd services
- Consider pre-mounting for faster access

## Integration Examples

### Automated Activation
```bash
# Add to your shell profile for automatic detection
if [[ -f /path/to/hidden/nails-overlay.py ]]; then
    if ! ./nails-overlay.py status | grep -q "Active"; then
        sudo ./nails-overlay.py activate
        sudo nixos-rebuild switch
    fi
fi
```

### Systemd Service
```ini
[Unit]
Description=NAILS Auto-Activation
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/path/to/hidden/nails-overlay.py activate
ExecStart=/run/current-system/sw/bin/nixos-rebuild switch
User=root
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
