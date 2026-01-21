# NAILS Usage Guide

## Quick Start

### 1. Setup VeraCrypt Hidden Volume
```bash
# Create a VeraCrypt volume with hidden partition
# Mount the hidden volume to a directory, e.g., /media/hidden

cd /media/hidden
git clone <nails-repo> .
```

### 2. Build NAILS
```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build release binary
cargo build --release

# Binary available at: ./target/release/nails
# Optional: Create symlink for easy access
sudo ln -s $(pwd)/target/release/nails /usr/local/bin/nails
```

### 3. Initialize and Configure Hidden Environment
```bash
# Initialize NAILS structure
nails init

# Edit your hidden system configuration
vim config/configuration.nix

# Verify configuration syntax
nixos-rebuild dry-build -I nixos-config=config/configuration.nix
```

### 4. Activate Hidden Environment
```bash
# Activate overlay (requires root)
sudo nails activate

# Your system now has access to hidden packages and configuration
```

### 5. Deactivate and Clean Up
```bash
# Deactivate hidden environment
sudo nails deactivate

# Unmount VeraCrypt hidden volume
veracrypt --dismount /media/hidden

# System returns to original decoy state
```

## Advanced Usage

### Environment Status
```bash
# Check current status
nails status

# Verbose status with debugging info
nails -v status
```

### Package Management
```bash
# Add packages to hidden environment
vim config/configuration.nix  # Add to environment.systemPackages

# Rebuild with updated configuration
sudo nails rebuild
```

### Emergency Operations
```bash
# Emergency cleanup (removes all traces immediately)
sudo nails emergency-clean

# Force deactivation if something goes wrong
sudo umount -f /nix /etc /var /home
sudo nails emergency-clean
```

## Development Workflow

### Building from Source
```bash
# Debug build (faster compilation, includes debug symbols)
cargo build

# Run directly without installing
cargo run -- status

# Run with verbose logging
RUST_LOG=debug cargo run -- activate

# Release build (optimized, stripped binary)
cargo build --release
```

### Running Tests
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_state_machine

# Run integration tests only
cargo test --test integration_tests

# Run with logging
RUST_LOG=debug cargo test
```

### Code Quality
```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt --check

# Run linter
cargo clippy

# Strict linting
cargo clippy -- -D warnings

# Security audit
cargo audit

# Check for outdated dependencies
cargo outdated
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
├── nails                    # Rust binary (CLI entry point)
├── target/                  # Cargo build artifacts
│   ├── debug/              # Debug builds
│   └── release/            # Optimized release builds
├── src/                     # Rust source code
│   ├── main.rs            # CLI interface
│   ├── manager.rs         # Main orchestration
│   ├── overlay.rs         # Overlay filesystem management
│   ├── config.rs          # Configuration handling
│   ├── nixos.rs           # NixOS integration
│   ├── state.rs           # State management
│   └── error.rs           # Error types
├── config/                  # Hidden system configuration
│   ├── configuration.nix
│   └── hardware-configuration.nix
├── overlays/                # Overlay filesystem data
│   ├── etc/                # Configuration overlays
│   ├── nix/                # Package store overlays
│   └── work/               # Overlay work directories
├── backups/                 # System configuration backups
├── .nails-state            # Runtime state tracking
├── Cargo.toml               # Rust dependencies
└── Cargo.lock               # Dependency lock file
```

## Troubleshooting

### Overlay Won't Mount
- Check if you have root privileges (`sudo`)
- Ensure /nix is not already mounted as overlay (`findmnt /nix`)
- Verify hidden volume is properly mounted and writable
- Check kernel supports overlay filesystem: `grep overlay /proc/filesystems`

### Build Errors
- Ensure Rust 1.70+ is installed: `rustc --version`
- Update Rust toolchain: `rustup update`
- Clean build artifacts: `cargo clean && cargo build`
- Check for missing system dependencies

### System Won't Build
- Check configuration.nix syntax with `nixos-rebuild dry-build`
- Ensure hardware-configuration.nix is present and valid
- Verify all referenced packages exist in nixpkgs
- Check logs: `journalctl -xe`

### Can't Switch Back to Decoy
- Check if backup configuration exists in backups/
- Manually restore /etc/nixos/ from backup
- Use `nixos-rebuild switch --rollback` if needed
- As last resort, use emergency-clean: `sudo nails emergency-clean`

### Emergency Recovery
```bash
# If overlay is stuck
sudo umount -f /nix /etc /var /home
sudo systemctl daemon-reload

# If binary won't run
cd /media/hidden
cargo build --release
sudo ./target/release/nails emergency-clean

# If system won't boot
# Boot from NixOS installer
# Mount system drive
# Restore /etc/nixos from backup
# Run nixos-rebuild switch
```

## Performance Considerations

### Build Time
- Debug builds: ~30-60 seconds (faster compilation)
- Release builds: ~2-5 minutes (full optimizations)
- Incremental builds: ~5-10 seconds after first build
- Consider using `cargo check` for faster iteration

### Runtime Performance
- Overlay filesystem adds ~5-10% overhead
- Hidden volume encryption may impact I/O performance
- System rebuilds occur within overlay, not affecting host
- Binary size: ~2-5MB (stripped release build)

### Memory Usage
- Minimal runtime footprint (<10MB typical)
- Rust's zero-cost abstractions provide native performance
- No garbage collection pauses
- Predictable memory usage patterns

## Integration Examples

### Automated Activation
```bash
# Add to your shell profile for automatic detection
if [[ -f /path/to/hidden/target/release/nails ]]; then
    if ! /path/to/hidden/target/release/nails status | grep -q "ACTIVE"; then
        sudo /path/to/hidden/target/release/nails activate
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
ExecStart=/path/to/hidden/target/release/nails activate
User=root
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

### Shell Alias
```bash
# Add to ~/.bashrc or ~/.zshrc
alias nails='/path/to/hidden/target/release/nails'
alias nails-activate='sudo nails activate'
alias nails-deactivate='sudo nails deactivate'
alias nails-status='nails status'
```
