# NAILS - NixOS Anti-forensics Isolation & Layering System

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![NixOS](https://img.shields.io/badge/NixOS-supported-blue.svg)](https://nixos.org/)

A novel anti-forensics framework that combines VeraCrypt hidden volumes with NixOS's declarative configuration system and Linux overlay filesystems to provide cryptographically undetectable dual-environment computing.

## 🎯 Problem Statement

Current anti-forensics solutions require manual management, leave detectable metadata traces, and operate independently from the operating system. This creates usability gaps and limits effectiveness for users requiring cryptographic plausible deniability.

## 💡 Solution Overview

NAILS leverages three key technologies:
- **VeraCrypt Hidden Volumes**: Cryptographically undetectable storage
- **Linux Overlay Filesystems**: Zero-trace environment switching
- **NixOS Declarative Configuration**: Reproducible system states

The result is a system that can instantly transition between a clean "decoy" state and a hidden "real" working environment while maintaining complete plausible deniability.

## 🏗️ Architecture

```
Hidden Volume Structure:
├── nails                   # Rust binary (main CLI entry point)
├── src/                    # Rust source code
│   ├── main.rs            # CLI interface
│   ├── manager.rs         # Main orchestration
│   ├── overlay.rs         # Overlay filesystem management
│   ├── config.rs          # Configuration handling
│   ├── nixos.rs           # NixOS integration
│   ├── state.rs           # State management
│   └── error.rs           # Error handling
├── config/                # Hidden system configurations
│   ├── configuration.nix  # Main NixOS config
│   └── hardware-configuration.nix
└── overlays/              # Overlay filesystem data
    ├── etc/               # Configuration overlays
    ├── nix/               # Package store overlays
    └── work/              # Overlay work directories
```

## ✨ Key Features

- **🔒 Cryptographic Plausible Deniability**: Uses VeraCrypt hidden volumes that are mathematically undetectable
- **⚡ Instant Environment Switching**: Near-instantaneous transition via kernel overlays
- **📝 Declarative Configuration**: Full NixOS configuration management for hidden environment
- **🧹 Zero Forensic Footprint**: Host system remains completely untouched via overlay isolation
- **🚨 Emergency Sanitization**: Instant rollback to clean state with `emergency-clean`
- **🔄 Live Configuration Updates**: Rebuild hidden system without deactivating environment
- **💾 Storage Optimization**: Overlay approach eliminates package duplication
- **🔐 Automatic Safety Backups**: Critical system files backed up before activation
- **🦀 Memory-Safe Implementation**: Written in Rust for enhanced security and minimal forensic artifacts
- **⚙️ Zero-Cost Abstractions**: Compiled binary with native performance and low memory footprint

## 🚀 Installation

### Prerequisites
- NixOS with kernel overlay filesystem support
- VeraCrypt for hidden volume creation
- Rust 1.70+ (stable channel recommended, tested with 1.91.1)
- Root access for overlay operations

### Setup Process

1. **Create VeraCrypt Hidden Volume**
   ```bash
   # Create a VeraCrypt volume with hidden partition
   # Mount the hidden volume (e.g., to /media/hidden)
   ```

2. **Install Rust (if not already installed)**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. **Build and Install NAILS**
   ```bash
   cd /media/hidden
   git clone https://github.com/your-repo/nails .

   # Build release binary
   cargo build --release

   # Binary available at: ./target/release/nails
   # Optional: Add to PATH or create symlink
   sudo ln -s $(pwd)/target/release/nails /usr/local/bin/nails
   ```

4. **Initialize Hidden Environment**
   ```bash
   # Initialize NAILS structure
   nails init

   # Edit your hidden configuration
   nano config/configuration.nix
   ```

## 📖 Usage

### Basic Commands

```bash
# Initialize hidden overlay structure
nails init

# Activate hidden environment (requires root)
sudo nails activate

# Check current status
nails status

# Rebuild system with configuration changes
sudo nails rebuild

# Deactivate hidden environment
sudo nails deactivate

# Emergency cleanup (immediate sanitization)
sudo nails emergency-clean
```

### Command Options

```bash
# Verbose output for debugging
nails -v <command>

# Show version information
nails --version

# Get help
nails -h
```

### Typical Workflow

```bash
# 1. Mount VeraCrypt hidden volume
veracrypt --mount /path/to/volume /media/hidden

# 2. Navigate to NAILS directory
cd /media/hidden

# 3. Activate hidden environment
sudo nails activate

# 4. Your system now has access to hidden packages and configs
# Make changes, use hidden tools, etc.

# 5. Optional: Update configuration and rebuild
nano config/configuration.nix
sudo nails rebuild

# 6. Deactivate when finished
sudo nails deactivate

# 7. Unmount hidden volume
veracrypt --dismount /media/hidden
```

## ⚙️ Configuration

The hidden system configuration extends your base NixOS setup:

```nix
# config/configuration.nix
{ config, pkgs, lib, ... }:
{
  # Import base system configuration
  imports = [ /etc/nixos/configuration.nix ];

  # Hidden packages
  environment.systemPackages = with pkgs; [
    tor
    gnupg
    keepassxc
    signal-desktop
    # Add your sensitive tools here
  ];

  # Hidden services
  services.tor.enable = true;
  services.openssh.enable = false;  # Disable SSH in hidden mode

  # Hidden user accounts
  users.users.ghost = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" ];
    hashedPassword = "$6$...";  # Set secure password
  };

  # Network configuration for privacy
  networking.firewall.enable = true;
  networking.networkmanager.enable = true;
}
```

## 🛡️ Security Model

### Defense Layers

1. **Cryptographic Layer**: VeraCrypt AES-256 encryption with plausible deniability
2. **Isolation Layer**: Linux kernel overlays prevent host contamination
3. **Configuration Layer**: NixOS immutable configurations ensure consistency
4. **Emergency Layer**: Instant sanitization capabilities

### Security Properties

- **Undetectability**: Hidden volumes are cryptographically indistinguishable from random data
- **Non-persistence**: No traces remain on host system after deactivation
- **Atomicity**: Operations succeed completely or fail safely
- **Rollback**: Always possible to return to clean decoy state

## 🎯 Use Cases

- **👥 Journalists**: Protect sources and investigations with cryptographic deniability
- **✊ Activists**: Secure communications with instant environment switching
- **🔬 Security Researchers**: Isolated analysis environments with zero contamination
- **🕵️ Privacy Advocates**: General-purpose secure computing with untraceability

## 📊 Technical Benefits

- **Zero Host Contamination**: All changes isolated to overlay filesystems
- **Instant Operations**: Overlay mounting/unmounting is near-instantaneous
- **Live Updates**: Rebuild system without deactivating environment
- **Atomic Operations**: Failed operations leave system in consistent state
- **Complete Reversibility**: Always possible to return to original state

## 🔧 Development

### Project Structure
```
nails/
├── src/
│   ├── main.rs            # CLI entry point and argument parsing
│   ├── manager.rs         # Main orchestration logic
│   ├── overlay.rs         # Overlay filesystem operations
│   ├── config.rs          # Configuration management
│   ├── nixos.rs           # NixOS integration
│   ├── state.rs           # State tracking
│   ├── error.rs           # Custom error types
│   └── lib.rs             # Library exports
├── Cargo.toml             # Rust dependencies and metadata
└── tests/                 # Integration tests
```

### Contributing

This is research software under active development. Contributions welcome:

- 🐛 **Bug Reports**: Security issues, functionality problems
- 🚀 **Features**: Additional safety mechanisms, performance improvements
- 📚 **Documentation**: Usage examples, security analysis
- 🔍 **Testing**: Forensic evaluation, performance benchmarks

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-repo/nails
cd nails

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build in debug mode
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- status

# Build optimized release
cargo build --release

# Code quality checks
cargo clippy -- -D warnings
cargo fmt --check

# Security audit
cargo audit
```

## 📋 System Requirements

- **OS**: NixOS (any recent version with overlay filesystem support)
- **Storage**: VeraCrypt for hidden volume creation
- **Permissions**: Root access for overlay filesystem operations
- **Rust**: 1.70+ stable channel (tested with 1.91.1)
- **Space**: Sufficient storage in hidden volume for overlay data

## 🚨 Important Notes

### Emergency Procedures

If something goes wrong:
```bash
# Emergency cleanup (removes all overlays immediately)
sudo nails emergency-clean

# If binary is unavailable, manual cleanup:
sudo umount /nix /etc /var /home 2>/dev/null || true
```

### Performance Considerations

- Overlay filesystems add minimal overhead
- Hidden volume encryption may impact I/O performance
- System rebuilds occur within overlay, not affecting host

### Forensic Considerations

- Always unmount hidden volume when not in use
- Use `emergency-clean` if system compromise is suspected
- Regular decoy activity maintains plausible cover story

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is for **educational and research purposes only**. Users are responsible for compliance with local laws and regulations. The authors make no warranties about the security properties of this software.

**Use at your own risk.**

---

*NAILS represents novel research in combining kernel overlay filesystems with cryptographic plausible deniability for anti-forensics applications.*
