# NAILS - NixOS Anti-forensics Isolation & Layering System

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
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
├── nails.py                # Main CLI entry point
├── nails/                  # Core Python modules
│   ├── manager.py         # Main orchestration
│   ├── overlay.py         # Overlay filesystem management
│   ├── config.py          # Configuration handling
│   ├── nixos.py           # NixOS integration
│   └── state.py           # State management
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

## 🚀 Installation

### Prerequisites
- NixOS with kernel overlay filesystem support
- VeraCrypt for hidden volume creation
- Python 3.12+
- Root access for overlay operations

### Setup Process

1. **Create VeraCrypt Hidden Volume**
   ```bash
   # Create a VeraCrypt volume with hidden partition
   # Mount the hidden volume (e.g., to /media/hidden)
   ```

2. **Install NAILS**
   ```bash
   cd /media/hidden
   git clone https://github.com/your-repo/nails .
   pip install -e .
   ```

3. **Initialize Hidden Environment**
   ```bash
   # Initialize NAILS structure
   ./nails.py init

   # Edit your hidden configuration
   nano config/configuration.nix
   ```

## 📖 Usage

### Basic Commands

```bash
# Initialize hidden overlay structure
./nails.py init

# Activate hidden environment (requires root)
sudo ./nails.py activate

# Check current status
./nails.py status

# Rebuild system with configuration changes
sudo ./nails.py rebuild

# Deactivate hidden environment
sudo ./nails.py deactivate

# Emergency cleanup (immediate sanitization)
sudo ./nails.py emergency-clean
```

### Command Options

```bash
# Verbose output for debugging
./nails.py -v <command>

# Show version information
./nails.py --version

# Get help
./nails.py -h
```

### Typical Workflow

```bash
# 1. Mount VeraCrypt hidden volume
veracrypt --mount /path/to/volume /media/hidden

# 2. Navigate to NAILS directory
cd /media/hidden

# 3. Activate hidden environment
sudo ./nails.py activate

# 4. Your system now has access to hidden packages and configs
# Make changes, use hidden tools, etc.

# 5. Optional: Update configuration and rebuild
nano config/configuration.nix
sudo ./nails.py rebuild

# 6. Deactivate when finished
sudo ./nails.py deactivate

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
├── __init__.py            # Package initialization
├── manager.py             # Main orchestration logic
├── overlay.py             # Overlay filesystem operations
├── config.py              # Configuration management
├── nixos.py               # NixOS integration
├── state.py               # State tracking
└── exceptions.py          # Custom exceptions
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

# Install development dependencies
pip install -e ".[dev]"

# Run tests (when available)
python -m pytest

# Code quality checks
pre-commit run --all-files
```

## 📋 System Requirements

- **OS**: NixOS (any recent version with overlay filesystem support)
- **Storage**: VeraCrypt for hidden volume creation
- **Permissions**: Root access for overlay filesystem operations
- **Python**: 3.12+ with dependencies listed in `pyproject.toml`
- **Space**: Sufficient storage in hidden volume for overlay data

## 🚨 Important Notes

### Emergency Procedures

If something goes wrong:
```bash
# Emergency cleanup (removes all overlays immediately)
sudo ./nails.py emergency-clean

# If script is unavailable, manual cleanup:
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
