# NAILS - NixOS Anti-forensics Isolation & Layering System

A novel anti-forensics framework that integrates VeraCrypt hidden volumes with NixOS's declarative configuration system to provide cryptographically undetectable dual-environment computing.

## Problem Statement

Current anti-forensics solutions require manual management and leave detectable metadata traces, limiting their effectiveness for users requiring cryptographic plausible deniability. Existing tools operate independently from the operating system, creating usability and security gaps.

## Solution Overview

NAILS combines VeraCrypt's cryptographically undetectable hidden volumes with NixOS's functional package management to create a computing environment that can instantly transition between a clean "decoy" state and a hidden "real" working environment.

### Key Innovation

The system uses a Python script that sits in the root of a VeraCrypt hidden volume alongside configuration and overlay directories. When activated, this script uses Linux kernel overlay filesystems to overlay-mount the hidden volume's Nix store and configurations over the system's `/nix` and `/etc` directories, seamlessly providing access to a completely different set of packages and configurations while maintaining plausible deniability. This approach provides efficient storage usage and zero forensic traces on the host system.

## Technical Approach

- **VeraCrypt Integration**: Hidden volumes provide cryptographic plausible deniability
- **Kernel Overlay Filesystems**: Python script handles mounting/unmounting hidden overlays using kernel overlay support
- **NixOS Declarative Config**: Custom Nix configurations manage hidden system states and packages  
- **Emergency Sanitization**: Instant rollback to forensically clean states via overlay deactivation
- **Safe Rebuild System**: Update hidden configurations without deactivating the environment

## Architecture

```
Hidden Volume Structure:
├── nails.py                # Main overlay management script
├── config/                 # Hidden system configurations
│   ├── configuration.nix
│   └── hardware-configuration.nix
├── overlay/                # Overlay filesystem structures
│   ├── etc/               # Configuration overlays
│   ├── nix/               # Package store overlays
│   ├── var/               # Variable data overlays
│   └── home/              # User data overlays
├── work/                   # Overlay filesystem work directories
├── safety/                 # Automatic safety backups
└── backups/               # Manual backup storage
```

## Features

- **Cryptographic Plausible Deniability**: Uses VeraCrypt hidden volumes that are undetectable
- **Seamless Environment Switching**: Instant transition between decoy and hidden environments using kernel overlays
- **Declarative Configuration**: Full NixOS configuration management for hidden environment
- **Minimal Forensic Footprint**: Host system remains completely untouched via overlay isolation
- **Emergency Sanitization**: Instant rollback to clean state via overlay deactivation  
- **Live Configuration Updates**: Rebuild hidden system without deactivating environment
- **Storage Optimization**: Overlay approach eliminates package duplication
- **Automatic Safety Backups**: Critical system files backed up before overlay activation

## Installation

1. Create a VeraCrypt volume with a hidden partition
2. Mount the hidden volume and clone NAILS inside
3. Initialize the hidden overlay structure and configurations
4. Configure the decoy system for normal operation

```bash
# Clone the repository into your mounted hidden volume
git clone https://github.com/your-repo/nails
cd nails

# Initialize NAILS overlay structure
./nails.py init
```

## Usage

The main script `nails.py` is designed to be placed in the root of your VeraCrypt hidden volume:

### Basic Commands

```bash
# Initialize hidden overlay structure and configurations
./nails.py init

# Activate hidden environment (overlay-mount hidden configurations)
sudo ./nails.py activate

# Check current status
./nails.py status

# Rebuild system with configuration changes (while active)
sudo ./nails.py rebuild

# Deactivate hidden environment (remove overlays)
sudo ./nails.py deactivate

# Emergency cleanup (remove all traces immediately)
sudo ./nails.py emergency-clean
```

### Typical Workflow

```bash
# 1. Initial setup (one time)
./nails.py init

# 2. Activate hidden environment
sudo ./nails.py activate

# 3. Edit hidden configuration as needed
nano config/configuration.nix

# 4. Apply changes without deactivating
sudo ./nails.py rebuild

# 5. When finished, return to decoy state
sudo ./nails.py deactivate
```

## Configuration Management

The hidden system configuration extends your existing NixOS configuration:

```nix
# config/configuration.nix
{ config, pkgs, lib, ... }:
{
  # Import existing system config as base
  imports = [ /etc/nixos/configuration.nix ];
  
  # Add hidden packages
  environment.systemPackages = with pkgs; [
    tor gnupg keepassxc
    # Add your hidden tools here
  ];
  
  # Hidden services
  services.tor.enable = true;
  
  # Hidden user
  users.users.ghost = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };
}
```

## Security Model

- **Cryptographic Layer**: VeraCrypt AES-256 encryption with plausible deniability
- **System Layer**: NixOS immutable configurations and atomic operations
- **Isolation Layer**: Linux kernel overlay filesystems for complete host isolation
- **Emergency Layer**: Instant sanitization via overlay deactivation

## Research Contribution

This represents the first academic exploration of kernel overlay filesystems for anti-forensics applications. By combining NixOS's functional approach with VeraCrypt's cryptographic plausible deniability and Linux kernel overlay technology, the research addresses gaps in current anti-forensics literature while creating practical tools for high-risk users.

## Use Cases

- **Journalists**: Protect sensitive sources and investigations with instant environment switching
- **Activists**: Secure communications and organizational tools with plausible deniability
- **Security Researchers**: Compartmentalized analysis environments with zero host contamination
- **Privacy Advocates**: General-purpose secure computing with cryptographic undetectability

## Technical Benefits

- **Zero Host Contamination**: All changes written to overlay, host filesystem untouched
- **Instant Activation/Deactivation**: Overlay mounting is near-instantaneous 
- **Live Configuration Updates**: Rebuild system without environment cycling
- **Automatic Rollback**: Failed operations leave system in consistent state
- **Complete Untraceability**: No artifacts remain after deactivation

## Expected Deliverables

- [x] Working open-source anti-forensics framework using kernel overlays
- [x] Safe rebuild system for live configuration updates
- [x] Comprehensive safety and emergency cleanup mechanisms
- [ ] Performance analysis of overlay filesystem operations and nested encryption
- [ ] Security evaluation against forensic tools and techniques
- [ ] Academic publication for privacy and security conferences

## System Requirements

- NixOS (any recent version with overlay filesystem support)
- VeraCrypt for hidden volume creation
- Root access for overlay filesystem operations
- Sufficient space in hidden volume for overlay storage

## Contributing

This is research software under active development. Contributions welcome but please understand this is experimental technology. Issues and pull requests should focus on:

- Security improvements
- Performance optimizations  
- Additional safety mechanisms
- Documentation improvements

## License

See LICENSE file for details.

## Disclaimer

This software is for educational and research purposes. Users are responsible for compliance with local laws and regulations. The authors make no warranties about the security properties of this software - use at your own risk.
