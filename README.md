# NAILS - NixOS Anti-forensics Isolation & Layering System

A novel anti-forensics framework that integrates VeraCrypt hidden volumes with NixOS's declarative configuration system to provide cryptographically undetectable dual-environment computing.

## Problem Statement

Current anti-forensics solutions require manual management and leave detectable metadata traces, limiting their effectiveness for users requiring cryptographic plausible deniability. Existing tools operate independently from the operating system, creating usability and security gaps.

## Solution Overview

NAILS combines VeraCrypt's cryptographically undetectable hidden volumes with NixOS's functional package management to create a computing environment that can instantly transition between a clean "decoy" state and a hidden "real" working environment.

### Key Innovation

The system uses a Python script that sits in the root of a VeraCrypt hidden volume alongside a `nix/` directory. When activated, this script uses UnionFS-FUSE to union-mount the hidden volume's Nix store with the system's `/nix` directory, seamlessly providing access to a completely different set of packages and configurations while maintaining plausible deniability. This approach avoids duplication of packages and allows for efficient storage usage.

## Technical Approach

- **VeraCrypt Integration**: Hidden volumes provide cryptographic plausible deniability
- **UnionFS-FUSE Management**: Python script handles mounting/unmounting hidden volumes using user-space union filesystems
- **NixOS Declarative Config**: Custom Nix modules manage hidden volume mounting and selective persistence
- **Emergency Sanitization**: Leverage NixOS generations for instant rollback to forensically clean states

## Architecture

```
Hidden Volume Structure:
├── nails-unionfs.py     # Main UnionFS management script
├── nix/                # Hidden Nix store
│   └── store/          # Hidden packages and derivations
├── config/             # Hidden system configurations
│   ├── configuration.nix
│   └── hardware-configuration.nix
└── data/               # User data and applications
```

## Features

- **Cryptographic Plausible Deniability**: Uses VeraCrypt hidden volumes that are undetectable
- **Seamless Environment Switching**: Instant transition between decoy and hidden environments
- **Declarative Configuration**: Full NixOS configuration management for both environments
- **Minimal Forensic Footprint**: Base system remains clean by default
- **Emergency Sanitization**: Quick rollback to clean state using NixOS generations
- **Storage Optimization**: No package duplication; hidden and decoy environments share the same Nix store where possible

## Installation

1. Create a VeraCrypt volume with a hidden partition
2. Mount the hidden volume and place the NAILS scripts inside
3. Initialize the hidden Nix store and configurations
4. Configure the decoy system for normal operation

```bash
# Clone the repository
git clone https://github.com/your-repo/nails
cd nails

# Install system components (run as root)
sudo ./install.sh

# Initialize NAILS in your hidden volume
./nails.py init
```

## Usage

The main script `nails.py` is designed to be placed in the root of your VeraCrypt hidden volume:

```bash
# Activate hidden environment (union-mount hidden nix store)
./nails.py activate

# Deactivate hidden environment (remove union mount)
./nails.py deactivate

# Check current status
./nails.py status

# Emergency cleanup (remove all traces)
./nails.py emergency-clean
```

## Research Contribution

This represents the first academic exploration of declarative configuration systems for anti-forensics applications. By combining NixOS's functional approach with VeraCrypt's cryptographic plausible deniability, the research addresses gaps in current anti-forensics literature while creating practical tools for journalists, activists, and privacy advocates.

## Security Model

- **Cryptographic Layer**: VeraCrypt AES-256 encryption with plausible deniability
- **System Layer**: NixOS immutable configurations and atomic rollbacks
- **Application Layer**: UnionFS-FUSE for seamless environment switching
- **Emergency Layer**: Instant sanitization and rollback capabilities

## Use Cases

- **Journalists**: Protect sensitive sources and investigations
- **Activists**: Secure communications and organizational tools
- **Researchers**: Compartmentalized analysis environments
- **Privacy Advocates**: General-purpose secure computing

## Expected Deliverables

- [x] Working open-source anti-forensics framework
- [ ] Performance analysis of nested encryption and union filesystem operations
- [ ] Security evaluation against common forensic tools
- [ ] Academic publication for privacy/security conferences

## Contributing

This is research software. Contributions welcome but please understand this is experimental technology.

## License

See LICENSE file for details.

## Disclaimer

This software is for educational and research purposes. Users are responsible for compliance with local laws and regulations.
