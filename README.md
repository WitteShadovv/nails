# NAILS — NixOS Anti-forensics Isolation & Layering System

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![NixOS](https://img.shields.io/badge/NixOS-required-5277C3.svg)](https://nixos.org/)
[![Test Pipeline](https://github.com/nails-project/nails/actions/workflows/test.yml/badge.svg)](https://github.com/nails-project/nails/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/badge/coverage->85%25-brightgreen.svg)](docs/definition-of-done.md)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-yellow.svg)](CHANGELOG.md)

> **Instant, cryptographically deniable dual-environment computing on NixOS.**
>
> NAILS combines hidden volumes, Linux overlay filesystems, and NixOS's declarative
> configuration system to provide a hidden computing environment that is mathematically
> impossible to prove exists — and that switches in 2–5 seconds.

---

## Table of Contents

- [What Is NAILS?](#what-is-nails)
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Architecture](#architecture)
- [Development](#development)
- [System Requirements](#system-requirements)
- [Troubleshooting](#troubleshooting)
- [Use Cases](#use-cases)
- [Known Limitations](#known-limitations)
- [Project Status](#project-status)
- [License & Disclaimer](#license--disclaimer)

---

## What Is NAILS?

NAILS is a security tool for NixOS that lets you maintain two completely separate computing
environments — a visible **decoy system** and a hidden **real environment** — and switch between
them near-instantly.

The hidden environment lives inside any mounted directory you control: a VeraCrypt hidden
volume, a remote server accessed over SSHFS, an encrypted microSD card, or anything else.
When inactive, no forensic evidence of the hidden environment exists on the host system.
When active, Linux kernel overlays layer the hidden environment on top of the decoy without
ever modifying the base system.

**The result:** If your device is seized, you hand over the decoy password. The adversary sees a
normal encrypted NixOS installation. The hidden volume is indistinguishable from random data.

This is not a new idea. What is new is doing it *correctly* at the OS level — with declarative
reproducibility, automated artifact cleanup, and a Rust implementation that eliminates entire
classes of forensic residue that interpreted-language tools inevitably leave behind.

---

## How It Works

```
┌────────────────────────────────────────────────────────────────────────┐
│  DECOY SYSTEM  (always visible, always plausible)                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Standard NixOS + LUKS full-disk encryption                     │   │
│  │  Mundane applications, believable user data                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  OVERLAY LAYER  (active only when hidden storage is mounted)             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  OverlayFS mounts from hidden storage backend                   │   │
│  │  /nix  /etc  /home  /var  layered over decoy (copy-on-write)   │   │
│  │  All writes go to hidden storage — host remains untouched       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  HIDDEN ENVIRONMENT  (inside hidden storage)                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Full NixOS configuration (configuration.nix)                   │   │
│  │  Hidden packages, services, user accounts, secrets              │   │
│  │  State file + logs — all forensically isolated                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

**Defense layers:**

| Layer | Technology | Protects Against |
|---|---|---|
| **1 — Encryption** | LUKS full-disk + hidden volume (e.g. VeraCrypt AES-256) | Disk forensics, casual inspection |
| **2 — Impermanence** | NixOS tmpfs root (ephemeral base system) | Artifact-based forensics, accidental trace leakage |
| **3 — Overlay isolation** | Linux OverlayFS copy-on-write | Host contamination during active sessions |
| **4 — Artifact cleanup** | Automatic history, temp, and log sanitization | Post-deactivation forensic recovery |
| **5 — Memory safety** | Rust implementation with deterministic RAII cleanup | Binary forensic artifacts, interpreter traces |

### How NixOS configuration integration works

A critical property: **the base system configuration is forensically clean**. It contains no
NAILS-specific modules and no indication that a hidden environment exists.

Every NixOS installation imports `hardware-configuration.nix` by default — it contains hardware
detection results and is entirely unremarkable. During activation, NAILS overlays `/etc/nixos/`
with a modified version that adds one hidden import statement. This is indistinguishable from
any other NixOS system.

Upon deactivation the overlay is removed and the original file is restored with no trace of
modification.

### Storage backend flexibility

NAILS makes no assumptions about where the hidden environment lives. It accepts hidden data from
**any mounted directory**:

- **Local VeraCrypt hidden volumes** — offline access, strong cryptographic deniability
- **SSHFS / NFS over Tor** — hidden data never touches local storage; ideal for border crossings
- **Concealed hardware** — encrypted microSD cards; physical deniability on top of cryptographic
- **Anything else** that provides a directory tree with the required structure

Different threat situations call for different storage strategies. NAILS stays out of that decision.

### Extended overlay strategy

Beyond `/home` and `/etc`, NAILS optionally overlays high-activity directories (`/var`, `/tmp`,
`/srv`, `/opt`) with **tmpfs-backed upper layers**. Writes during the hidden session are captured
in RAM and destroyed immediately on unmount — they never reach the hidden storage and never
persist to disk, even if the system is examined immediately after deactivation.

### Boot partition handling

On NixOS with impermanence, `/boot` is typically a vfat (FAT32) EFI System Partition. The Linux
kernel does not support overlayfs on vfat — not even as a read-only lower layer (missing `d_type`
support). NAILS detects this automatically and uses a **snapshot pivot** strategy: the contents of
`/boot` are copied into a tmpfs in RAM, the tmpfs is used as the overlay lower layer, and the
result is bind-mounted over the original `/boot`. A preflight check validates that the target is
small enough (< 1 GB) to fit in RAM. This ensures `nixos-rebuild` writes new boot generations to
the overlay rather than the real `/boot` — preventing boot failures when the hidden volume is
absent.

---

## Key Features

- **🔒 Cryptographic plausible deniability** — VeraCrypt hidden volumes are mathematically
  indistinguishable from random data. You cannot be compelled to prove something that cannot
  be proven to exist.

- **⚡ 2–5 second switching** — Overlay mount/unmount is a kernel operation. After the
  one-time first-run NixOS profile build (median 34 s), activation is near-instant (median 2.1 s).

- **🧹 Zero forensic footprint** — 0% artifact detection across all categories in forensic
  testing with Autopsy, Sleuth Kit, and Volatility (n=30, standard deactivation).

- **🚨 One-command emergency response** — `nails emergency` triggers immediate deactivation in
  under 3 seconds. No levels to choose. No parameters to remember.

- **📝 Declarative hidden environment** — Your entire hidden system is defined in
  `configuration.nix`. If your hardware is seized, `git clone` + `nixos-rebuild` reconstructs
  your identical environment on new hardware.

- **🔄 Automatic rollback on failure** — Every operation either completes fully or rolls back to
  a known-good state. Partial activation is impossible.

- **🔍 Forensic verification** — `nails verify` runs a post-deactivation scan to confirm no
  artifacts remain on the host system.

- **📦 Storage-agnostic** — VeraCrypt, SSHFS over Tor, microSD, or any other mounted directory.
  Choose the backend that fits your threat model.

- **🦀 Rust implementation** — No interpreter overhead, no `.pyc` files, no GC pauses.
  Deterministic memory cleanup via RAII. Binary is ~2–5 MB stripped, starts in under 10 ms.

---

## Prerequisites

Before installing NAILS, you need:

| Requirement | Notes |
|---|---|
| **NixOS** | Any recent version with OverlayFS support (kernel 3.18+) |
| **NixOS impermanence** | Ephemeral tmpfs root strongly recommended for full deniability |
| **Hidden storage backend** | VeraCrypt volume, SSHFS mount, or any other mounted directory |
| **Rust 1.93+** | Stable channel. Only needed to build from source. |
| **Root access** | Required for `activate`, `deactivate`, `emergency`. |

> **Why NixOS only?**
> NAILS is built on NixOS's unique properties: declarative configuration, reproducible profiles,
> and the impermanence module. These are not available on general Linux distributions.

---

## Installation

### Option 1: Build from Source (Recommended)

Clone the repository onto your hidden volume, then build:

```bash
# 1. Mount your hidden volume first
veracrypt --mount /path/to/container /mnt/hidden

# 2. Clone onto the hidden volume
git clone https://github.com/nails-project/nails /mnt/hidden/nails
cd /mnt/hidden/nails

# 3. Build the release binary
cargo build --release

# 4. The binary is at:
./target/release/nails --version
```

**Optional:** Create a symlink for easy access. NAILS uses the binary's parent directory to
auto-detect the hidden volume root, so a symlink is fully supported:

```bash
sudo ln -s /mnt/hidden/nails/target/release/nails /usr/local/bin/nails
```

### Option 2: Nix Flake (NixOS Users)

```nix
# flake.nix
{
  inputs.nails.url = "github:nails-project/nails";

  outputs = { nixpkgs, nails, ... }: {
    nixosConfigurations.my-machine = nixpkgs.lib.nixosSystem {
      modules = [
        nails.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

---

## Quick Start

### 1. Initialize the hidden environment structure

```bash
nails init
```

This creates the required directory structure inside your hidden volume:
`config/`, `overlays/`, `logs/`, and `.nails/`.

### 2. Write your hidden NixOS configuration

```bash
$EDITOR /mnt/hidden/nails/nixos/configuration.nix
```

Example `configuration.nix`:

```nix
{ config, pkgs, lib, ... }:
{
  imports = [ /etc/nixos/configuration.nix ];  # Extend the decoy system

  environment.systemPackages = with pkgs; [
    tor
    gnupg
    keepassxc
    signal-desktop
  ];

  services.tor.enable = true;
  services.openssh.enable = false;

  users.users.ghost = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" ];
    hashedPassword = "$6$...";
  };
}
```

### 3. Configure your decoy system for impermanence

This is the base NixOS configuration that is **always visible to forensics**. It looks like any
other NixOS installation:

```nix
# /etc/nixos/configuration.nix
{ config, pkgs, lib, inputs, ... }:
{
  imports = [
    inputs.impermanence.nixosModules.impermanence
    ./hardware-configuration.nix  # Standard import — forensically unremarkable
  ];

  # Ephemeral root filesystem — artifacts don't survive reboot
  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "defaults" "size=8G" "mode=755" ];
  };

  # Explicitly declare what persists across reboots
  environment.persistence."/persist" = {
    hideMounts = true;
    directories = [ "/etc/nixos/" ];
  };
}
```

### 4. Activate the hidden environment

```bash
sudo nails activate
```

NAILS runs pre-flight checks (hidden storage mounted? sufficient space? swap disabled?),
builds the NixOS profile on first run (one-time, median ~34 s), and mounts the overlays.

### 5. Work in your hidden environment

Your system now has access to hidden packages, configurations, and user accounts.
Everything you do is isolated in the overlay — the decoy is untouched.

### 6. Deactivate when finished

```bash
sudo nails deactivate
```

Overlays are unmounted, shell history is sanitized, and the system returns to decoy state.
Unmount your hidden storage afterward:

```bash
veracrypt --dismount /mnt/hidden
```

### 7. Verify no artifacts remain

```bash
nails verify
```

Runs a forensic artifact scan against the host system. Target: 0% detection.

---

## Commands

### `nails activate`

Mount the hidden overlay environment. Requires root.

```
sudo nails activate [OPTIONS]

Options:
  --no-preflight          Skip pre-flight checks (DANGEROUS — expert use only)
  --no-kill-session       Do not kill the graphical session before activating
  --kill-session          Kill the graphical session (default)
  --accept-pivot-risks    Allow pivot mount fallback (degraded security)
  --no-pivot              Abort if any volume requires pivot mount (default)
  -y, --yes               Skip all confirmation prompts (default)
  --interactive           Prompt for confirmations
  --no-clear-history      Skip shell history cleanup on deactivation
  -v, --verbose           Verbose output (-v, -vv for more detail)
  -q, --quiet             Show only final result
  --json                  Output in JSON format
  --plain                 ASCII-only output (no Unicode symbols)
  --no-color              Disable colored output
```

**What activation does:**
1. Runs pre-flight validation (hidden storage accessible? available space? swap status?)
2. Builds a NixOS profile from `nixos/configuration.nix` (first run only; median ~34 s)
3. Fast-switches the NixOS profile on subsequent runs (median ~2.1 s)
4. Mounts overlay filesystems (`/nix`, `/etc`, `/home`, `/var`)
5. Optionally mounts tmpfs-backed overlays for `/tmp`, `/srv`, `/opt`
6. Updates the shell prompt indicator

### `nails deactivate`

Unmount overlays and return to decoy state. Requires root.

```
sudo nails deactivate [OPTIONS]

Options:
  --no-clear-history      Skip shell history sanitization
  -v, --verbose           Verbose output
  -q, --quiet             Errors only
  --json                  JSON output
  --plain                 ASCII-only output
  --no-color              Disable colors
```

**What deactivation does:**
1. Unmounts overlay filesystems in reverse order
2. Cleans shell history (removes `nails` invocations)
3. Removes temporary files
4. Rotates and trims hidden volume logs
5. Verifies no artifacts remain on the host
6. Rolls back automatically if any step fails

### `nails emergency`

Immediate deactivation with a 3-second abort window. Requires root.

```
sudo nails emergency [OPTIONS]

Options:
  --no-countdown          Skip the 3-second countdown (proceed immediately)
  -v, --verbose           Verbose output
  -q, --quiet             Errors only
  --json                  JSON output
  --plain                 ASCII-only output
  --no-color              Disable colors
```

> **Design principle:** This command must be typeable reflexively under extreme stress.
> No levels to choose. No parameters required. Press `Ctrl+C` within 3 seconds to abort.

Speed is prioritized over thoroughness. If overlays cannot be unmounted cleanly, a system
reboot is initiated — on NixOS with impermanence, the ephemeral tmpfs root ensures all
artifacts are wiped on restart. Completed in under 3 seconds in all test runs (maximum
observed: 2.9 s across n=30).

### `nails status`

Show current system state and security posture.

```
nails status [OPTIONS]

Options:
  -v, --verbose           Show detailed overlay mount information
  --json                  JSON output
  --plain                 ASCII-only output
  --no-color              Disable colors
```

Example output:

```
┌─────────────────────────────────────────────┐
│  NAILS STATUS                               │
│  State:    ACTIVE                           │
│  Uptime:   0h 14m 32s                       │
│  Overlays: 4/4 mounted                      │
│                                             │
│  ⚠  Remember: deactivate before shutdown   │
└─────────────────────────────────────────────┘
```

### `nails verify`

Scan the host system for NAILS artifacts after deactivation.

```
nails verify [OPTIONS]

Options:
  --deep                  Deep scan (slower, more thorough)
  --json                  JSON output
```

Runs the same forensic validation checks used in CI/CD to confirm the host is clean.
Target: 0% artifact detection rate.

### Global Flags

```
nails [GLOBAL OPTIONS] <COMMAND>

Global Options:
  --config <PATH>         Path to config file (overrides binary-relative discovery)
  -v, --verbose           Verbose output (stackable: -v, -vv, -vvv)
  -q, --quiet             Quiet mode: errors and warnings only
  --no-logs               Log to stdout only (skip hidden volume log file)
  --version               Print version
  -h, --help              Print help
```

---

## Configuration

### Zero-Config Operation

NAILS requires no configuration file. Place the binary on your hidden volume and run it.
The hidden volume root is auto-derived from the binary's location:

```
/mnt/hidden/nails/target/release/nails → uses /mnt/hidden/nails as root
/mnt/hidden/nails     (symlink target)  → correctly resolves to /mnt/hidden/nails
```

**Priority order for hidden volume root detection:**
1. Explicit value in `config/nails.toml` (if present)
2. Binary's parent directory (auto-detected)
3. Fallback constant: `/mnt/hidden-volume`

### Manual Configuration (`config/nails.toml`)

For advanced setups, create a TOML config file on the hidden volume:

```toml
# config/nails.toml

# Explicit override (use this only if auto-detection fails)
hidden_volume_root = "/custom/mount"

# Override default paths
state_file_path = "/custom/mount/.nails/state.json"
log_path        = "/custom/mount/logs"

# Overlay configuration (advanced)
[[overlays]]
name   = "nix"
lower  = "/nix"
upper  = "/custom/mount/overlays/nix/upper"
work   = "/custom/mount/overlays/nix/work"
target = "/nix"

[[overlays]]
name   = "etc"
lower  = "/etc"
upper  = "/custom/mount/overlays/etc/upper"
work   = "/custom/mount/overlays/etc/work"
target = "/etc"

[[overlays]]
name   = "home"
lower  = "/home"
upper  = "/custom/mount/overlays/home/upper"
work   = "/custom/mount/overlays/home/work"
target = "/home"
```

### Hidden Volume File Structure

```
/mnt/hidden/nails/
├── target/release/nails       # NAILS binary
│
├── nixos/
│   └── configuration.nix      # Hidden NixOS system configuration
│
├── config/
│   └── nails.toml             # Optional: NAILS configuration
│
├── etc/                       # Upper layer for /etc overlay
│   └── nixos/
│       └── hardware-configuration.nix  # Modified with hidden import (at runtime)
│
├── home/                      # Upper layer for /home overlay
│
├── nix/                       # Upper layer for /nix overlay
│
├── .work/                     # OverlayFS work directories
│   ├── etc/
│   └── home/
│
├── .nails/
│   └── state.json             # Runtime state (only accessible when volume is mounted)
│
└── logs/                      # Audit log (7-day retention, 10 MB max)
    └── nails.log
```

> **Forensic note:** All state and logs live exclusively on the hidden volume. Unmounting the
> volume makes them inaccessible. NAILS will refuse to write state or logs outside the
> hidden volume root.

---

## Security Model

### Threat Model

NAILS is designed to resist **post-seizure forensic analysis** — the scenario where an adversary
physically controls your device, decrypts the LUKS outer layer, and attempts to prove the
existence of a hidden environment.

| Attack Vector | NAILS Mitigation | Limitation |
|---|---|---|
| Disk forensics (offline) | VeraCrypt hidden volumes; OverlayFS write isolation | VeraCrypt must be unmounted |
| Artifact-based forensics | NixOS impermanence (ephemeral tmpfs root); automated cleanup on deactivation | User must actually deactivate |
| Memory forensics (cold boot) | Rust deterministic cleanup; no GC pauses | Keys persist in RAM; ~1–5 min window after power-off |
| Live system analysis | Emergency command; shutdown fallback | System captured before response |
| Supply chain | `cargo audit` on every commit; Cargo.lock committed | — |

### What NAILS Protects

- Hidden packages, applications, and data
- Hidden user accounts and configurations
- Activity logs and shell history
- Network configuration and browsing traces
- Cryptographic keys and secrets stored in the hidden environment

### What NAILS Does Not Protect

- Cold boot attacks (memory artifacts survive 1–5 minutes after power loss)
- Live system compromise (if an adversary has root on a running active system)
- Side-channel attacks (timing, power, EM emissions)
- Physical keylogging or screen capture

### Operational Security Recommendations

```
✔  Always unmount the hidden storage after deactivating.
✔  Use NixOS impermanence (ephemeral tmpfs root) for maximum defense-in-depth.
✔  Disable swap, or use encrypted swap — never unencrypted swap.
✔  Maintain plausible decoy activity (files, browser history, documents).
✔  Test your emergency procedure before relying on it.
✔  Use UTC timezone to avoid fingerprinting via clock offsets.
✔  Verify the system is clean with `nails verify` after every deactivation.
✔  For border crossings, consider SSHFS-over-Tor backends so no hidden data touches the device.
```

---

## Architecture

### Workspace Structure

NAILS uses a Cargo workspace with a strict thin-CLI / thick-library separation:

```
nails/
├── Cargo.toml                 # Workspace manifest + shared dependency versions
│
├── nails-cli/                 # Binary crate (~25 lines of entry-point code)
│   └── src/
│       ├── main.rs            # Entry point: parse args → call core
│       └── cli/
│           ├── args.rs        # Clap CLI struct definitions (source of truth for all flags)
│           ├── commands/      # One file per subcommand
│           ├── logging.rs     # Tracing subscriber initialization
│           ├── output/        # Terminal formatting
│           ├── safety.rs      # Root privilege checks
│           └── detach.rs      # Detached process support
│
└── nails-core/                # Library crate: all business logic
    └── src/
        ├── lib.rs             # Public API re-exports
        ├── manager/           # NailsManager orchestrator (Facade pattern)
        ├── state/             # Type-safe state machine + persistence
        ├── config/            # Configuration loading and validation
        ├── filesystem/        # FilesystemTrait + Real/Mock implementations
        ├── overlay/           # OverlayFS mount/unmount operations
        ├── preflight/         # Pre-flight validation registry
        ├── nixos/             # NixOS profile builder + config injection
        ├── cleanup/           # History, temp files, log sanitization
        ├── deactivation/      # DeactivationOrchestrator with rollback
        ├── emergency/         # Emergency deactivation with countdown
        ├── status/            # Status command + security posture
        ├── verify/            # Forensic artifact scanner
        ├── shell/             # Shell prompt instrumentation scripts
        ├── logging/           # Logging with hidden volume path validation
        ├── process/           # Process detection and session management
        ├── output/            # Structured CLI output formatting
        └── error.rs           # NailsError enum (12 variants, thiserror)
```

**Why this separation?**
- All business logic is testable without root privileges (via `MockFilesystem`)
- The core library is reusable by future interfaces (GUI, daemon, TUI)
- The CLI layer can be replaced independently of core logic

### State Machine

NAILS enforces a type-safe state machine. Invalid transitions are rejected at the type level —
the compiler prevents illegal states before code ever runs.

```
  ┌─────────┐   activate    ┌────────────┐   complete    ┌────────┐
  │INACTIVE │──────────────▶│ ACTIVATING │──────────────▶│ ACTIVE │
  └─────────┘               └────────────┘               └───┬────┘
       ▲                                                      │
       │                  deactivate                          │
       │   ┌──────────────────────────────────────────────────┘
       │   ▼
       │  ┌──────────────┐   complete
       └──│ DEACTIVATING │──────────────▶ INACTIVE
          └──────────────┘

  Any state ──▶ EMERGENCY (always reachable, highest priority)
```

### Key Design Patterns

| Pattern | Where Used | Why |
|---|---|---|
| **RAII guards** | `StateGuard`, `OverlayGuard` | Automatic rollback on failure or panic |
| **Trait abstraction** | `FilesystemTrait` | Enables test mocking without root |
| **Builder pattern** | `ConfigBuilder`, `NailsManager::new()` | Validated construction with smart defaults |
| **Facade** | `NailsManager` | Single entry point to all subsystems |
| **Command** | Each public manager method | Symmetry between CLI commands and core ops |

---

## Development

### Building from Source

```bash
# Debug build (fast compile, includes debug symbols)
cargo build

# Release build (optimized, stripped binary)
cargo build --release

# Check for errors without producing a binary (fastest)
cargo check
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output (useful for seeing test names)
cargo test -- --nocapture

# Run a specific test
cargo test test_state_transitions

# Run with debug logging
RUST_LOG=debug cargo test

# Run integration tests only
cargo test --test '*'
```

> **No root required:** 99% of the test suite runs without elevated privileges.
> The `MockFilesystem` trait implementation simulates all filesystem operations.

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting (CI gate)
cargo fmt --check

# Run linter
cargo clippy

# Strict lint (CI gate — zero warnings allowed)
cargo clippy -- -D warnings

# Security audit (checks all transitive dependencies)
cargo audit

# Test coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html --output-dir coverage/
```

### Pre-commit Hooks

NAILS enforces quality gates on every commit via `pre-commit`:

```bash
pip install pre-commit
pre-commit install
```

Hooks run automatically on `git commit`:

| Hook | What It Checks |
|---|---|
| `cargo-audit` | Dependency vulnerabilities (blocks on high/critical) |
| `rust-fmt` | Code formatting |
| `rust-clippy` | Zero clippy warnings |
| `rust-test` | All tests pass |
| `rust-coverage` | ≥ 85% test coverage |
| `commit-msg` | Conventional Commits format |
| `nixfmt` | Nix file formatting |
| `statix` | Nix anti-pattern linting |

### CI/CD Pipeline

Six-job GitHub Actions pipeline runs on every push and pull request:

```
format-check → lint → test → coverage → audit → benchmark
```

All jobs must pass before merging. Coverage reports are uploaded as artifacts and
posted as PR comments.

### Contributing

NAILS welcomes contributions. Before submitting:

1. All submissions must pass the [Definition of Done](docs/definition-of-done.md) criteria.
2. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
3. Maintain ≥ 85% test coverage.
4. Zero `clippy` warnings.
5. Clean `cargo audit` (no high/critical vulnerabilities).

```
feat(activate): add --dry-run flag for safe testing
fix(overlay): handle EBUSY on forced unmount
docs(readme): add systemd service example
test(state): add property-based tests for emergency transitions
```

**Branch naming:**

```
feature/story-NNN-short-description
bugfix/issue-NNN-short-description
docs/topic-name
```

See [docs/development-guide.md](docs/development-guide.md) for the full contribution workflow.

---

## System Requirements

| Component | Requirement |
|---|---|
| **OS** | NixOS (any recent version) |
| **Kernel** | Linux 3.18+ (OverlayFS support) |
| **Architecture** | `x86_64` (primary); other architectures untested |
| **Rust** | 1.93+ stable channel (build from source only) |
| **Hidden storage** | User-managed (VeraCrypt, SSHFS, or any mounted directory) |
| **Privileges** | Root (`sudo`) for `activate`, `deactivate`, `emergency` |
| **Disk space** | Depends on hidden environment size; overlays are copy-on-write |
| **RAM** | < 10 MB typical runtime footprint |

### Performance

Measured on standardized hardware (8 GB RAM, 256 GB SSD, Intel AES-NI), n=30 runs each:

| Operation | Median | 95th Percentile | Requirement |
|---|---|---|---|
| `activate` (first run) | 34.2 s | 52.8 s | one-time |
| `activate` (subsequent) | 2.1 s | 3.4 s | < 5 s ✓ |
| `deactivate` | 2.4 s | 3.1 s | < 5 s ✓ |
| `emergency` | 1.8 s | 2.3 s | **< 3 s ✓** |
| `status` | 0.08 s | 0.12 s | < 500 ms ✓ |
| Binary startup | < 10 ms | — | — |

---

## Troubleshooting

### Overlay won't mount

```bash
# Check kernel support
grep overlay /proc/filesystems

# Check if already mounted
findmnt /nix

# Verify hidden storage is mounted and writable
ls -la /mnt/hidden/
```

### Build errors

```bash
# Check Rust version
rustc --version    # must be 1.93+

# Update toolchain
rustup update stable

# Clean artifacts and rebuild
cargo clean && cargo build
```

### Coverage below threshold

```bash
# See which lines are uncovered
cargo tarpaulin --out Html --output-dir coverage/
# Open coverage/tarpaulin-report.html in a browser
```

### /boot overlay fails with "filesystem not supported"

This happens when `/boot` is a vfat/FAT32 partition (common for EFI). NAILS detects
overlay-incompatible filesystems automatically and uses a **snapshot pivot** — the contents
are copied to a tmpfs in RAM and overlayed there. No extra flags needed. If the preflight
check fails because `/boot` is too large (> 1 GB), add it to `overlay_exclusions` in your
config file.

```bash
# Check /boot filesystem type
findmnt -n -o FSTYPE /boot

# Activate normally — vfat snapshot pivot is automatic
sudo nails activate
```

### Can't return to decoy state

```bash
# Emergency cleanup (force-removes all overlays)
sudo nails emergency

# Manual unmount if binary is unavailable
sudo umount -f /nix /etc /var /home 2>/dev/null || true
sudo systemctl daemon-reload

# Restore from backup if /etc/nixos is corrupted
sudo nixos-rebuild switch --rollback
```

### Emergency: system won't respond

If the NAILS binary itself is unavailable:

```bash
# Manually unmount overlays
sudo umount -lf /nix /etc /home /var

# Rebuild the binary from source
cd /mnt/hidden/nails
cargo build --release
sudo ./target/release/nails emergency
```

If overlays cannot be unmounted at all, **reboot**. On NixOS with impermanence (ephemeral
tmpfs root), all non-persistent artifacts are automatically wiped on restart.

---

## Use Cases

NAILS is designed for technically skilled users operating under genuine adversarial threat:

- **Journalists** protecting source communications and unpublished investigations from
  newsroom raids or border device searches.

- **Security researchers** maintaining isolated analysis environments with zero contamination
  risk to their primary system.

- **Activists** in jurisdictions where device contents can lead to prosecution, requiring
  instant and deniable environment switching.

- **Privacy advocates** who want the strongest possible protection for sensitive personal
  communications and data.

> **Important:** NAILS is research software. Formal forensic validation against state-level
> forensic capabilities is ongoing. Do not rely on NAILS as your sole protection in
> life-critical situations without independent verification.

---

## Known Limitations

**Memory forensics — cold boot attacks.**
Encryption keys persist in RAM during active use. An adversary who can obtain a live RAM dump
within minutes of power-off may recover them. This is shared by all comparable tools (TAILS,
Qubes, VeraCrypt). CPU-register key storage (TRESOR-style) is planned for a future release.

**Tested tools, not all possible tools.**
The forensic evaluation used Autopsy, Sleuth Kit, and Volatility under controlled conditions.
Sufficiently motivated adversaries may develop detection techniques beyond what was tested.
NAILS makes forensic analysis expensive and difficult — it does not claim to be undetectable
by any conceivable adversary.

**Single-user systems only.**
Multi-user setups with per-user hidden environments are not supported in the current release.

**Hardware-level attacks are out of scope.**
SSD wear leveling, hardware keyloggers, and firmware-level compromises fall outside the threat
model. The threat model covers software-visible forensic artifacts.

**Network-mounted storage requires connectivity.**
SSHFS/NFS backends require network access during the hidden session. If the connection drops,
the overlay becomes unavailable. For offline use, prefer a local VeraCrypt volume.

---

## Project Status

NAILS is under active development. The project follows a milestone-driven release cadence:

| Milestone | Target | Status |
|---|---|---|
| **Epic 1: Foundation** | Jan 2026 | ✅ Complete |
| **v0.1.0 Alpha** — 5 core commands functional | Mar 2026 | 🔄 In progress |
| **v0.2.0 Beta** — Complete command suite + emergency | May 2026 | ⏳ Planned |
| **v1.0.0 Release** — Forensically validated | Jun 2026 | ⏳ Planned |

See [CHANGELOG.md](CHANGELOG.md) for detailed change history and [docs/epics.md](docs/epics.md)
for the full development roadmap.

---

## License & Disclaimer

This project is licensed under the **GNU Affero General Public License v3.0**.
See [LICENSE](LICENSE) for the full text.

> **Disclaimer:** This software is for educational and security research purposes.
> Users are solely responsible for compliance with applicable laws and regulations.
> The authors make no warranties — express or implied — about the security properties
> of this software in any specific threat environment.
>
> **Use at your own risk. Test thoroughly before relying on it.**

---

*NAILS is thesis research exploring the intersection of declarative operating systems,
cryptographic plausible deniability, and automated operational security.*
