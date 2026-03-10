# NAILS — NixOS Anti-forensics Isolation & Layering System

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![NixOS](https://img.shields.io/badge/NixOS-required-5277C3.svg)](https://nixos.org/)
[![Test Pipeline](https://github.com/WitteShadovv/nails/actions/workflows/test.yml/badge.svg)](https://github.com/WitteShadovv/nails/actions/workflows/test.yml)
[![Coverage: >=85%](https://img.shields.io/badge/coverage-%3E%3D85%25-brightgreen.svg)](CHANGELOG.md)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](CHANGELOG.md)

> **Fast-switching dual-environment computing on NixOS, designed to support plausible deniability workflows.**
>
> NAILS combines hidden volumes, Linux overlay filesystems, and NixOS's declarative
> configuration system to provide a hidden computing environment designed to reduce obvious
> host-side traces within the documented threat model.

---

## Table of Contents

- [What Is NAILS?](#what-is-nails)
- [How It Works](#how-it-works)
- [Release Artifact Reproducibility](#release-artifact-reproducibility)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Common Workflows](#common-workflows)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Architecture](#architecture)
- [Development](#development)
- [System Requirements](#system-requirements)
- [Troubleshooting](#troubleshooting)
- [Use Cases](#use-cases)
- [Known Limitations](#known-limitations)
- [Project Status](#project-status)
- [Acknowledgments](#acknowledgments)
- [License & Disclaimer](#license--disclaimer)

---

## What Is NAILS?

NAILS is a security tool for NixOS that lets you maintain two completely separate computing
environments — a visible **decoy system** and a hidden **real environment** — and switch between
them near-instantly.

The hidden environment lives inside a mounted directory tree you control: a local encrypted
volume, a remote filesystem, removable media, or any other backend that behaves like a normal
Linux filesystem and supports symbolic links. When inactive, the goal is that no NAILS-specific
evidence remains on the host system.
When active, Linux kernel overlays layer the hidden environment on top of the decoy without
ever modifying the base system.

**Intended outcome:** In the offline-seizure case, after proper deactivation and dismounting, the
decoy should present as a normal encrypted NixOS installation. When paired with a hidden-volume
backend such as VeraCrypt, the hidden container is intended to appear as random data to standard
forensic tooling.

This is not a new idea. What is new is an OS-level, declarative approach focused on reducing common
host artifacts, with a Rust implementation that avoids interpreter-generated residue such as
bytecode caches and runtime dependencies.

---

## How It Works

```
┌────────────────────────────────────────────────────────────────────────┐
│  DECOY SYSTEM  (always visible, always plausible)                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Standard NixOS + LUKS full-disk encryption                     │   │
│  │  Mundane applications, believable user data                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  OVERLAY LAYER  (active only when hidden storage is mounted)           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  OverlayFS mounts from hidden storage backend                   │   │
│  │  /nix  /etc  /home  /var  layered over decoy (copy-on-write)    │   │
│  │  All writes go to hidden storage — host remains untouched       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  HIDDEN ENVIRONMENT  (inside hidden storage)                           │
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

A critical design goal is to keep the base system configuration mundane and low-signal. It should
not contain persistent NAILS-specific modules while inactive.

Every NixOS installation imports `hardware-configuration.nix` by default — it contains hardware
detection results and is entirely unremarkable. During activation, NAILS overlays `/etc/nixos/`
with a modified version that adds one hidden import statement. In ordinary inspection, this should
look similar to a normal NixOS configuration change.

Upon successful deactivation, the overlay is removed and the original file is restored. Operators
should still verify the decoy state and dismount hidden storage before treating the system as safe.

### Storage backend flexibility

NAILS is storage-agnostic. The hidden root must already be mounted, writable, and backed by a
filesystem that supports symbolic links.

- **Kernel-managed encrypted mounts** — the safest default for `nails activate`, especially when
  the graphical session will be killed before activation completes
- **Remote filesystems** — viable if they present a normal writable directory tree and remain
  available for the full activation window
- **Removable media** — viable if mounted as a normal Linux filesystem and kept mounted until
  deactivation is complete
- **User-session-scoped VeraCrypt / FUSE mounts** — risky with the default activation path, because
  killing the user session can tear the mount down underneath NAILS

Different threat situations call for different storage strategies. NAILS does not mount the hidden
backend for you — it assumes the backend is already mounted correctly before activation begins.

### Extended overlay strategy

Beyond `/home` and `/etc`, NAILS optionally overlays high-activity directories (`/var`, `/tmp`,
`/srv`, `/opt`) with **tmpfs-backed upper layers**. These writes are intended to stay in RAM and
be discarded on unmount, reducing the chance that they persist on disk. This does not rule out
recovery from RAM, swap, logs, or other system-level traces.

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

## Release Artifact Reproducibility

NAILS now has one canonical Nix-built release artifact for Linux:

- flake attribute: `.#nails-release`
- target: `x86_64-unknown-linux-musl`

CI verifies this artifact by:

- building the canonical release bundle with Nix
- running `nix-store --realise --check` on the release derivation
- rebuilding it in two independent GitHub Actions jobs
- comparing the archive, checksums, and binary hash byte-for-byte

This is evidence of deterministic output for the pinned source revision, build instructions, and
tested CI environment. GitHub attestation provides provenance for the published artifact, but does
not by itself prove reproducibility.

For local rebuild instructions and the exact scope of the guarantee, see
`docs/release-artifact-reproducibility.md`.

---

## Key Features

- **🔒 Plausible deniability primitives** — When paired with hidden-volume technology such as
  VeraCrypt, NAILS can fit a plausible-deniability workflow. Real-world deniability still depends
  on system state, operator behavior, and adversary capabilities.

- **⚡ Fast switching architecture** — Overlay mount/unmount is a kernel operation. The design aims
  for near-instant activation after the initial NixOS build path is satisfied.

- **🧹 Forensic hygiene by design** — State, logs, and writable overlay layers stay on the hidden
  backend, with additional cleanup and verification support for operator workflows.

- **🚨 One-command live cleanup** — `nails emergency` removes active overlays without waiting for a
  reboot, but the hidden storage may still need to be dismounted manually afterward.

- **📝 Declarative hidden environment** — Your hidden environment lives in
  `config/nixos/configuration.nix` or a hidden flake. `git clone` + `nixos-rebuild` can recreate a
  functionally similar environment on new hardware, subject to pinned inputs and host differences.

- **🔄 Rollback on failure** — NAILS tracks activation state and attempts rollback on failure. Do
  not assume rollback succeeded silently; verify state explicitly and reboot into decoy if anything
  looks wrong.

- **🔍 Forensic verification support** — `nails verify` scans for known/common post-deactivation
  artifacts on the host system. A clean result is evidence, not proof.

- **📦 Storage-agnostic** — Local encrypted volumes, remote filesystems, and removable media all
  work if they present a mounted Linux directory tree that stays available for the full session.

- **🦀 Rust implementation** — Avoids interpreter-generated artifacts such as `.pyc` files and
  reduces some memory-safety risks. Runtime overhead is expected to be low, with exact size and
  startup characteristics depending on the final release build.

---

## Prerequisites

Before installing NAILS, you need:

| Requirement | Notes |
|---|---|
| **NixOS** | Any recent version with OverlayFS support (kernel 3.18+) |
| **NixOS impermanence** | Ephemeral tmpfs root strongly recommended for the strongest documented posture |
| **Hidden storage backend** | User-managed mounted filesystem with symlink support |
| **Rust 1.93+** | Stable channel. Only needed to build from source. |
| **Root access** | Required for `activate`, `deactivate`, `emergency`. |

> **Why NixOS only?**
> NAILS is built on NixOS's unique properties: declarative configuration, repeatable rebuilds with
> pinned inputs, and the impermanence module. These are not available on general Linux distributions.

---

## Installation

### Option 1: GitHub Release Binary (Default)

Mount the hidden storage first, then download the release binary directly onto the mounted hidden
root and run that copy.

```bash
# 1. Mount hidden storage first
veracrypt --mount /path/to/container /mnt/hidden

# 2. Download the appropriate release asset from GitHub Releases
#    and place the real executable on the hidden root
install -m0755 /path/to/downloaded/nails /mnt/hidden/nails
```

Verify the published checksum before first use. For higher assurance, rebuild the tagged source
locally and compare it against the release artifact using the reproducible-build verification
instructions published with that release.

> **Operator safety:** The default path assumes the hidden root is already mounted, writable, and
> stays available for the entire session. NAILS does not mount or protect the storage backend for you.

> **Important:** Zero-config path discovery only trusts the binary installed on hidden storage.
> Build outputs, store paths, and temporary locations are intentionally rejected for hidden-root
> auto-discovery. If you run NAILS from any other location, set `hidden_volume_root` explicitly or
> use `--config`.

> **Symlink note:** A host-side symlink such as `/usr/local/bin/nails -> /mnt/hidden/nails` is only
> a convenience entry point. NAILS resolves symlinks before discovering paths, so the real target
> binary location controls config discovery and hidden-root detection. Use the binary on the mounted
> hidden root directly unless you have explicitly accepted that exposure.

### Option 2: Build from Source

Mount your hidden storage first, then build the binary and install the real executable onto that
mounted hidden root:

```bash
# 1. Mount hidden storage first
veracrypt --mount /path/to/container /mnt/hidden

# 2. Clone the repository onto hidden storage
git clone https://github.com/WitteShadovv/nails /mnt/hidden/src/nails
cd /mnt/hidden/src/nails

# 3. Build the release binary
cargo build --release

# 4. Install the real executable onto the hidden root
install -m0755 ./target/release/nails /mnt/hidden/nails

# 5. Optional host-side symlink if you accept the exposure
sudo ln -s /mnt/hidden/nails /usr/local/bin/nails
```

**Important:** zero-config path discovery works from the installed binary on hidden storage, not
from `./target/release/nails`. Build directories and `/nix/store` paths are intentionally rejected
for hidden-root auto-discovery, so running the binary in place falls back to `/mnt/hidden-volume`
unless you set `hidden_volume_root` explicitly.

**Current hidden paths:**

- **Runtime config (optional):** `{hidden}/config/nails.yaml`
- **Hidden NixOS module:** `{hidden}/config/nixos/configuration.nix`
- **Hidden overlaid hardware config:** `{hidden}/etc/nixos/hardware-configuration.nix`
- **Staged symlink (managed by NAILS):** `{hidden}/etc/nixos/nails/configuration.nix`
- **State file:** `{hidden}/state.json`
- **Logs:** `{hidden}/logs/`

> **Hidden storage requirements:** The hidden root must already be a mounted, writable directory.
> The filesystem must support symbolic links. Linux filesystems such as `ext4` work; `FAT32` and
> `exFAT` do not.
>
> **VeraCrypt note:** `veracrypt --mount` is only safe with the default activation path if the
> resulting mount survives termination of the user session. If the mount depends on a GUI-session
> FUSE process, prefer `cryptsetup` with a kernel-managed mount instead.

### Option 3: Nix Flake (Build Package / Dev Shell)

```bash
# Optional: enter the pinned Rust dev shell
nix develop

# Build the package
nix build .#nails

# Install the built binary onto the hidden root
install -m0755 ./result/bin/nails /mnt/hidden/nails
```

Because `./result/bin/nails` resolves into `/nix/store`, you should copy it onto hidden storage
before using zero-config mode. If you choose to run a store path directly, provide an explicit
config with `hidden_volume_root`, or use `--config`.

---

## Quick Start

### 1. Create the hidden configuration layout

```bash
mkdir -p /mnt/hidden/etc/nixos
cp /etc/nixos/hardware-configuration.nix /mnt/hidden/etc/nixos/hardware-configuration.nix
```

NAILS does not yet provide a `nails init` subcommand, so create these paths directly. The hidden
module at `/mnt/hidden/config/nixos/configuration.nix` is now auto-generated on first activation if
it is missing.

Then make sure the hidden hardware config imports the hidden module:

```bash
$EDITOR /mnt/hidden/etc/nixos/hardware-configuration.nix
```

Add the hidden import to its `imports` list:

```nix
{ config, pkgs, lib, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
    ./nails/configuration.nix
  ];
}
```

If you want an explicit runtime config, place it at:

```bash
$EDITOR /mnt/hidden/config/nails.yaml
```

Minimal example:

```yaml
hidden_volume_root: /mnt/hidden
# Optional:
# nixos_flake: /mnt/hidden/nixos#my-host
```

If `config/nails.yaml` is missing, NAILS falls back to binary-relative discovery.

### 2. Optional: write your hidden NixOS configuration

```bash
$EDITOR /mnt/hidden/config/nixos/configuration.nix
```

If this file does not exist, NAILS auto-generates a minimal hidden module:

```nix
{ pkgs, ... }: {
  environment.systemPackages = [ pkgs.ripgrep ];
}
```

That keeps activation working out of the box and adds one hidden-only package that is not present in
the base test system. If you want a real hidden environment, replace that generated file with your
own module before the next activation.

Example `configuration.nix`:

```nix
{ pkgs, ... }:
{

  environment.systemPackages = with pkgs; [
    tor
    gnupg
    keepassxc
    signal-desktop
  ];

  services.tor.enable = true;

  users.users.ghost = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" ];
  };
}
```

> **Do not** import `/etc/nixos/configuration.nix` from this file. NAILS injects the hidden module
> through the overlaid `/etc/nixos/hardware-configuration.nix` path.

### 3. Optional: provide a hidden flake

Current build-target selection is:

1. `{hidden}/nixos/flake.nix`
2. `/etc/nixos/flake.nix`
3. `/etc/nixos/configuration.nix`

If you want NAILS to build from a hidden flake, place it at:

```bash
$EDITOR /mnt/hidden/nixos/flake.nix
```

If you need an explicit flake reference or attribute, use `--flake /absolute/path#attr` or set
`nixos_flake:` in `config/nails.yaml`.

### 4. Configure your decoy system for impermanence

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

### 5. Activate the hidden environment

```bash
sudo nails activate
```

By default, `activate` behaves as if you passed:

- `--kill-session`
- `--yes`
- `--no-pivot`

On a graphical desktop, NAILS detaches into a transient systemd unit, terminates the graphical
session, restarts the display manager, and continues activation in the background.

> **Warning:** Save your work first. Unsaved GUI state will be lost.
>
> **Safe to proceed only if all of the following are true:**
> - the hidden storage is already mounted
> - the mount is writable
> - the mount survives loss of the current user session
>
> If you cannot verify those conditions on your exact setup, do **not** use the default path. Use
> `--no-kill-session --interactive` or reconfigure the storage backend first.

When the login screen returns, log in only after activation has completed and only with an account
that exists in the activated configuration.

If you do **not** want the session terminated, opt out explicitly:

```bash
sudo nails activate --no-kill-session --interactive
```

> **Operational note:** Default activation kills the graphical user session first, then
> continues from a detached worker in `system.slice`. Your hidden storage must still be mounted
> after that session dies.
>
> - **User-session-scoped VeraCrypt / FUSE mounts are risky.** If the mount depends on the GUI
>   session, a user `systemd --user` instance, or a FUSE daemon owned by that session, killing the
>   session can tear the mount down underneath NAILS.
> - **Prefer `cryptsetup` + kernel-managed mounts with the default activation path.** A kernel
>   block-device mount survives the death of the GUI session, so the detached root worker can still
>   finish activation, cleanup, and display-manager restart.
> - In practice, the detached worker must still be able to read from and write to the hidden
>   storage after the user session ends, without relying on the old session or any user-space
>   FUSE process.

### 6. Work in your hidden environment

Your system now has access to hidden packages, configurations, and user accounts.
Everything you do is isolated in the overlay — the decoy is untouched.

### 7. Deactivate when finished

```bash
sudo nails deactivate
```

`deactivate` currently returns the system to decoy state by triggering an immediate reboot. The
hidden storage may still be mounted until the reboot completes, so treat the safe end-state as:

1. the machine has rebooted into the decoy system
2. you are back in the decoy environment
3. the hidden storage has been manually dismounted

After the reboot, log into your decoy account again, then unmount the hidden storage before any
ordinary decoy use:

```bash
veracrypt --dismount /mnt/hidden
```

### 8. Verify from the decoy side

```bash
nails verify
```

If you keep a decoy-side copy of the binary for verification, run `nails verify` after returning to
the decoy side and after manually dismounting the hidden storage. If your only `nails` binary lives
on the hidden storage, dismount first and treat the previous session's logs plus your manual
operator checks as the final confirmation path.

---

## Commands

### `nails activate`

Activate the hidden environment. Requires root.

```text
sudo nails activate [OPTIONS]

Options:
      --config <PATH>        Path to configuration file (overrides binary-relative discovery)
      --no-preflight         Skip pre-flight checks (DANGEROUS - expert use only)
  -q, --quiet                Quiet mode: only show final result
  -v, --verbose...           Verbose output (-v for detailed, -vv for debug)
      --json                 Output results in JSON format
      --no-color             Disable colored output
      --plain                ASCII-only output (no Unicode symbols)
      --no-clear-history     Skip clearing shell history on deactivation
      --kill-session         Kill graphical session before activation (enabled by default)
      --no-kill-session      Do not kill session (interactive mode)
      --accept-pivot-risks   Accept pivot mount fallback for any volume (degraded security)
      --no-pivot             Abort if any volume requires pivot mount (strict security, enabled by default)
  -y, --yes                  Skip all confirmation prompts (enabled by default)
      --interactive          Prompt for confirmations (interactive mode)
      --flake <FLAKE_REF>    NixOS flake reference (e.g. /etc/nixos#hostname)
```

**What activation does:**
1. Runs pre-flight checks unless explicitly skipped
2. Stages the hidden NixOS config symlink and validates the hidden storage layout
3. May kill the graphical session and continue from a detached systemd worker
4. Mounts overlays and applies the hidden NixOS configuration
5. Uses `--flake`, then hidden `nixos/flake.nix`, then `/etc/nixos/flake.nix`, then legacy `/etc/nixos/configuration.nix`
6. Leaves you in the hidden environment after you log in again if session kill was used

### `nails deactivate`

Return to decoy state. Requires root.

```text
sudo nails deactivate [OPTIONS]

Options:
      --config <PATH>        Path to configuration file (overrides binary-relative discovery)
      --no-clear-history     Skip shell history cleanup
  -q, --quiet                Suppress output except errors
  -v, --verbose...           Increase verbosity (-v for details, -vv for debug)
      --json                 Output results in JSON format
      --no-color             Disable colored output
      --plain                ASCII-only output (no Unicode symbols)
```

**What deactivation does:**
1. Restores `/run/current-system` to the decoy system profile
2. Calls `systemctl reboot`
3. Returns you to the decoy environment after reboot

This is the current fast path. It does **not** perform the thorough in-process unmount and cleanup
sequence documented in older versions of this README. After the reboot, the operator must still
confirm the decoy system is back and manually dismount the hidden storage.

### `nails emergency`

Thorough deactivation without reboot. Requires root.

```text
sudo nails emergency [OPTIONS]

Options:
      --config <PATH>        Path to configuration file (overrides binary-relative discovery)
      --no-countdown         Skip the 3-second countdown (proceed immediately)
      --quiet                Suppress output except final result
  -v, --verbose...           Increase verbosity (-v for details, -vv for debug)
      --json                 Output results in JSON format
      --no-color             Disable colored output
      --plain                ASCII-only output (no Unicode symbols)
```

**What emergency does:**
1. Transitions to the deactivating state
2. Unmounts ephemeral overlays first and persistent overlays after
3. Restarts `nix-daemon` if `/nix` was overlaid
4. Switches back to the decoy configuration without reboot
5. Verifies base config cleanliness when `/etc` was overlaid

> **Important:** `--no-countdown` is currently accepted for compatibility only. Do not rely on it
> to change emergency behavior.

After `emergency`, the hidden storage may still be mounted. If you are safe to do so, dismount it
manually before returning to ordinary decoy use. If you cannot dismount it cleanly, or if you are
unsure cleanup completed, reboot immediately.

### `nails status`

Show current system state and security posture.

```text
nails status [OPTIONS]

Options:
      --config <PATH>        Path to configuration file (overrides binary-relative discovery)
      --json                 Output results in JSON format
      --plain                ASCII-only output (no Unicode box drawing or emoji)
      --no-color             Disable colored output
  -v, --verbose             Display detailed overlay mount information
```

`status` always exits successfully. If the state file is missing or invalid, it reports `INACTIVE`
with context instead of failing.

### `nails verify`

Scan the host system for NAILS artifacts after deactivation.

```text
nails verify [OPTIONS]

Options:
      --deep                 Perform deep scan (slower, more thorough)
      --json                 Output results as JSON
```

The verifier checks mounted overlays, known artifact paths, running NAILS processes, and memory
warnings. `--deep` adds scans of `/tmp`, `/var/tmp`, `/var/log`, and common shell history files.
Treat a clean result as a check for known/common artifacts, not a proof that no trace is
recoverable.

## Common Workflows

### Check the current state

Use `nails status` before activation, after reboot, or before dismounting hidden storage.

```bash
nails status
nails status -v
```

### Activate without killing the current session

If you have not verified that the hidden backend survives session termination, avoid the default
activation path:

```bash
sudo nails activate --no-kill-session --interactive
```

### Return to decoy state without reboot

If normal deactivation is unavailable or unsafe, use the live cleanup path:

```bash
sudo nails emergency
```

After `emergency`, dismount the hidden storage manually when it is safe to do so.

---

### Global Flags

```text
nails [GLOBAL OPTIONS] <COMMAND>

Global Options:
      --config <PATH>        Path to configuration file (overrides binary-relative discovery)
  -v, --verbose...           Verbose output (-v, -vv, -vvv)
  -q, --quiet                Quiet mode: only show errors and warnings
      --no-logs              Skip file logging (only log to stdout)
  -V, --version              Print version
  -h, --help                 Print help
```

---

## Configuration

### Zero-Config Operation

NAILS can run without a config file. If none is found, it uses built-in defaults.

**Config file discovery order:**
1. `--config <PATH>`
2. `{resolved-binary-dir}/config/nails.yaml`
3. `{current-working-directory}/config/nails.yaml` if the binary path cannot be determined

**Hidden volume root resolution order:**
1. `hidden_volume_root` in YAML (`hidden_volume_path` is also accepted as an alias)
2. Resolved binary parent directory
3. Fallback constant: `/mnt/hidden-volume`

> **Important:** Auto-derivation does **not** trust build/store locations such as `target/debug`,
> `target/release`, `target/llvm-cov-target`, or `/nix/store`. In those cases NAILS falls back to
> `/mnt/hidden-volume` unless you set `hidden_volume_root` explicitly.

### Manual Configuration (`config/nails.yaml`)

For advanced setups, place a YAML config at `config/nails.yaml`.

```yaml
# config/nails.yaml

# Optional explicit hidden-volume root override.
hidden_volume_root: /mnt/hidden-volume
# Backward-compatible alias also accepted:
# hidden_volume_path: /mnt/hidden-volume

# Derived from hidden_volume_root when omitted
state_file_path: /mnt/hidden-volume/state.json
log_path: /mnt/hidden-volume/logs

minimum_space_mb: 500

# Overlay selection
overlay_mode: auto  # auto (default) or explicit

# Additional exclusions in auto mode
overlay_exclusions:
  - /nix

# Remove entries from the default exclusion set
overlay_exclusions_remove:
  - /mnt

# Used only when overlay_mode: explicit
overlays:
  - name: home
    lower: /home
    upper: /mnt/hidden-volume/home
    work: /mnt/hidden-volume/.work/home
    target: /home

extended_overlays:
  enabled: false
  directories:
    - path: /var
      tmpfs_upper_size: 1G
      tmpfs_work_size: 512M

clear_history: true
preflight_checks: true
default_verbosity: info
color_output: true
verify_on_deactivate: true
milestone_tips: true
show_opsec_reminders: true

max_log_size_mb: 10
retention_days: 7

color_scheme:
  enabled: true
  hidden:
    background: "#1a1a2e"
    foreground: "#e0e0e0"
  decoy:
    reset: true

# Passed directly to: nixos-rebuild --flake <value>
nixos_flake: /etc/nixos#my-host
```

**Current top-level config keys:**

- `hidden_volume_root`
- `state_file_path`
- `overlays`
- `minimum_space_mb`
- `extended_overlays`
- `overlay_mode`
- `overlay_exclusions`
- `overlay_exclusions_remove`
- `clear_history`
- `preflight_checks`
- `default_verbosity`
- `color_output`
- `verify_on_deactivate`
- `milestone_tips`
- `show_opsec_reminders`
- `log_path`
- `max_log_size_mb`
- `retention_days`
- `color_scheme`
- `nixos_flake`

### Overlay Behavior

`overlay_mode: auto` is the default and the recommended mode. In auto mode, NAILS:

- enumerates directories under `/`
- applies the effective exclusion list
- creates overlay upper directories automatically under `{hidden_volume_root}/{name}`
- creates work directories under `{hidden_volume_root}/.work/{name}`

`overlay_mode: explicit` uses only the entries in `overlays`.

**Default auto-mode exclusions:**

- `/proc`
- `/sys`
- `/dev`
- `/run`
- `/mnt`
- `/bin`
- `/usr`
- `/lib`
- `/lib64`
- `/sbin`
- `/lost+found`
- `/Downloads`

Notes:

- `/boot` is **not** excluded by default.
- Removing `/proc`, `/sys`, `/dev`, or `/run` from the exclusion list is allowed, but will likely cause mount failures.

### Extended Overlays

`extended_overlays` enables RAM-backed tmpfs overlays for selected directories.

Each entry uses:

- `path`
- `tmpfs_upper_size`
- `tmpfs_work_size`

These overlays are ephemeral: their writable layers live in RAM and disappear on unmount. They do
not create persistent upper/work directories on the hidden volume.

### Terminal Color Scheme

`color_scheme` controls automatic terminal color changes when entering and leaving the hidden
environment.

Defaults:

- `color_scheme.enabled: true`
- hidden background: `#1a1a2e`
- hidden foreground: `#e0e0e0`
- decoy reset: `true`

### NixOS Build Target Selection

`nixos_flake` is optional.

**Precedence:**
1. CLI `--flake`
2. config `nixos_flake`
3. auto-discovery

If auto-discovery is used, NAILS checks in this order:

1. `{hidden_volume_root}/nixos/flake.nix`
2. `/etc/nixos/flake.nix`
3. `/etc/nixos/configuration.nix`

### Hidden Volume File Structure

```text
<hidden_volume_root>/
├── config/
│   ├── nails.yaml                    # Optional YAML config
│   └── nixos/
│       └── configuration.nix         # Hidden NixOS module imported at activation
├── nixos/
│   └── flake.nix                     # Optional flake root for auto-discovery
├── state.json                        # Runtime state
├── logs/                             # Hidden-volume log directory
├── .work/                            # OverlayFS work directories
│   ├── boot/
│   ├── etc/
│   ├── home/
│   ├── var/
│   └── ...
├── boot/                             # Persistent upper dir for /boot
├── etc/                              # Persistent upper dir for /etc
│   └── nixos/
│       └── nails/
│           └── configuration.nix     # Symlink to config/nixos/configuration.nix
├── home/                             # Persistent upper dir for /home
├── var/                              # Persistent upper dir for /var
└── ...                               # One top-level upper dir per overlaid target
```

A few important details:

- The current layout uses root-level upper directories such as `home/`, `etc/`, `var/`, and `boot/` - not `overlays/<name>/upper/`.
- OverlayFS work directories live under `.work/<name>/`.
- Runtime state lives at `state.json` in the hidden-volume root.
- `config/nails.yaml` is optional.
- `config/nixos/configuration.nix` is the hidden module imported into the overlaid NixOS config path.
- If you use flakes, the hidden flake auto-discovery location is `nixos/flake.nix`.
- `extended_overlays` are RAM-backed and therefore do not appear in the persistent on-disk tree above.

> **Forensic note:** NAILS-managed runtime state and file logs are intended to stay on the hidden
> volume. Unmounting the volume makes them inaccessible. Other evidence sources outside NAILS's
> control may still exist.

---

## Security Model

### Threat Model

NAILS is designed to resist **post-seizure forensic analysis** — the scenario where an adversary
physically controls your device, decrypts the LUKS outer layer, and attempts to prove the
existence of a hidden environment.

| Attack Vector | NAILS Mitigation | Limitation |
|---|---|---|
| Disk forensics (offline) | VeraCrypt hidden volumes; OverlayFS write isolation | VeraCrypt must be unmounted |
| Artifact-based forensics | NixOS impermanence (ephemeral tmpfs root); cleanup and verification workflow | User must actually deactivate or reboot into decoy state |
| Memory forensics (cold boot) | Rust deterministic cleanup; no GC pauses | Keys persist in RAM; ~1–5 min window after power-off |
| Live system analysis | Emergency command; operator-controlled reboot fallback | System captured before response |
| Supply chain | `cargo audit` on every commit; Cargo.lock committed | — |

### What NAILS Helps Isolate

- Filesystem-resident hidden packages, applications, and user data
- Hidden user accounts and local configuration changes
- Some shell history, temp-file, and log artifacts when the documented workflow is followed
- Secrets stored inside the hidden environment's mounted backend

### What NAILS Does Not Protect

- Cold boot attacks (memory artifacts survive 1–5 minutes after power loss)
- Live system compromise (if an adversary has root on a running active system)
- Side-channel attacks (timing, power, EM emissions)
- Physical keylogging or screen capture

### Operational Security Recommendations

```
✔  Always unmount the hidden storage after deactivating or after emergency cleanup.
✔  For VeraCrypt-style hidden volumes, keep the outer volume believable and never mount the outer and hidden volumes at the same time.
✔  Use a strong hidden-volume passphrase and test your exact mount method before relying on the default activation path.
✔  Use NixOS impermanence (ephemeral tmpfs root) for maximum defense-in-depth.
✔  Disable swap, or use encrypted swap — never unencrypted swap.
✔  Maintain plausible decoy activity (files, browser history, documents).
✔  Test your emergency procedure before relying on it.
✔  Use UTC timezone to avoid fingerprinting via clock offsets.
✔  Verify the system with `nails verify` after every hidden session; a clean result is not a guarantee.
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
        ├── filesystem/        # Filesystem trait + Real/Mock implementations
        ├── overlay/           # OverlayFS mount/unmount operations
        ├── preflight/         # Pre-flight validation registry
        ├── nixos/             # NixOS profile builder + config injection
        ├── cleanup/           # History, temp files, log sanitization
        ├── deactivation/      # DeactivationOrchestrator with rollback
        ├── emergency/         # Emergency deactivation helpers
        ├── status/            # Status command + security posture
        ├── verify/            # Forensic artifact scanner
        ├── shell/             # Shell prompt instrumentation scripts
        ├── logging/           # Logging with hidden volume path validation
        ├── process/           # Process detection and session management
        ├── output/            # Structured CLI output formatting
        └── error.rs           # NailsError enum (thiserror-based)
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
| **Trait abstraction** | `Filesystem` | Enables test mocking without root |
| **Builder pattern** | `ConfigBuilder`, `NailsManager::new()` | Validated construction with smart defaults |
| **Facade** | `NailsManager` | Single entry point to all subsystems |
| **Command** | Each public manager method | Symmetry between CLI commands and core ops |

---

## Development

### Building from Source

```bash
# Debug build (fast compile, includes debug symbols)
cargo build

# Release build (optimized)
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

> **No root required:** Most of the test suite runs without elevated privileges.
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

# Test coverage (requires cargo-llvm-cov)
cargo llvm-cov --all-features --workspace --html --output-dir coverage/html
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

The repository uses GitHub Actions for format, lint, test, coverage, audit, benchmark, and final
status validation:

```text
format-check -> lint -> test -> coverage -> audit -> benchmark -> ci-success
```

All jobs must pass before merging. Coverage reports are uploaded as artifacts and
posted as PR comments.

### Contributing

NAILS welcomes contributions. Before submitting:

1. All submissions must pass the Definition of Done criteria.
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

See the development guide for the full contribution workflow.

---

## System Requirements

| Component | Requirement |
|---|---|
| **OS** | NixOS (any recent version) |
| **Kernel** | Linux 3.18+ (OverlayFS support) |
| **Architecture** | `x86_64` (primary); other architectures untested |
| **Rust** | 1.93+ stable channel (build from source only) |
| **Hidden storage** | User-managed mounted filesystem with symlink support |
| **Privileges** | Root (`sudo`) for `activate`, `deactivate`, `emergency` |
| **Disk space** | Depends on hidden environment size; overlays are copy-on-write |
| **RAM** | Low runtime footprint is a design goal; exact usage depends on build and workload |

### Performance

Performance targets are tracked in the design and CI pipeline, but the benchmark harness is still
being filled out. The current placeholder targets are:

| Operation | Target |
|---|---|
| `activate` (subsequent) | < 5 s |
| `emergency` | < 3 s |
| `status` | < 500 ms |
| Binary startup | < 10 ms |

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
cargo llvm-cov --all-features --workspace --html --output-dir coverage/html
# Open coverage/html/index.html in a browser
```

### /boot overlay fails with "filesystem not supported"

This happens when `/boot` is a vfat/FAT32 partition (common for EFI). NAILS detects
overlay-incompatible filesystems automatically and uses a **snapshot pivot** — the contents
are copied to a tmpfs in RAM and overlaid there. No extra flags needed. If the preflight
check fails because `/boot` is too large (> 1 GB), add it to `overlay_exclusions` in your
config file only if you accept that hidden rebuilds may then touch the real `/boot` and leave
visible boot artifacts.

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
cd /mnt/hidden/src/nails
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

See [CHANGELOG.md](CHANGELOG.md) for detailed change history.

---

## Acknowledgments

Development of NAILS was assisted by Claude (Anthropic) — Sonnet and Opus models were used
for code generation, testing, and documentation throughout the project.
All code has been reviewed, tested, and validated by the author.

---

## License & Disclaimer

This project is licensed under the **GNU General Public License v3.0**.
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
