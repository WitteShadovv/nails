<div align="center">
  <img src="docs/assets/logo.png" alt="NAILS logo" width="160" />
  <h1>NAILS — NixOS Anti-forensics Isolation &amp; Layering System</h1>

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![NixOS](https://img.shields.io/badge/NixOS-required-5277C3.svg)](https://nixos.org/)
[![CI](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml/badge.svg)](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/WitteShadovv/nails?display_name=tag)](https://github.com/WitteShadovv/nails/releases)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)

</div>

> **A NixOS-only CLI for layering a hidden environment over a decoy system.**

NAILS is a NixOS-only tool that layers a hidden environment on top of a believable decoy system by
combining a user-managed hidden storage backend, OverlayFS, and declarative NixOS configuration.

> [!WARNING]
> NAILS is **alpha** security software. It is intended for technically experienced users who can
> test their exact setup, storage backend, and operating procedure before relying on it.

## What NAILS does

NAILS is built around two environments on the same machine:

- a visible **decoy** NixOS installation that should remain mundane and plausible
- a hidden **real** environment stored on a mounted backend you control

When activated, NAILS overlays parts of the decoy system with hidden state and configuration. When
deactivated correctly and the hidden backend is dismounted, the host returns to its normal decoy
state within the documented threat model.

NAILS does **not** provide encryption itself. It relies on an external storage backend such as
VeraCrypt or LUKS/`cryptsetup` for hidden or encrypted storage.

## How it works

At a high level:

1. You mount a hidden, writable Linux filesystem that supports symbolic links.
2. `nails activate` overlays selected paths such as `/etc`, `/home`, `/var`, and optionally `/boot`.
3. Hidden NixOS configuration and hidden state become active without permanently rewriting the decoy.
4. `nails deactivate` or `nails emergency` removes overlays and returns the system to decoy state.

Key design points:

- **NixOS-specific workflow** using declarative rebuilds and profile switching
- **Storage-agnostic backend model** as long as the backend is already mounted and writable
- **Overlay-based isolation** so writes go to hidden storage rather than the decoy base system
- **Verification support** through `nails verify` for known/common post-deactivation artifacts

## Before you use it

NAILS is designed for a narrow threat model and operational style.

### Requirements

| Requirement | Notes |
|---|---|
| NixOS | Required |
| Hidden storage backend | Must already be mounted, writable, and support symbolic links |
| Root access | Required for `activate`, `deactivate`, and `emergency` |
| Rust 1.93+ | Only needed to build from source |
| Impermanence-style setup | Strongly recommended for the strongest documented posture |

### Important constraints

- NAILS does **not** mount, unlock, or protect the hidden backend for you.
- The default activation path may terminate the graphical session before activation completes.
- Your backend must remain mounted for the full hidden session and through deactivation.
- A clean `nails verify` result is evidence for known/common artifacts, **not proof** that no trace remains.

## Installation

### Option 1: Use the latest published GitHub release bundle

Download the latest published bundle from the canonical [GitHub Releases page](https://github.com/WitteShadovv/nails/releases).
GitHub Releases may contain either a manually published stable release for an exact version tag or a tagged prerelease for an immutable prerelease tag. Use the newest release line appropriate for your testing or deployment. Mount the hidden storage first, then place the published `nails` executable directly on that hidden root. Do not leave the binary on the decoy filesystem:

```bash
# Mount hidden storage first
veracrypt --mount /path/to/container /mnt/hidden

# Install the release binary onto hidden storage
install -m0755 /path/to/downloaded/nails /mnt/hidden/nails
```

Verify the published checksums before first use. For higher assurance, rebuild the published source revision and compare it against the bundle using the reproducibility guidance in
[`docs/release-artifact-reproducibility.md`](docs/release-artifact-reproducibility.md).

### Option 2: Build from source

```bash
git clone https://github.com/WitteShadovv/nails /mnt/hidden/src/nails
cd /mnt/hidden/src/nails
cargo build --release
install -m0755 ./target/release/nails /mnt/hidden/nails
```

### Option 3: Build with Nix

```bash
nix build .#nails
install -m0755 ./result/bin/nails /mnt/hidden/nails
```

> [!NOTE]
> Zero-config path discovery trusts the binary installed on hidden storage. If you run NAILS from
> a build directory or `/nix/store`, set `hidden_volume_root` explicitly or use `--config`.

## Quick start

1. **Mount your hidden storage**.

   ```bash
   veracrypt --mount /path/to/container /mnt/hidden-volume
   ```

2. **Bootstrap the hidden layout** on the mounted backend.

   ```bash
   nails init /mnt/hidden-volume
   ```

3. **Optionally review the generated config**.

   ```bash
   $EDITOR /mnt/hidden-volume/config/nails.yaml
   ```

   Minimal example:

   ```yaml
   hidden_volume_root: /mnt/hidden-volume
   # Optional:
   # nixos_flake: /mnt/hidden-volume/nixos#my-host
   ```

4. **Add or replace the hidden NixOS configuration** if you do not want the generated starter
   module.

   ```bash
   $EDITOR /mnt/hidden-volume/config/nixos/configuration.nix
   ```

5. **Activate the hidden environment**.

   ```bash
   sudo nails activate
   ```

   Use this safer path if you have not verified that the backend survives session termination:

   ```bash
   sudo nails activate --no-kill-session --interactive
   ```

6. **Return to decoy state when finished**.

   ```bash
   sudo nails deactivate
   ```

7. **After reboot, dismount the hidden backend** and verify from the decoy side.

   ```bash
   veracrypt --dismount /mnt/hidden-volume
   nails verify
   ```

## Command overview

| Command | Purpose |
|---|---|
| `nails init <PATH>` | Bootstrap a hidden-volume layout on an existing mounted root |
| `sudo nails activate` | Activate the hidden environment |
| `sudo nails deactivate` | Return to decoy state and reboot |
| `sudo nails emergency` | Remove overlays without waiting for a reboot |
| `nails status` | Show current state and security posture |
| `nails verify` | Scan for known/common host artifacts after deactivation |
| `nails notify-dispatch` | Dispatch pending desktop notifications on login |

For full flag-level usage, run `nails --help` or `nails <command> --help`.

## Threat model and limitations

NAILS is intended primarily for **post-seizure forensic analysis** scenarios: an adversary has the
device and attempts to prove the existence of a hidden environment after the fact.

NAILS can help reduce host-side artifacts, but it does **not** protect against every class of attack.

### Out of scope or not fully solved

- live compromise of an already active system
- cold-boot and memory-forensics attacks
- hardware implants, firmware compromise, or physical keylogging
- side-channel attacks such as timing, power, or EM analysis
- operator mistakes such as failing to deactivate cleanly or leaving the hidden backend mounted

If you are operating in a high-risk context, validate your exact procedure end to end before using
NAILS in the field.

## Reproducible release artifact

NAILS has one canonical Nix-built Linux release artifact:

- flake attribute: `.#nails-release`
- target: `x86_64-unknown-linux-musl`

To reproduce the release bundle locally for a specific revision:

```bash
nix build -L .#nails-release -o result --option accept-flake-config false
```

See [`docs/release-artifact-reproducibility.md`](docs/release-artifact-reproducibility.md) for the
scope of the reproducibility claim and artifact verification details.

## Related projects

- **NAILS** (this repository) is the NixOS-only CLI and workflow for layering a hidden environment over an existing decoy system you operate.
- **[NAILS OS](https://github.com/WitteShadovv/nails-os)** is a separate installable NixOS distribution with its own live ISO, installer, persistence model, and system-level security design.

They are related projects, but they are not interchangeable products and do not share the same installation or threat-model boundaries.

## Documentation and project policies

### User and operator references

- [GitHub Releases](https://github.com/WitteShadovv/nails/releases) *(published stable releases and prereleases)*
- [Change history](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [Release artifact reproducibility](docs/release-artifact-reproducibility.md)

### Contributing and governance

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Code owners](CODEOWNERS)

## Project status

NAILS is actively maintained and currently released as **alpha** software.

- Stable GitHub releases are created manually from exact stable tags; exact stable tag pushes are verification-only.
- Suffixed prerelease tags may publish immutable GitHub prereleases directly.
- Interfaces and operator workflows are still subject to change between alpha releases.
- Use it only after testing your exact hardware, storage backend, activation path, and recovery procedure.
- Security claims are bounded by the documented threat model and by the checks you perform on your own setup.

## Acknowledgements

- [Tails](https://tails.net)
- [NixOS](https://nixos.org)
- [Tor Project](https://www.torproject.org)
- [nix-community/impermanence](https://github.com/nix-community/impermanence)

NAILS has been developed with AI-assisted tooling for drafting code, tests, and documentation. All security-relevant design decisions, code changes, and published documentation remain the responsibility of the maintainer and are intended to be reviewed and validated before release.

## License and disclaimer

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE).

> [!CAUTION]
> This software is provided for educational and security research purposes. It comes with no
> warranty, and it should not be treated as a guarantee of deniability or forensic invisibility in
> any specific threat environment.
