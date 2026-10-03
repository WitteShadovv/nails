<div align="center">
  <img src="docs/assets/logo.png" alt="NAILS logo" width="160" />
  <h1>NAILS — NixOS Anti-forensics Isolation &amp; Layering System</h1>

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/platforms-NixOS%20%7C%20Debian%2012%2B%20%7C%20Ubuntu%2024.04%2B-5277C3.svg)](#platform-support)
[![CI](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml/badge.svg)](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/WitteShadovv/nails?display_name=tag)](https://github.com/WitteShadovv/nails/releases)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)

</div>

> **A CLI for layering a hidden environment over a decoy system, with first-class NixOS support and an overlay-only mode for the Debian family.**

NAILS layers a hidden environment on top of a believable decoy system by combining a user-managed
hidden storage backend, OverlayFS, and — on NixOS — declarative configuration. NixOS is the
first-class platform; Debian 12+ and Ubuntu 24.04+ run in a reduced overlay-only mode. See
[Platform support](#platform-support) for what each platform does and the hosts NAILS refuses.

> [!WARNING]
> NAILS is **alpha** security software. It is intended for technically experienced users who can
> test their exact setup, storage backend, and operating procedure before relying on it.

## What NAILS does

NAILS is built around two environments on the same machine:

- a visible **decoy** NixOS installation that should remain mundane and plausible
- a hidden **real** environment stored on a mounted backend you control

When activated, NAILS overlays parts of the decoy system with hidden state and configuration. When
deactivation finishes and the backend is no longer mounted, the host returns to its normal decoy
state within the documented [threat model](docs/threat-model.md).

NAILS does **not** provide encryption itself. It relies on an external storage backend such as
VeraCrypt or LUKS/`cryptsetup` for hidden or encrypted storage.

## How it works

At a high level:

1. You mount a hidden, writable Linux filesystem that can host an overlayfs upper layer (symbolic links, trusted xattrs, a valid readdir `d_type`, and whiteouts).
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
| Supported platform | NixOS, Debian 12+, or Ubuntu 24.04+. See [Platform support](#platform-support); other hosts are refused at detection. |
| Hidden storage backend | Any mounted, writable Linux filesystem that can host an overlayfs upper (symlinks, trusted xattrs, `d_type`, whiteouts) — e.g. ext4, xfs, btrfs, f2fs. NFS, CIFS/SMB, 9p, most FUSE mounts, and FAT/exFAT/NTFS cannot. See [docs/backends.md](docs/backends.md) for what is tested and the hazards of each backend. |
| Root access | Required for `activate`, `deactivate`, and `emergency` |
| Rust 1.93+ | Only needed to build from source |
| Amnesic decoy | Required: the decoy must keep no durable record of the hidden session. Activation fails closed otherwise (override with `--accept-persistent-decoy`). See [docs/decoy-requirements.md](docs/decoy-requirements.md). |
| Impermanence-style setup | Strongly recommended for the strongest documented posture; see [docs/decoy-requirements.md](docs/decoy-requirements.md) |

### Platform support

NAILS detects the host from `/etc/os-release` and the running init, then selects a backend. The
matrix below matches what detection actually accepts.

| Platform | Support | Notes |
|---|---|---|
| NixOS | Full | Declarative hidden configuration: `nixos-rebuild`, profile switching, and the full `/nix` + `/run/current-system` restoration. |
| Debian 12+ | Overlay-only | Hidden session is OverlayFS alone — no declarative config layer. `/usr` and the core roots stay read-only as the leak guard; a volatile journald journal (and no active rsyslog/syslog-ng/auditd) is required. Requires the merged-usr layout. |
| Ubuntu 24.04+ | Overlay-only | As Debian; `/snap` is excluded from the overlay. |
| Debian family derivatives | Provisional | A host whose `ID_LIKE` names `debian`/`ubuntu` is accepted on the same overlay-only terms, but its base release is not version-gated. |
| Fedora, Arch, other distributions | Refused | No validated backend yet; detection declines with a documented message. Planned — see [ROADMAP.md](ROADMAP.md). |
| ostree / image-based hosts | Refused | NAILS cannot overlay an immutable system. |
| Non-systemd hosts (OpenRC, runit, …) | Refused | Teardown and session handling require systemd. |

Older releases (Debian 11 and earlier, Ubuntu before 24.04) are refused because they predate the
merged-usr layout the read-only `/usr` guard depends on.

### Important constraints

- NAILS does **not** mount, unlock, or protect the hidden backend for you.
- The default activation path may terminate the graphical session before activation completes.
- Your backend must remain mounted for the full hidden session and through deactivation.
- The account you run `sudo nails` from must be a local account listed in `/etc/passwd`: the static release binary does not use NSS. A directory account (LDAP, SSSD) cannot be resolved, so its shell history is not cleaned (only `/root` is), shell integration is skipped, login notifications are not delivered, and the `fresh-home` persona mode refuses to activate.
- A clean `nails verify` result is evidence for known/common artifacts, **not proof** that no trace remains.

### Hidden-volume space and overlay copy-up

OverlayFS copies a lower file into the hidden upper **in full** the first time it
is written, truncated, or re-chmod/chowned, so the first write to a large file
(Nix database, browser profile, VM image) can stall on a slow or encrypted
backend, and the upper only grows across sessions — deactivation never reclaims
it. To keep activation fast and the volume small:

- watch usage with `nails status`, which reports the hidden volume's total, used
  and free space without scanning it;
- keep bulky directories out of the overlay with `overlay_exclusions`, and put
  caches on RAM-backed `extended_overlays` tmpfs layers;
- run `nix-collect-garbage -d` and clear caches **inside** the hidden session;
- while deactivated, roll a target back to its decoy lower with
  `sudo /mnt/data/nails reset-upper <TARGET>` (it confirms first, prunes no whiteouts
  automatically, and warns that resetting `/nix` drops the hidden Nix store).

See [docs/operator-guide.md](docs/operator-guide.md) for the full
maintenance guidance.

## Installation

NAILS is installed by copying a verified static binary onto the mounted hidden root, and in no other way. [`docs/distribution.md`](docs/distribution.md) lists which channels are supported and why the usual registries and package managers are not.

### Install the verified release binary

Download the latest published bundle from the canonical [GitHub Releases page](https://github.com/WitteShadovv/nails/releases).
Each release is built from an annotated version tag; `-rc.N` versions are marked as prereleases. Use the newest release line appropriate for your testing or deployment. Mount the hidden storage first, then place the published `nails` executable directly on that hidden root. Do not leave the binary on the decoy filesystem:

```bash
# Open and mount hidden storage first
sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden \
  "$HOME/Downloads/family_photos" data
sudo mount /dev/mapper/data /mnt/data

# Install the release binary onto hidden storage
install -m0755 /path/to/downloaded/nails /mnt/data/nails
```

Verify the download before first use, as [`docs/verify-release.md`](docs/verify-release.md) describes: the checksum, the build provenance, and where to do it without leaving a trace on the decoy system. For higher assurance, rebuild the published source revision and compare it against the bundle using the reproducibility guidance in
[`docs/release-artifact-reproducibility.md`](docs/release-artifact-reproducibility.md).

### Upgrading from inside a hidden session

The builds below are for upgrading an existing install, not for a first install. Run them only inside an active hidden session: the build caches (`~/.cargo`, `/nix/store`, the `result` GC root) then land on the hidden upper layer, never on the decoy. See [`docs/distribution.md`](docs/distribution.md).

From source:

```bash
git clone https://github.com/WitteShadovv/nails /mnt/data/src/nails
cd /mnt/data/src/nails
cargo build --release
install -m0755 ./target/release/nails /mnt/data/nails
```

With Nix:

```bash
nix build .#nails
install -m0755 ./result/bin/nails /mnt/data/nails
```

> [!NOTE]
> Zero-config path discovery trusts the binary installed on hidden storage. If you run NAILS from
> a build directory or `/nix/store`, set `hidden_volume_root` explicitly or use `--config`.

## Quick start

1. **Mount your hidden storage**.

   ```bash
   sudo cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden \
     "$HOME/Downloads/family_photos" data
   sudo mount /dev/mapper/data /mnt/data
   ```

   This opens a VeraCrypt hidden volume stored in a file container. [docs/backends.md](docs/backends.md)
   has the commands for a whole-device VeraCrypt volume and for LUKS2, and the discard and
   timestamp hazards of each; never add `--allow-discards`.

   Keep the mapping name, the mount point and the filesystem label neutral (the examples use
   `data` and `/mnt/data`). None of them may hint at hidden storage: they surface in
   `/dev/mapper`, `/dev/disk/by-label`, generated mount unit names and the journal, and NAILS
   warns at activation when any of them contains a telling word.

2. **Bootstrap the hidden layout** on the mounted backend.

   ```bash
   sudo /mnt/data/nails init /mnt/data
   ```

   Run `init` by its full path on the hidden volume and with `sudo`: the mount point
   is root-owned after `sudo mount`, and `nails` is never placed on the decoy `PATH`.
   `init` checks the target before writing anything and refuses a directory that is not a
   mounted volume of its own, so the layout never lands on the decoy disk;
   `--allow-unmounted` overrides this for a directory-style backend. On NixOS it seeds the
   hidden NixOS layout from `/etc/nixos/hardware-configuration.nix`; `--hardware-config <PATH>`
   names another base and `--no-hardware-config` skips the layout. It reports each item as
   created or already present and ends with the next steps.

3. **Optionally review the generated config**.

   ```bash
   $EDITOR /mnt/data/config/nails.toml
   /mnt/data/nails config validate
   ```

   The file is strict TOML: every key is optional (an empty file uses the defaults) and unknown
   keys are rejected. Leave `hidden_volume_root` unset to derive it from the binary location.
   Example:

   ```toml
   nixos_flake = "/mnt/data/nixos#my-host"
   ```

   `nails config show` prints the effective configuration and where each value comes from;
   `nails config show --example` prints every key. [docs/configuration.md](docs/configuration.md)
   lists every key with its default and effect, and explains which directories are overlaid.

4. **Add or replace the hidden NixOS configuration** if you do not want the generated starter
   module.

   ```bash
   $EDITOR /mnt/data/config/nixos/configuration.nix
   ```

5. **Activate the hidden environment**.

   ```bash
   sudo /mnt/data/nails activate
   ```

   Use this safer path if you have not verified that the backend survives session
   termination — it keeps the current graphical session running and mounts only
   what can be overlaid live:

   ```bash
   sudo /mnt/data/nails activate --session keep
   ```

6. **Return to decoy state when finished**.

   ```bash
   sudo /mnt/data/nails deactivate
   ```

7. **Verify from the hidden side, before handing the machine over.**

   The binary lives on the hidden volume, not on the decoy, so run `verify`
   from the hidden environment — while it is still mounted, before
   `deactivate`:

   ```bash
   sudo /mnt/data/nails verify --deep
   ```

   To inspect the decoy itself for leftovers, mount its image or partition
   read-only and scan it offline, again from the hidden side:

   ```bash
   sudo /mnt/data/nails verify --offline --root /mnt/decoy
   ```

   A clean result reports what it checked and lists what it did not; it is
   evidence against known artifacts, not proof the decoy is untouched.

## Command overview

The binary lives on the hidden volume and is never placed on the decoy `PATH`, so
every invocation uses its full path (the examples use `/mnt/data/nails`). `sudo`'s
`secure_path` excludes the hidden root, so a bare `sudo nails`-style call (no path)
would not resolve.

| Command | Purpose |
|---|---|
| `sudo /mnt/data/nails init <PATH>` | Bootstrap a hidden-volume layout on an existing mounted root |
| `sudo /mnt/data/nails activate` | Activate the hidden environment |
| `sudo /mnt/data/nails deactivate` | Return to decoy state and reboot |
| `sudo /mnt/data/nails emergency` | Tear everything down now, without waiting for a reboot |
| `sudo /mnt/data/nails recover` | Reconcile a stuck state and finish an interrupted teardown |
| `/mnt/data/nails status` | Show current state, security posture, and hidden-volume disk usage |
| `sudo /mnt/data/nails verify` | Scan for known/common host artifacts (from the hidden side, live or `--offline`) |
| `/mnt/data/nails check` | Report readiness to activate without changing anything (alias: `doctor`) |
| `sudo /mnt/data/nails reapply` | Rebuild and switch the hidden configuration layer while active (NixOS) |
| `sudo /mnt/data/nails reset-upper <TARGET>` | Delete a target's persistent overlay upper (while deactivated) |
| `/mnt/data/nails config path\|show\|validate` | Locate, inspect or check the configuration file |

For full flag-level usage, run `/mnt/data/nails --help` or
`/mnt/data/nails <command> --help`.

## CLI reference

### Global flags

Accepted before or after the subcommand (`nails -q status` and `nails status -q`
are the same).

| Flag | Effect |
|---|---|
| `-c`, `--config <PATH>` | Read this TOML file instead of the binary-relative default |
| `-v`, `--verbose` | More diagnostics on stderr (`-v` debug, `-vv` trace); conflicts with `--quiet` |
| `-q`, `--quiet` | Print only errors and the final result |
| `--color <auto\|always\|never>` | When to emit ANSI colour (default `auto`) |
| `--ascii` | Use ASCII markers instead of Unicode symbols and box drawing |
| `--json` | Print a machine-readable JSON envelope on stdout |
| `--no-log-file` | Do not write the log file on the hidden volume (stderr still logs) |

### `activate` flags

| Flag | Effect |
|---|---|
| `-y`, `--yes` | Proceed without the confirmation prompt (otherwise it prompts on a terminal and refuses without one) |
| `--session <kill\|keep>` | Terminate the graphical session before mounting (`kill`, the default) or keep it running (`keep`) |
| `--pivot <refuse\|allow\|ask>` | How to handle a volume that needs a pivot mount (default `refuse`) |
| `--overlay-only` | Mount overlays only; skip the platform configuration layer |
| `--risky-services <restart\|skip>` | Restart risky services still referencing a target, or leave them as reported survivors (overrides `risky_services`) |
| `--terminate-interactive` | Force-terminate interactive programs holding a target instead of aborting |
| `--accept-persistent-decoy` | Activate despite a persistent decoy posture (overrides `accept_persistent_decoy`) |
| `--nixos-flake <REF>` | NixOS: flake reference `<path>#<host>` to pass to `nixos-rebuild --flake` |
| `--dry-run` | Preview the steps without changing anything |
| `--no-preflight` | Skip pre-flight checks (dangerous; expert use only) |

`deactivate` takes `-y`/`--yes` and `--no-clear-history`. `emergency` takes
`--countdown <SECS>` (an abortable wait; teardown is immediate by default) and
`--poweroff`/`--reboot` to clear RAM once teardown finishes. `verify` takes
`--deep`, and `--offline --root <MOUNT>` to scan a mounted decoy image.

### Exit codes

Every command returns one of these; they are a stable contract a script can
branch on.

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | The operation failed |
| `2` | Command-line usage error |
| `3` | The configuration file or environment was unusable |
| `4` | A pre-flight check refused the operation |
| `5` | The operation needs privileges it did not have |
| `6` | The on-disk state could not be trusted |
| `7` | The system is degraded or a reboot is required to finish |
| `8` | The host is not one NAILS can operate on |
| `9` | Completed, but with a warning the caller should act on |
| `10` | `verify` found warnings |
| `11` | `verify` found critical artifacts |
| `130` | Cancelled by a signal (SIGINT/SIGTERM); overlays rolled back |

### JSON output

With `--json`, every command writes one line: a stable envelope with
`schema_version` (currently `1`), the `command` name, an `ok` boolean, and either
a typed `data` object (success) or a typed `error` object with a snake_case
`code`, a `message` and an optional `hint` (failure). Bump the schema version
signals an incompatible change to a field's meaning.

## Threat model and limitations

NAILS targets **post-seizure forensic analysis** of a powered-off device. It
reduces host-side artifacts; it does not protect against every class of attack.
The hidden session shares the host's network identity and any remote state with
the decoy, and by default the decoy account and home as well. The adversary, assumptions,
out-of-scope list, residual channels and evaluation scope are in
[docs/threat-model.md](docs/threat-model.md). Read it, and validate your exact
procedure end to end, before relying on NAILS in a high-risk context.

For sensitive work, set `persona.mode = "fresh-home"` and disconnect the decoy's
sync and account clients; the [operator guide](docs/operator-guide.md#threat-model-limitations)
explains why and how.

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

## Upgrading

This release changes operator-facing interfaces. There is no backwards-compatibility
shim: convert your setup before running the new binary.

- **Configuration format.** Configuration is now strict TOML. Convert `nails.yaml`
  to `config/nails.toml` next to the binary on the hidden volume (see
  [docs/configuration.md](docs/configuration.md) for every key and its default).
  Unknown keys, wrong types and TOML syntax errors are rejected with a one-line
  message rather than silently falling back to a default.
- **Invocation.** Always run the binary by its full path on the hidden volume
  (`sudo /mnt/data/nails …`). No copy, symlink or `PATH` entry on the decoy is
  supported.
- **Flags.** The output flags are now global and accepted in any position; the old
  per-command output flags (`--plain`, `--no-color`, `--no-logs`,
  `--verbose-details`) are removed in favour of `--color`, `--ascii`, `--quiet`,
  `--verbose` and `--no-log-file`. Session handling moved to
  `activate --session <kill|keep>`. See [CLI reference](#cli-reference).
- **Exit codes and JSON.** The process now returns the documented
  [exit codes](#exit-codes), and `--json` emits the versioned envelope
  (`schema_version = 1`) described under [JSON output](#json-output).
- **State schema.** The on-disk `state.json` carries a `version` field and records
  the `boot_id` it was written under, so a state file left by a previous boot is
  recognised as stale. There is no separate "emergency" state: an interrupted or
  partial teardown is recorded as `Degraded`, which `nails recover` reconciles. A
  state file written by an incompatible version is treated as a safe default
  (inactive) rather than trusted.

> [!NOTE]
> The release changelog mirrors these upgrade notes under its own "Upgrading"
> heading; keep [CHANGELOG.md](CHANGELOG.md) and this section in step when cutting
> a release.

## Related projects

- **NAILS** (this repository) is the NixOS-only CLI and workflow for layering a hidden environment over an existing decoy system you operate.
- **[NAILS OS](https://github.com/WitteShadovv/nails-os)** is a separate installable NixOS distribution with its own live ISO, installer, persistence model, and system-level security design.

They are related projects, but they are not interchangeable products and do not share the same installation or threat-model boundaries.

## Documentation and project policies

### User and operator references

- [GitHub Releases](https://github.com/WitteShadovv/nails/releases) *(published stable releases and prereleases)*
- [Change history](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [Storage backends](docs/backends.md)
- [Distribution channels](docs/distribution.md)
- [Verify a release](docs/verify-release.md)
- [Release artifact reproducibility](docs/release-artifact-reproducibility.md)

### Contributing and governance

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Code owners](CODEOWNERS)

## Project status

NAILS is actively maintained and currently released as **alpha** software.

- Releases are drafted by the release workflow from annotated version tags and published by the maintainer ([RELEASING.md](RELEASING.md)); `-rc.N` versions are prereleases.
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
