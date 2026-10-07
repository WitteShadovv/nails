<div align="center">
  <img src="docs/assets/logo.png" alt="NAILS logo" width="160" />
  <h1>NAILS — Overlay environment manager</h1>

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/platforms-NixOS%20%7C%20Debian%2013%2B%20%7C%20Ubuntu%2024.04%2B-5277C3.svg)](#platform-support)
[![CI](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml/badge.svg)](https://github.com/WitteShadovv/nails/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/WitteShadovv/nails?display_name=tag)](https://github.com/WitteShadovv/nails/releases)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#project-status)

</div>

> **A CLI for running a hidden session on a decoy system: one overlay over the whole decoy root, entered and left with a soft-reboot, with first-class NixOS support and a plain root overlay on Debian 13 and Ubuntu 24.04+.**

NAILS runs a hidden environment on top of a believable decoy system by combining a user-managed
hidden storage backend, one OverlayFS over the whole decoy root, systemd's soft-reboot
(`systemctl soft-reboot`, systemd 254 or newer) and — on NixOS — a declarative hidden
configuration. NixOS is the first-class platform; Debian 13 and Ubuntu 24.04+ run the same session
with whatever the hidden `/etc` holds. See [Platform support](#platform-support) for what each
platform does and the hosts NAILS refuses.

> [!WARNING]
> NAILS is **alpha** security software. It is intended for technically experienced users who can
> test their exact setup, storage backend, and operating procedure before relying on it. Read the
> [operator guide](docs/operator-guide.md) and the [threat model](docs/threat-model.md) first.

## What NAILS does

NAILS is built around two environments on the same machine:

- a visible **decoy** installation that should remain mundane and plausible
- a hidden **real** environment stored on a mounted backend you control

Activation builds one overlay over the whole decoy root, with every change kept on the hidden
volume, and soft-reboots into it. Every program of the decoy closes, the operator is logged out,
and the hidden session starts at its own login screen. Inside it every process — the desktop,
applications and services — runs on the overlay, and no userspace process can reach the decoy
filesystem by any path. Deactivation soft-reboots back into the plain decoy root, which starts at
its own login screen. Once the backend is closed, the host is back in its normal decoy state
within the documented [threat model](docs/threat-model.md).

NAILS does **not** provide encryption itself. It relies on an external storage backend such as
VeraCrypt or LUKS/`cryptsetup` for hidden or encrypted storage.

## How it works

At a high level:

1. You mount a hidden, writable Linux filesystem that can host an overlayfs upper layer (symbolic links, trusted xattrs, a valid readdir `d_type`, and whiteouts).
2. `nails activate`, run on the decoy, checks the host, then mounts one overlay at `/run/nextroot`: the decoy root as the read-only lower, `<hidden-root>/root/upper` as the upper. Every other decoy filesystem gets a safe decision first: the ESP and `/boot` are bound read-only, a separately mounted filesystem such as `/home` gets an overlay of its own, and swap, unmounted disks and network filesystems are masked.
3. On NixOS with a hidden configuration, the hidden system is built into the next root's store (nothing reaches the decoy `/nix`) and activated there; no bootloader is touched and no system profile changes. On Debian and Ubuntu the hidden configuration is whatever the upper's `/etc` holds.
4. Activation soft-reboots. systemd stops every decoy program, switches root into the overlay and starts the hidden userspace there.
5. `nails deactivate` soft-reboots back into the plain decoy root and closes the hidden backend on the way; `nails emergency` kills every hidden program at once and does the same, or powers off.

Key design points:

- **One overlay, no process heuristics**: every process of the hidden session starts inside the overlay, so there is nothing to find, restart or kill on the decoy side, and writes to `/usr`, `/var` or `/nix` land in the upper like any other
- **A persistent upper**: the hidden root's changes stay on the hidden volume across sessions
- **Nothing installed on the decoy**: the session is set up at runtime from the hidden volume, with no boot entry, initrd change or unit on the decoy disk
- **Storage-agnostic backend model** as long as the backend is already mounted, writable and kernel-managed
- **Verification support** through `nails verify` for known/common artifacts

The design and its evidence are recorded in
[ADR 0008](docs/adr/0008-whole-root-soft-reboot.md).

## Before you use it

NAILS is designed for a narrow threat model and operational style.

### Requirements

| Requirement | Notes |
|---|---|
| Supported platform | NixOS, Debian 13+, or Ubuntu 24.04+, with systemd 254 or newer. See [Platform support](#platform-support); other hosts are refused. |
| Hidden storage backend | Any mounted, writable, kernel-managed Linux filesystem that can host an overlayfs upper (symlinks, trusted xattrs, `d_type`, whiteouts) — e.g. ext4, xfs, btrfs, f2fs. NFS, CIFS/SMB, 9p, most FUSE mounts, and FAT/exFAT/NTFS cannot. See [docs/backends.md](docs/backends.md) for what is tested and the hazards of each backend. |
| Root access | Required for `activate`, `deactivate`, `emergency`, `recover` and `reset-upper` |
| Rust 1.93+ | Only needed to build from source |
| Amnesic decoy | Required: the decoy must keep no durable record of the hidden session. Activation fails closed otherwise (override with `--accept-persistent-decoy`). See [docs/decoy-requirements.md](docs/decoy-requirements.md). |
| Impermanence-style setup | Strongly recommended for the strongest documented posture; see [docs/decoy-requirements.md](docs/decoy-requirements.md). The decoy *root* itself must still be a disk filesystem (see below). |

### Platform support

NAILS detects the host from `/etc/os-release` and the running init, then the pre-flight checks
confirm that it can soft-reboot. The matrix below matches what detection and the checks accept.

| Platform | Support | Notes |
|---|---|---|
| NixOS | Full | A hidden NixOS configuration (flake or `configuration.nix`) is built into the hidden root's store and entered in the same soft-reboot. It must run on the decoy's kernel. Pinned nixpkgs without `soft-reboot.target`/`systemd-soft-reboot.service` need a small module, which `nails check` prints. |
| Debian 13 (trixie) and newer | Root overlay | The same whole-root session; the hidden configuration is whatever the upper's `/etc` holds. Requires the merged-`/usr` layout. |
| Ubuntu 24.04 and newer | Root overlay | As Debian. |
| Debian family derivatives | Provisional | A host whose `ID_LIKE` names `debian`/`ubuntu` is accepted on the same terms when its systemd is new enough; its base release is not version-gated. |
| Debian 12, Ubuntu 22.04 | Refused | systemd is too old for a soft-reboot (252 and 249). |
| Fedora, Arch, other distributions | Refused | No validated backend yet; detection declines with a documented message. Planned — see [ROADMAP.md](ROADMAP.md). |
| ostree / image-based hosts | Refused | NAILS cannot overlay an immutable system. |
| Non-systemd hosts (OpenRC, runit, …) | Refused | The session is entered and left with a systemd soft-reboot. |

The `decoy-root` check also refuses a decoy whose root is a tmpfs (an impermanent root), ZFS or
an overlay: the way back mounts the decoy root again by its device.

### Important constraints

- NAILS does **not** mount, unlock, or protect the hidden backend for you.
- **Activation and deactivation log you out.** Every program closes at the soft-reboot; save your
  work first. The hidden session and, afterwards, the decoy start at their own login screens.
- Your backend must be kernel-managed (dm-crypt, a loop device): a FUSE mount dies with the
  programs at the soft-reboot. It stays mounted for the whole hidden session and is closed by the
  switch back.
- What the soft-reboot leaves is in RAM only: the kernel ring buffer (`dmesg`), the soft-reboot
  counter (two per session) and the unchanged boot ID and uptime. Power off after a session when
  that matters.
- The account you run `sudo` from must be a local account listed in `/etc/passwd`: the static
  release binary does not use NSS, so a directory account (LDAP, SSSD) cannot be resolved.
- A clean `nails verify` result is evidence for known/common artifacts, **not proof** that no trace remains.

### Hidden-volume space and copy-up

The hidden root's upper persists across sessions. OverlayFS copies a lower file into the upper
**in full** the first time it is written, truncated, or re-chmod/chowned, so the first write to a
large file (the Nix database, a browser profile, a VM image) can stall on a slow or encrypted
backend, and the upper only grows. A file copied up earlier also **shadows** later decoy updates
of the same file: after the decoy updates itself (a package upgrade, a NixOS rebuild of the decoy),
the hidden session still sees its own older copy. To keep the volume small and current:

- watch usage with `nails status`, which reports the hidden volume's total, used
  and free space without scanning it;
- run `nix-collect-garbage -d` and clear caches **inside** the hidden session;
- from the decoy, delete a path's hidden copy with
  `sudo /mnt/data/nails reset-upper <PATH>` so the decoy's own files show through again (it
  confirms first, and warns that resetting `/nix` drops the hidden Nix store). It is refused in
  the hidden session, where the upper is the live root.

See [docs/operator-guide.md](docs/operator-guide.md#copy-up-cost-and-shadowed-decoy-updates) for
the full maintenance guidance.

## Installation

NAILS is installed by copying a verified static binary onto the mounted hidden root, and in no other way. [`docs/distribution.md`](docs/distribution.md) lists which channels are supported and why the usual registries and package managers are not.

### Install the verified release binary

Download the latest bundle from the canonical [GitHub Releases page](https://github.com/WitteShadovv/nails/releases) and verify its artifacts (see [RELEASING.md](RELEASING.md) for how releases are produced). Mount the hidden storage first, then place the published `nails` executable directly on that hidden root. Do not leave the binary on the decoy filesystem:

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

This is the shortest runnable path. The [operator guide](docs/operator-guide.md) walks the same
steps in full, organised around where each one runs, with a recovery runbook and the honest limits.

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
   lists every key with its default and effect.

4. **On NixOS, add or replace the hidden configuration** if you do not want the generated starter
   module.

   ```bash
   $EDITOR /mnt/data/config/nixos/configuration.nix
   ```

   It is built against the decoy's own `/etc/nixos` plus the hidden hardware configuration that
   `init` placed in the hidden root (`/mnt/data/root/upper/etc/nixos/`). A flake given with
   `nixos_flake` or `--nixos-flake` is used instead.

5. **Check readiness, then activate.**

   ```bash
   sudo /mnt/data/nails check
   sudo /mnt/data/nails activate
   ```

   `check` runs the same pre-flight checks as `activate` and changes nothing; `activate
   --dry-run` previews the steps. Activation prepares the hidden root, prints its result and
   soft-reboots: every program closes and you are logged out. Log in again at the hidden
   session's login screen. As its last step activation kills the decoy's interactive shells, so
   the activation command is never written to a history file.

6. **Return to the decoy when finished**, from inside the hidden session.

   ```bash
   sudo /mnt/data/nails deactivate
   ```

   The hidden session shuts down in order, the hidden backend is closed by the switch, and the
   decoy starts at its own login screen. Before handing the machine over, prefer
   `deactivate --poweroff`, and leave the machine off for a few minutes. A soft-reboot keeps the
   kernel's RAM state, and a warm reboot does not clear RAM either: DRAM keeps its contents across
   a reset unless the firmware honours the TCG memory-overwrite request (MOR), and setting MOR
   itself writes EFI NVRAM.

7. **Verify from the hidden side, before handing the machine over.**

   The binary lives on the hidden volume, not on the decoy, so run `verify`
   from the hidden session, before `deactivate`:

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

| Command | Where | Purpose |
|---|---|---|
| `sudo /mnt/data/nails init <PATH>` | decoy | Bootstrap a hidden-volume layout on an existing mounted root |
| `sudo /mnt/data/nails check` | decoy | Report readiness to activate without changing anything (alias: `doctor`) |
| `sudo /mnt/data/nails activate` | decoy | Soft-reboot into the hidden session |
| `sudo /mnt/data/nails deactivate` | hidden session | Soft-reboot back to the plain decoy (`--poweroff` to power off) |
| `sudo /mnt/data/nails emergency` | either | Kill the hidden session at once and return to the decoy (or power off); on the decoy, remove an interrupted activation |
| `sudo /mnt/data/nails recover` | decoy | Remove what an interrupted activation left in `/run` |
| `/mnt/data/nails status` | either | Show the live session, security posture, and hidden-volume disk usage |
| `sudo /mnt/data/nails verify` | hidden session | Scan for known/common host artifacts (live, or `--offline` against a decoy image) |
| `sudo /mnt/data/nails rehearse` | both | Plant a canary in a hidden session, then scan the raw decoy disk for it |
| `sudo /mnt/data/nails reset-upper <PATH>` | decoy | Delete a path's hidden copy from the hidden root's upper |
| `/mnt/data/nails config path\|show\|validate` | either | Locate, inspect or check the configuration file |

For full flag-level usage, run `/mnt/data/nails --help` or
`/mnt/data/nails <command> --help`, or read [docs/cli.md](docs/cli.md).

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
| `-y`, `--yes` | Proceed without the confirmation prompt (otherwise it prompts on a terminal and refuses without one, because it logs you out) |
| `--overlay-only` | NixOS: enter with the decoy's own system, without building the hidden configuration (the hidden `/etc` and home still apply) |
| `--nixos-flake <REF>` | NixOS: the hidden configuration as a flake reference `<path>#<host>` |
| `--accept-persistent-decoy` | Activate despite a persistent decoy posture (overrides `accept_persistent_decoy`) |
| `--dry-run` | Preview the steps without changing anything |
| `--no-preflight` | Skip pre-flight checks (dangerous; expert use only) |

`deactivate` takes `-y`/`--yes` and `--poweroff` (power off instead of
returning to the decoy). `emergency` takes `--countdown <SECS>` (an abortable
wait; it acts immediately by default), `--poweroff` (power off instead of
returning to the decoy; RAM decays) and `--reboot` (a full reboot, which does not
clear RAM). `recover` takes no options. `verify` takes `--deep`, and
`--offline --root <MOUNT>` to scan a mounted decoy image.

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
| `7` | The system is degraded, or an interrupted activation needs `nails recover` |
| `8` | The host is not one NAILS can operate on |
| `9` | Completed, but with a warning the caller should act on |
| `10` | `verify` found warnings |
| `11` | `verify` found critical artifacts, or `rehearse scan` found its canary |
| `130` | Cancelled by a signal (SIGINT/SIGTERM); the entry was rolled back |

### JSON output

With `--json`, every command writes one line: a stable envelope with
`schema_version` (currently `1`), the `command` name, an `ok` boolean, and either
a typed `data` object (success) or a typed `error` object with a snake_case
`code`, a `message` and an optional `hint` (failure). Bump the schema version
signals an incompatible change to a field's meaning.

## Threat model and limitations

NAILS targets **post-seizure forensic analysis** of a powered-off device. It
reduces host-side artifacts; it does not protect against every class of attack.
The hidden session runs on the decoy's kernel and shares the host's network
identity and any remote state with the decoy, and by default it starts from the
decoy account and home as well. The adversary, assumptions,
out-of-scope list, residual channels and evaluation scope are in
[docs/threat-model.md](docs/threat-model.md). Read it, and validate your exact
procedure end to end, before relying on NAILS in a high-risk context.

For sensitive work, do not start the decoy's sync and account clients in the
hidden session; the [operator guide](docs/operator-guide.md#threat-model-limitations)
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

Upgrade only while NAILS is inactive: end the session with `nails deactivate` (or, on the decoy,
`nails recover` after an interrupted activation) with the old binary before replacing it. This
release changes operator-facing interfaces. There is no backwards-compatibility shim: convert your
setup before running the new binary.

- **Session mode.** The per-directory overlays (`/etc`, `/home`, `/var`, …) are gone. The only
  mode is the whole-root session entered and left with a soft-reboot (systemd 254 or newer, so
  Debian 12 and Ubuntu 22.04 are no longer supported). The hidden root's layers live under
  `<hidden-root>/root/` (`upper`, `work`, `mounts`, `cache`); the uppers of the old mode
  (`<hidden-root>/<name>` and `<hidden-root>/.work`) are not read. Move what you need from them
  into the hidden session, then delete them. On NixOS the hidden hardware configuration moves to
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it.
- **Configuration format.** Configuration is now strict TOML. Convert any earlier
  YAML configuration to `config/nails.toml` next to the binary on the hidden volume
  (see [docs/configuration.md](docs/configuration.md) for every key and its default).
  Unknown keys, wrong types and TOML syntax errors are rejected with a one-line
  message rather than silently falling back to a default. The overlay keys
  (`overlays`, `overlay_mode`, `overlay_exclusions`, `overlay_exclusions_remove`,
  `allow_leaky_exclusions`), `risky_services`, `nixos_switch_required`,
  `clear_history`, `prompt_label`, `[color_scheme]` and `[emergency]` are removed and
  now rejected as unknown keys.
- **Invocation.** Always run the binary by its full path on the hidden volume
  (`sudo /mnt/data/nails …`). No copy, symlink or `PATH` entry on the decoy is
  supported.
- **Flags and commands.** The output flags are now global and accepted in any position; the old
  per-command output flags (`--plain`, `--no-color`, `--no-logs`,
  `--verbose-details`) are removed in favour of `--color`, `--ascii`, `--quiet`,
  `--verbose` and `--no-log-file`. `activate --session`, `--pivot`, `--risky-services` and
  `--terminate-processes`, `deactivate --no-clear-history`, `emergency --lock-backend`, and the
  `reapply` and `notify-dispatch` commands are removed. See [CLI reference](#cli-reference).
- **Exit codes and JSON.** The process now returns the documented
  [exit codes](#exit-codes), and `--json` emits the versioned envelope
  (`schema_version = 1`) described under [JSON output](#json-output).
- **State schema.** The on-disk `state.json` carries a `version` field. The states
  are `Inactive`, `Active` and `Degraded`; `nails status` reads the live session from the
  mount table and the session plan in `/run`, because a soft-reboot keeps the boot ID. A
  state file written by an incompatible version is treated as a safe default
  (inactive) rather than trusted.

> [!NOTE]
> The release changelog mirrors these upgrade notes under its own "Upgrade notes"
> heading; keep [CHANGELOG.md](CHANGELOG.md) and this section in step when cutting
> a release.

## Related projects

- **NAILS** (this repository) is the CLI and workflow for running a hidden session over an existing decoy system you operate.
- **[NAILS OS](https://github.com/WitteShadovv/nails-os)** is a separate installable NixOS distribution with its own live ISO, installer, persistence model, and system-level security design.

They are related projects, but they are not interchangeable products and do not share the same installation or threat-model boundaries.

## Documentation and project policies

### User and operator references

- [Project site](https://nails.run)
- [Operator guide](docs/operator-guide.md) — the full workflow, recovery runbook and honest limits
- [Threat model](docs/threat-model.md) — adversary, assumptions, residual channels and evaluation scope
- [Decoy requirements](docs/decoy-requirements.md) — what the decoy system must and must not keep
- [Storage backends](docs/backends.md) — which backends are tested and the hazards of each
- [Configuration reference](docs/configuration.md) — every `nails.toml` key with its default and effect
- [CLI reference](docs/cli.md) — commands, flags, exit codes and the JSON envelope
- [Architecture overview](docs/architecture.md) — how the crates and runtime layers fit together
- [Distribution channels](docs/distribution.md)
- [Verify a release](docs/verify-release.md)
- [Release artifact reproducibility](docs/release-artifact-reproducibility.md)
- [GitHub Releases](https://github.com/WitteShadovv/nails/releases)
- [Change history](CHANGELOG.md)
- [Roadmap](ROADMAP.md)

### Contributing and governance

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Code owners](CODEOWNERS)

## Project status

NAILS is actively maintained and currently released as **alpha** software.

- How releases are produced, numbered and verified is documented in [RELEASING.md](RELEASING.md).
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

Copyright (C) 2025-2026 WitteShadovv.

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE).

> [!CAUTION]
> This software is provided for educational and security research purposes. It comes with no
> warranty, and it should not be treated as a guarantee of deniability or forensic invisibility in
> any specific threat environment.
