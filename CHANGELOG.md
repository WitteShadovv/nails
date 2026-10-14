# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project
uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit history.

Each release is one annotated `v*` tag: a single workflow builds, rebuilds, tests and attests it
and drafts the GitHub release, which a maintainer then publishes (see `RELEASING.md`). The section
of this changelog for that version becomes the release notes word for word, and
`docs/verify-release.md` explains how to verify the assets.

## [Unreleased]

NAILS 0.3.0 replaces the per-directory live overlays of 0.2 with one design: the hidden session is
an overlay over the whole decoy root, entered and left with `systemctl soft-reboot` (ADR 0008).
Debian 13 and Ubuntu 24.04 or newer join NixOS as decoys.

### Upgrade notes

Upgrade only while NAILS is inactive: end a 0.2 session with its own `nails deactivate` (a reboot
ends it too) before replacing the binary. This release breaks compatibility with earlier state,
config and CLI surfaces; there are no compatibility shims.

- The decoy needs systemd 254 or newer. The hidden root lives under `<hidden-root>/root/`
  (`upper`, `work`, `mounts`, `cache`); the uppers of the 0.2 per-directory overlays
  (`<hidden-root>/<name>`, `<hidden-root>/.work`) are not read. Move what you need into a hidden
  session and delete them. On NixOS the hidden hardware configuration now lives in
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it.
- The hidden root must be a volume of its own. NAILS now refuses a root that 0.2 accepted: a folder
  (no mount point), a btrfs subvolume or bind of a folder of a filesystem the decoy uses, a logical
  volume in the decoy's volume group, an image file on a decoy filesystem, and an overlay, FUSE,
  network or ZFS filesystem. Move the hidden volume to a device of its own (see "Where setup
  happens" in the operator guide). An unprivileged `check` or `status` on a distribution whose
  `/etc/crypttab` only root can read gets `storage_unjudged` and logs to stderr only; run it with
  `sudo`.
- Configuration moves from `nails.yaml` (YAML) to strict `config/nails.toml` (TOML) next to the
  binary. Convert each key by hand: `hidden_volume_path` is now `hidden_volume_root` (leave it
  unset to derive it from the binary's location), unknown keys are rejected, and the keys listed
  under "Removed" must be deleted. `nails init` writes a documented template and
  `nails config show --example` prints every key.
- Invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`); nails is never on
  the decoy `PATH`. `activate --flake` is now `--nixos-flake`, `status -v` is now
  `status --details`, `--plain` and `--no-color` are replaced by `--ascii` and
  `--color auto|always|never`, and `--no-logs` by `--no-log-file`; see "Removed" for the flags
  that are gone.
- Exit codes and JSON output changed. JSON output carries `schema_version = 1`; scripts that
  parsed the old output must be updated against the exit-code table in `nails --help` and the
  schemas under `docs/schemas/`.
- The on-disk state schema changed. Delete any pre-existing `state.json` from a clean inactive
  system; do not hand-edit it. `nails recover` removes what an interrupted activation left.

### Added

- The whole-root session (ADR 0008). `nails activate` builds one overlay over the whole decoy root
  at `/run/nextroot` (the decoy root read-only as the lower, `<hidden-root>/root/upper` as the
  upper), applies a fixed policy to every other decoy filesystem (the ESP and `/boot` bound
  read-only, other mounted local filesystems overlaid with an upper under
  `<hidden-root>/root/mounts/`, swap, unmounted disks, network filesystems and disk-backed overlay
  entries masked), binds `/run` and the hidden volume into it, writes the session plan with a RAM
  copy of the binary and configuration to `/run/overlay-runtime`, and soft-reboots. Every process
  of the hidden session starts inside the overlay. Activation logs you out after a confirmation
  (`-y` skips it) and, as its last step, kills the decoy's interactive shells, so the activation
  command never reaches a history file.
- On NixOS the hidden system is built into the next root's store (`nix build --store
  /run/nextroot`, the evaluation cache on the hidden volume), activated chrooted, and entered by
  repointing `/run/current-system` after every decoy unit has stopped: one soft-reboot, no
  bootloader install, no system profile change. Inside the hidden session `/etc/nixos` is the
  hidden configuration and `nixos-rebuild test` applies changes. `--overlay-only` enters with the
  decoy's own system plus the hidden `/etc` and home. The paths of the hidden system's closure
  that still come from the decoy store are copied onto the hidden volume, so a decoy that
  garbage-collects or rebuilds between sessions no longer breaks the hidden system. On Debian and
  Ubuntu the hidden configuration is the upper's `/etc`.
- The switch in both directions runs from the RAM copy (`ExecStart=` of
  `systemd-soft-reboot.service`) and acts only on an armed plan. On the way back it scrubs `/run`
  of what the hidden session added, restores libmount's `utab`, writes journald's kmsg cursor so
  the decoy journal imports no hidden kernel record, and resets units the session left failed. The
  session keeps working with `blk-availability.service` (Debian, Ubuntu), Ubuntu 26.04's D-Bus
  units and NixOS static addresses (`networking.interfaces`), whose stop would otherwise unmount
  the hidden volume, stall the login screen or drop the network.
- `nails deactivate` runs in the hidden session and soft-reboots back to the plain decoy;
  `--poweroff` powers off instead. The hidden volume is unmounted and its device-mapper stack
  closed by the switch itself, so dm-crypt wipes the master key from RAM; a backend that is not
  device-mapper based is unmounted but not closed.
- `nails emergency` acts at once, before argument parsing, configuration and logging: in the
  hidden session it prepares the way back, marks the backend for closing, enqueues the soft-reboot
  with PID 1 and kills every hidden cgroup (`cgroup.kill`); the machine returns to the decoy's
  normal login screen. `--countdown <SECS>` waits first with a Ctrl+C hint, `--poweroff` and
  `--reboot` replace the soft-reboot back, and a way back that cannot be prepared powers off. The
  result names the action and any fallback, the cgroups and processes killed, the timed phases and
  any mount left behind; an emergency that leaves a mount behind, or can only ask the kernel to
  power off, exits 7. On the decoy, it removes what an interrupted activation left.
- `nails recover` removes an interrupted activation's leftovers on the decoy (`/run/nextroot`,
  `/run/overlay-runtime`, the transition drop-in) and resets the state.
- `nails check` (alias `doctor`, and what `activate --dry-run` runs): a read-only readiness report
  built from the same pre-flight registry as activation, with each check's result and fix, the
  effective configuration, the decision for every decoy filesystem and the persona mode. It writes
  nothing, supports `--json` and exits 4 when a check fails.
- The attach gate: `init`, `activate`, `check`, `deactivate`, `reset-upper`, `rehearse plant` and
  the log and state writers accept only a hidden root that is a mounted volume of its own, before
  anything is written or probed. They refuse a folder, a second filesystem mounted over the root
  and, outside the session, storage the decoy uses (per its mount table, `/etc/fstab`,
  `/etc/crypttab` and sysfs); in the session only the volume the session started from is accepted.
  A refusal is one neutral message with exit 4 and a code (`not_separate_volume`, `root_covered`,
  `storage_unjudged`) that names no storage tool or device, and `--no-preflight` does not skip it.
  `--allow-decoy-storage` (`init`, `activate`, `check`) turns a refusal of decoy storage into a
  warning for storage the operator knows the decoy does not use; `status` shows the choice. Run as
  root, the gate reads `/etc/fstab` and `/etc/crypttab` without updating their access time.
- New pre-flight checks: `systemd-version`, `soft-reboot-units` (prints the module an older
  nixpkgs needs), `decoy-root` (refuses a tmpfs, ZFS or overlay decoy root), `session-state`,
  `fstab-policy`, `mount-namespace` (activation must share PID 1's mount namespace),
  `upper-fs-capability` (the hidden filesystem can host an overlay upper), `host-tools` (names any
  missing tool and its package), `backend-entries` (refuses a decoy crypttab or fstab line that
  opens or mounts the hidden volume), `decoy-persistence` (refuses a persistent journal or an
  active rsyslog, syslog-ng or auditd unless `accept_persistent_decoy` or
  `--accept-persistent-decoy` is set; warns about a persistent root filesystem, atime, crash-dump
  channels and the NixOS auto-upgrade timer), and the warn-only `backend-detect` (discard, file
  container timestamps, copy-on-write hosts), `binary-location`, `inherited-autostart`,
  `incremental-history-flush`, `memory-wipe` (`init_on_free=1`), `sleep-policy` and
  `residue-catalog`. Failures end with one ordered list of fixes, and checks that depend on a failed
  one are skipped with a reason.
- Disks during the session (`[session_mounts]`): the session watcher raises a neutral desktop alert
  for every read-write mount of a disk outside the hidden volume and for a disk mounted over the
  hidden root or one of its parents, which `status` also names (`hidden_root_covered_by`);
  nothing NAILS writes reaches such a cover. Opt-in `read_only` makes every disk the session does
  not use read-only at the block layer until the way back. Alerts go out through `notify-send` or,
  where it is missing, `busctl`.
- The backend watcher (`[backend_watch]`) alerts when the hidden backend fails mid-session and,
  only when opted in, runs the emergency after a debounce.
- `[sleep_policy]` (`warn` by default, `block` or `teardown`): `block` holds sleep and idle block
  inhibitors, and the lid switch's when a closed lid would sleep; `teardown` powers off through the
  emergency before the machine sleeps.
- Persona options (`[persona]`): `mode = "fresh-home"` gives the operator an empty home in the
  upper instead of the decoy home, and `mask_inherited` hides inherited decoy autostart entries and
  user units from the hidden session. An optional NixOS module and NetworkManager drop-in give the
  hidden session its own MAC addresses and hostname.
- `nails rehearse`: `plant` puts a random canary into a hidden session, and after the way back
  `scan` searches the raw decoy devices (or disk images with `--offline`) for it; `status` and
  `reset` follow the rehearsal. The scan exits 0 when the canary is not found, 11 when it is and 9
  when a device could not be read in full.
- `nails verify --offline --root <mount>` scans a mounted decoy image, and `--examiner` reports the
  setup traces an examiner looks for (encryption headers, containers, crypttab lines of every
  TrueCrypt and VeraCrypt kind, LVM archives, tooling and history), grouped by what they suggest;
  `--disk <device>` adds partition-level checks. A residue catalog names every class of trace a
  session or its setup can leave, with its mitigation; `verify` and the `residue-catalog` check run
  its probes, and the residue tables in the docs are generated from it.
- `nails activate` writes a read-only decoy residue report under `<hidden-root>/reports/` before
  the switch and prints a one-line summary.
- `nails config path|show|validate`: `show` prints every effective value and its source
  (default, file, cli, derived), `--example` prints every key, and `validate` checks a file
  strictly.
- `nails reset-upper <PATH>` deletes a path's hidden copy from the upper, so the decoy's own files
  show through again (for example after a decoy update); it is refused in the hidden session.
- `nails completions <shell>`, a man page (`nails.1`), a Markdown CLI reference (`docs/cli.md`),
  JSON schemas under `docs/schemas/`, and EXAMPLES and an exit-code table in `--help`. The release
  archive ships the man page, the CLI reference, the operator guide and the threat model.
- `nails status` reports the live session from the mount table and the session plan (posture
  `decoy`, `active`, `transitioning`, `degraded` or `unknown`), the policy for every decoy
  filesystem, whether the decoy keeps a persistent log store, the persona mode and how long the last
  activation took. An interrupted entry exits 7 and points at `nails recover`, as does a record
  that still says active after a power loss.
- SIGINT and SIGTERM cancel an activation and remove the half-built next root (exit 130), SIGHUP
  no longer aborts a running command, and NAILS lowers its own OOM score.
- NAILS disables its own core dumps before parsing its arguments, so a crash cannot write its
  memory to the decoy.
- Documentation: an operator guide organised by where each step runs, with a recovery runbook,
  `docs/threat-model.md`, `docs/configuration.md`, `docs/backends.md`,
  `docs/decoy-requirements.md`, `docs/architecture.md`, `docs/distribution.md`,
  `docs/verify-release.md` and architecture decision records under `docs/adr/`.

### Changed

- Configuration is strict TOML: unknown keys are rejected with a did-you-mean hint, a removed key
  says so, configured paths are validated when the file is loaded (relative, `..`, symlinked or
  out-of-root paths are rejected), and a missing or invalid `--config` file exits 3.
- One stable machine interface: a typed JSON envelope (`schema_version`, `command`, `ok`, and
  `data` or `error`; `activate --json` streams progress events before its result) and one
  exit-code table for every command (pre-flight refusals 4, missing
  root 5, untrusted state 6, degraded or interrupted 7, unsupported host 8, completed with
  warnings 9, `verify` warnings and critical findings 10 and 11, cancelled 130).
- Output flags (`-c`, `-v`/`-q`, `--color`, `--ascii`, `--json`, `--no-log-file`) are global.
  Colour is never used on piped output and honours `NO_COLOR` and `CLICOLOR_FORCE`; console lines
  no longer carry a timestamp.
- `activate`, `deactivate`, `emergency` and `recover` refuse to run without root before writing
  anything, with a `sudo` hint and exit 5.
- `nails init` checks the target, the attach gate first, before writing anything, supports
  `--json`, `--hardware-config` and `--no-hardware-config`, reports each item as created or
  already present, and ends with numbered next steps.
- The swap check classifies each device: RAM-only zram passes, swap on dm-crypt with a random key
  warns, and disk or file swap, fixed-key encrypted swap and hibernation are refused. A hidden
  NixOS hardware configuration that NAILS seeds has the decoy's `swapDevices` and `resumeDevice`
  commented out.
- The disk-space check is one floor (`minimum_space_mb`, 500 MB); `rebuild_space_mb` (4096 MB) is
  checked before a hidden NixOS build.
- `nails verify` names the checks it ran and the areas it did not, and reports session leftovers.
- On NixOS the hidden `hardware-configuration.nix` wraps the original (kept as
  `hardware-configuration.base.nix`) instead of patching it, a `nix-instantiate --parse` check
  rejects an unparseable configuration, the base-configuration check scans every `.nix` file under
  `/etc/nixos` for references to the hidden volume, and the hidden NixOS module forces
  `system.autoUpgrade.enable = false`.
- Unsupported hosts are refused before any write, with exit 8: Debian before 13, Ubuntu before
  24.04, non-merged-`/usr` layouts, ostree or image-based systems, systems without systemd, and
  distributions not yet validated (Fedora, Arch).
- A corrupt or unreadable state file is reported as an unknown state: `status` shows it and
  `activate` refuses, instead of treating it as inactive.
- The project describes itself with one platform-neutral tagline ("Overlay environment manager");
  sources carry SPDX headers, and `REUSE.toml`, `NOTICE` and DCO sign-off guidance are added.
- Vulnerabilities are reported through GitHub private vulnerability reporting first, with
  `security@nails.run` as the fallback; conduct reports go to `contact@nails.run`.
- Releases come from one tag-triggered workflow that checks the tag against the version,
  `Cargo.lock` and this changelog, builds from source, rebuilds on a fresh runner, runs the full
  E2E suite, attests the assets and an SBOM, and drafts the release with this section as its
  notes. `docs/verify-release.md` explains how to verify the assets.
- Development: the library is split into crates along the session's boundaries (ADR 0010), unsafe
  code is denied outside scoped, commented sites, the toolchain is pinned in
  `rust-toolchain.toml` (1.93.0), the flake pins nixos-unstable of 2026-10-11, and a `justfile` is
  the single source of local and CI commands. The VM tests cover the session on NixOS, Debian 13
  and Ubuntu 24.04, with host-side checks of the decoy disk image.
- CI: one required `gate` check per pull request, E2E VM tests on GitHub-hosted runners (affected
  tests per pull request, the full suite on `main` and nightly), scheduled advisory, stress,
  mutation and benchmark jobs, and dependency checks through cargo-deny only.

### Removed

- The per-directory live overlays (`/etc`, `/home`, `/var`, … on the running decoy) and everything
  that served them: process detection, restart and kill, the display-manager restart, the
  overlay pivot, the shell-history cleaner, the shell prompt marker and terminal colour scheme, and
  the desktop notifications after activation with their XDG autostart entry.
- The `notify-dispatch` command; the `activate` flags `--no-clear-history`, `--kill-session`,
  `--no-kill-session`, `--accept-pivot-risks`, `--no-pivot` and `--interactive`;
  `deactivate --no-clear-history`; `emergency --no-countdown` (emergency now acts at once); and the
  per-command `--plain` and `--no-color` flags and the global `--no-logs`.
- The configuration keys `overlays`, `overlay_mode`, `overlay_exclusions`,
  `overlay_exclusions_remove`, `extended_overlays` and the ephemeral overlays, `clear_history`,
  `color_scheme`, `preflight_checks`, `default_verbosity`, `color_output`, `verify_on_deactivate`,
  `milestone_tips`, `max_log_size_mb` and `retention_days`.
- The XOR string obfuscation: the binary is identifiable, and the documentation says so.
- `docs/USER-SECURITY-GUIDE.md` and `docs/vulnerability-handling.md`, replaced by the operator
  guide, the threat model and `SECURITY.md`.

### Fixed

- On NixOS, `activate`, `deactivate` and `emergency` work when a systemd unit starts them (a panic
  key, `systemd-run`): the Nix tools are found in the root-owned system directories when the
  caller's `PATH` lacks them, and a legacy build without `NIX_PATH` takes `nixpkgs` from root's
  `nixos` channel.
- Pre-flight results are reported once and honour `--quiet` and `--json`.
- Resolved the RUSTSEC advisories in the dependency graph and restored the Nix release build
  ([#54](https://github.com/WitteShadovv/nails/pull/54)).

### Security

- Nothing NAILS writes reaches the decoy: the state file, its lock, logs, reports and staged
  configuration are written only onto an attached hidden root, through `openat2` beneath it, so a
  planted symlink or `..` cannot redirect them; log files are created mode 0600, and a panic goes
  to the hidden-root log, not stderr.
- Commands NAILS starts run from a cleared environment with a fixed, root-owned `PATH`, so a
  caller's `PATH` or `NIX_*` cannot steer which binaries a root child runs.
- The release binary carries no test hook: test-only code compiles only under a non-default
  `test-hooks` feature.
- The release binary links the musl of the pinned nixpkgs (1.2.6, with nixpkgs' patches for
  CVE-2026-6042 and CVE-2026-40200) instead of the musl 1.2.5 that ships with the Rust toolchain,
  so the musl the release SBOM names is the one in the binary. The build fails if its linker map
  shows `libc.a` or one of musl's crt files from anywhere else.
- The release binary no longer refers to the Rust toolchain that built it, so installing the
  `nails` package through Nix no longer keeps the toolchain (about 2.6 GB) alive.
- The release SBOM records the CVEs that nixpkgs patches musl against as backported fixes in the
  musl component's `pedigree` and gives musl its CPE. A new attested release asset,
  `musl.openvex.json`, marks those CVEs as fixed; scan with
  `grype sbom:sbom.cdx.json --vex musl.openvex.json`.

## [0.2.0] - 2026-05-08

### Changed

- Bumped the Rust workspace version to `0.2.0`.
- Hardened release publication around immutable tag-based workflows: exact stable tags are
  verification-only, stable publication is deliberate/manual, and prerelease publication is tied to
  suffixed prerelease tags.
- Refined release workflow permissions and repository targeting so GitHub release automation works
  reliably under repository rulesets.

### Fixed

- Created `state.json` during `nails init` and preflight when needed, preventing init/preflight
  flows from missing expected state metadata.
- Fixed release workflow regressions after the immutable-release restructuring.

## [0.1.0] - 2026-04-27

### Added

- Established the Rust workspace split between `nails-cli` and `nails-core`, including shared
  workspace metadata, custom error types, a filesystem abstraction for testing, and the initial
  quality-gate infrastructure.
- Implemented the core lifecycle model: typed state transitions, state-file serialization,
  checksummed state metadata, RAII state guards, and the `NailsManager` orchestration layer.
- Added the preflight validation system with checks for hidden storage readiness, swap exposure,
  available space, overlay directories, current state, NixOS configuration, symlink support, and
  selected flake build targets.
- Implemented activation support for OverlayFS-based hidden sessions, NixOS configuration overlays,
  deterministic mount ordering, reverse-order rollback, process/session handling, display-manager
  restart behavior, and NixOS build/switch integration.
- Added support for flake-based activation via `--flake`, config-fingerprint fast paths,
  missing-only build paths, automatic overlay strategy selection, `/var` overlays, optional `/boot`
  pivoting, and bind-mounted fallbacks for overlay-incompatible targets.
- Implemented deactivation and emergency cleanup flows, including standard reboot-based cleanup,
  emergency no-reboot cleanup, force-unmount fallback behavior, cleanup reporting, and post-cleanup
  verification hooks.
- Added user-facing commands and output for status reporting, verification scans, emergency
  deactivation, progress indicators, verbosity controls, no-color handling, desktop notifications,
  and notification dispatch.
- Added shell integration and forensic-safety support, including prompt/alias management,
  in-memory and on-disk history cleanup, automatic terminal color-scheme switching, structured
  logging, sanitized log paths, and timestamp-based log rotation.
- Added Nix-based end-to-end validation infrastructure covering the basic workflow, emergency
  deactivation, forensic cleanliness, snapshot diffs, and performance scenarios.
- Added reproducible Nix release packaging for the canonical Linux artifact, checksum generation,
  SBOM/supply-chain checks, dependency auditing, coverage gates, and release-path verification.
- Added public project documentation and governance files, including release reproducibility
  guidance, CI documentation, support and security policies, issue templates, code of conduct,
  roadmap updates, and public README guidance.

### Changed

- Migrated the project surface from early prototype planning into a Rust-first implementation with a
  focused CLI crate and domain-oriented core library.
- Refactored the CLI and core library into focused modules for activation, deactivation, cleanup,
  config, filesystem access, logging, manager orchestration, NixOS integration, overlays,
  preflight checks, shell integration, state, status, and verification.
- Reworked CI from the initial pipeline into consolidated, cached workflows using `cargo-llvm-cov`,
  pinned tooling, reusable release/reproducibility jobs, and trusted full E2E validation.
- Replaced deprecated `serde_yaml` usage with `serde-saphyr` and refreshed Rust/GitHub Actions
  dependencies, including `thiserror`, `colored`, `signal-hook`, and Node.js 24-compatible actions.
- Aligned public documentation with the current alpha threat model, release process, support scope,
  NAILS OS separation, artifact format, and AI-assisted development disclosure.

### Removed

- Removed the legacy Python implementation after the Rust migration became the maintained code path.

### Fixed

- Hardened activation and deactivation around partial overlays, same-device submounts, overlay
  permission mismatches, display-manager restart timing, NixOS generation switching, fast-path
  activation, and deactivation base-configuration checks.
- Hardened hidden configuration and hardware-configuration handling to fail earlier and avoid unsafe
  or ambiguous activation states.
- Improved forensic cleanup by addressing shell-history persistence, alias stdout leakage,
  cleanup/log formatting, temporary-file cleanup, and post-deactivation artifact checks.
- Stabilized E2E and unit coverage by serializing fragile switch-to-configuration tests, moving real
  filesystem tests into test-only paths, expanding activation/deactivation guard coverage, and
  bringing measured coverage above the documented threshold.
- Fixed release and CI regressions around workflow permissions, reproducibility comparisons,
  GitHub CLI repository targeting, artifact naming, release tag handling, cargo-sbom output format,
  Dependabot configuration, and pre-commit coverage parity.

### Security

- Added comprehensive shell-history protection and cleanup verification for forensic-safety goals.
- Added SBOM generation, dependency/security audit workflows, cargo-geiger integration, and public
  vulnerability-handling documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for public contribution guidance.

[Unreleased]: https://github.com/WitteShadovv/nails/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/WitteShadovv/nails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WitteShadovv/nails/releases/tag/v0.1.0
