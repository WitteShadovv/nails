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

### Added

- A configurable active-state prompt label (empty by default) and a guard that writes the shell rc
  block and autostart entry only when the target lives on a NAILS overlay, warning and skipping
  otherwise.
- A single `/proc/self/mountinfo` parser with kernel octal-escape decoding and overlay-option
  escaping, shared across the filesystem and overlay layers.
- State file v2 with `boot_id` and `owner_pid`, a `Degraded` state for partial teardowns, and an
  inter-process lock that serialises state-mutating commands, so a second `activate` while one is
  running fails fast with the running operation's PID.
- A fast privileged overlay and teardown integration test tier, run in a required mount-namespace
  CI job, with a development guide for running it locally.
- The `nails config path|show|validate` subcommands to locate, inspect and check the configuration
  file; `show` reports the effective value and source (default/file/cli/derived) for each key in
  human or `--json` form, and `show --example` prints every key.
- `docs/configuration.md`, a configuration reference kept in step with the code by a test, listing
  every key with its type, default and effect and documenting the overlay exclusion rules.
- A stable CLI machine interface: one typed JSON envelope on stdout (`schema_version`, `command`,
  `ok`, and `data` or `error`), state and verification as tagged snake_case objects, a documented
  exit-code table returned from `main` (verify warnings and critical exit 10 and 11, preflight
  refusals 4), and an opt-in `status --exit-status`.
- The `risky_services` config key and the `--risky-services`/`--terminate-interactive` activate
  flags; non-interactive activation no longer silently skips risky-service restarts or
  force-terminates interactive user processes, and surviving decoy writers are tracked by identity.
- A scheduled maintenance workflow (crate fetcher canary, Rust cache warming, stress loop and a
  task-dispatch input) and a `report-status` action that tracks red runs of `main`, scheduled jobs
  and releases in `ci-red`/advisory issues.
- Preflight refuses activation outside PID 1's mount namespace or when `/` lacks shared
  propagation, and probes that the hidden root can host an overlayfs upper layer (trusted xattrs,
  `d_type`, whiteouts), naming the filesystem type when it cannot.
- A `backend-detect` preflight that warns, never fails, about discard-enabled VeraCrypt or plain
  mappings, file-container timestamp exposure and containers on copy-on-write filesystems, plus
  `docs/backends.md` with the backend support matrix and per-backend deniability notes.
- GitHub issue forms for bug reports and feature requests that require an OPSEC acknowledgement and
  no longer ask for `nails status` output.
- `nails status` reports hidden-volume disk usage (used, total and free) from a single `statvfs`
  call, and a new `nails reset-upper <target>` clears a target's persistent overlay upper (allowed
  only while inactive and unmounted, with a confirmation prompt and a warning when the target is
  `/nix`).
- Preflight now warns when the hidden-volume mount path, device-mapper name or filesystem label
  contains a word that hints at hidden storage, and the built-in default root name is neutral.
- The strict `allow_leaky_exclusions` key, which lists the load-bearing directories (`/home`,
  `/root`, `/etc`, `/var`, `/nix`, `/srv`, `/opt` and a disk-backed `/tmp`) an Auto-mode overlay
  exclusion is permitted to send to the decoy disk; any other exclusion of one of these is refused.
- `nails check` (alias `doctor`), a read-only readiness report built from the same preflight
  registry as activation: it prints each check's result plus the effective configuration, overlay
  targets, session handling and NixOS profile, supports the `--json` envelope, writes nothing and
  exits 4 when any check fails. `activate --dry-run` is now an alias for it.
- A warn-only binary-location preflight that flags a running binary, or a `PATH` symlink to it,
  outside the hidden volume; the generated hidden `configuration.nix` is now a commented template
  of hidden-session settings instead of a one-package stub.
- `docs/distribution.md` (supported and unsupported install channels and platform tiers),
  `docs/verify-release.md` (the single release verification guide) and `RELEASING.md` (the release
  checklist).
- A manual `e2e-hetzner.yml` workflow that runs the E2E suite on one single-use Hetzner runner.
- An opt-in `persona.mode = "fresh-home"` that bind-mounts a clean home from the hidden volume over
  the operator's home, so the decoy home stays hidden during a session; the default `shared-home`
  now warns at activation, and `nails status` and `nails check` report the persona mode.
- A UEFI end-to-end test asserting that the ESP and EFI NVRAM stay unchanged across an
  activate/deactivate cycle.
- A fast `ci-python` flake check and `just ci-python` recipe running the `ci/` unittest suite, ruff
  and mypy.
- Architecture decision records under `docs/adr/`.

### Changed

- The base-config suspicious-reference preflight now matches the configured hidden volume root and
  its backing device (resolved from `/proc/self/mountinfo`) and scans every `.nix` under
  `/etc/nixos` instead of only `hardware-configuration.nix`.
- Overlay-mount and missing-config failures now carry typed error variants (mount errno, config
  path) so the pivot and config-default fallbacks branch on the cause rather than on
  error-message text.
- A corrupt or unreadable state file now loads as an explicit unknown state: `status` reports it and
  `activate` refuses, instead of silently treating it as inactive or hard-failing every command.
- Updated hidden-storage examples to open VeraCrypt-compatible hidden containers with
  `cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden` before mounting the mapper device.
- Clarified post-reboot verification guidance so the standard reboot path no longer asks operators
  to manually unmount or close the hidden backend after reboot; emergency and recovery guidance
  still documents manual `umount` and `cryptsetup close` steps.
- Directed non-security conduct reports to `contact@nails.run` while preserving
  `security@nails.run` for vulnerability-sensitive communications.
- CI gates dependency advisories only on the shipped dependency graph (x86_64 Linux, no
  dev-dependencies) and only when `Cargo.toml`, `Cargo.lock`, or `deny.toml` change; a weekly
  scheduled workflow runs the full cross-target, dev-inclusive scan. Each `deny.toml` advisory
  ignore now requires an `# expires: YYYY-MM-DD` date, enforced by `ci/deny_ignores.py`.
- `nix flake check` is now a fast lint gate (nixfmt, statix, deadnix, shellcheck, actionlint,
  zizmor, and shard-weight checks); the flake exposes `x86_64-linux` only. E2E VM tests moved to
  `legacyPackages.x86_64-linux.e2e.<name>` with metadata under
  `legacyPackages.x86_64-linux.e2e-metadata`, the E2E test `performance` was renamed to
  `performance-validation`, and `run-e2e-tests.sh -i` now takes exactly one leaf test.
- The `nails` package and E2E VM tests now build identically across commits and hosts (constant
  `SOURCE_DATE_EPOCH`, cargo-only source, fixed 2-core VMs), and CI sets up Nix through one
  `.github/actions/setup-nix` action with an optional project binary cache.
- Updated `serial_test` to 3.5, which no longer pulls in the `scc` dependency.
- External commands start through one `ProcessRunner`, which applies the test-safety guard;
  `systemctl`, `loginctl`, `kill` and `cp` are resolved from fixed system directories (NixOS
  profile, then `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`) instead of a hardcoded NixOS path or the
  caller's `PATH`; directory sizing and `sync` run in-process.
- Configuration is now strict TOML (`config/nails.toml` next to the binary) instead of YAML: unknown
  keys are rejected with a did-you-mean hint, and a missing or invalid `--config` file makes
  `activate`, `status`, `verify` and the `config` subcommands print a single error line and exit 3,
  while `emergency` and `deactivate` warn once and continue with binary-derived defaults.
- Output, verbosity and config flags (`-c`, `-v`/`-q`, `--color auto|always|never`, `--ascii`,
  `--json`, `--no-log-file`) are global and accepted before or after the subcommand; `status -v` is
  now `--details`; colour is resolved once per stream (terminal, `TERM`, `CLICOLOR_FORCE`, with an
  empty `NO_COLOR` treated as unset) and never colours piped output, and DECOY shows an uncoloured
  neutral mark distinct from CRITICAL.
- Redesigned the `nails activate`/`deactivate` flags (`--session kill|keep`, `--pivot
  refuse|allow|ask`, `-y`), made the session-kill and deactivate-reboot confirmations reachable, and
  reported the detached activation outcome.
- `NailsManager` activation and deactivation run over an owned `&mut` context; the `Arc<Mutex>`
  state cache and the separate deactivation orchestrator layer are removed.
- NixOS `hardware-configuration.nix` is wrapped (the original is preserved as
  `hardware-configuration.base.nix`) instead of text-patched, and a `nix-instantiate --parse`
  preflight gate rejects an unparseable config before any overlay is mounted.
- E2E tests run from one workflow (`e2e.yml`) on GitHub-hosted runners (affected tests per PR, the
  full suite on push to main, every driver nightly, Hetzner reserved for a manual lane); failed
  tests are retried once and retry-passes are reported as FLAKY. The bash E2E runners and the
  shard-weight script are replaced by the tested `ci.e2e` Python package (`python3 -m ci.e2e`).
- The Rust toolchain is single-sourced from `rust-toolchain.toml`, the flake devShell is the only
  dev environment, a `justfile` is the single source of local and CI commands, incremental dev and
  test builds are re-enabled, and pre-commit hooks split into a fast offline stage and a pre-push
  `just check`.
- Dependency automation reworked (grouped monthly Dependabot with correct Conventional Commit
  titles, a PR-title check, and flake/pre-commit auto-update and monthly `Cargo.lock` refresh
  workflows); the shipped dependency footprint is trimmed (`signal-hook` removed, chrono built
  without default features).
- Overlay mounts always set `index=off,metacopy=off,redirect_dir=off`.
- The security guide no longer recommends TRIM or `fstrim` on volumes that carry a hidden volume and
  documents the discard, timestamp and copy-on-write hazards of each backend.
- `.gitignore` no longer lists personal or planning paths and its packaging patterns are anchored;
  the shell-history forensics page is trimmed to what NAILS does about each history surface.
- `nails init` validates that the target is a mounted volume of its own, writable and
  symlink-capable, and that any hardware config is readable, before writing anything, and writes
  nothing on refusal; it adds `--allow-unmounted`, `--hardware-config` and `--no-hardware-config`,
  supports `--json`, reports each item as created or already present, drops the unused `overlays/`
  directory, rejects a global `--config`, and ends with numbered next steps.
- Standard deactivation no longer reinstalls the decoy configuration: the redundant
  `switch-to-configuration switch` on the real disk is gone (the reboot already boots the decoy),
  switch actions are a non-installing enum that can only request `test`, and a failed reboot falls
  back to `test`, so the bootloader, ESP and EFI NVRAM are left untouched.
- CI is now a lean parallel pull-request gate with a single required `gate` check and a path filter
  that lets docs-only changes skip the Rust and Nix jobs; the nextest `ci` profile retries a failed
  test once and reports FLAKY tests, `nix-pr-verify.yml` is folded into `ci.yml`, and the branch
  ruleset should require `gate` instead of `CI Success`.
- Releases run from one tag-triggered workflow that checks the tag against the version,
  `Cargo.lock` and `CHANGELOG.md`, builds from source and rebuilds on a fresh runner, runs the full
  E2E suite, attests the assets and an SBOM that includes musl, and drafts the release with the
  changelog section as notes; the archive is now `nails-<version>-x86_64-unknown-linux-musl.tar.gz`
  and the build runs cargo with `--locked`.
- CI is consolidated into seven workflows (`ci`, `e2e`, `e2e-hetzner`, `scheduled`, `release`,
  `reproducibility`, `pr-title`); flake-lock and pre-commit updates and the weekly reproducibility
  rebuild run from `scheduled.yml`, and `docs/ci.md` documents the test and CI tiers, checked
  against the workflows by `just docs-check`.
- Unsafe code is denied at compile time through workspace lints (each remaining site carries a
  scoped allow and a `SAFETY` comment), clippy size lints are enabled, and the Rust file-size check
  is a sub-second script with no exemptions shared by pre-commit, `just check` and CI.
- Benchmarks run weekly against the previous run's baseline (slowdowns warn, a missing result
  fails), and the E2E performance test times nails' own `duration_ms` inside the guest and runs
  only nightly.
- Neither crate can be published to a registry (`publish = false`), and the README's only first
  install is the verified release binary; source and Nix builds are documented for upgrades from
  inside a hidden session.
- Preflight checks no longer write: activation stages the hidden NixOS configuration before the
  checks run, and the storage check only reports what activation would create when run read-only.
- External control commands (systemctl, loginctl, `nix store ping`, ldd, cp and reboot dispatch)
  run under per-command deadlines, and long `nixos-rebuild` and `switch-to-configuration` steps
  report periodic progress instead of running silently.
- `nails activate`, `nails check`/`--dry-run` and the `nixos-build-target` preflight share one NixOS
  build-target discovery, and activation refuses unsupported hosts (ostree/image-based or
  non-systemd) with exit status 8.
- Every subsystem resolves the operator through one target-user resolver, so under sudo or a
  detached run shell-history and related cleanup target the operator's home and files stay
  operator-owned.
- Docs and E2E tests use neutral storage names (mapper and label `data`, mount point `/mnt/data`),
  and the user security guide gains a Pre-Activation Residue section.
- The scheduled flaky-test lane runs the suite threaded, single-threaded and shuffled with a printed
  seed, and the dev shell provides zsh and fish.
- Internal planning identifiers are removed from source, tests and docs.

### Removed

- The XOR string-obfuscation module and its indistinguishability claims; the obfuscated literals
  are inlined and the binary is now described honestly as identifiable.
- The non-functional in-memory shell-history clear (a `bash -c` subprocess that could never
  reach the parent shell) and the free `emergency_deactivate` re-export; emergency deactivation
  goes through `NailsManager::emergency_deactivate`.
- `cargo-audit` from CI, pre-commit, both dev shells, and `scripts/ci-local.sh`; dependency
  advisories are now covered entirely by cargo-deny.
- The `NAILS_E2E_SYSTEM` and `NAILS_E2E_VM_*` environment overrides, the `apps.e2e-test-interactive`
  output, the `checks.*.e2e-*` mapping, and the nix-community binary cache.
- The `extended_overlays` and ephemeral-overlay configuration features, the `hidden_volume_path`
  alias, the `nails config show --no-preflight` preview, and the `default_verbosity`, `color_output`,
  `milestone_tips`, `verify_on_deactivate`, `preflight_checks`, `max_log_size_mb` and `retention_days`
  keys (none of which had any effect); `/Downloads` is also no longer a default overlay exclusion.
- The `--plain`, `--no-color` and `--no-logs` flags and the `NAILS_NO_COLOR` environment variable,
  replaced by `--color` and `--ascii`; the six separate E2E and forensics-eval workflows,
  `scripts/ci-local.sh`, `scripts/burn-in.sh` and `shell.nix`.
- The unused `.github/scripts/package-release.sh`; the flake's `nails-release` builds the release.
- The copy of the systemd closure into `/run/nails/systemctl-cache` on every activation; systemctl
  runs through the existing read-only store bind instead.
- The placeholder benchmarks and the PR benchmark-budget job, the cargo-geiger report, the Codecov
  upload, `publish-release.yml`, `release-core.yml` and the slsa-github-generator provenance, the
  forensics-eval workflows and `update-flake-lock.yml`.
- `docs/vulnerability-handling.md`; the maintainer triage and disclosure process now lives in
  `SECURITY.md`.

### Fixed

- Notification signal files are written atomically with a numeric collision suffix, so two
  notifications sharing a title within the same millisecond no longer overwrite each other.
- The activation security label is derived from writer processes still referencing the decoy after
  mount rather than from the overlay mount method, so a direct mount that leaves surviving writers is
  no longer mislabeled `OPTIMAL`.
- E2E VM tests now time out after 900 s by default (1500 s for the performance test) and fail with
  diagnostics after a 300 s power-off deadline instead of hanging for the driver's full hour; shard
  weights no longer include two recorded one-hour hangs, and full-suite shards upload per-test
  durations with a non-blocking weight-drift report.
- The E2E runner recorded a failed `nix build` as a pass and passed a bare revision to `--affected`
  as a flake reference; outcomes are now read from the store and `--affected` pins a `git+file`
  revision, evaluating both sides in one `nix eval`.
- Nix store writes made in a hidden session land in the hidden overlay instead of the decoy
  partition: the overlaid `/nix/store` is self-bound read-only rather than re-bound to the
  pre-overlay store.
- nix-daemon and journald are restarted on every teardown path after `/nix` and `/var` are
  unmounted, including deactivation after a failed `/nix/store` unmount and activation rollback.
- The init-namespace store bind is skipped when NAILS already shares PID 1's mount namespace, and
  its forked helper uses only async-signal-safe calls.
- Deactivation now attempts every overlay unmount and ends in a `Degraded` state that reports the
  remaining mounts, instead of claiming a remount that never happened and returning to `Active`.
- Overlay opaque-marker handling runs in-process and only on NAILS-managed paths (`/etc/nixos`), so
  preflight and `activate --dry-run` no longer write to the hidden volume, hidden-session whiteouts
  in user data and `/nix` survive, and the `attr` package is no longer required.
- Shell and editor history cleanup now targets the operator's real home plus `/root` instead of
  root's home alone, so under `sudo` and the detached unit the operator's history files are reached.
- The `just coverage` recipe no longer dies with a SIGPIPE error when the coverage report is large;
  it reads only the root coverage element and fails with a message when the report has no line rate.
- A failure after the overlays are mounted (the session restart or the final state write) now
  unmounts them before the state is rolled back and before the session restarts onto the decoy;
  mounts that cannot be removed are recorded as `Degraded` instead of the state claiming `Inactive`.
- Preflight results are reported once, through the log output, so they honour `--quiet` and
  `--json` instead of being printed twice.
- Detached activation and deactivation keep identifying data out of the system journal: transient
  units are auto-named with a neutral description, worker output goes to the hidden-root log rather
  than the journal by default (with an opt-in debug escape hatch), the history-cleanup pattern list
  stays off the log stream, and a panic hook sends crash payloads and source paths to the hidden-root
  log rather than stderr.
- The hidden NixOS flake is checked with `nix` only after `/nix` and `/root` are overlaid; the
  pre-overlay preflight performs static checks only, so the hidden configuration stays off the decoy
  Nix store, database and root cache, and a broken flake fails with the overlays rolled back.
- Emergency deactivation on a corrupt or unreadable state file tears down the NAILS overlays found
  in the live mount table instead of refusing.
- Deactivate and emergency teardown remove the read-only `/nix/store` bind left in PID 1's mount
  namespace, so it is no longer pinned after a hidden session ends.
- `nails activate` refuses to stage configuration onto a hidden root that is not a positively
  attached volume, and `verify` no longer flags logs stored on the hidden volume as residue.

### Security

- `unmount` refuses any mount NAILS did not create, so stale state can no longer lazily force-detach
  a real `/home`, `/nix`, or `/boot`.
- Configured paths in `nails.toml` are validated when the file is loaded: a relative or
  non-normalized path, a `..` component, a symlinked or out-of-root hidden volume, and a `,` or `:`
  in an overlay path are each rejected with a specific error.
- Vulnerabilities are reported through GitHub private vulnerability reporting first, with
  `security@nails.run` as the PGP-capable fallback.
- Files NAILS writes into user home paths (shell rc block, autostart entry) and notification signal
  files are written through a symlink-safe open (`openat2` with `RESOLVE_NO_SYMLINKS`/`RESOLVE_BENEATH`
  and an `O_EXCL`/`O_NOFOLLOW` temporary) and owned by the operator with the correct numeric gid,
  closing a symlink-redirect (CWE-59) write as root.
- Logs and staged configuration are written only when the hidden root is a positively attached
  volume: the logging layer now verifies the root's device differs from `/` (not merely that the
  path exists) and falls back to stderr otherwise, read-only subcommands never create log
  directories or files, and log files are created mode 0600.
- Commands spawned through the process runner start from a cleared environment rebuilt from an
  allowlist — a fixed, root-owned PATH plus `LANG`/`LC_*`/`TERM` — so a caller's PATH or `NIX_*`
  can no longer steer which binaries a root child runs; `NIX_PATH` is passed through only for
  channel-based `nixos-rebuild`.
- The release binary no longer carries any test-detection heuristic or test hook: these compile only
  under a non-default `test-hooks` feature (or each crate's own test build), so no executable path,
  environment variable or service exemption can disable real host operations in a shipped build.
- An overlay-targets safety floor refuses, in both modes, any overlay target that would cover the
  hidden volume root, state file, log directory or the running binary (symlinks resolved), so the
  hidden volume can no longer disappear under an Auto-mode `/media` overlay and the hidden session's
  state and logs cannot be written through to the decoy disk.
- The detached root worker runs with a fixed, root-owned PATH and no `NIX_*` passthrough, so a
  caller's environment cannot steer root tool resolution or Nix evaluation; the user security guide
  documents the trusted computing base and a verified update procedure.
- Notification signal files are created 0600 and get their mode on the open descriptor, so a symlink
  swapped into the operator-owned queue cannot redirect root's chmod.

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
