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

### Upgrade notes

Upgrade only while NAILS is inactive: end a 0.2 session with its own `nails deactivate` (a reboot
ends it too) before replacing the binary. This release breaks compatibility with earlier state,
config and CLI surfaces; there are no compatibility shims.

- The whole-root session is the only session mode (ADR 0008). It needs systemd 254 or newer;
  besides NixOS, Debian 13 and Ubuntu 24.04 or newer are now supported as decoys. The hidden root
  lives under
  `<hidden-root>/root/` (`upper`, `work`, `mounts`, `cache`); the uppers of the per-directory
  overlays (`<hidden-root>/<name>`, `<hidden-root>/.work`) are not read. Move what you need into a
  hidden session and delete them. On NixOS the hidden hardware configuration now lives in
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it. Remove the deleted
  configuration keys listed under "Removed" from `nails.toml`: they are rejected as unknown keys.
- Configuration moves from `nails.yaml` (YAML) to strict `config/nails.toml` (TOML): convert each
  key by hand, unknown keys are now rejected, and `nails init` regenerates a documented template.
- Invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`); nails is never on
  the decoy `PATH`. Several `activate`/`deactivate` flags were removed (for example
  `--no-kill-session`, and the `--session` flag that briefly replaced it); see "Removed".
- Exit codes and the JSON envelope changed (`schema_version = 1`); scripts that parsed the old
  output must be updated against the new exit-code table and envelope.
- The on-disk state schema changed (adds `boot_id`, removes the `Emergency` state). Delete any
  pre-existing `state.json` from a clean inactive system; do not hand-edit it — use `nails recover`
  to reconcile a stuck state.

### Added

- The whole-root session (ADR 0008). `nails activate` builds one overlay over the whole decoy root at
  `/run/nextroot` (the decoy root read-only as the lower, `<hidden-root>/root/upper` as the upper),
  applies a fixed fstab policy to every other decoy filesystem (the ESP and `/boot` bound
  read-only, other mounted local filesystems overlaid with an upper under
  `<hidden-root>/root/mounts/`, swap, unmounted disks, network filesystems and disk-backed overlay
  entries masked), binds `/run` and the hidden volume into it, checks the init the way PID 1 will,
  writes the session plan with a RAM copy of the binary and config to `/run/overlay-runtime`,
  installs the transition drop-in and soft-reboots (`systemctl soft-reboot`). Every process of the
  hidden session starts inside the overlay; no userspace process can reach the decoy filesystem.
  As its last step activation SIGKILLs the decoy's interactive shells, so the activation command
  never reaches a history file.
- On NixOS the hidden system is built into the next root's store (`nix build --store
  /run/nextroot`, the evaluation cache on the hidden volume), activated chrooted with a private
  `/run`, and entered by repointing `/run/current-system` after every decoy unit has stopped: one
  soft-reboot, no bootloader install, no system profile change. Inside the hidden session
  `/etc/nixos` is the hidden configuration and `nixos-rebuild test` applies changes.
  `--overlay-only` enters with the decoy's own system plus the hidden `/etc` and home. Debian 13
  and Ubuntu 24.04+ run the same session with the hidden configuration in the upper's `/etc`.
- The hidden NixOS system no longer depends on the decoy store: before activating it, activation
  copies every path of its closure still read from the decoy store up into the store overlay's
  upper on the hidden volume (through the overlay; the decoy store is never written), recorded in
  `<hidden-root>/root/store-kept` so later entries copy only new paths, and `nix-store --verify`
  drops paths the decoy deleted from the hidden store database before the build. A decoy that
  garbage-collects or rebuilds between sessions no longer breaks the hidden system (T-137, VM test
  `session-nixos-store-gc`).
- Disks mounted during the hidden session (T-143). The session watcher raises a neutral desktop
  alert for every read-write mount of a block device outside the hidden volume
  (`[session_mounts] alert`, on by default; the watcher now also runs for it). Opt-in
  `[session_mounts] read_only` makes every disk the session does not use read-only at the block
  layer for the session, through a runtime udev rule for disks attached during it and a watcher
  sweep as a fallback; the way back makes exactly those disks writable again. `nails deactivate`
  unmounts disks mounted during the session before the way back. VM test `session-disk-mounts`.
- The transition step (`ExecStart=` of `systemd-soft-reboot.service`, run from the RAM copy) acts
  only on an armed plan. On the way back it scrubs `/run` of what the hidden session added (an
  allowlist that never touches sockets, `/run/udev`, credentials or the current/booted system
  links), restores libmount's `utab` and writes journald's kmsg cursor, so the decoy journal
  imports no hidden kernel record. An unarmed populated `/run/nextroot` is detached, so a later
  plain `reboot` (a soft-reboot on systemd 255+) never enters a leftover tree.
- Pre-flight checks `systemd-version` (254 or newer; Debian 12 and Ubuntu 22.04 refused),
  `soft-reboot-units` (prints the module a pinned nixpkgs needs), `decoy-root` (refuses a tmpfs,
  ZFS or overlay decoy root), `session-state` and `fstab-policy` (lists the decision for every
  decoy filesystem).
- `nails status` reports the live session (hidden root, entry under way, interrupted entry, plain
  decoy) from the mount table and the session plan, since a soft-reboot keeps the boot ID; an
  interrupted entry exits 7 with "run `nails recover`".
- Session VM tests under `nix/e2e-tests/tests/session/` (`session-lifecycle`, `session-emergency`,
  `session-interrupted-entry`, `session-fstab-policy`, `session-nixos-hidden-system`, and the
  promoted soft-reboot spike as `soft-reboot-mechanics`) and soft-reboot helpers in
  `nix/e2e-tests/py/nails_e2e/session.py`. The distribution smoke tests run the session on Debian 13
  and Ubuntu 24.04.
- Activation results reach the operator reliably. A committed activation pushes its queued
  result notifications straight into the operator's graphical session (`systemd-run --user
  --machine=<user>@.host`, falling back to `runuser`), removing each one delivered; with no
  session bus they stay queued as before. `nails notify-dispatch` keeps dispatching while an
  activation is in progress (signalled by a marker in the notifications directory) for up to 15
  minutes, instead of giving up after a fixed idle count. A missing `notify-send` is recorded once
  on the hidden volume, and `nails status` lists undelivered notifications
  (`undelivered_notifications` and `notify_send_missing` in `--json`).
- Activation reports progress through one reporter per surface: on an interactive terminal a
  spinner line shows the step and its elapsed time, with the overlay being mounted or the latest
  build line under it, and each finished step stays behind with its duration; on a pipe or
  `TERM=dumb` one plain line per step, per overlay and per 30 s heartbeat (never the raw build
  line); under `--json` typed `progress` events (`step`/`total_steps`/`label`, `detail`,
  `elapsed_seconds`); and a detached worker writes nothing to stdout or stderr. Step lines no longer
  carry an `INFO` prefix.
- `nails status` shows an activation in flight while the state is `activating`: the phase,
  step and elapsed time, read from a progress record the activation keeps on the hidden volume
  (`progress.json`, removed when the activation returns). This is the only view of a detached
  activation. `status` also reports how long the last successful activation took; `status --json`
  gains the optional `activation_in_flight` and `last_activation` objects, and the state file
  gains `last_activation`.
- An operator guide (`docs/operator-guide.md`) organised by where each step runs, with a
  `findmnt`-driven recovery runbook and honest limits, replacing `docs/USER-SECURITY-GUIDE.md`.
- `nails activate` writes a read-only pre-mount decoy residue report under
  `<hidden-root>/reports/` and prints a one-line summary; dry runs and already-active systems skip
  it.
- `nails completions <shell>`, a generated man page (`nails.1`) and Markdown CLI reference
  (`docs/cli.md`), canonical JSON schemas under `docs/schemas/` for status, verify, activate,
  deactivate and emergency output, and an EXAMPLES section in `--help`; the release tarball ships
  the man page, CLI reference, operator guide and threat model.
- `docs/architecture.md`, ADR 0005 comparing the live overlay with boot-time full-root overlay
  mechanisms, and a Markdown link and retired-name check (`scripts/docs-check.sh`) wired into the
  flake checks, pre-commit and CI.
- `nails recover` reconciles a stuck state and finishes an interrupted, degraded or corrupt-state
  teardown from the live mount table (a corrupt state file is kept as `state.json.bad`), and
  `nails emergency` now runs from any state; on a clean inactive system both are a no-op success.
- An in-session backend watcher (`[backend_watch]`) alerts the user when the hidden backend fails
  mid-session and, only when opted in, runs emergency after a debounce; activation keeps a RAM copy
  of the binary, config and mount manifest under `/run` so emergency stays runnable without the
  hidden volume.
- Emergency ends the hidden graphical session and stops the services the hidden configuration
  started, then restarts the display manager so the decoy greeter returns.
- `nails emergency --countdown <SECS>` (opt-in, with a Ctrl+C hint) and `--poweroff`/`--reboot`
  after teardown; the result lists detached and force-detached overlays, cleanup errors, the
  page-cache and history results and the backend-close commands, and a degraded teardown prints
  REBOOT REQUIRED and exits 7.
- Root `--help` explains the workflow and lists exit codes, every command has EXAMPLES, and path
  arguments carry shell value hints.
- Fault-injection E2E group (`faults`) and a strict hidden-volume teardown helper that fails and
  lists holders when the encrypted backend cannot be closed.
- Persona-separation E2E tests (sync pull-back as a known limitation, fresh-home without sync,
  stale decoy writers, masked decoy user timer) and a shared base node for E2E specs without a
  `nodes` block; README and the security guide document the remote-state and sync-client
  limitation.

- SIGINT/SIGTERM during an in-progress activation now cancel it and roll the system back to
  Inactive (exit code 130), SIGHUP no longer aborts a running operation, and mutating commands
  survive out-of-memory pressure (`OOMPolicy=continue` on the transient units plus a lowered OOM
  score, with child processes left as the preferred victim).
- A per-PR Debian/Ubuntu container smoke tier (`scripts/distro-smoke/`) that drives the overlay-only
  backend through the full lifecycle in privileged systemd containers, asserting `/usr` writes fail
  with EROFS while active and that decoy paths are byte-identical afterward, wired as a non-required
  CI matrix job.
- `nails reapply` applies a fixed hidden NixOS configuration in place while active; a failed hidden
  switch is now reported as "activated with warnings" (JSON `success_with_warnings`, exit code 9)
  and `nails status` shows the hidden configuration as not applied.
- E2E coverage for the real offline hidden NixOS rebuild, default auto-mode overlay lifecycle,
  fast-path re-activation, an impermanent decoy profile, and a control-run plus canary-user check
  for `/var/lib/nixos` drift, alongside an exhaustive state-transition-table test and
  path-containment property tests.
- Privileged commands (`activate`, `deactivate`, `emergency`) now fail fast when run without root,
  printing a `sudo <command>` hint and exiting without writing a log or state file.
- Pre-flight failures now show each check's own remediation and finish with one ordered list of
  fixes.

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
  refusals 4).
- The `risky_services` config key and the `--risky-services`/`--terminate-processes` activate
  flags; activation never signals a process that has no systemd unit (interactive or not) without
  `--terminate-processes`, a risky holder that cannot be restarted under the `restart` policy makes
  activation fail closed instead of surviving silently, and surviving decoy writers are tracked by
  identity and classified (surviving, stale_lower, unverifiable) by a post-mount `/proc` rescan.
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
- An inventory of the decoy autostart entries, enabled user services, lingering and display-manager
  autologin the hidden session inherits, reported as a warning by `nails check` and the activation
  confirmation, with opt-in hidden-only masking of autostart entries and user units through
  `[persona] mask_inherited`.
- An optional hidden network-identity NixOS module and NetworkManager drop-in (random MAC, distinct
  hostname), and documentation of the account and network identifiers the hidden session shares
  with the decoy.
- A warn-only `snapshot-memory` preflight check comparing the RAM the snapshot tmpfs of
  overlay-incompatible targets would pin with `MemAvailable`.
- A shared artifact registry that is the single source of what an activation writes, consumed by
  `verify`, the base-config preflight and the E2E `indicators.json` fixture (kept in step by a drift
  test), plus name-independent dm-crypt and loop-device detection in `verify`.
- Host-side decoy disk-image checks in the E2E suite (`fls`, strings, journal and store parsers in
  `disk_forensics.py` with null and positive controls and a persistent forensic VM profile) that
  image the decoy root rather than the hidden ciphertext.
- E2E coverage for VeraCrypt (tcrypt), bind-mounted and NFS-unsuitable hidden-root backends, and a
  regular-file `/etc/nixos` VM fixture in place of `/etc/static` symlinks.
- An E2E forensic test proving hidden-session Nix store writes land only in the hidden `/nix`
  overlay and leave no trace on the decoy disk image or store database.
- A platform `ConfigLayer` seam: the NixOS-only declarative half of activation (staging, fingerprint,
  `/etc` import, build, switch and decoy restore) is skipped on hosts without a config layer
  (FHS/Debian), so overlay-only is the absence of a layer rather than a parallel code path.
- The overlay policy is now platform data and keeps the decoy read-only during a hidden session (the
  decoy root and `/usr` on FHS hosts; `/bin` and `/usr` overlaid on NixOS), enforced by a preflight
  check, a fail-closed read-only guard undone on teardown, and a status/verify check.
- Submounts hidden under overlay targets (snap squashfs, separate partitions, tmpfs) are re-attached
  read-only or given their own nested overlay, so they stay visible while writes stay off the decoy
  disk; `/snap`, `/.snapshots`, `/sysroot`, `/ostree` and `/efi` are excluded from overlay on FHS
  hosts.
- Activation refuses a persistent decoy journal (override with `--allow-persistent-journal`) and
  re-homes `systemd-journald` onto the `/var` overlay with a verified rollback, so hidden-session
  logs do not leak to the decoy journal.
- `nails verify` flags leftover NAILS overlays and staging binds left mounted at non-standard
  targets, drawn from the live mount table.
- A platform-aware decoy-persistence pre-flight check: a persistent journal or an active rsyslog,
  syslog-ng or auditd refuses activation unless `accept_persistent_decoy` (or
  `--accept-persistent-decoy`) is set; a persistent root filesystem, atime-recording mounts,
  crash-dump channels and the NixOS auto-upgrade timer warn. `docs/decoy-requirements.md` describes
  the amnesic decoy profiles NAILS expects.
- A portable Debian/Ubuntu VM smoke suite (`nix/distro-tests`) with a bounded distro matrix
  planner and an informational `distro-e2e` CI workflow.
- A filesystem contract suite run against both the in-memory mock and the real filesystem, and a
  weekly mutation-testing job.
- A `[sleep_policy]` configuration table (`warn` by default, `block` or `teardown`) with a
  `sleep-policy` pre-flight check that warns when logind would suspend an active session, and a
  session sleep guard that holds a logind inhibitor (`block`) or runs the bounded emergency
  teardown on `PrepareForSleep` (`teardown`).
- A long NixOS build or switch now shows its most recent output line in the progress heartbeat, not
  just the elapsed time.
- `nails status` (human and `--json`) now reports when the decoy keeps a persistent log/audit store
  and never presents an active-on-persistent-decoy system as fully secure.

### Changed

- The library is split into crates along the session's boundaries (ADR 0010): `nails-base`,
  `nails-platform`, `nails-session` and `nails-forensics` below `nails-core`, which re-exports them.
  Tests pin the crate graph and keep verification read-only. No user-visible change.
- `nails deactivate` runs in the hidden session and soft-reboots back to the plain decoy: it mounts
  the decoy root at `/run/nextroot`, marks the hidden backend's device-mapper stack for deferred
  removal and records the state as inactive; the orderly shutdown stops every hidden program and
  the switch unmounts the hidden volume and closes its mapping. `--poweroff` powers off instead.
- `nails emergency` runs before argument parsing, the configuration and logging. In the hidden
  session it prepares the way back, marks the backend for deferred removal, enqueues the
  soft-reboot directly with PID 1 and kills every hidden cgroup at once (`cgroup.kill`); the
  machine returns to the decoy's normal login screen, and nothing logs in automatically.
  `--poweroff` powers off; a way back that cannot be prepared powers off instead, and a power
  action that cannot be enqueued asks the kernel. The backend is always closed. On the decoy it
  removes what an interrupted activation left. Its timed phases go to the hidden-volume log.
- `nails recover` runs on the decoy and removes an interrupted activation's leftovers: it detaches
  `/run/nextroot`, removes `/run/overlay-runtime` and the transition drop-in, reloads the service
  manager and resets the state.
- `nails reset-upper <PATH>` deletes a path's hidden copy from the hidden root's upper (and a
  separately overlaid filesystem's upper), so the decoy's own files show through again, for
  example after a decoy update that an earlier copy-up shadows. It is refused in the hidden
  session.
- The backend watcher (`[backend_watch]`) and the sleep guard (`[sleep_policy]`) run as runtime
  units of the hidden session from the RAM copy; the watcher's automatic emergency returns to the
  decoy, and the sleep guard's `teardown` mode powers off before the machine sleeps.
- The state machine has three states (`Inactive`, `Active`, `Degraded`).
- The README, operator guide, configuration reference, architecture overview and E2E harness
  guide describe the whole-root session; ADR 0008 is accepted and supersedes ADR 0005.
- Every I/O error names the path it concerns: `NailsError::IoError` is now a struct variant
  carrying the path (for a process that failed to start, the program) and renders as
  `<path>: <error>`, or the error alone when it already names the path. The implicit conversion
  from `std::io::Error` is gone; callers attach the path with `NailsError::io` or
  `IoResultExt::at_path`. Prompt I/O names `/dev/stderr`/`/dev/stdin`, and "cannot determine the
  operator's home" is now an invalid-state error rather than an I/O error.
- Process-restart classification now reads host process-name tables from the platform layer, and
  activation walks `/proc` once per mount phase instead of once per overlay target.
- Emergency and recovery teardown signal a still-running activation owner before unmounting, and the
  activation summary and its login notification now show the RAM-backed emergency command.
- The project uses one platform-neutral tagline ("Overlay environment manager") across the README,
  flake, crate metadata, help text and docs, dropping the NixOS acronym expansion; crate `authors`
  and `homepage` now name the real holder and https://nails.run, both crates set `publish = false`,
  and licensing metadata is added (SPDX headers on all sources, `REUSE.toml`, `NOTICE`,
  `LICENSES/GPL-3.0-or-later.txt`, a README copyright line) with DCO sign-off guidance in
  `CONTRIBUTING.md`.
- `docs/threat-model.md` is the single threat-model source (assumptions, state shared with the
  decoy, residual channels, evaluation scope); README, SECURITY.md and the operator guide link to
  it.
- The README is rewritten around a runnable quick start, a support matrix and a documentation
  index; release and tag policy lives only in `RELEASING.md`, SECURITY.md names concrete supported
  versions, and ROADMAP.md is organised as Now/Next/Later.
- Overlay-only activation reports that no rebuild step was requested and writes no rebuild
  notification.
- Emergency teardown starts immediately, detaches the overlays first and runs cleanup afterwards;
  it drops only clean page cache after unmount (no global `sync`, no secure-delete of the encrypted
  upper) and no longer claims memory sanitization or a decoy switch. `--no-countdown` is removed.
- Internal commands (`notify-dispatch`, `watch`) are hidden from help.

- Processes blocking an overlay target are now classified by write capability rather than mere
  presence: a writable or directory file descriptor (parsed from `/proc/PID/fdinfo` open flags), a
  shared-writable (`rw-s`) file mapping, or a cwd/root inside the target marks a process as blocking,
  while read-only holders are skipped. Path matching is component-wise and strips the kernel's
  `" (deleted)"` suffix (fixing `/opt2` matching `/opt`), and chrooted or foreign-namespace
  processes are flagged as unverifiable writers.
- The CLI and persisted state are now driven by the platform model: generic "Overlay environment
  manager" about/help text, a NixOS-only `--nixos-flake` (replacing `--flake`), activation progress
  steps whose total and labels follow the active path (7 with a declarative layer, 5 overlay-only /
  FHS) so NixOS steps never render off-path, no rebuild notification when no layer ran, a
  de-duplicated kill-session prompt, and a typed per-platform state section that surfaces the
  hidden-system generation on NixOS only.
- Shell-history anti-forensics no longer writes to the decoy disk after unmount by default, kills
  every interactive shell (including root's) before teardown so in-memory history is never flushed,
  offers an opt-in same-inode (`O_NOFOLLOW`, no `O_CREAT`) history overwrite instead of temp+rename,
  and warns when the operator's shell flushes history incrementally (zsh `INC_APPEND_HISTORY`/
  `SHARE_HISTORY`, bash `history -a` in `PROMPT_COMMAND`).
- NAILS builds and caches the hidden NixOS system toplevel explicitly and switches to it before
  restarting the session, failing closed by default (new `nixos.switch_required` option); the
  config fingerprint now covers the whole hidden config tree.
- `nails init` and pre-flight checks are platform-aware: a non-NixOS (FHS/Debian) host gets no NixOS
  layout or NixOS-only checks, unsupported hosts are refused before any write, and generic
  symlink/reboot failures use typed `UnsupportedFilesystem`/`RebootFailed` errors instead of the
  NixOS error.
- Human console output no longer prints a per-line timestamp (the precise timestamp is kept only in
  the JSON log file), and overlay activation now shows a per-overlay `mounting <path> (i/N)`
  progress line.
- Desktop notifications now dispatch through the shared bounded process runner with a cleared,
  allowlisted environment: the operator's session variables (`XDG_RUNTIME_DIR`,
  `DBUS_SESSION_BUS_ADDRESS`, display) are passed explicitly while the fixed `PATH` is applied last.
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
- The snapshot tmpfs for an overlay-incompatible target (such as a vfat `/boot`) is sized from the
  target's measured content plus headroom instead of a fixed 1 GiB.
- `nails status` reports a kernel-truth posture (decoy/active/degraded/inconsistent/unknown) with
  posture-driven, fail-closed exit codes, replacing the state-file-trusting security posture and the
  `--exit-status` flag; JSON adds the state source, per-overlay ownership and upperdir, and any
  remaining live NAILS mounts.
- Host tools now resolve through a per-platform, root-trust-checked resolver instead of hardcoded
  NixOS paths, and a new host-tools preflight check fails early naming any missing tool and its
  package.
- The `/nix` overlay lifecycle is gated on the host (full restoration only on NixOS; a non-NixOS host
  with `/nix` overlaid only cycles `nix-daemon`), and the auto and explicit overlay mount paths are
  unified into one loop.
- `nails verify` reports an honest headline naming the checks it ran and the areas it did not,
  scans every user home and all overlay upperdirs, matches NAILS processes by binary identity, adds
  platform package-drift scanning, and supports an offline image mode (`--offline --root`).
- The hidden-volume state file, state lock and notification writes are resolved with `openat2`
  under the hidden root, so a planted symlink or `..` cannot redirect them onto the decoy.
- `--allow-persistent-journal` is replaced by `--accept-persistent-decoy`; the hidden NixOS module
  now forces `system.autoUpgrade.enable = false`.
- The swap pre-flight classifies each device: RAM-only zram is allowed, disk or file swap,
  fixed-key encrypted swap and hibernation are refused, the check is repeated after the hidden
  switch and before deactivation, `verify` reports swap as a warning or critical finding, and the
  decoy's `swapDevices`/`resumeDevice` are no longer copied into the hidden configuration.
- The disk-space pre-flight is a single hard floor (500 MB by default); a new `rebuild_space_mb`
  key (4096 MB by default) is checked after mounting and before a hidden NixOS rebuild, a
  post-switch notification warns when the hidden volume is nearly full, and a full volume during
  the build is reported as `hidden-volume-full` with `nails reapply` guidance.
- Platform detection supports Debian 13+ and Ubuntu 24.04+ (no hidden build: the hidden
  configuration is the upper's `/etc`) and refuses older releases, non-merged-usr layouts and
  unvalidated distributions (Fedora, Arch, unknown) with a documented message.
- Coverage is measured over production code only against one threshold in
  `.config/coverage.toml`; the filesystem mock no longer ships in release builds.
- Operator docs now invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`,
  one mount point throughout) and add a CLI/exit-code/JSON reference, a hidden-generation panic
  switch snippet (root-owned oneshot, scoped polkit rule, keybinding, with a NOPASSWD warning), and
  replace the hand-deletion of `state.json` and decoy-side verification guidance with `nails
  recover` and pre-reboot/offline verification.
- Preflight now skips hidden-volume-dependent checks with a clear reason instead of cascading
  failures, names the exact swap devices to disable, and activation reports an overlay rollback
  truthfully (only when one actually ran) after a failed activation.
- The build and test inputs are current as of October 2026. The flake pins nixos-unstable of
  2026-10-11 and a matching rust-overlay; the Rust toolchain stays at 1.93.0. The VM tests run
  systemd 261 and take `soft-reboot.target` and `systemd-soft-reboot.service` from nixpkgs, which
  installs them from NixOS 26.05 on; an older nixpkgs still needs the module `nails check` prints.
  The repository's Python is 3.14: the ruff and mypy targets, the E2E helper package, the dev
  shell and the flake checks.
- CI runs on `ubuntu-26.04` with updated action pins (among them checkout v7, create-pull-request
  v8, action-semantic-pull-request v6 and install-nix-action v31.11.1, whose Nix 2.35.2 is not
  affected by GHSA-vh5x-56v6-4368 and GHSA-gr92-w2r5-qw5p) and with cargo-nextest 0.9.146,
  cargo-llvm-cov 0.9.1, just 1.58.0, cargo-deny 0.20.2 and cyclonedx-cli 0.33.1. `just deny`
  checks the two shipped targets one at a time, because cargo-deny 0.20 takes `--target` only
  once. The self-hosted Hetzner runner is provisioned at runner 2.338.0 on Ubuntu 26.04.
- Dependabot also updates `flake.lock`, the pre-commit hooks and `rust-toolchain.toml`, the
  toolchain together with the `rust-overlay` input in one pull request, after the same 7-day
  cooldown as the Cargo and Actions updates. It replaces the flake.lock and pre-commit refresh jobs
  of `scheduled.yml`.
- `deny.toml` allows the Zlib licence, which the dev-only `foldhash` carries, so the full-graph
  dependency check passes again, and drops the licence clarifications for `ring` and `webpki`,
  which are no longer dependencies.

### Removed

- The per-directory live overlays (`/etc`, `/home`, `/var`, … on the running decoy) and everything
  that served them: process detection, classification, restart and kill, the journald re-homing,
  the display-manager restart, the writer rescans, the graphical-session spare logic, the
  read-only `/usr` guard, the RAM snapshot of VFAT targets, the shell-history cleaner and the
  desktop notifications after activation (the backend watcher's immediate alert stays).
- The `activate` flags `--session`, `--pivot`, `--risky-services` and `--terminate-processes`,
  `deactivate --no-clear-history`, `emergency --lock-backend`, and the `reapply` and
  `notify-dispatch` commands.
- The configuration keys `overlays`, `overlay_mode`, `overlay_exclusions`,
  `overlay_exclusions_remove`, `allow_leaky_exclusions`, `risky_services`,
  `nixos_switch_required`, `clear_history`, `prompt_label`, the `[color_scheme]` table and the
  `[emergency]` table (`lock_backend`, `close_command`), and the ephemeral overlay directories.
- The per-PR `distro-smoke` container lane (`scripts/distro-smoke/`, the `distro-smoke` job in
  `ci.yml` and its `distro-runner` input). It drove the live-overlay lifecycle, and a container
  cannot soft-reboot; the Debian and Ubuntu VM tests in `distro-e2e.yml` cover the session.
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
- The standalone `nix/forensics-eval` evaluation framework and its runner scripts; forensic coverage
  now lives in the E2E suite as host-side decoy disk-image checks.

### Fixed

- `check` and `activate` read the decoy's `/etc/fstab` without updating its access time. The file
  was opened without `O_NOATIME`, so on a `relatime` decoy a check could stamp it with the time of
  the check. Run as root, the read now leaves the access time alone; an unprivileged `check`
  cannot, because the kernel grants `O_NOATIME` only to the file's owner and to root.
- On NixOS, `activate`, `deactivate` and `emergency` work when a systemd unit starts them (a
  panic key, `systemd-run`). Such a unit has a minimal `PATH` and no `NIX_PATH`, so the entry
  failed with "nix-build not found on PATH" and then "file 'nixpkgs/nixos' was not found". The
  Nix tools are now also looked up in the root-owned system directories when the caller's `PATH`
  lacks them, and a legacy build whose caller has no `NIX_PATH` takes `nixpkgs` from root's
  `nixos` channel, as NixOS's default `nix.nixPath` does. Found by hand on NixOS 26.05 in a
  VirtualBox VM.
- After an emergency, the decoy no longer lists units as failed that the session left failed:
  the session's own runtime units (`overlay-runtime-monitor.service`,
  `overlay-runtime-power.service`) and decoy units the kill caught while they stopped
  (`nscd.service` and `generate-shutdown-ramfs.service` on NixOS). PID 1 carried their failed
  state across the soft-reboot, visible in `systemctl --failed` until the decoy's next boot. The
  entry now records the units already failed, and the way back resets every other failed unit,
  so the decoy keeps only its own earlier failures. Found by hand on Debian 13 and NixOS 26.05 in
  VirtualBox VMs.
- On Ubuntu 26.04 the login screen comes up on both sides of the switch again. Its
  `dbus.service` and `dbus.socket` are no longer stopped at shutdown (`DefaultDependencies=no`)
  but do not survive a soft-reboot either, so the bus died in the final kill while PID 1 kept its
  socket open: the new manager waited about 90 s on it, then marked every D-Bus-activated service
  (accounts-daemon among them) as failed to load, and gdm never started. A plain
  `systemctl soft-reboot` on Ubuntu 26.04 does the same. The session now adds runtime drop-ins
  that stop both units at `shutdown.target`, as Debian 13 and Ubuntu 24.04 do, so the switch takes
  about 10 s and the bus starts again in the other root. Found by hand in a VirtualBox VM.
- The whole-root session survives `blk-availability.service`, which Debian and Ubuntu enable
  wherever `dmsetup` is installed. Its stop, `blkdeactivate -u`, unmounted the hidden volume below
  `/run/nextroot` during the soft-reboot into the session, which then came up without the volume
  at its path (binary, logs and upper unreachable), and would unmount a LUKS or LVM decoy root on
  the way back. The transition drop-in now comes with a runtime drop-in that clears the unit's stop
  until the way back, and `verify` reports one that is left. Found on real hardware (Debian 13);
  covered by `session-fstab-policy` (a decoy filesystem on LVM) and the Ubuntu 24.04 distribution
  smoke test. The drop-in sorts after `override.conf` and NixOS's `overrides.conf`, and the entry
  refuses (`stop-guard`) when systemd still reports a stop command after the reload.
- A NixOS decoy with a static address (`networking.interfaces`) keeps its network through the
  switch. Its `network-addresses-<interface>.service` deleted the address when it stopped, and a
  soft-reboot does not replay the device event that starts it again: the other root came up
  without an address in both directions. Its stop is cleared from activation to the way back, by
  a prefix drop-in that covers every interface. Found on real hardware (NixOS 26.05).
- The in-session alerts (a disk mounted read-write, the hidden volume gone) reach the desktop
  where `notify-send` is not installed, as on Debian's GNOME and KDE desktops: the same
  notification goes out through systemd's `busctl`.
- `verify --examiner` no longer reports vendor firmware as encrypted containers: the container
  search skips `/usr/lib/firmware` and `/lib/firmware` (Intel microcode read as random) and says
  so under what was not checked.
- `status` on the plain decoy explains a record that still says Active after a power loss or a
  reset in the session, and points at `nails recover`.
- The read-only guard on a Debian-family host keeps the decoy root read-only in place, with the
  per-mount read-only flag on the root mount, instead of stacking a self-bind on `/`. The stacked
  bind left the root writable for every running process, could not be unmounted (`EBUSY`), piled
  up across activations and left two mount table entries for `/`, a layout systemd's PID 1 can
  abort on. A busy guard on another tree such as `/usr` is now detached lazily at teardown instead
  of staying in place, and a failed start of the in-session watcher logs `systemd-run`'s message
  and no longer waits on PID 1 without a limit.
- Resolved the RUSTSEC advisories in the dependency graph and restored the Nix release build
  ([#54](https://github.com/WitteShadovv/nails/pull/54)).
- The preflight README defers to rustdoc for the registered checks and states the real 500 MB
  free-space floor instead of 1024 MB.
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
- File logging resolves its configuration through the single `--config` entry point and no longer
  silently falls back to binary-derived defaults when the configuration fails to load.
- A stale `Active` state left by an unclean shutdown no longer makes `nails activate` a silent no-op;
  activation reconciles the persisted state against the kernel boot id and mount table, resetting a
  stale file or refusing an inconsistent one instead of mounting nothing.
- Session cleanup no longer stops a user systemd unit system-wide: only units under `system.slice`
  are mapped to the system manager, and non-systemd or ostree hosts are refused at detection.
- Activation no longer requires the `attr` package (`getfattr`/`setfattr`) or `du`/`find` to be
  installed, so preflight passes on hosts without them.
- Hidden-session Nix store writes no longer land on the decoy partition, the systemd closure
  byte-copy is removed, and `nix-daemon`/`systemd-journald` are restarted on every teardown path.

### Security

- Pivot overlay staging and the vfat `/boot` snapshot are staged on the `/run` tmpfs instead of the
  persistent decoy root, so no NAILS scaffolding reaches the decoy disk image.
- The activation residue report and the login notification read and clear paths write, read and
  unlink through the symlink-safe openat2 hidden-root helper, so a symlink planted at one of those
  paths is refused instead of followed off the hidden volume.
- Teardown relinquishes the journal before unmounting /var, then rotates and scrubs the volatile
  runtime journal under `/run/log/journal`; emergency and recovery report the scrub and warn that
  only a reboot is a complete remedy.
- Deactivation makes no write to any decoy filesystem after unmount by default (whole-file
  truncation and secure-delete are no longer forced), removing the deactivation-time artifact the
  post-unmount scrub left on the decoy; the pre-teardown shell kill plus an amnesic decoy base are
  the defenses, and a warn-only preflight flags shells that flush history incrementally.
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
- Overlay upper and work directories are created through an `openat2`-contained resolver beneath
  the hidden root, so a symlink or `..` planted on the hidden volume cannot redirect them onto the
  decoy filesystem; on a kernel without `openat2` activation fails closed.
- The self-hosted E2E runner tarball is verified against a pinned SHA-256 during Hetzner
  provisioning, so a tampered or truncated download aborts before it runs as root.
- Opt-in emergency backend close/lock (`[emergency] lock_backend` or `nails emergency
  --lock-backend`, with an optional `close_command` for non-dm backends) lazy-unmounts the hidden
  root and defers device-mapper removal so the encryption key is wiped from RAM once the last
  reference drops; `nails emergency`, `nails status` and `nails verify` now report "hidden root
  still mounted at <path>" as Critical whenever the hidden root is left mounted, and without the
  opt-in the exact manual close sequence is printed.
- The release binary links the musl of the pinned nixpkgs (1.2.6, with nixpkgs' patches for
  CVE-2026-6042 and CVE-2026-40200) instead of the musl 1.2.5 that ships with the Rust toolchain,
  so the musl the release SBOM names is the one in the binary. The build fails if its linker map
  shows `libc.a` or one of musl's crt files (`crt1.o`, `rcrt1.o`, `Scrt1.o`, `crti.o`, `crtn.o`)
  from anywhere else.
- The release binary no longer refers to the Rust toolchain that built it. Its musl toolchain
  drops `rust-src`, whose store path rustc wrote into std's panic locations, so installing the
  `nails` package through Nix kept the whole toolchain (about 2.6 GB) alive. Panic locations in std
  now read `/rustc/<commit>/library/…`, as in upstream Rust builds, and the build fails if the
  binary refers to the toolchain again.
- The release SBOM records the CVEs that nixpkgs patches musl against (read from its patch names)
  as backported fixes in the musl component's `pedigree`, and gives musl its CPE, so scanners
  check it at all. A new attested release asset, `musl.openvex.json`, marks those CVEs as fixed;
  scanners ignore `pedigree`, so scan with `grype sbom:sbom.cdx.json --vex musl.openvex.json`.

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
