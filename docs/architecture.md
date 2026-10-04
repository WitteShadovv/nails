# Architecture overview

This is a map of how NAILS is put together: the crates, the seam that keeps
host-specific behaviour in one place, and the runtime layers an activation runs
through. It is an orientation document, not a specification — the code and the
[architecture decision records](adr/README.md) are authoritative where they
disagree with this page.

## Two crates

NAILS is a Cargo workspace with a deliberately thin binary and a library that
holds everything else.

- **`nails-cli`** parses arguments, renders human and JSON output, prompts, and
  turns results into the documented exit codes. It contains no activation logic:
  it builds a request, hands it to the library, and formats what comes back.
- **`nails-core`** holds all the business logic — host detection, configuration,
  the state machine, pre-flight checks, overlay mounting, the NixOS build and
  switch, deactivation and verification. It is testable without root because
  every side effect goes through a trait.

Keeping the logic in the library (rather than in the binary) is recorded in
[ADR 0001](adr/0001-core-library-boundary.md).

## The platform seam

Every host-specific decision is made in one module, `platform`, so the rest of
the code never branches on "is this NixOS?" directly.

1. **Detection.** `platform::detect` reads `/etc/os-release`,
   `/run/current-system`, `/run/ostree-booted` and PID 1 once, producing a
   `HostProfile`.
2. **Selection.** A single function maps that profile to a backend implementing
   the `Platform` trait:
   - `NixOsPlatform` — the first-class backend: a declarative config layer plus
     the full `/nix` + `/var` + `/etc` overlay handling.
   - `FhsPlatform` — the overlay-only backend for systemd FHS hosts, validated
     first on Debian/Ubuntu, with other FHS families treated as provisional.
   - `UnsupportedPlatform` — refuses ostree / image-based hosts and non-systemd
     init with a typed error. For those hosts the refusal *is* the behaviour.
3. **Policy.** The trait collects the decisions that used to be scattered across
   the CLI, the manager and the mount loop: which trees to overlay, never
   overlay, or keep read-only (`overlay_policy`); where host tools live
   (`host_command_dirs`); and how to restore the decoy on deactivation
   (`restore_base_system`).

The declarative part of a host is expressed through a separate `ConfigLayer`.
NixOS supplies one (`NixOsConfigLayer`), which builds the hidden system and
switches to it; FHS hosts and any `--overlay-only` run have no layer, so the
build-and-switch step is skipped entirely and reports that no rebuild was
requested. This is why an overlay-only activation runs no rebuild and writes no
"rebuild complete" notification.

Adding a new distribution means adding a `Platform` backend (and, if it is
declarative, a `ConfigLayer`); nothing else in the codebase needs to learn about
it.

## Runtime layers

An activation moves through these layers, all inside `nails-core`:

- **Configuration** (`config`) loads strict TOML (`nails.toml`), layers CLI
  overrides on top, and derives the hidden-volume root from the binary location
  when it is not set. See the [configuration reference](configuration.md).
- **State machine** (`state`) models the system as a type-safe enum
  (`Inactive`, `Activating`, `Active`, `Deactivating`, `Degraded`) with only the
  legal transitions expressible, persisted to `state.json` with the boot id it
  was written under. The rationale is in
  [ADR 0003](adr/0003-type-safe-state-machine.md).
- **Pre-flight** (`preflight`) runs a registry of trait-based checks — backend
  readiness, overlay-filesystem capability, space, the amnesic-decoy guard, and
  more — before anything is mounted, and fails closed.
- **Overlay mounting** (`overlay`) mounts the selected trees with the hidden
  backend as the upper layer. Path containment and the mount APIs are described
  in [ADR 0004](adr/0004-detached-mount-apis.md). Why NAILS takes this overlay
  live from the running system, rather than at boot like `grub-live`,
  `overlayroot` or `systemd.volatile=overlay`, is recorded in
  [ADR 0005](adr/0005-live-overlay-vs-boot-time-overlay.md).
- **Config switch** (`nixos`, via the `ConfigLayer`) builds and switches to the
  hidden NixOS configuration on NixOS; a no-op elsewhere.
- **Deactivation and verification** (`deactivation`, `verify`) unmount in
  reverse order, restore the decoy, and scan for known residue.

## Testing without root

Filesystem and process effects are reached through the `Filesystem` and process
traits, with mock implementations used in tests. This lets almost the entire
library be unit-tested without root or a real mount, and is recorded in
[ADR 0002](adr/0002-trait-filesystem-testability.md). End-to-end behaviour that
genuinely needs a booted system — real overlays, the NixOS switch, forensic
residue — is covered by the NixOS VM tests under `nix/e2e-tests`.
