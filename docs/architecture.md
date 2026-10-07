# Architecture overview

This is a map of how NAILS is put together: the crates, the seam that keeps
host-specific behaviour in one place, and the runtime layers an activation runs
through. It is an orientation document, not a specification — the code and the
[architecture decision records](adr/README.md) are authoritative where they
disagree with this page.

## Three crates

NAILS is a Cargo workspace with a deliberately thin binary, a library that
holds everything else, and a small crate for the emergency hot path and the
soft-reboot transition.

- **`nails-cli`** parses arguments, renders human and JSON output, prompts, and
  turns results into the documented exit codes. It contains no activation logic:
  it builds a request, hands it to the library, and formats what comes back.
- **`nails-core`** holds all the business logic — host detection, configuration,
  the state machine, pre-flight checks, the whole-root session (entry, fstab
  policy, the hidden NixOS build, the way back, the probes `status` uses) and
  verification. It is testable without root because every side effect goes
  through a trait.
- **`nails-teardown`** holds everything the panic path and the soft-reboot
  transition need, with no configuration and no logging
  (`nails_teardown::whole_root`): the session plan on `/run`, the mount
  primitives and the pre-switch init check, the transition step, the `/run`
  snapshot and scrub, the kmsg cursor, the way back, the runtime units and
  masks, the kill of all userspace and the emergency hot path. It also holds the
  mountinfo parser and the cgroup, pidfd and shell kills. It depends on
  `rustix`, `libc` and `serde` only, so `main` can run the emergency and the
  transition before clap, the configuration or tracing exist.

Keeping the logic in the library (rather than in the binary) is recorded in
[ADR 0001](adr/0001-core-library-boundary.md); the teardown crate and its
boundary in [ADR 0007](adr/0007-emergency-architecture.md) and
[ADR 0008](adr/0008-whole-root-soft-reboot.md).

## The platform seam

Every host-specific decision is made in one module, `platform`, so the rest of
the code never branches on "is this NixOS?" directly.

1. **Detection.** `platform::detect` reads `/etc/os-release`,
   `/run/current-system`, `/run/ostree-booted` and PID 1 once, producing a
   `HostProfile`.
2. **Selection.** A single function maps that profile to a backend implementing
   the `Platform` trait:
   - `NixOsPlatform` — the first-class backend, with a declarative config layer
     that builds the hidden system into the next root's store.
   - `FhsPlatform` — the backend for systemd FHS hosts, validated first on
     Debian/Ubuntu, with other FHS families treated as provisional. The hidden
     configuration is whatever the upper's `/etc` holds.
   - `UnsupportedPlatform` — refuses ostree / image-based hosts and non-systemd
     init with a typed error. For those hosts the refusal *is* the behaviour.
3. **Policy.** The trait collects the host-specific decisions: where host tools
   live (`host_command_dirs`), which declarative build target activation and
   `check` use (`discover_build_target`), and which artifact scanners `verify`
   runs (`artifact_scanners`).

The declarative part of a host is expressed through a separate `ConfigLayer`.
NixOS supplies one (`NixOsConfigLayer`), whose hidden system is built into the
next root's store; FHS hosts and any `--overlay-only` run have no layer, so the
build step is skipped and the session enters with the decoy's own system plus
the hidden `/etc`.

Adding a new distribution means adding a `Platform` backend (and, if it is
declarative, a `ConfigLayer`); nothing else in the codebase needs to learn about
it.

## Runtime layers

An activation moves through these layers, all inside `nails-core` unless noted:

- **Configuration** (`config`) loads strict TOML (`nails.toml`), layers CLI
  overrides on top, and derives the hidden-volume root from the binary location
  when it is not set. See the [configuration reference](configuration.md).
- **State machine** (`state`) models the recorded state as a type-safe enum
  (`Inactive`, `Active`, `Degraded`) with only the legal transitions
  expressible, persisted to `state.json`. Because a soft-reboot keeps the boot
  ID, the live session (hidden root, entry under way, interrupted entry, plain
  decoy) is read from the mount table and the session plan
  (`session::probe`), not from the state file. The rationale for the typed
  states is in [ADR 0003](adr/0003-type-safe-state-machine.md).
- **Pre-flight** (`preflight`, plus `session::checks`) runs a registry of
  trait-based checks — systemd version and the soft-reboot units, the decoy
  root, the fstab policy, backend readiness, overlay-filesystem capability,
  space, the amnesic-decoy guard, and more — before anything is mounted, and
  fails closed.
- **Entry** (`session::entry`, `session::policy`, `session::nixos`) snapshots
  `/run`, writes the session plan and the RAM copy of the binary to
  `/run/overlay-runtime`, mounts the root overlay at `/run/nextroot`, builds
  and activates the hidden NixOS system there, applies the fstab policy, checks
  the init and installs the transition drop-in. Any failure undoes all of it, so
  a populated `/run/nextroot` is never left behind. Path containment and the
  mount APIs are described in [ADR 0004](adr/0004-detached-mount-apis.md); why
  the overlay covers the whole root and is entered with a soft-reboot, rather
  than taken live per directory or at boot, is recorded in
  [ADR 0008](adr/0008-whole-root-soft-reboot.md), which supersedes
  [ADR 0005](adr/0005-live-overlay-vs-boot-time-overlay.md).
- **Transition** (`nails-teardown`, `whole_root::transition`) is the
  `ExecStart=` of `systemd-soft-reboot.service`, run by systemd from the RAM
  copy as the last userspace step before each switch. It acts only on an armed
  plan: entering, it repoints `/run/current-system` (NixOS) and installs the
  session's runtime units and masks; leaving, it repoints back, scrubs `/run`,
  restores `utab` and writes the kmsg cursor. An unarmed populated
  `/run/nextroot` is detached instead.
- **Way back and emergency** (`session::leave`, `nails-teardown`'s
  `whole_root::ret` and `whole_root::emergency`) mount the decoy root at
  `/run/nextroot`, mark the backend for deferred removal and enqueue the
  soft-reboot; the emergency kills every hidden cgroup first. Emergency runs
  the hot path from `main` before clap (the design history is in
  [ADR 0007](adr/0007-emergency-architecture.md)).
- **Verification** (`verify`) scans for known residue, live or offline against
  a decoy image.

## Testing without root

Filesystem and process effects are reached through the `Filesystem` and process
traits, with mock implementations used in tests. This lets almost the entire
library be unit-tested without root or a real mount, and is recorded in
[ADR 0002](adr/0002-trait-filesystem-testability.md). End-to-end behaviour that
genuinely needs a booted system — real soft-reboots, the hidden NixOS system,
the fstab policy, forensic residue — is covered by the NixOS VM tests under
`nix/e2e-tests` and the Debian/Ubuntu tier under `nix/distro-tests`.
