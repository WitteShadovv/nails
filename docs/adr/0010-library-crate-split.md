# 10. Library crates split along the session's boundaries

- Status: accepted, implemented (T-138)
- Date: 2026-10-08
- Supersedes: the two-crate layout of [ADR 0001](0001-core-library-boundary.md)
  (its decision stands: the CLI holds no business logic)
- Related: [ADR 0007](0007-emergency-architecture.md) (the `nails-teardown`
  boundary), [ADR 0008](0008-whole-root-soft-reboot.md) (the whole-root session)

## Context

`nails-core` held host detection, the platform backends, configuration and
state, the whole-root session, verification, the residue catalog, rehearse and
the orchestration in one crate. Nothing stopped one area from reaching into
another: the process runner called into the platform for its trust check, the
platform held verify's drift scanners, and the artifact registry named a
runtime path through the session's reader. ADR 0001 only separated the CLI.

The whole-root soft-reboot (ADR 0008) changed the seams. The live-overlay
engine (mount strategies, pivot, process restarts) is gone, the session's
mechanics that must run without configuration are already in `nails-teardown`,
and what remains falls into five areas with a clear direction between them.

## Decision

The library is six crates, listed top-down:

```text
nails-cli
nails-core        manager (enter, leave, recover, reset-upper), the pre-flight
                  registry and its checks, status, TestWorld
nails-forensics   verify (examiner's view, drift scanners, residue report), the
                  forensic readers, the residue catalog and its check, rehearse
nails-session     entry, fstab policy, hidden NixOS build, way back, session
                  checks and probes, persona, runtime copy, watcher, sleep guard
nails-platform    detection, the Platform backends, the NixOS configuration
                  layer and its checks, the NixOS builder, the backend chain
nails-base        error, the Filesystem and process seams, configuration,
                  state, artifact registry, attach gate, logging, output,
                  notifications, the pre-flight framework and the swap check
nails-teardown    the session plan, mountinfo parser, transition, emergency
                  hot path
```

A crate depends only on crates listed below it. Precisely:

| Crate | Depends on |
| --- | --- |
| `nails-teardown` | none (`rustix`, `libc`, `serde` only; ADR 0007) |
| `nails-base` | `nails-teardown` (the mountinfo and `/proc` readers) |
| `nails-platform` | `nails-base` |
| `nails-session` | `nails-base`, `nails-platform`, `nails-teardown` |
| `nails-forensics` | `nails-base`, `nails-platform`, `nails-session`, `nails-teardown` |
| `nails-core` | all of the above |
| `nails-cli` | `nails-core`, `nails-teardown` |

- **Configuration and state sit in `nails-base`**, not in `nails-core`: the
  session, the pre-flight checks and verification all read them, so they have
  to be below those crates for the graph to have no cycle.
- **`nails-core` is the facade.** It re-exports every moved module under its
  old path (`nails_core::config`, `nails_core::verify`, …) and the old root
  re-exports, so the CLI and the integration tests did not change, and keeps
  only the orchestration that needs every area at once.
- **Pre-flight checks live with their area.** The framework (trait, result,
  registry) is in `nails-base`; the NixOS configuration checks are in
  `nails-platform`, the session checks in `nails-session`, the residue-catalog
  check in `nails-forensics`, and `nails-core` assembles the registry.
- **Verification only reads.** `nails-forensics` may name `nails-teardown`'s
  readers (the mountinfo parser, the plan format, the next-root and drop-in
  paths) and `nails-session`'s probes and unit names, never the code that
  enters, leaves or tears down a session.
- **Unit tests never reach the host in any library crate.** The base switches
  that used `cfg(test)` (the host-interaction skip, the state attach gate,
  immediate alerts) now ask `runtime_safety::in_unit_tests()`. Each crate's
  unit-test binary sets it before `main` with `nails_base::unit_test_mode!()`;
  a shipped build answers `false` at compile time.

Tests hold the boundaries: `nails-core/tests/crate_graph.rs` pins the table
above, `nails-forensics/tests/boundary.rs` the read-only rule, and
`nails-teardown/tests/boundary.rs` the hot path's dependencies.

### Alternatives

- **Keep configuration and state in `nails-core`, with the other crates above
  it.** The manager needs the platform and the session, and the platform,
  session and verification need the configuration, so this has a cycle.
- **A `nails-overlay` crate for the mount engine** (the T-138 plan before
  ADR 0008). The live-overlay engine no longer exists; the whole-root mount
  primitives belong to the hot path in `nails-teardown`.
- **Rename `nails-core` to the base crate and add an orchestration crate on
  top.** Every `nails_core::` path in the CLI and the tests would change, for
  no gain over a facade.

## Consequences

- An area cannot reach into another against the graph; Cargo refuses a cycle
  and the tests refuse a new edge.
- Each crate builds with only the dependencies its area uses (`zbus` in
  `nails-session`, `memchr` in `nails-forensics`, `tracing-subscriber` and
  `colored` in `nails-base`).
- A moved `pub(crate)` item that another crate uses became `pub`; the
  `runtime_safety` module and the test seams are `#[doc(hidden)]`.
- Every new crate directory must be listed where the crate directories are:
  the workspace members, the flake's `sourceFiles` and the `nails-source`
  check, the `rust` and E2E path filters, and the orphan-module scan.
