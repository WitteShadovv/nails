# 2. Filesystem access behind a trait for root-free testing

- Status: accepted
- Date: 2026-10-02

## Context

NAILS mounts overlays, writes state, cleans history, and rebinds the Nix store.
Doing any of that for real needs root and mutates the host, which is unsafe and
slow to drive from a unit test. Without an abstraction, the orchestration code
would be reachable only through full end-to-end runs, leaving the bulk of its
branches (error paths, rollback, partial failures) untested.

## Decision

All filesystem and mount interaction goes through a `Filesystem` trait.
`NailsManager` and the pre-flight checks are generic over `F: Filesystem`.
Production uses `RealFilesystem` (actual syscalls); tests use `MockFilesystem`,
an in-memory implementation that records operations and injects failures.

## Consequences

- The large majority of the orchestration test suite runs as an ordinary
  unprivileged `cargo test`, with no root and no real mounts.
- Error and rollback paths can be provoked deterministically by making the mock
  fail a specific operation.
- Every new filesystem capability must be added to the trait and mirrored in the
  mock, which is deliberate friction that keeps the seam honest.
- End-to-end VM tests remain necessary for behaviour that only the real kernel
  can show (actual overlay semantics, namespace handling); the trait does not
  replace them.
