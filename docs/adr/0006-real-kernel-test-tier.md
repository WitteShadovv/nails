# 6. A rootless real-kernel test tier, and limits on mocks

- Status: accepted
- Date: 2026-10-06
- Amends: [ADR 0002](0002-trait-filesystem-testability.md)

## Context

ADR 0002 moved filesystem and mount access behind a trait so orchestration can
be tested without root. The mocks then became the only test of several kernel
behaviours, and five bugs passed every unit test and failed only in the NixOS
VM suite: overlay `st_dev`, a no-op `reapply`, an emergency broken-pipe panic,
a 28 s systemctl call, and overlay-only activation against real mountinfo. A
prototype of the tier below found one more, the decoding of overlay layer
paths from mountinfo, within minutes. The evidence is in
[testing-strategy.md](../testing-strategy.md).

Since Linux 5.11 an unprivileged process can create a user namespace and mount
tmpfs, bind mounts and overlayfs inside it.

## Decision

- Add a real-kernel test tier that runs in an ordinary `cargo test`.
  `nails_core::test_support::Rerun` re-executes a test in a fresh user + mount
  namespace and skips when the host has none. CI requires the tests to run, not
  skip.
- Overlays pass `redirect_dir=nofollow` instead of `off`. It behaves the same on
  every kernel build, and an unprivileged mount accepts it, so the tier mounts
  overlays with the production options.
- Parsers of kernel and tool output are tested against captured real output
  (`nails-core/tests/fixtures/kernel/`), not only hand-written strings.
- Mocks remain the tool for orchestration logic, error injection and host-global
  effects. They are not enough on their own for kernel semantics, output
  formats, test hooks that bypass host code, or systemd interactions. Tests
  assert effects, not calls. The full policy is in the strategy document.

## Consequences

- Mount ids, mountinfo, fdinfo, atime, overlay shadowing and pipe behaviour are
  tested on every PR, in milliseconds, without root.
- `trusted.*` xattr behaviour (directory whiteouts, opaque directories) cannot
  be tested unprivileged. It stays in the root-only `privileged-mounts` job and
  the VM suite.
- GitHub's `ubuntu-24.04` needs `kernel.apparmor_restrict_unprivileged_userns=0`
  before the tests can run there.
- The mock-only mount contract and the remaining hook-bypassed host code have a
  migration list to work through. Until it is done, the VM suite stays the only
  check for those paths.
