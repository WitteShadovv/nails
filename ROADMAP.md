# Roadmap

NAILS is in **alpha**. This roadmap is a Now / Next / Later view of where the project is going. It
is about direction, not dates.

> [!NOTE]
> Roadmap items describe current priorities, not release commitments. Ordering may change as the
> project and its threat-model validation evolve. Issue links point at open discussions; open a new
> issue if the scenario you care about is not tracked.

## Now

Work in progress for the current release line.

- **Debian/Ubuntu support.** Debian 13 and Ubuntu 24.04+ are the first non-NixOS platform. The
  platform layer detects the host, refuses unsupported layouts (ostree/rpm-ostree,
  transactional-update and non-systemd init), and runs the same whole-root session, with the hidden
  configuration in the upper's `/etc` instead of a NixOS build. Tracked in [#5](https://github.com/WitteShadovv/nails/issues/5) and
  [#6](https://github.com/WitteShadovv/nails/issues/6).
- **Safer activation, deactivation and recovery.** Reduce partial-failure cases during activation
  and the way back, tighten handling of a lost hidden volume, and improve recovery when an
  operation is interrupted or the operator falls back to `nails emergency` / `nails recover`.
- **Stronger post-deactivation verification.** Widen `nails verify` coverage for common host-side
  artifacts and keep its output explicit about what was and was not checked, without implying broader
  guarantees than the threat model supports.
- **Tighter public documentation.** Keep the top-level docs aligned with the shipped surface and
  supported workflow, remove stale guidance, and make the limits of the tool clear to an external
  reader.

## Next

Planned once the current line is stable.

- **Fedora backend.** A validated backend for the Fedora family, covering its usr-merge layout
  and dnf/rpm package-drift scanning.
- **Arch backend.** A validated backend for Arch and close derivatives, with pacman-based drift
  scanning. The platform layer is built so a new distribution is a backend plus a detection-table
  entry, not a rewrite.
- **aarch64 support.** Build, test and release the binary for 64-bit ARM alongside x86-64, and
  exercise it in the E2E suite.

## Later / Research

Longer-horizon work and open questions, not yet scheduled.

- **Memory forensics.** Study and harden against RAM-resident traces of a hidden session.
- **Cross-backend evaluation.** Extend the disk-image leak checks and the VM/container smoke tiers so
  every supported distribution is exercised end-to-end, with adding a distribution being one
  detection-table entry.
- **OpenRC / ostree support.** Explore whether non-systemd init systems and image-based
  (ostree/rpm-ostree) hosts can be supported safely rather than refused.
- **Usability study.** Evaluate the operator workflow with real users to find where setup, recovery
  and verification are error-prone.

## How to read this roadmap

In general, NAILS prioritizes, in order:

1. Safety, security and correctness
2. Reliability of core system workflows
3. Clear operator experience and recovery paths
4. Maintainability and testability
5. Documentation that matches shipped behavior

## Feedback

If there is a capability, hardening effort or workflow improvement you would like prioritized, open
an issue with the operating scenario and the risk you are trying to address. Issues are public, so
describe the scenario in general terms rather than your actual setup.
