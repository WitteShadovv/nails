# Roadmap

NAILS is in **alpha**. This roadmap summarizes the work most likely to matter to evaluators,
operators, and contributors in the next stages of the project.

> [!NOTE]
> Roadmap items describe current priorities, not release commitments. Ordering may change as the
> project and its threat model validation evolve.

## Near-term priorities

### 1. Safer activation, deactivation, and recovery

- Reduce partial-failure cases during activation and teardown.
- Tighten handling around mount loss, overlay conflicts, and state transitions.
- Improve recovery behavior when an operation is interrupted or the operator must fall back to
  `nails emergency`.

### 2. Stronger post-deactivation verification

- Expand `nails verify` coverage for common host-side artifacts.
- Make verification output clearer about what was checked, what was not checked, and what remains
  operator responsibility.
- Keep verification behavior aligned with the documented threat model rather than implying broader guarantees.

### 3. Clearer hidden-volume setup and configuration

- Make initial setup less error-prone for the supported NixOS workflow.
- Improve config validation and error reporting before high-impact operations run.
- Clarify the assumptions NAILS makes about the mounted hidden backend and supported filesystem behavior.

### 4. Higher confidence in lifecycle testing and releases

- Add more automated coverage around lifecycle transitions and failure handling.
- Keep release artifacts reproducible and easier to audit.
- Improve confidence that documented operator paths match what CI and release validation actually test.

### 5. Tighter public documentation

- Keep top-level docs aligned with the current public surface and supported workflow.
- Remove stale guidance and avoid linking to material that is not part of the public project surface.
- Make it easier for an external reader to understand what NAILS does, what it assumes, and where its limits are.

## Longer-term work

- Better coverage for advanced and edge-case operating scenarios.
- Continued internal refactoring to keep orchestration logic testable and maintainable.
- More lifecycle hardening around optional or higher-risk paths such as `/boot` overlays.
- Continued performance and regression monitoring where it improves operator safety or reliability.

## How to read this roadmap

In general, NAILS prioritizes:

1. Safety, security, and correctness
2. Reliability of core system workflows
3. Clear operator experience and recovery paths
4. Maintainability and testability
5. Documentation that matches shipped behavior

## Feedback

If there is a capability, hardening effort, or workflow improvement you would like to see
prioritized, open an issue or start a public discussion with the operating scenario and risk you are
trying to address.
