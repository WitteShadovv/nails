# 3. System state as a type-safe enum

- Status: accepted
- Date: 2026-10-02

## Context

A NAILS host moves through a small set of states: inactive (the decoy), the
transient activating and deactivating phases, and active. Leaving the system in
an inconsistent transient state can leak forensic evidence, so the state model
has to make illegal combinations hard to reach and easy to reason about. A free
set of boolean flags would allow contradictory combinations and scatter the
transition rules.

## Decision

System state is a single `SystemState` enum. Each variant carries the metadata
that is meaningful for that state and nothing else, so invalid states cannot be
represented. Transitions are encoded as methods that move between variants, and
the persisted state file serialises the enum rather than loose flags.

## Consequences

- Invalid states are unrepresentable, and the compiler rejects transitions the
  model does not allow.
- Rollback has a single well-defined target: the previous variant captured
  before an operation began.
- Adding a state is a deliberate change to the enum and its transitions, which
  surfaces every call site that must handle it.
- The serialised form is tied to the enum shape; a change to the variants is a
  change to the on-disk state format and must be treated as such.
