# 1. Core library holds all business logic

- Status: accepted
- Date: 2026-10-02

## Context

NAILS ships as a Cargo workspace with two crates: `nails-core` (library) and
`nails-cli` (binary). Activation, deactivation, overlay management, cleanup,
state transitions, pre-flight checks, and NixOS integration are all
security-sensitive and must be exercised directly by tests. A binary that mixes
argument parsing, terminal output, and orchestration is hard to test and tempts
duplicated logic across subcommands.

## Decision

All orchestration and domain logic lives in `nails-core`. `nails-cli` is a thin
shell: it parses arguments, resolves configuration, renders output, and calls
into the core. The CLI contains no isolation, cleanup, or state-machine logic of
its own.

## Consequences

- The whole threat-relevant surface is testable without going through the binary
  or a terminal.
- Behaviour is defined once in the library, so subcommands cannot drift apart.
- The CLI stays small enough to audit, and an alternative front end (for example
  a future daemon) could reuse the same core.
- Contributors must resist adding logic to the CLI for convenience; such logic
  belongs in the core with its own tests.
