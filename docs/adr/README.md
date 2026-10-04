# Architecture Decision Records

This directory records the architecture decisions that shape NAILS: the choices
that are expensive to reverse and that the rest of the code assumes without
restating. Each record is a short, dated note describing the context, the
decision, and the consequences we accepted.

Records are immutable once accepted. When a decision changes, add a new record
that supersedes the old one rather than editing history.

| ADR | Title |
| --- | --- |
| [0001](0001-core-library-boundary.md) | Core library holds all business logic |
| [0002](0002-trait-filesystem-testability.md) | Filesystem access behind a trait for root-free testing |
| [0003](0003-type-safe-state-machine.md) | System state as a type-safe enum |
| [0004](0004-detached-mount-apis.md) | Path containment with openat2, and how we mount |
| [0005](0005-live-overlay-vs-boot-time-overlay.md) | Live overlay vs boot-time overlay mechanisms |
