# History

Documents kept for the record. They describe NAILS as it was before the current
design, so their commands, module paths, test names and numbers are often out of
date. Do not follow them as instructions; the current documents are indexed in
[docs/README.md](../README.md).

The main break is [ADR 0008](../adr/0008-whole-root-soft-reboot.md): NAILS used
to overlay a running decoy system directory by directory (the "live-overlay"
mode: per-directory overlays, process detection and restarts, journald
re-homing). It now enters one whole-root overlay with a soft-reboot, and the
live-overlay mode is gone.

| Document | What it records | Current counterpart |
|---|---|---|
| [testing-strategy-live-overlay.md](testing-strategy-live-overlay.md) | The bugs that passed every unit test, the survey of mocks and the T-139 test migration, on the live-overlay code | [testing-strategy.md](../testing-strategy.md) |
| [e2e-performance-live-overlay.md](e2e-performance-live-overlay.md) | Where the live-overlay VM suite spent its time, the flakes found in its failure history and the fixes | [nix/e2e-tests/README.md](../../nix/e2e-tests/README.md) |

Superseded design records stay in [docs/adr/](../adr/README.md) with their status,
because records are never edited away: [ADR 0005](../adr/0005-live-overlay-vs-boot-time-overlay.md)
(superseded by 0008) and [ADR 0009](../adr/0009-dual-root-emergency.md) (research,
not adopted).
