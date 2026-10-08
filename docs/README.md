# NAILS documentation

Start with the [project README](../README.md) for what NAILS is, its
requirements and a quick start. The documents below go deeper, grouped by who
they are for. File names stay flat under `docs/` because the CLI's own messages
and the release bundle refer to them by path.

## Operators

Read these before relying on NAILS, in roughly this order.

| Document | What it covers |
|---|---|
| [Threat model](threat-model.md) | The adversary, the assumptions, what is out of scope, the residual channels and what was evaluated. The only place the threat model is written down. |
| [Decoy requirements](decoy-requirements.md) | What the decoy must and must not keep (amnesic journal, no syslog or swap, lid switch, shell history), how to set it up per platform, and the full residue catalog. |
| [Storage backends](backends.md) | Which hidden-volume backends work, how to open each, and their deniability hazards (discards, timestamps, copy-on-write). |
| [Operator guide](operator-guide.md) | The whole workflow by where each step runs, ending a session (deactivate, emergency, recover), the panic switch, the recovery runbook and the honest limits. |
| [Verify a release](verify-release.md) | Checking a downloaded release (checksum and provenance) without leaving a trace on the decoy. |
| [Distribution channels](distribution.md) | Why the only install path is a verified binary on the hidden volume. |
| [Shell history forensics](bash-history-forensics.md) | Where a shell can record commands, and how NAILS and the decoy setup keep them off the decoy disk. |

## Reference

| Document | What it covers |
|---|---|
| [CLI reference](cli.md) | Every command, flag and exit code. Generated from the code; regenerate with `REGENERATE_CLI_DOCS=1 cargo test -p nails-cli --test cli_reference`. Also shipped as the `nails.1` man page. |
| [Configuration reference](configuration.md) | Every `nails.toml` key with its default, what the session covers (the fstab policy), persona modes, the backend watcher, the sleep policy. Its key table is checked against the code. |
| [JSON schemas](schemas/) | The schemas of the `--json` output of `activate`, `deactivate`, `emergency`, `status` and `verify`. |

## Design

| Document | What it covers |
|---|---|
| [Architecture overview](architecture.md) | The crates and how they depend on each other, the platform seam, and the runtime layers of a session. |
| [Architecture decision records](adr/README.md) | The decisions that shape NAILS. [ADR 0008](adr/0008-whole-root-soft-reboot.md) (the whole-root soft-reboot session) is the one to read first. |
| [Threat model](threat-model.md) | Listed under operators as well; it is also the design's yardstick. |

## Development

| Document | What it covers |
|---|---|
| [Contributing](../CONTRIBUTING.md) | Setup, the test tiers in brief, conventions, sign-off. |
| [Development guide](development-guide.md) | The crate layering, the test tiers in detail, tests and the process environment, the root-only test. |
| [Testing strategy](testing-strategy.md) | Which test tier covers what, and the mock policy. |
| [VM test suite](../nix/e2e-tests/README.md) | The NixOS VM tests: running, writing and sharding them, and the Debian and Ubuntu tests. |
| [CI and release automation](ci.md) | Every workflow and job, the gate, the caches, the release workflow. |
| [Security validation](security-validation.md) | SBOMs, the dependency policy, release verification in automation. |
| [Release artifact reproducibility](release-artifact-reproducibility.md) | What the reproducible-build claim covers and how to rebuild a release. |
| [Releasing](../RELEASING.md) | The maintainer's release checklist. |
| [Documentation assets](assets/README.md) | The logo, the banner and the terminal screenshots, and how to regenerate them. |

## History

[history/](history/README.md) keeps records that describe NAILS before the
whole-root session (the live-overlay mode): the earlier testing-strategy
evidence and the VM suite measurements. They are not current guidance.

## Project

[Changelog](../CHANGELOG.md) · [Roadmap](../ROADMAP.md) ·
[Security policy](../SECURITY.md) · [Support](../SUPPORT.md) ·
[Code of conduct](../CODE_OF_CONDUCT.md)
