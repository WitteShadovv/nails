# Forensics Evaluation Subsystem

This subsystem is the campaign-style forensic evaluation layer. It is responsible for
staged evidence export, baseline-aware analysis, report generation, and comparing
forensic outcomes across a scenario timeline.

It is not the owner of normal product-behavior validation. Keep these boundaries explicit:

- Normal E2E owns product behavior, lifecycle flows, cleanup, verify/preflight paths,
  state transitions, session handling, and similar end-user/system behavior.
- Legacy forensic E2E owns coarse VM-internal forensic spot checks.
- `forensics-eval` owns staged evidence export, baseline-aware analysis, reports, and
  campaign-style forensic evaluation.

Do not duplicate normal E2E coverage in `forensics-eval`. If a test is primarily checking
behavioral correctness rather than forensic outputs and evidence deltas, it belongs in the
normal E2E suite instead.

This subsystem now supports two execution modes:

- **Live mode (default)**: real acquisition/export for `direct-headless` + `direct-baseline`.
- **Fixture mode (demo/smoke only)**: replay from an existing fixture bundle via `--fixture-run-dir`.

## Default behavior

Running the wrapper without fixture overrides uses the built-in real exporter:

```bash
scripts/run-forensics-eval.sh
```

That path spins up fresh NixOS test VMs per stage and exports real evidence for:

- `baseline`
- `active`
- `post-standard`
- `post-emergency`

Live mode now fails if any of those required stages are missing, placeholder, or empty.

## Fixture/demo mode

Fixture mode is still supported for smoke/demo validation, but it is no longer the default success path:

```bash
scripts/run-forensics-eval.sh \
  --fixture-run-dir nix/forensics-eval/fixtures/samples/sample-run
```

## Validation and contracts

- Profile and scenario ids are validated against the Nix subsystem definitions.
- Built-in analyzer outputs are schema-validated against the bundled schemas under `fixtures/schemas/`.
- The live exporter writes host/export metadata for each stage under `metadata/`.
- The analyzer lane now enforces the `active` positive-control contract and fails if the
  supported required analyzers skip/error there or if active findings are fully absent/
  allowlist-masked.

## Metadata-driven local sharding

Local orchestration now has a metadata output at `forensics-eval-metadata.<system>`.
It exposes ordered `leafTests`, `availableTargets`, and `groups` for scenario/profile
execution, plus per-leaf scenario/profile mappings.

Use `scripts/run-forensics-eval-tests.sh` to resolve those targets locally:

```bash
scripts/run-forensics-eval-tests.sh --dry-run ci
scripts/run-forensics-eval-tests.sh --shard-index 1 --shard-count 2 all -- \
  --fixture-run-dir nix/forensics-eval/fixtures/samples/sample-run
```

Useful targets currently include:

- `ci`: the ordered fast-test subset used by CI. It is currently the same single built-in
  live-supported leaf, but it is documented as the CI subset rather than as a promise about
  broader live support.
- `live`: built-in live-supported leaves only.
- `all`: every supported scenario/profile leaf from Nix metadata
- `scenario:<id>`: all leaves for one scenario
- `profile:<id>`: all leaves for one profile

Extra arguments after `--` are passed through to `scripts/run-forensics-eval.sh` for
each selected leaf.

The ordinary GitHub Actions regression lane is intentionally non-privileged and fixture-backed:

```bash
python3 -m unittest discover -s nix/forensics-eval/tests -p 'test_*.py'
./nix/forensics-eval/checks/smoke-demo.sh "$PWD/tmp/forensics-eval-smoke"
```

## Current built-in live support

Built-in real acquisition is intentionally narrow and currently supports only the single
built-in live path below:

- profile: `direct-headless`
- scenario: `direct-baseline`

Other combinations must currently provide an explicit `--stage-export-cmd`. In particular, `graphical` and `vfat-boot` are not currently treated as built-in live-supported.
