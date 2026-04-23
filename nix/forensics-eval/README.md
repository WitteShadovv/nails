# Forensics Evaluation Subsystem

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

- `ci` / `live`: built-in live-supported leaves
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

Built-in real acquisition is intentionally minimal-safe and currently targets only:

- profile: `direct-headless`
- scenario: `direct-baseline`

Other combinations must currently provide an explicit `--stage-export-cmd`. In particular, `graphical` and `vfat-boot` are not currently treated as built-in live-supported.
