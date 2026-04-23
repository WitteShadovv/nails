# Forensics Analyzer Framework

Stable CLI entrypoint:

```bash
python3 nix/forensics-eval/analyzers/run_analyzers.py \
  --run-dir /path/to/run \
  --stage post-standard \
  --stage post-emergency \
  --baseline-dir /path/to/run/baseline \
  --manifest nix/forensics-eval/analyzers/registry.json \
  --allowlist nix/forensics-eval/fixtures/allowlists/default.json \
  --output /path/to/run/compare
```

The analyzer runner writes:

- `analyzers/<stage>/<analyzer>.json`
- `summary.json`
- `report.md`
- `findings-diff.json`
- `findings-diff.md`

The framework is intentionally read-only with respect to stage evidence. Scratch files are kept under a separate scratch directory.

The `active` stage is an enforced positive-control contract in the supported lane: the
runner exits non-zero if required analyzers skip/error there or if all expected active
findings are absent or fully masked by allowlists.
