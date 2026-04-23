#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/forensics-check-smoke.XXXXXX")}"

python3 "$ROOT/nix/forensics-eval/runners/run_forensics_eval.py" \
  --project-root "$ROOT" \
  --fixture-run-dir "$ROOT/nix/forensics-eval/fixtures/samples/sample-run" \
  --out "$OUT"

python3 - <<'PY' "$OUT"
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
summaries = sorted(root.glob('*/summary.json'))
if not summaries:
    raise SystemExit('no summary.json produced')
if len(summaries) != 1:
    raise SystemExit(f'expected exactly one summary.json, found {len(summaries)} under {root}')
run_dir = summaries[0].parent
summary = json.loads(summaries[0].read_text(encoding='utf-8'))

assert summary['acquisitionMode'] == 'fixture', summary
assert summary['result'] == 'findings', summary
assert summary['findingCount'] > 0, summary
assert (run_dir / 'report.md').is_file()

comparisons = {item['id']: item for item in summary['comparisons']}
standard = comparisons['baseline-vs-post-standard']
emergency = comparisons['baseline-vs-post-emergency']

assert standard['status'] == 'complete', standard
assert emergency['status'] == 'complete', emergency

standard_counts = standard['comparison']['counts']
assert (
    standard_counts['added']
    + standard_counts['removed']
    + standard_counts['changed']
    > 0
), standard
assert standard['canaryScan']['findingCount'] > 0, standard

emergency_counts = emergency['comparison']['counts']
assert emergency['canaryScan']['findingCount'] == 0, emergency
assert (
    emergency_counts['added']
    + emergency_counts['removed']
    + emergency_counts['changed']
    > 0
), emergency

print(str(run_dir))
PY
