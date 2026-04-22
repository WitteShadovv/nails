#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${1:-$ROOT/tmp/forensics-check-live}"

python3 "$ROOT/nix/forensics-eval/runners/run_forensics_eval.py" \
  --project-root "$ROOT" \
  --out "$OUT"

python3 - <<'PY' "$OUT"
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
summaries = sorted(root.glob('*/summary.json'))
if not summaries:
    raise SystemExit('no summary.json produced')
summary_path = summaries[-1]
summary = json.loads(summary_path.read_text(encoding='utf-8'))
assert summary['acquisitionMode'] == 'live', summary
stages = {stage['name']: stage for stage in summary['stages']}
for name in ('baseline', 'active', 'post-standard', 'post-emergency'):
    stage = stages[name]
    assert stage['status'] == 'exported', stage
    assert stage['hashRecord']['entryCount'] > 0, stage
assert (summary_path.parent / 'report.md').is_file()
assert (summary_path.parent / 'compare' / 'report.md').is_file()
print(str(summary_path.parent))
PY
