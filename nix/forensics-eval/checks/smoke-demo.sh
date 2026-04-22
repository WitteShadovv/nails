#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${1:-$ROOT/tmp/forensics-check-smoke}"

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
summary = json.loads(summaries[-1].read_text(encoding='utf-8'))
assert summary['acquisitionMode'] == 'fixture', summary
assert (summaries[-1].parent / 'report.md').is_file()
print(str(summaries[-1].parent))
PY
