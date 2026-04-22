#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from framework import write_json, write_text  # noqa: E402
from renderers.campaign import (  # noqa: E402
    build_campaign_summary,
    collect_run_summaries,
    render_campaign_markdown,
)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Render multi-run analyzer campaign summaries."
    )
    parser.add_argument(
        "--campaign-dir",
        required=True,
        help="Directory containing per-run analyzer summaries.",
    )
    parser.add_argument(
        "--output", default=None, help="campaign-summary.json output path."
    )
    parser.add_argument(
        "--report", default=None, help="campaign-summary.md output path."
    )
    args = parser.parse_args(argv)

    campaign_dir = Path(args.campaign_dir).expanduser().resolve()
    summaries = collect_run_summaries(campaign_dir)
    payload = build_campaign_summary(campaign_dir, summaries)
    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else campaign_dir / "campaign-summary.json"
    )
    report = (
        Path(args.report).expanduser().resolve()
        if args.report
        else campaign_dir / "campaign-summary.md"
    )
    write_json(output, payload)
    write_text(report, render_campaign_markdown(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
