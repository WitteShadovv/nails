import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[3]
ANALYZERS_DIR = ROOT / "nix" / "forensics-eval" / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from renderers.markdown import render_report  # noqa: E402
from renderers.summary import build_summary  # noqa: E402


class SummaryPositiveControlTest(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "analyzers": [
                {"id": "path_delta", "enabled": True, "optional": False},
                {"id": "canary_scan", "enabled": True, "optional": False},
                {"id": "indicator_scan", "enabled": True, "optional": False},
                {"id": "autopsy_adapter", "enabled": True, "optional": True},
            ]
        }

    def _build_summary(self, results):
        return build_summary(
            run_id="run-001",
            profile="default",
            scenario_id="sample",
            iteration=1,
            run_dir="/tmp/run",
            output_dir="/tmp/run/compare",
            stages=["active"],
            manifest=self.manifest,
            manifest_path="/tmp/manifest.json",
            allowlist_paths=["/tmp/allowlist.json"],
            results=results,
        )

    def test_positive_control_requires_each_required_analyzer_to_preserve_findings(
        self,
    ):
        summary = self._build_summary(
            [
                {
                    "analyzer": "path_delta",
                    "stage": "active",
                    "status": "finding",
                    "summary": {"headline": "delta found"},
                    "findings": [
                        {
                            "id": "path-delta-hit",
                            "title": "Delta",
                            "severity": "high",
                            "classification": "artifact",
                            "evidence": [
                                {"path": "/tmp/a", "detail": "delta", "type": "file"}
                            ],
                        }
                    ],
                    "metrics": {"allowlisted": 0},
                },
                {
                    "analyzer": "canary_scan",
                    "stage": "active",
                    "status": "clean",
                    "summary": {"headline": "all findings allowlisted"},
                    "findings": [],
                    "metrics": {"allowlisted": 2},
                },
                {
                    "analyzer": "indicator_scan",
                    "stage": "active",
                    "status": "clean",
                    "summary": {"headline": "no preserved matches"},
                    "findings": [],
                    "metrics": {"allowlisted": 0},
                },
                {
                    "analyzer": "autopsy_adapter",
                    "stage": "active",
                    "status": "skipped",
                    "summary": {"headline": "optional adapter unavailable"},
                    "findings": [],
                    "metrics": {},
                },
            ]
        )

        self.assertEqual(summary["status"], "error")
        self.assertEqual(len(summary["contractFailures"]), 1)
        contract = summary["stages"][0]["positiveControlContract"]
        self.assertFalse(contract["satisfied"])
        self.assertEqual(
            contract["requiredAnalyzers"],
            ["path_delta", "canary_scan", "indicator_scan"],
        )
        self.assertEqual(contract["preservedFindingAnalyzers"], ["path_delta"])
        self.assertIn(
            "required analyzer canary_scan produced only allowlisted findings",
            contract["failures"],
        )
        self.assertIn(
            "required analyzer indicator_scan produced no preserved non-allowlisted findings",
            contract["failures"],
        )
        self.assertEqual(
            contract["allowlistMaskedAnalyzers"],
            [{"analyzer": "canary_scan", "allowlisted": 2}],
        )
        self.assertEqual(
            contract["requiredAnalyzerResults"],
            [
                {
                    "analyzer": "path_delta",
                    "status": "finding",
                    "findingCount": 1,
                    "allowlisted": 0,
                    "satisfied": True,
                    "reason": None,
                },
                {
                    "analyzer": "canary_scan",
                    "status": "clean",
                    "findingCount": 0,
                    "allowlisted": 2,
                    "satisfied": False,
                    "reason": "all findings were allowlisted (2 suppressed)",
                },
                {
                    "analyzer": "indicator_scan",
                    "status": "clean",
                    "findingCount": 0,
                    "allowlisted": 0,
                    "satisfied": False,
                    "reason": "no preserved non-allowlisted findings",
                },
            ],
        )

    def test_markdown_reports_analyzer_specific_positive_control_failures(self):
        summary = self._build_summary(
            [
                {
                    "analyzer": "path_delta",
                    "stage": "active",
                    "status": "finding",
                    "summary": {"headline": "delta found"},
                    "findings": [
                        {
                            "id": "path-delta-hit",
                            "title": "Delta",
                            "severity": "high",
                            "classification": "artifact",
                            "evidence": [
                                {"path": "/tmp/a", "detail": "delta", "type": "file"}
                            ],
                        }
                    ],
                    "metrics": {"allowlisted": 0},
                },
                {
                    "analyzer": "canary_scan",
                    "stage": "active",
                    "status": "error",
                    "summary": {
                        "headline": "token load failed",
                        "error": "token load failed",
                    },
                    "findings": [],
                    "metrics": {"allowlisted": 0},
                },
                {
                    "analyzer": "indicator_scan",
                    "stage": "active",
                    "status": "finding",
                    "summary": {"headline": "indicator found"},
                    "findings": [
                        {
                            "id": "indicator-hit",
                            "title": "Indicator",
                            "severity": "medium",
                            "classification": "artifact",
                            "evidence": [
                                {
                                    "path": "/tmp/b",
                                    "detail": "indicator",
                                    "type": "file",
                                }
                            ],
                        }
                    ],
                    "metrics": {"allowlisted": 0},
                },
            ]
        )

        report = render_report(
            ROOT
            / "nix"
            / "forensics-eval"
            / "fixtures"
            / "templates"
            / "report.md.tmpl",
            summary,
            [],
            {"comparisons": []},
        )

        self.assertIn(
            "Required `canary_scan`: `error` with 0 preserved findings", report
        )
        self.assertIn("(token load failed)", report)
        self.assertIn(
            "Failure: required analyzer canary_scan ended as error: token load failed",
            report,
        )


if __name__ == "__main__":
    unittest.main()
