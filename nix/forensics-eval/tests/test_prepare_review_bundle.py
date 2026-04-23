import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PREPARE_BUNDLE = ROOT / "scripts" / "prepare-forensics-review-bundle.py"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sample_analyzer_payload(*, sensitive: bool) -> dict[str, object]:
    detail = (
        "Matched token nails.forensics.sample:history:1111 in exported content"
        if sensitive
        else "Matched fixture indicator in exported content"
    )
    evidence = {
        "type": "content-match",
        "path": "/exports/active/leak.txt",
        "detail": detail,
    }
    if sensitive:
        evidence["snippet"] = (
            "Operation Nightingale\nnails.forensics.sample:history:1111"
        )
    return {
        "contractVersion": "1",
        "analyzer": "canary_scan",
        "stage": "active",
        "status": "finding",
        "summary": {"headline": "Fixture finding preserved"},
        "findings": [
            {
                "id": "canary-hit",
                "title": "Fixture canary detected",
                "severity": "high",
                "classification": "canary",
                "description": "Fixture description preserved for review.",
                "evidence": [dict(evidence)],
            }
        ],
        "evidence": [dict(evidence)],
        "metrics": {"matches": 1},
    }


def _create_campaign_fixture(
    root: Path, *, sensitive: bool = False, missing_relpath: str | None = None
) -> Path:
    campaign_dir = root / "campaign"
    run_dir = campaign_dir / "run-001"

    _write(
        campaign_dir / "campaign-summary.json",
        json.dumps({"runCount": 1, "runs": ["run-001"]}, indent=2) + "\n",
    )
    _write(campaign_dir / "campaign-summary.md", "# Campaign Summary\n\nFixture run.\n")
    _write(
        run_dir / "run-manifest.json", json.dumps({"runId": "run-001"}, indent=2) + "\n"
    )
    _write(
        run_dir / "summary.json",
        json.dumps({"runId": "run-001", "acquisitionMode": "fixture"}, indent=2) + "\n",
    )
    _write(
        run_dir / "report.md", "# Run Report\n\nNo sensitive evidence snippets here.\n"
    )
    _write(
        run_dir / "scenario.json",
        json.dumps({"scenarioId": "fixture-scenario"}, indent=2) + "\n",
    )
    _write(
        run_dir / "compare" / "summary.json",
        json.dumps({"status": "finding", "findings": 1}, indent=2) + "\n",
    )
    _write(
        run_dir / "compare" / "report.md",
        "# Analyzer Report\n\n"
        "### active / canary_scan\n"
        "- `high` `canary-hit`: Fixture canary detected\n"
        + (
            "  evidence: `/exports/active/leak.txt` - Matched token nails.forensics.sample:history:1111 in exported content - `Operation Nightingale / nails.forensics.sample:history:1111`\n"
            if sensitive
            else "  evidence: `/exports/active/leak.txt` - Matched fixture indicator in exported content\n"
        ),
    )
    _write(
        run_dir / "compare" / "findings-diff.json",
        json.dumps({"contractVersion": "1", "stages": {}, "comparisons": []}, indent=2)
        + "\n",
    )
    _write(
        run_dir / "compare" / "findings-diff.md",
        "# Analyzer Findings Diff\n\nNo diffs.\n",
    )
    _write(
        run_dir / "compare" / "baseline-vs-active.json",
        json.dumps({"stage": "active", "counts": {"changed": 1}}, indent=2) + "\n",
    )
    _write(
        run_dir / "compare" / "stage-hashes" / "active.json",
        json.dumps({"stage": "active", "hash": "abc123"}, indent=2) + "\n",
    )
    _write(
        run_dir / "compare" / "analyzers" / "active" / "canary_scan.json",
        json.dumps(_sample_analyzer_payload(sensitive=sensitive), indent=2) + "\n",
    )
    _write(run_dir / "active" / "artifacts" / "leak.txt", "raw evidence stays out\n")

    if missing_relpath is not None:
        (campaign_dir / missing_relpath).unlink()

    return campaign_dir


class PrepareReviewBundleTest(unittest.TestCase):
    def _run_prepare(
        self, campaign_dir: Path, bundle_dir: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PREPARE_BUNDLE),
                "--campaign-dir",
                str(campaign_dir),
                "--bundle-dir",
                str(bundle_dir),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_missing_required_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = _create_campaign_fixture(
                Path(tmp), missing_relpath="run-001/compare/findings-diff.json"
            )
            bundle_dir = Path(tmp) / "bundle"

            result = self._run_prepare(campaign_dir, bundle_dir)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing required review artifacts", result.stderr)
            self.assertIn("run-001/compare/findings-diff.json", result.stderr)

    def test_happy_path_passes_and_keeps_bundle_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = _create_campaign_fixture(Path(tmp), sensitive=False)
            bundle_dir = Path(tmp) / "bundle"

            result = self._run_prepare(campaign_dir, bundle_dir)

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(
                (bundle_dir / "review-bundle-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["sanitizationApplied"])
            self.assertEqual(manifest["sanitizedFiles"], [])
            self.assertIn("run-001/compare/report.md", manifest["includedFiles"])
            self.assertFalse(
                (bundle_dir / "run-001" / "active" / "artifacts" / "leak.txt").exists()
            )

    def test_sanitized_bundle_redacts_sensitive_snippets_and_preserves_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = _create_campaign_fixture(Path(tmp), sensitive=True)
            bundle_dir = Path(tmp) / "bundle"

            result = self._run_prepare(campaign_dir, bundle_dir)

            self.assertEqual(result.returncode, 0, result.stderr)
            source_analyzer = (
                campaign_dir
                / "run-001"
                / "compare"
                / "analyzers"
                / "active"
                / "canary_scan.json"
            ).read_text(encoding="utf-8")
            self.assertIn("nails.forensics.sample:history:1111", source_analyzer)
            self.assertIn("Operation Nightingale", source_analyzer)

            bundled_analyzer_path = (
                bundle_dir
                / "run-001"
                / "compare"
                / "analyzers"
                / "active"
                / "canary_scan.json"
            )
            bundled_analyzer = json.loads(
                bundled_analyzer_path.read_text(encoding="utf-8")
            )
            bundled_analyzer_text = bundled_analyzer_path.read_text(encoding="utf-8")
            self.assertNotIn(
                "nails.forensics.sample:history:1111", bundled_analyzer_text
            )
            self.assertNotIn("Operation Nightingale", bundled_analyzer_text)
            self.assertEqual(bundled_analyzer["status"], "finding")
            self.assertEqual(bundled_analyzer["findings"][0]["id"], "canary-hit")
            self.assertEqual(
                bundled_analyzer["findings"][0]["title"], "Fixture canary detected"
            )
            self.assertEqual(bundled_analyzer["findings"][0]["severity"], "high")
            self.assertIn(
                "<redacted:snippet:",
                bundled_analyzer["findings"][0]["evidence"][0]["snippet"],
            )
            self.assertIn(
                "<redacted:canary:",
                bundled_analyzer["findings"][0]["evidence"][0]["detail"],
            )

            bundled_report_path = bundle_dir / "run-001" / "compare" / "report.md"
            bundled_report = bundled_report_path.read_text(encoding="utf-8")
            self.assertIn("### active / canary_scan", bundled_report)
            self.assertIn("Fixture canary detected", bundled_report)
            self.assertNotIn("nails.forensics.sample:history:1111", bundled_report)
            self.assertNotIn("Operation Nightingale", bundled_report)
            self.assertIn("<redacted:snippet:", bundled_report)

            manifest = json.loads(
                (bundle_dir / "review-bundle-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["sanitizationApplied"])
            self.assertIn(
                "run-001/compare/analyzers/active/canary_scan.json",
                manifest["sanitizedFiles"],
            )
            self.assertIn("run-001/compare/report.md", manifest["sanitizedFiles"])


if __name__ == "__main__":
    unittest.main()
