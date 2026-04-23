from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
FORENSICS_EVAL_ROOT = REPO_ROOT / "nix" / "forensics-eval"
SAMPLE_RUN_DIR = FORENSICS_EVAL_ROOT / "fixtures" / "samples" / "sample-run"
RUNNER_SCRIPT = FORENSICS_EVAL_ROOT / "runners" / "run_forensics_eval.py"
RUN_ANALYZERS_SCRIPT = FORENSICS_EVAL_ROOT / "analyzers" / "run_analyzers.py"
CAMPAIGN_RENDERER_SCRIPT = (
    FORENSICS_EVAL_ROOT / "analyzers" / "render_campaign_summary.py"
)


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module {module_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _patch_runner_for_fixture_mode(
    patches: ExitStack, runner_module, *, campaign_id: str
):
    patches.enter_context(
        patch.object(
            runner_module,
            "validate_profile_and_scenario",
            new=lambda *args, **kwargs: None,
        )
    )
    patches.enter_context(
        patch.object(
            runner_module,
            "build_campaign_id",
            new=lambda config: campaign_id,
        )
    )


def _patch_inprocess_subcommands(patches: ExitStack, runner_module):
    analyzers_module = _load_module(
        "forensics_eval_test_fixture_runner_analyzers",
        RUN_ANALYZERS_SCRIPT,
    )
    campaign_module = _load_module(
        "forensics_eval_test_fixture_runner_campaign_renderer",
        CAMPAIGN_RENDERER_SCRIPT,
    )

    def fake_run_process(argv, *, cwd, env):
        with patch.dict(os.environ, env, clear=True):
            script_path = Path(argv[1]).resolve()
            if script_path == RUN_ANALYZERS_SCRIPT.resolve():
                return_code = analyzers_module.main(argv[2:])
            elif script_path == CAMPAIGN_RENDERER_SCRIPT.resolve():
                return_code = campaign_module.main(argv[2:])
            else:  # pragma: no cover - defensive guard for unexpected subprocesses
                raise AssertionError(f"unexpected subprocess target: {script_path}")

        if return_code != 0:
            raise runner_module.RunnerError(
                f"Command failed with exit code {return_code}: {' '.join(argv)}"
            )

        return {
            "argv": argv,
            "cwd": str(cwd),
            "returnCode": return_code,
            "stdout": "",
            "stderr": "",
        }

    patches.enter_context(
        patch.object(runner_module, "run_process", new=fake_run_process)
    )


class RunForensicsEvalFixtureModeTests(unittest.TestCase):
    def test_run_forensics_eval_fixture_mode_creates_pipeline_outputs(self):
        runner = _load_module(
            "forensics_eval_test_run_forensics_eval_fixture_mode",
            RUNNER_SCRIPT,
        )

        with ExitStack() as patches, tempfile.TemporaryDirectory() as tmp:
            _patch_runner_for_fixture_mode(
                patches, runner, campaign_id="fixture-campaign"
            )
            _patch_inprocess_subcommands(patches, runner)

            out_dir = Path(tmp) / "forensics-eval"
            exit_code = runner.main(
                [
                    "--project-root",
                    str(REPO_ROOT),
                    "--profile",
                    "direct-headless",
                    "--scenario",
                    "sample",
                    "--fixture-run-dir",
                    str(SAMPLE_RUN_DIR),
                    "--out",
                    str(out_dir),
                ]
            )

            self.assertEqual(exit_code, 0)

            run_dir = out_dir / "fixture-campaign-run-001"
            compare_dir = run_dir / "compare"

            self.assertTrue((run_dir / "scenario.json").is_file())
            self.assertTrue((run_dir / "canaries.json").is_file())
            self.assertTrue((run_dir / "run-manifest.json").is_file())
            self.assertTrue((run_dir / "summary.json").is_file())
            self.assertTrue((run_dir / "report.md").is_file())
            self.assertTrue((compare_dir / "summary.json").is_file())
            self.assertTrue((compare_dir / "report.md").is_file())
            self.assertTrue((compare_dir / "findings-diff.json").is_file())
            self.assertTrue((compare_dir / "findings-diff.md").is_file())
            self.assertTrue((compare_dir / "baseline-vs-post-standard.json").is_file())
            self.assertTrue((compare_dir / "baseline-vs-post-emergency.json").is_file())
            self.assertTrue((compare_dir / "stage-hashes" / "baseline.json").is_file())
            self.assertTrue((compare_dir / "stage-hashes" / "active.json").is_file())
            self.assertTrue(
                (compare_dir / "stage-hashes" / "post-standard.json").is_file()
            )
            self.assertTrue(
                (compare_dir / "stage-hashes" / "post-emergency.json").is_file()
            )
            self.assertTrue(
                (
                    compare_dir / "analyzers" / "post-standard" / "path_delta.json"
                ).is_file()
            )
            self.assertTrue(
                (
                    compare_dir / "analyzers" / "post-emergency" / "path_delta.json"
                ).is_file()
            )

            summary = _read_json(run_dir / "summary.json")
            run_manifest = _read_json(run_dir / "run-manifest.json")
            compare_summary = _read_json(compare_dir / "summary.json")
            comparison = _read_json(compare_dir / "baseline-vs-post-standard.json")

            self.assertEqual(summary["runId"], "fixture-campaign-run-001")
            self.assertEqual(summary["campaignId"], "fixture-campaign")
            self.assertEqual(summary["acquisitionMode"], "fixture")
            self.assertEqual(summary["result"], "findings")
            self.assertGreater(summary["findingCount"], 0)
            self.assertEqual(summary["mutationCount"], 0)

            stage_statuses = {
                stage["name"]: stage["status"] for stage in summary["stages"]
            }
            self.assertEqual(
                stage_statuses,
                {
                    "baseline": "exported",
                    "active": "placeholder",
                    "post-standard": "exported",
                    "post-emergency": "exported",
                },
            )

            self.assertEqual(
                run_manifest["analyzerOutputs"],
                {
                    "summary": "compare/summary.json",
                    "report": "compare/report.md",
                },
            )
            self.assertEqual(
                run_manifest["analyzerCommand"]["kind"], "builtin-analyzer-runner"
            )
            self.assertEqual(compare_summary["status"], "finding")
            self.assertEqual(comparison["status"], "complete")
            self.assertGreater(comparison["comparison"]["counts"]["added"], 0)
            self.assertGreater(comparison["canaryScan"]["findingCount"], 0)

    def test_run_forensics_eval_fixture_mode_generates_campaign_summary(self):
        runner = _load_module(
            "forensics_eval_test_run_forensics_eval_campaign_summary",
            RUNNER_SCRIPT,
        )

        with ExitStack() as patches, tempfile.TemporaryDirectory() as tmp:
            _patch_runner_for_fixture_mode(
                patches, runner, campaign_id="fixture-campaign"
            )

            out_dir = Path(tmp) / "forensics-eval"
            exit_code = runner.main(
                [
                    "--project-root",
                    str(REPO_ROOT),
                    "--profile",
                    "direct-headless",
                    "--scenario",
                    "sample",
                    "--fixture-run-dir",
                    str(SAMPLE_RUN_DIR),
                    "--out",
                    str(out_dir),
                    "--iterations",
                    "2",
                    "--skip-analyzers",
                ]
            )

            self.assertEqual(exit_code, 0)

            campaign_summary_path = out_dir / "campaign-summary.json"
            campaign_report_path = out_dir / "campaign-summary.md"
            self.assertTrue(campaign_summary_path.is_file())
            self.assertTrue(campaign_report_path.is_file())

            campaign_summary = _read_json(campaign_summary_path)
            self.assertEqual(campaign_summary["campaignId"], "fixture-campaign")
            self.assertEqual(campaign_summary["iterations"], 2)
            self.assertEqual(campaign_summary["result"], "findings")
            self.assertGreater(campaign_summary["totals"]["findingCount"], 0)
            self.assertEqual(
                [run["runId"] for run in campaign_summary["runs"]],
                [
                    "fixture-campaign-run-001",
                    "fixture-campaign-run-002",
                ],
            )

            self.assertTrue(
                (out_dir / "fixture-campaign-run-001" / "summary.json").is_file()
            )
            self.assertTrue(
                (out_dir / "fixture-campaign-run-002" / "summary.json").is_file()
            )

    def test_run_forensics_eval_fixture_mode_fail_on_findings_returns_2(self):
        runner = _load_module(
            "forensics_eval_test_run_forensics_eval_fail_on_findings",
            RUNNER_SCRIPT,
        )

        with ExitStack() as patches, tempfile.TemporaryDirectory() as tmp:
            _patch_runner_for_fixture_mode(patches, runner, campaign_id="fixture-fail")

            out_dir = Path(tmp) / "forensics-eval"
            exit_code = runner.main(
                [
                    "--project-root",
                    str(REPO_ROOT),
                    "--profile",
                    "direct-headless",
                    "--scenario",
                    "sample",
                    "--fixture-run-dir",
                    str(SAMPLE_RUN_DIR),
                    "--out",
                    str(out_dir),
                    "--skip-analyzers",
                    "--fail-on-findings",
                ]
            )

            self.assertEqual(exit_code, 2)

            summary = _read_json(out_dir / "fixture-fail-run-001" / "summary.json")
            self.assertEqual(summary["result"], "findings")
            self.assertGreater(summary["findingCount"], 0)


if __name__ == "__main__":
    unittest.main()
