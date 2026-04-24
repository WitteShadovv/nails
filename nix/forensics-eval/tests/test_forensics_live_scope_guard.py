import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "forensics_live_scope_guard.py"
PLANNER_METADATA_JSON = json.dumps(
    {
        "availableTargets": [
            "ci",
            "all",
            "live",
            "scenario:direct-baseline",
            "profile:direct-headless",
            "profile:graphical",
            "profile:vfat-boot",
            "direct-baseline/direct-headless",
            "direct-baseline/graphical",
            "direct-baseline/vfat-boot",
        ],
        "leafTests": [
            "direct-baseline/direct-headless",
            "direct-baseline/graphical",
            "direct-baseline/vfat-boot",
        ],
        "groups": {
            "ci": ["direct-baseline/direct-headless"],
            "all": [
                "direct-baseline/direct-headless",
                "direct-baseline/graphical",
                "direct-baseline/vfat-boot",
            ],
            "live": ["direct-baseline/direct-headless"],
            "scenario:direct-baseline": [
                "direct-baseline/direct-headless",
                "direct-baseline/graphical",
                "direct-baseline/vfat-boot",
            ],
            "profile:direct-headless": ["direct-baseline/direct-headless"],
            "profile:graphical": ["direct-baseline/graphical"],
            "profile:vfat-boot": ["direct-baseline/vfat-boot"],
        },
        "leaves": {
            "direct-baseline/direct-headless": {
                "scenarioId": "direct-baseline",
                "profileId": "direct-headless",
                "recommendedMode": "builtin-live",
            },
            "direct-baseline/graphical": {
                "scenarioId": "direct-baseline",
                "profileId": "graphical",
                "recommendedMode": "fixture-or-custom-exporter",
            },
            "direct-baseline/vfat-boot": {
                "scenarioId": "direct-baseline",
                "profileId": "vfat-boot",
                "recommendedMode": "fixture-or-custom-exporter",
            },
        },
        "builtinLiveLeafTests": ["direct-baseline/direct-headless"],
    }
)


def _load_module():
    spec = importlib.util.spec_from_file_location("forensics_live_scope_guard", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


class ForensicsLiveScopeGuardTest(unittest.TestCase):
    def _valid_plan(self, *, iterations="1"):
        return {
            "requestedTargets": ["live"],
            "resolvedLeaves": ["direct-baseline/direct-headless"],
            "builtinLiveSupportedLeaves": ["direct-baseline/direct-headless"],
            "modes": ["standard", "emergency"],
            "iterations": iterations,
        }

    def test_validate_live_scope_plan_accepts_expected_live_plan(self):
        result = MODULE.validate_live_scope_plan(
            self._valid_plan(iterations="5"),
            expected_requested_target="live",
            allowed_leaves=["direct-baseline/direct-headless"],
            min_iterations=1,
            max_iterations=5,
        )
        self.assertEqual(result.requested_target, "live")
        self.assertEqual(result.iterations, 5)
        self.assertEqual(result.resolved_leaves, ("direct-baseline/direct-headless",))

    def test_validate_live_scope_plan_rejects_non_live_requested_target(self):
        with self.assertRaisesRegex(MODULE.ValidationError, "requestedTargets"):
            MODULE.validate_live_scope_plan(
                {
                    **self._valid_plan(),
                    "requestedTargets": ["ci"],
                },
                expected_requested_target="live",
                allowed_leaves=["direct-baseline/direct-headless"],
                min_iterations=1,
                max_iterations=5,
            )

    def test_validate_live_scope_plan_rejects_scope_expansion(self):
        with self.assertRaisesRegex(MODULE.ValidationError, "fail-closed"):
            MODULE.validate_live_scope_plan(
                {
                    **self._valid_plan(),
                    "resolvedLeaves": [
                        "direct-baseline/direct-headless",
                        "direct-baseline/graphical",
                    ],
                },
                expected_requested_target="live",
                allowed_leaves=["direct-baseline/direct-headless"],
                min_iterations=1,
                max_iterations=5,
            )

    def test_validate_live_scope_plan_rejects_builtin_live_drift(self):
        with self.assertRaisesRegex(MODULE.ValidationError, "metadata drifted"):
            MODULE.validate_live_scope_plan(
                {
                    **self._valid_plan(),
                    "builtinLiveSupportedLeaves": [
                        "direct-baseline/direct-headless",
                        "direct-baseline/vfat-boot",
                    ],
                },
                expected_requested_target="live",
                allowed_leaves=["direct-baseline/direct-headless"],
                min_iterations=1,
                max_iterations=5,
            )

    def test_validate_live_scope_plan_rejects_invalid_iterations(self):
        with self.assertRaisesRegex(MODULE.ValidationError, "iterations"):
            MODULE.validate_live_scope_plan(
                self._valid_plan(iterations="6"),
                expected_requested_target="live",
                allowed_leaves=["direct-baseline/direct-headless"],
                min_iterations=1,
                max_iterations=5,
            )

    def test_cli_writes_outputs_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            github_output = tmp_path / "github-output.txt"
            github_summary = tmp_path / "github-summary.md"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--plan-json",
                    json.dumps(self._valid_plan(iterations="2")),
                    "--github-output",
                    str(github_output),
                    "--github-step-summary",
                    str(github_summary),
                    "--summary-title",
                    "Hosted live-target preflight",
                ],
                check=True,
                capture_output=True,
                text=True,
                cwd=ROOT,
            )

            stdout_payload = json.loads(completed.stdout)
            self.assertEqual(stdout_payload["iterations"], 2)
            self.assertEqual(
                stdout_payload["resolvedLeaves"], ["direct-baseline/direct-headless"]
            )

            output_text = github_output.read_text(encoding="utf-8")
            self.assertIn("iterations=2", output_text)
            self.assertIn("modes=standard,emergency", output_text)
            self.assertIn("resolved_leaves<<EOF", output_text)
            self.assertIn("builtin_live_leaves<<EOF", output_text)

            summary_text = github_summary.read_text(encoding="utf-8")
            self.assertIn("## Hosted live-target preflight", summary_text)
            self.assertIn("direct-baseline/direct-headless", summary_text)

    def test_cli_integration_uses_repo_planner(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--target",
                "live",
                "--iterations",
                "1",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env={
                **os.environ,
                "NAILS_FORENSICS_EVAL_METADATA_JSON": PLANNER_METADATA_JSON,
            },
        )
        stdout_payload = json.loads(completed.stdout)
        self.assertEqual(stdout_payload["requestedTarget"], "live")
        self.assertEqual(
            stdout_payload["builtinLiveSupportedLeaves"],
            ["direct-baseline/direct-headless"],
        )


if __name__ == "__main__":
    unittest.main()
