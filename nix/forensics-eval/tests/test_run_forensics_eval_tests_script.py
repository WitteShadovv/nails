import json
import os
import subprocess
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[3] / "scripts" / "run-forensics-eval-tests.sh"
)

STUB_METADATA = {
    "availableTargets": [
        "ci",
        "all",
        "live",
        "scenario:sample",
        "scenario:alt",
        "profile:direct-headless",
        "profile:triage",
        "sample.direct-headless",
        "sample.triage",
        "alt.direct-headless",
    ],
    "leafTests": [
        "sample.direct-headless",
        "sample.triage",
        "alt.direct-headless",
    ],
    "groups": {
        "ci": ["sample.direct-headless", "sample.triage"],
        "all": [
            "sample.direct-headless",
            "sample.triage",
            "alt.direct-headless",
        ],
        "live": ["sample.direct-headless"],
        "scenario:sample": ["sample.direct-headless", "sample.triage"],
        "scenario:alt": ["alt.direct-headless"],
        "profile:direct-headless": [
            "sample.direct-headless",
            "alt.direct-headless",
        ],
        "profile:triage": ["sample.triage"],
    },
    "leaves": {
        "sample.direct-headless": {
            "scenarioId": "sample",
            "profileId": "direct-headless",
            "recommendedMode": "builtin-live",
        },
        "sample.triage": {
            "scenarioId": "sample",
            "profileId": "triage",
            "recommendedMode": "fixture",
        },
        "alt.direct-headless": {
            "scenarioId": "alt",
            "profileId": "direct-headless",
            "recommendedMode": "fixture",
        },
    },
}


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["NAILS_FORENSICS_EVAL_METADATA_JSON"] = json.dumps(STUB_METADATA)
    return subprocess.run(
        ["bash", str(SCRIPT_PATH), "--dry-run", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class RunForensicsEvalTestsScriptTest(unittest.TestCase):
    def test_dry_run_resolves_leaf_directly(self) -> None:
        result = run_script("sample.direct-headless")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), ["sample.direct-headless"])

    def test_dry_run_resolves_scenario_group(self) -> None:
        result = run_script("scenario:sample")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip().splitlines(),
            ["sample.direct-headless", "sample.triage"],
        )

    def test_dry_run_resolves_profile_group(self) -> None:
        result = run_script("profile:direct-headless")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip().splitlines(),
            ["sample.direct-headless", "alt.direct-headless"],
        )

    def test_dry_run_resolves_builtin_group(self) -> None:
        result = run_script("ci")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip().splitlines(),
            ["sample.direct-headless", "sample.triage"],
        )

    def test_shard_validation_rejects_missing_pair(self) -> None:
        result = run_script("--shard-index", "1", "ci")

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "--shard-index and --shard-count must be provided together",
            result.stderr,
        )

    def test_shard_validation_rejects_non_positive_index(self) -> None:
        result = run_script("--shard-index", "0", "--shard-count", "2", "ci")

        self.assertEqual(result.returncode, 1)
        self.assertIn("--shard-index must be a positive integer", result.stderr)

    def test_shard_validation_rejects_index_larger_than_count(self) -> None:
        result = run_script("--shard-index", "3", "--shard-count", "2", "ci")

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "--shard-index must be less than or equal to --shard-count",
            result.stderr,
        )

    def test_dry_run_applies_sharding_after_resolution(self) -> None:
        result = run_script("--shard-index", "2", "--shard-count", "2", "all")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), ["sample.triage"])


if __name__ == "__main__":
    unittest.main()
