import json
import tempfile
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[3]
ANALYZERS_DIR = ROOT / "nix" / "forensics-eval" / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext  # noqa: E402
from plugins.fls_oracle import FlsOracleAnalyzer  # noqa: E402


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class FlsOracleModesTest(unittest.TestCase):
    def _ctx(
        self,
        run_dir: Path,
        baseline_dir: Path,
        scenario: dict,
        canaries: dict | None,
    ) -> AnalyzerContext:
        return AnalyzerContext(
            run_dir=run_dir,
            output_dir=run_dir / "compare",
            scratch_dir=run_dir / "compare" / "scratch",
            baseline_dir=baseline_dir,
            stages={"baseline": baseline_dir, "active": run_dir / "active"},
            profile="direct-headless",
            scenario_id="sample",
            run_id="run-001",
            iteration=1,
            manifest={"analyzers": []},
            scenario=scenario,
            canaries=canaries,
            allowlist=AllowlistProfile.empty(),
        )

    def test_exact_mode_uses_path_template_with_canary_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline"
            active = root / "active"
            _write(baseline / "commands" / "baseline-fls-vdb.stdout", 'r/r 11: "."\n')
            _write(
                active / "commands" / "active-fls-vdb.stdout",
                'r/r 144: "/history/nails.forensics.sample:history:1111"\n',
            )
            scenario = {
                "oracles": {
                    "flsOracle": {
                        "exactStageExpectations": {
                            "active": [
                                {
                                    "label": "history-canary",
                                    "pathTemplate": "/history/{canary:history}",
                                }
                            ]
                        }
                    }
                }
            }
            canaries = {
                "namespace": "nails.forensics.sample",
                "entries": [
                    {
                        "label": "history",
                        "token": "nails.forensics.sample:history:1111",
                    }
                ],
            }

            result = FlsOracleAnalyzer().analyze(
                self._ctx(root, baseline, scenario, canaries), "active", active
            )
            payload = result.to_dict()
            self.assertEqual(payload["status"], "finding")
            self.assertEqual(payload["summary"]["oracleMode"], "exact-oracle")
            self.assertEqual(payload["metrics"]["exactExpectedCount"], 1)
            self.assertEqual(payload["findings"][0]["id"], "fls-exact-hit")

    def test_heuristic_fallback_when_exact_oracle_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline"
            active = root / "active"
            _write(baseline / "commands" / "baseline-fls-vdb.stdout", 'r/r 11: "."\n')
            _write(
                active / "commands" / "active-fls-vdb.stdout",
                'r/r 144: "/home/testuser/financial-data.csv"\n',
            )
            scenario = {
                "oracles": {
                    "flsOracle": {
                        "exactStageExpectations": {
                            "active": [
                                {
                                    "label": "missing-canary",
                                    "pathTemplate": "/history/{canary:history}",
                                }
                            ]
                        }
                    }
                }
            }

            result = FlsOracleAnalyzer().analyze(
                self._ctx(root, baseline, scenario, canaries=None), "active", active
            )
            payload = result.to_dict()
            self.assertEqual(payload["status"], "finding")
            self.assertEqual(payload["summary"]["oracleMode"], "heuristic-fallback")
            self.assertEqual(
                payload["metrics"]["unresolvedExactExpectations"], ["missing-canary"]
            )
            self.assertEqual(payload["findings"][0]["id"], "fls-output-hit")


if __name__ == "__main__":
    unittest.main()
