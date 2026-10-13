"""Tests for ci/e2e/distro.py, the distribution VM smoke matrix planner.

Nix is not needed here: the metadata is handed in as the plain data the flake's
``e2e-distro-metadata`` attribute exposes, and the planner is pure.
"""

from __future__ import annotations

import unittest

from ci.e2e import distro


def sample_metadata(
    *,
    scenarios: dict[str, list[str]] | None = None,
    timeouts: dict[str, int] | None = None,
) -> distro.DistroMetadata:
    scenarios = scenarios or {
        "debian-12": ["debian-12-smoke"],
        "debian-13": ["debian-13-smoke"],
        "ubuntu-24.04": ["ubuntu-24.04-smoke"],
    }
    if timeouts is None:
        timeouts = {name: 2400 for members in scenarios.values() for name in members}
    return distro.DistroMetadata(
        distros=list(scenarios),
        scenarios=scenarios,
        timeouts=timeouts,
    )


class ParseMetadataTest(unittest.TestCase):
    def test_parses_well_formed_payload(self) -> None:
        payload = {
            "distros": ["debian-12", "ubuntu-24.04"],
            "scenarios": {
                "debian-12": ["debian-12-smoke"],
                "ubuntu-24.04": ["ubuntu-24.04-smoke"],
            },
            "timeouts": {"debian-12-smoke": 2400, "ubuntu-24.04-smoke": 2400},
        }
        meta = distro.parse_distro_metadata(payload)
        self.assertEqual(meta.distros, ["debian-12", "ubuntu-24.04"])
        self.assertEqual(meta.scenarios["debian-12"], ["debian-12-smoke"])
        self.assertEqual(meta.timeouts["ubuntu-24.04-smoke"], 2400)

    def test_rejects_non_object(self) -> None:
        with self.assertRaises(distro.DistroError):
            distro.parse_distro_metadata([])

    def test_rejects_missing_key(self) -> None:
        with self.assertRaises(distro.DistroError):
            distro.parse_distro_metadata({"distros": [], "scenarios": {}})

    def test_rejects_distro_without_scenarios(self) -> None:
        payload = {
            "distros": ["debian-12"],
            "scenarios": {},
            "timeouts": {},
        }
        with self.assertRaises(distro.DistroError):
            distro.parse_distro_metadata(payload)

    def test_rejects_scenario_without_timeout(self) -> None:
        payload = {
            "distros": ["debian-12"],
            "scenarios": {"debian-12": ["debian-12-smoke"]},
            "timeouts": {},
        }
        with self.assertRaises(distro.DistroError):
            distro.parse_distro_metadata(payload)


class ResolveTest(unittest.TestCase):
    def test_empty_request_returns_all(self) -> None:
        meta = sample_metadata()
        self.assertEqual(meta.resolve([]), meta.distros)

    def test_named_request_is_deduplicated_in_order(self) -> None:
        meta = sample_metadata()
        self.assertEqual(
            meta.resolve(["ubuntu-24.04", "debian-12", "ubuntu-24.04"]),
            ["ubuntu-24.04", "debian-12"],
        )

    def test_unknown_distro_raises(self) -> None:
        meta = sample_metadata()
        with self.assertRaises(distro.DistroError):
            meta.resolve(["fedora-40"])


class PlanMatrixTest(unittest.TestCase):
    def test_one_smoke_job_per_distro(self) -> None:
        meta = sample_metadata()
        matrix = distro.plan_distro_matrix(meta)
        include = matrix["include"]
        self.assertEqual(len(include), len(meta.distros))
        distros = [job["distro"] for job in include]
        self.assertEqual(distros, meta.distros)
        for job in include:
            self.assertEqual(job["count"], 1)
            self.assertEqual(job["index"], 1)
            tests = job["tests"]
            assert isinstance(tests, list)
            self.assertEqual(len(tests), 1)
            timeout = job["timeout"]
            assert isinstance(timeout, int)
            self.assertGreater(timeout, 0)

    def test_selecting_a_subset(self) -> None:
        meta = sample_metadata()
        matrix = distro.plan_distro_matrix(meta, ["debian-12"])
        self.assertEqual([job["distro"] for job in matrix["include"]], ["debian-12"])

    def test_total_jobs_never_exceed_ceiling(self) -> None:
        # Four distros, each with four scenarios, under a ceiling of eight: no
        # more than eight jobs total, so each distro gets two shards.
        scenarios = {
            name: [f"{name}-s{i}" for i in range(4)]
            for name in ("debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04")
        }
        meta = sample_metadata(scenarios=scenarios)
        matrix = distro.plan_distro_matrix(meta, max_jobs=8)
        self.assertLessEqual(len(matrix["include"]), 8)
        per_distro = {name: 0 for name in scenarios}
        covered: set[str] = set()
        for job in matrix["include"]:
            per_distro[str(job["distro"])] += 1
            tests = job["tests"]
            assert isinstance(tests, list)
            covered.update(str(t) for t in tests)
        self.assertTrue(all(count == 2 for count in per_distro.values()))
        # Every scenario is covered exactly once despite the sharding.
        self.assertEqual(
            covered, {name for members in scenarios.values() for name in members}
        )

    def test_more_distros_than_ceiling_still_runs_each(self) -> None:
        scenarios = {f"distro-{i}": [f"distro-{i}-smoke"] for i in range(10)}
        meta = sample_metadata(scenarios=scenarios)
        matrix = distro.plan_distro_matrix(meta, max_jobs=8)
        # Coverage is never dropped: every distribution still gets its job.
        self.assertEqual(len(matrix["include"]), 10)

    def test_rejects_non_positive_ceiling(self) -> None:
        meta = sample_metadata()
        with self.assertRaises(ValueError):
            distro.plan_distro_matrix(meta, max_jobs=0)


if __name__ == "__main__":
    unittest.main()
