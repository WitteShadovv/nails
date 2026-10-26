"""Tests for ci/e2e/distro.py, the distribution VM smoke matrix planner.

Nix is not needed here: the metadata is handed in as the plain data the flake's
``e2e-distro-metadata`` attribute exposes, and the planner is pure.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

from ci.e2e import __main__ as cli
from ci.e2e import distro


def sample_metadata(
    *,
    scenarios: dict[str, list[str]] | None = None,
    timeouts: dict[str, int] | None = None,
    probes: dict[str, str] | None = None,
) -> distro.DistroMetadata:
    scenarios = scenarios or {
        "debian-12": ["debian-12-smoke"],
        "debian-13": ["debian-13-smoke"],
        "ubuntu-24.04": ["ubuntu-24.04-smoke"],
    }
    if probes is None:
        probes = {
            name: f"{name}-probe"
            for name in ("arch-boxes", "fedora-44", "fedora-44-enforcing")
        }
    if timeouts is None:
        timeouts = {name: 2400 for members in scenarios.values() for name in members}
        timeouts.update({attr: 1200 for attr in probes.values()})
    return distro.DistroMetadata(
        distros=list(scenarios),
        scenarios=scenarios,
        timeouts=timeouts,
        probes=probes,
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

    def test_probes_are_optional(self) -> None:
        payload: dict[str, object] = {"distros": [], "scenarios": {}, "timeouts": {}}
        self.assertEqual(distro.parse_distro_metadata(payload).probes, {})

    def test_parses_probes(self) -> None:
        payload = {
            "distros": [],
            "scenarios": {},
            "timeouts": {"fedora-44-probe": 1200},
            "probes": {"fedora-44": "fedora-44-probe"},
        }
        meta = distro.parse_distro_metadata(payload)
        self.assertEqual(meta.probes, {"fedora-44": "fedora-44-probe"})

    def test_rejects_probe_without_timeout(self) -> None:
        payload = {
            "distros": [],
            "scenarios": {},
            "timeouts": {},
            "probes": {"fedora-44": "fedora-44-probe"},
        }
        with self.assertRaises(distro.DistroError):
            distro.parse_distro_metadata(payload)

    def test_rejects_probes_that_are_not_a_mapping(self) -> None:
        payload: dict[str, object] = {
            "distros": [],
            "scenarios": {},
            "timeouts": {},
            "probes": [],
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

    def test_smoke_plan_never_runs_a_probe(self) -> None:
        meta = sample_metadata()
        tests: set[str] = set()
        for job in distro.plan_distro_matrix(meta)["include"]:
            members = job["tests"]
            assert isinstance(members, list)
            tests.update(str(test) for test in members)
        self.assertFalse(tests & set(meta.probes.values()))


class PlanProbeMatrixTest(unittest.TestCase):
    def test_one_job_per_probe(self) -> None:
        meta = sample_metadata()
        include = distro.plan_probe_matrix(meta)["include"]
        self.assertEqual([job["distro"] for job in include], list(meta.probes))
        for job in include:
            self.assertEqual((job["index"], job["count"]), (1, 1))
            self.assertEqual(job["tests"], [meta.probes[str(job["distro"])]])
            self.assertEqual(job["seconds"], 1200)
            timeout = job["timeout"]
            assert isinstance(timeout, int)
            # The job outlives its driver's own limit.
            self.assertGreater(timeout * 60, 1200)

    def test_selecting_probes_in_order(self) -> None:
        meta = sample_metadata()
        include = distro.plan_probe_matrix(
            meta, ["fedora-44-enforcing", "arch-boxes", "fedora-44-enforcing"]
        )["include"]
        self.assertEqual(
            [job["distro"] for job in include], ["fedora-44-enforcing", "arch-boxes"]
        )

    def test_unknown_probe_raises(self) -> None:
        meta = sample_metadata()
        with self.assertRaises(distro.DistroError):
            distro.plan_probe_matrix(meta, ["debian-13"])

    def test_no_runnable_probe_raises(self) -> None:
        meta = sample_metadata(probes={})
        with self.assertRaises(distro.DistroError):
            distro.plan_probe_matrix(meta)


class DistroPlanCommandTest(unittest.TestCase):
    def plan(self, *argv: str) -> dict[str, list[dict[str, object]]]:
        out = io.StringIO()
        with mock.patch.object(
            cli.distro, "load_distro_metadata", return_value=sample_metadata()
        ):
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["distro-plan", *argv]), 0)
        matrix: dict[str, list[dict[str, object]]] = json.loads(out.getvalue())
        return matrix

    def test_smoke_is_the_default_suite(self) -> None:
        include = self.plan()["include"]
        self.assertEqual(
            [job["tests"] for job in include],
            [["debian-12-smoke"], ["debian-13-smoke"], ["ubuntu-24.04-smoke"]],
        )

    def test_probe_suite_plans_the_named_probes(self) -> None:
        include = self.plan("--suite", "probe", "fedora-44")["include"]
        self.assertEqual([job["tests"] for job in include], [["fedora-44-probe"]])


if __name__ == "__main__":
    unittest.main()
