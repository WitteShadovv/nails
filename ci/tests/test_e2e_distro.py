"""Tests for ci/e2e/distro.py, the distribution VM matrix planner.

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
    records: dict[str, str] | None = None,
    refusals: dict[str, str] | None = None,
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
    if records is None:
        records = {name: f"{name}-records" for name in ("debian-13", "ubuntu-24.04")}
    if refusals is None:
        refusals = {name: f"{name}-refusal" for name in ("arch-boxes", "fedora-44")}
    if timeouts is None:
        timeouts = {name: 2400 for members in scenarios.values() for name in members}
        timeouts.update({attr: 1200 for attr in probes.values()})
        timeouts.update({attr: 1800 for attr in records.values()})
        timeouts.update({attr: 900 for attr in refusals.values()})
    return distro.DistroMetadata(
        distros=list(scenarios),
        scenarios=scenarios,
        timeouts=timeouts,
        probes=probes,
        records=records,
        refusals=refusals,
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

    def test_records_and_refusals_are_optional(self) -> None:
        payload: dict[str, object] = {"distros": [], "scenarios": {}, "timeouts": {}}
        meta = distro.parse_distro_metadata(payload)
        self.assertEqual((meta.records, meta.refusals), ({}, {}))

    def test_parses_records_and_refusals(self) -> None:
        payload = {
            "distros": [],
            "scenarios": {},
            "timeouts": {"debian-13-records": 1800, "fedora-44-refusal": 1200},
            "records": {"debian-13": "debian-13-records"},
            "refusals": {"fedora-44": "fedora-44-refusal"},
        }
        meta = distro.parse_distro_metadata(payload)
        self.assertEqual(meta.records, {"debian-13": "debian-13-records"})
        self.assertEqual(meta.refusals, {"fedora-44": "fedora-44-refusal"})

    def test_rejects_a_driver_without_timeout(self) -> None:
        for key, table in (
            ("records", {"debian-13": "debian-13-records"}),
            ("refusals", {"fedora-44": "fedora-44-refusal"}),
        ):
            with self.subTest(key=key):
                payload = {"distros": [], "scenarios": {}, "timeouts": {}, key: table}
                with self.assertRaises(distro.DistroError):
                    distro.parse_distro_metadata(payload)

    def test_rejects_driver_tables_that_are_not_a_mapping(self) -> None:
        for key in ("records", "refusals"):
            with self.subTest(key=key):
                payload: dict[str, object] = {
                    "distros": [],
                    "scenarios": {},
                    "timeouts": {},
                    key: ["debian-13-records"],
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

    def test_smoke_plan_never_runs_a_driver(self) -> None:
        meta = sample_metadata()
        tests: set[str] = set()
        for job in distro.plan_distro_matrix(meta)["include"]:
            members = job["tests"]
            assert isinstance(members, list)
            tests.update(str(test) for test in members)
        drivers = {*meta.probes.values(), *meta.records.values()}
        self.assertFalse(tests & (drivers | set(meta.refusals.values())))

    def test_smoke_jobs_are_marked_and_do_not_gate(self) -> None:
        for job in distro.plan_distro_matrix(sample_metadata())["include"]:
            self.assertEqual((job["suite"], job["gating"]), ("smoke", False))


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

    def test_probe_jobs_are_marked_and_do_not_gate(self) -> None:
        for job in distro.plan_probe_matrix(sample_metadata())["include"]:
            self.assertEqual((job["suite"], job["gating"]), ("probe", False))


class PlanDriverMatrixTest(unittest.TestCase):
    def test_one_gating_job_per_records_scenario_and_refusal(self) -> None:
        meta = sample_metadata()
        for suite, table, seconds in (
            ("records", meta.records, 1800),
            ("refusal", meta.refusals, 900),
        ):
            with self.subTest(suite=suite):
                include = distro.plan_driver_matrix(meta, suite)["include"]
                self.assertEqual([job["distro"] for job in include], list(table))
                for job in include:
                    self.assertEqual(job["suite"], suite)
                    self.assertIs(job["gating"], True)
                    self.assertEqual((job["index"], job["count"]), (1, 1))
                    self.assertEqual(job["tests"], [table[str(job["distro"])]])
                    self.assertEqual(job["seconds"], seconds)
                    timeout = job["timeout"]
                    assert isinstance(timeout, int)
                    self.assertGreater(timeout * 60, seconds)

    def test_unknown_driver_names_its_suite(self) -> None:
        meta = sample_metadata()
        with self.assertRaisesRegex(distro.DistroError, "unknown refusal: debian-13"):
            distro.plan_driver_matrix(meta, "refusal", ["debian-13"])
        with self.assertRaisesRegex(
            distro.DistroError, "unknown records scenario: fedora-44"
        ):
            distro.plan_driver_matrix(meta, "records", ["fedora-44"])

    def test_a_suite_with_nothing_to_run_raises(self) -> None:
        meta = sample_metadata(records={}, refusals={})
        for suite in ("records", "refusal"):
            with self.subTest(suite=suite):
                with self.assertRaises(distro.DistroError):
                    distro.plan_driver_matrix(meta, suite)

    def test_smoke_is_no_driver_suite(self) -> None:
        with self.assertRaises(distro.DistroError):
            distro.plan_driver_matrix(sample_metadata(), "smoke")


class ExpandSuitesTest(unittest.TestCase):
    def test_all_is_smoke_records_and_refusal(self) -> None:
        self.assertEqual(distro.expand_suites(["all"]), ["smoke", "records", "refusal"])

    def test_suites_come_once_in_plan_order(self) -> None:
        self.assertEqual(
            distro.expand_suites(["probe", "refusal", "records", "refusal"]),
            ["records", "refusal", "probe"],
        )
        self.assertEqual(
            distro.expand_suites(["records", "all"]), ["smoke", "records", "refusal"]
        )

    def test_rejects_an_unknown_or_empty_selection(self) -> None:
        with self.assertRaises(distro.DistroError):
            distro.expand_suites(["oracle"])
        with self.assertRaises(distro.DistroError):
            distro.expand_suites([])


class PlanSuitesTest(unittest.TestCase):
    def suites_and_tests(
        self, *suites: str, names: tuple[str, ...] = ()
    ) -> list[tuple[object, object]]:
        include = distro.plan_matrix(sample_metadata(), suites, names)["include"]
        return [(job["suite"], job["tests"]) for job in include]

    def test_all_plans_smoke_records_and_refusal(self) -> None:
        self.assertEqual(
            self.suites_and_tests("all"),
            [
                ("smoke", ["debian-12-smoke"]),
                ("smoke", ["debian-13-smoke"]),
                ("smoke", ["ubuntu-24.04-smoke"]),
                ("records", ["debian-13-records"]),
                ("records", ["ubuntu-24.04-records"]),
                ("refusal", ["arch-boxes-refusal"]),
                ("refusal", ["fedora-44-refusal"]),
            ],
        )

    def test_only_the_records_and_refusal_jobs_gate(self) -> None:
        include = distro.plan_matrix(sample_metadata(), ["all", "probe"])["include"]
        gating = {str(job["suite"]) for job in include if job["gating"]}
        informational = {str(job["suite"]) for job in include if not job["gating"]}
        self.assertEqual(gating, {"records", "refusal"})
        self.assertEqual(informational, {"smoke", "probe"})

    def test_each_suite_runs_what_it_has_of_the_names(self) -> None:
        self.assertEqual(
            self.suites_and_tests("all", names=("fedora-44", "debian-13")),
            [
                ("smoke", ["debian-13-smoke"]),
                ("records", ["debian-13-records"]),
                ("refusal", ["fedora-44-refusal"]),
            ],
        )
        self.assertEqual(
            self.suites_and_tests("records", "refusal", names=("ubuntu-24.04",)),
            [("records", ["ubuntu-24.04-records"])],
        )

    def test_a_name_no_selected_suite_has_raises(self) -> None:
        with self.assertRaisesRegex(distro.DistroError, "unknown name: debian-12"):
            distro.plan_matrix(sample_metadata(), ["records", "refusal"], ["debian-12"])

    def test_a_plan_without_a_job_raises(self) -> None:
        # debian-13 is a distribution of the smoke suite with no scenario.
        meta = distro.DistroMetadata(
            distros=["debian-13"], scenarios={"debian-13": []}, timeouts={}
        )
        for suites in (["smoke"], ["smoke", "records"]):
            with self.subTest(suites=suites):
                with self.assertRaisesRegex(
                    distro.DistroError, "the plan holds no job"
                ):
                    distro.plan_matrix(meta, suites, ["debian-13"])

    def test_a_suite_with_nothing_to_run_fails_a_wider_plan(self) -> None:
        # The gate of an emptied suite must not vanish while the run passes.
        for empty, meta, reason in (
            ("records", sample_metadata(records={}), "no records scenario can run"),
            ("refusals", sample_metadata(refusals={}), "no refusal can run"),
            (
                "both",
                sample_metadata(records={}, refusals={}),
                "no records scenario can run",
            ),
        ):
            for suites in (["records", "refusal"], ["all"]):
                with self.subTest(empty=empty, suites=suites):
                    with self.assertRaisesRegex(distro.DistroError, reason):
                        distro.plan_matrix(meta, suites)

    def test_a_smoke_suite_with_nothing_to_run_fails_the_plan(self) -> None:
        cases: list[tuple[list[str], dict[str, list[str]]]] = [
            ([], {}),
            (["debian-13"], {"debian-13": []}),
        ]
        for distros, scenarios in cases:
            meta = distro.DistroMetadata(
                distros=distros,
                scenarios=scenarios,
                timeouts={"debian-13-records": 1800, "fedora-44-refusal": 900},
                records={"debian-13": "debian-13-records"},
                refusals={"fedora-44": "fedora-44-refusal"},
            )
            for suites in (["smoke"], ["all"]):
                with self.subTest(distros=distros, suites=suites):
                    with self.assertRaisesRegex(
                        distro.DistroError, "no smoke scenario can run"
                    ):
                        distro.plan_matrix(meta, suites)

    def test_the_names_may_leave_a_suite_out(self) -> None:
        meta = sample_metadata(refusals={})
        include = distro.plan_matrix(meta, ["records", "refusal"], ["debian-13"])
        self.assertEqual(
            [(job["suite"], job["tests"]) for job in include["include"]],
            [("records", ["debian-13-records"])],
        )

    def test_a_suite_alone_plans_as_its_own_planner(self) -> None:
        meta = sample_metadata()
        self.assertEqual(
            distro.plan_matrix(meta, ["smoke"], ["debian-13"]),
            distro.plan_distro_matrix(meta, ["debian-13"]),
        )
        self.assertEqual(
            distro.plan_matrix(meta, ["probe"]), distro.plan_probe_matrix(meta)
        )
        with self.assertRaises(distro.DistroError):
            distro.plan_matrix(meta, ["smoke"], ["fedora-44"])

    def test_rejects_non_positive_ceiling(self) -> None:
        with self.assertRaises(ValueError):
            distro.plan_matrix(sample_metadata(), ["all"], max_jobs=0)


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

    def test_all_is_the_default_suite(self) -> None:
        include = self.plan()["include"]
        self.assertEqual(
            [job["tests"] for job in include],
            [
                ["debian-12-smoke"],
                ["debian-13-smoke"],
                ["ubuntu-24.04-smoke"],
                ["debian-13-records"],
                ["ubuntu-24.04-records"],
                ["arch-boxes-refusal"],
                ["fedora-44-refusal"],
            ],
        )

    def test_smoke_suite_plans_the_smokes_alone(self) -> None:
        include = self.plan("--suite", "smoke")["include"]
        self.assertEqual(
            [job["tests"] for job in include],
            [["debian-12-smoke"], ["debian-13-smoke"], ["ubuntu-24.04-smoke"]],
        )

    def test_probe_suite_plans_the_named_probes(self) -> None:
        include = self.plan("--suite", "probe", "fedora-44")["include"]
        self.assertEqual([job["tests"] for job in include], [["fedora-44-probe"]])

    def test_suites_combine(self) -> None:
        include = self.plan("--suite", "records", "--suite", "refusal", "fedora-44")
        self.assertEqual(
            [job["tests"] for job in include["include"]], [["fedora-44-refusal"]]
        )

    def test_an_error_is_bad_input(self) -> None:
        err = io.StringIO()
        with mock.patch.object(
            cli.distro, "load_distro_metadata", return_value=sample_metadata()
        ):
            with contextlib.redirect_stderr(err):
                code = cli.main(["distro-plan", "--suite", "records", "fedora-44"])
        self.assertEqual(code, cli.EXIT_BAD_INPUT)
        self.assertIn("unknown records scenario: fedora-44", err.getvalue())


if __name__ == "__main__":
    unittest.main()
