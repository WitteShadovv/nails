"""Tests for distro-e2e.yml: its choice of suites and its result.

The scripts of the workflow's steps run here as the runner runs them, with bash
(and python3 for the runner the choice of suites normalises).
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from ci.e2e import distro

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "distro-e2e.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def job(name: str) -> str:
    """The lines of job ``name``, up to the comment or job after it."""
    jobs = workflow_text().partition("\njobs:\n")[2]
    match = re.search(rf"^  {re.escape(name)}:\n((?:    .*\n|\n)*)", jobs, re.M)
    if match is None:
        raise AssertionError(f"distro-e2e.yml has no job {name}")
    return match[1]


def step(job_text: str, step_id: str) -> str:
    """The lines of the step with ``id: step_id`` among the lines of a job."""
    steps = re.split(r"^(?=      - )", job_text, flags=re.M)
    marker = re.compile(rf"^ {{8}}id: {re.escape(step_id)}$", re.M)
    found = [text for text in steps if marker.search(text)]
    if len(found) != 1:
        raise AssertionError(f"the job has {len(found)} steps with id {step_id}")
    return found[0]


def script(step_text: str) -> str:
    """The ``run: |`` script of a step, as bash gets it."""
    found = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", step_text, re.M)
    if found is None:
        raise AssertionError("the step has no run: | script")
    return textwrap.dedent(found[1])


class SelectTest(unittest.TestCase):
    """The select step picks the suites by event and checks the inputs."""

    def setUp(self) -> None:
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.workdir = Path(tmp)
        self.output = self.workdir / "output"

    def select(self, **env: str) -> tuple[int, dict[str, str], str]:
        defaults = {
            "SUITE_INPUT": "",
            "RUNNER_INPUT": "",
            "MAX_JOBS_INPUT": "",
        }
        self.output.write_text("", encoding="utf-8")
        result = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                script(step(job("plan"), "select")),
            ],
            cwd=self.workdir,
            env={**os.environ, **defaults, **env, "GITHUB_OUTPUT": str(self.output)},
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        outputs: dict[str, str] = {}
        for line in self.output.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            outputs[key] = value
        return result.returncode, outputs, result.stdout + result.stderr

    def assert_selects(self, suites: str, **env: str) -> None:
        code, outputs, log = self.select(**env)
        self.assertEqual(code, 0, log)
        self.assertEqual(outputs.get("suites"), suites, log)

    def test_a_run_without_an_input_runs_every_suite_but_the_probes(self) -> None:
        # A schedule, or the 'distro-e2e' label on a pull request.
        self.assert_selects("all")

    def test_an_input_names_the_suite(self) -> None:
        for suite in ("all", "smoke", "records", "refusal", "probe"):
            with self.subTest(suite=suite):
                self.assert_selects(suite, SUITE_INPUT=suite)

    def test_an_unknown_suite_fails(self) -> None:
        code, _, log = self.select(SUITE_INPUT="oracle")
        self.assertEqual(code, 1)
        self.assertIn("::error::suite must be", log)

    def test_the_runner_and_the_ceiling_are_checked(self) -> None:
        code, outputs, log = self.select(RUNNER_INPUT='["self-hosted", "kvm"]')
        self.assertEqual(code, 0, log)
        self.assertEqual(outputs["runner"], '["self-hosted","kvm"]')
        self.assertEqual(outputs["max-jobs"], "8")
        code, _, log = self.select(MAX_JOBS_INPUT="0")
        self.assertEqual(code, 1)
        self.assertIn("::error::max-jobs must be a positive integer", log)

    def test_every_suite_it_accepts_is_one_the_planner_knows(self) -> None:
        accepted = re.search(
            r"^ +([a-z |]+)\) ;;$", script(step(job("plan"), "select")), re.M
        )
        if accepted is None:
            raise AssertionError("the select step lists no suites it accepts")
        names = [name.strip() for name in accepted[1].split("|")]
        self.assertCountEqual(names, [distro.ALL, *distro.SUITES])


class ResultTest(unittest.TestCase):
    """distro-result fails on the gating jobs and only warns on the others."""

    def report(self, **env: str) -> subprocess.CompletedProcess[str]:
        defaults = {
            "SUITES": "all",
            "DISTRO_JOBS": "3",
            "GATING_JOBS": "4",
            "PLAN_RESULT": "success",
            "DISTRO_RESULT": "success",
            "GATING_RESULT": "success",
        }
        return subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                script(step(job("distro-result"), "report")),
            ],
            env={**os.environ, **defaults, **env},
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def test_passes_when_every_job_passed(self) -> None:
        result = self.report()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("::", result.stdout)

    def test_fails_when_a_gating_job_failed_or_did_not_run(self) -> None:
        for red in ("failure", "cancelled", "skipped"):
            with self.subTest(result=red):
                result = self.report(GATING_RESULT=red)
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error::One or more records or refusal", result.stdout)

    def test_only_warns_when_a_smoke_scenario_or_a_probe_failed(self) -> None:
        result = self.report(DISTRO_RESULT="failure")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("::warning::One or more distro smoke scenarios", result.stdout)
        result = self.report(
            SUITES="probe",
            GATING_JOBS="0",
            GATING_RESULT="skipped",
            DISTRO_RESULT="failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("::warning::One or more distro probes", result.stdout)

    def test_passes_a_run_that_planned_no_gating_job(self) -> None:
        result = self.report(SUITES="smoke", GATING_JOBS="0", GATING_RESULT="skipped")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_passes_a_run_for_another_label(self) -> None:
        result = self.report(
            PLAN_RESULT="skipped",
            SUITES="",
            DISTRO_JOBS="",
            GATING_JOBS="",
            DISTRO_RESULT="skipped",
            GATING_RESULT="skipped",
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_fails_when_the_plan_failed(self) -> None:
        result = self.report(PLAN_RESULT="failure", GATING_RESULT="skipped")
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error::Planning the distro run failed.", result.stdout)

    def test_fails_closed_on_a_plan_that_set_no_suites_or_counts(self) -> None:
        for env in (
            {"SUITES": ""},
            {"GATING_JOBS": ""},
            {"DISTRO_JOBS": ""},
        ):
            with self.subTest(env=env):
                result = self.report(
                    **env, DISTRO_RESULT="skipped", GATING_RESULT="skipped"
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error::The plan set no suites", result.stdout)


class WorkflowShapeTest(unittest.TestCase):
    """The jobs are wired so that no gating job escapes distro-result."""

    def test_the_result_waits_for_every_job(self) -> None:
        jobs = re.findall(
            r"^  ([\w-]+):$", workflow_text().partition("\njobs:\n")[2], re.M
        )
        needs = re.search(r"^ {4}needs: \[(.+)\]$", job("distro-result"), re.M)
        if needs is None:
            raise AssertionError("distro-result needs no list of jobs")
        self.assertCountEqual(
            [name.strip() for name in needs[1].split(",")],
            [name for name in jobs if name != "distro-result"],
        )

    def test_the_gating_job_runs_the_plans_gating_entries(self) -> None:
        self.assertIn(
            "matrix: ${{ fromJSON(needs.plan.outputs.gating) }}", job("gating")
        )
        self.assertIn("select(.gating)", script(step(job("plan"), "matrix")))
        self.assertIn("select(.gating | not)", script(step(job("plan"), "matrix")))

    def test_a_run_for_another_label_gets_a_group_of_its_own(self) -> None:
        # The plan's condition and the concurrency suffix are complements: a
        # run that tests nothing must not cancel one that does.
        plan_if = re.search(r"^ {4}if: \$\{\{ (.+) \}\}$", job("plan"), re.M)
        if plan_if is None:
            raise AssertionError("the plan job has no if:")
        self.assertEqual(
            plan_if[1],
            "github.event_name != 'pull_request' || github.event.action != 'labeled'"
            " || github.event.label.name == 'distro-e2e'",
        )
        self.assertIn(
            "github.event_name == 'pull_request' && github.event.action == 'labeled'"
            " && github.event.label.name != 'distro-e2e'"
            " && format('-{0}', github.run_id)",
            workflow_text(),
        )


if __name__ == "__main__":
    unittest.main()
