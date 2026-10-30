"""Tests for ci/changes.py, the path filter of ci.yml, and for that of e2e.yml."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from ci import changes

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
# The crates of the root workspace that the nails binary never links: flake.nix
# builds it from their manifests alone, so their sources cannot change a VM
# test, and a change to them must not boot one.
NOT_IN_THE_BINARY = frozenset({"nails-oracle"})

NOTHING = {
    "rust": False,
    "testdata": False,
    "fuzz": False,
    "side": False,
    "deps": False,
    "nix": False,
    "workflows": False,
    "docs": False,
    "sbom": False,
}
EVERYTHING = {
    "rust": True,
    "testdata": True,
    "fuzz": True,
    "side": True,
    "deps": True,
    "nix": True,
    "workflows": True,
    "docs": True,
    "sbom": True,
}

# The filters each work job of ci.yml runs on, the || terms of the job's own
# if:. A job that loses one is skipped on a change only that filter matches, and
# gate passes the change untested: without testdata, for one, a change to a file
# only the Rust tests read would skip the rust job. Each needs changes alone: a
# job that also needs another is skipped whenever that one is, whatever its own
# filters say.
JOB_FILTERS = {
    "lint": ("rust", "fuzz", "side"),
    "rust": ("rust", "testdata"),
    "shuffle": ("rust",),
    "side-tests": ("rust", "side"),
    "deps": ("rust", "deps"),
    "gui-vet": ("rust", "side", "nix"),
    "privileged-mounts": ("rust",),
    "nix-build": ("rust", "nix", "side"),
    "lint-misc": ("nix", "workflows"),
    "docs-check": ("docs",),
    "sbom": ("sbom",),
}


def only(*names: str) -> dict[str, bool]:
    return {**NOTHING, **dict.fromkeys(names, True)}


def workspace_members() -> list[str]:
    """The members of the root Cargo workspace."""
    with (REPO_ROOT / "Cargo.toml").open("rb") as handle:
        members: list[str] = tomllib.load(handle)["workspace"]["members"]
    return members


def e2e_filter() -> re.Pattern[str] | None:
    """The path filter of e2e.yml's plan job, or None when it has none."""
    workflow = REPO_ROOT / ".github" / "workflows" / "e2e.yml"
    text = workflow.read_text(encoding="utf-8")
    match = re.search(r"^\s*relevant='([^']+)'$", text, re.MULTILINE)
    return re.compile(match[1]) if match else None


def ci_jobs() -> list[str]:
    """The names of the jobs of ci.yml."""
    jobs = CI_WORKFLOW.read_text(encoding="utf-8").partition("\njobs:\n")[2]
    return re.findall(r"^  ([\w-]+):$", jobs, re.M)


def ci_job(name: str) -> str:
    """The lines of job ``name`` in ci.yml, up to the comment or job after it."""
    jobs = CI_WORKFLOW.read_text(encoding="utf-8").partition("\njobs:\n")[2]
    match = re.search(rf"^  {re.escape(name)}:\n((?:    .*\n|\n)*)", jobs, re.M)
    if match is None:
        raise AssertionError(f"ci.yml has no job {name}")
    return match[1]


def ci_needs(name: str) -> list[str]:
    """The jobs that job ``name`` of ci.yml needs."""
    match = re.search(r"^ {4}needs: (.+)$", ci_job(name), re.M)
    if match is None:
        return []
    return [job.strip() for job in match[1].strip("[]").split(",")]


def ci_gated_jobs() -> list[str]:
    """The jobs of ci.yml that gate must wait for: all but gate and those after it."""
    return [job for job in ci_jobs() if job != "gate" and "gate" not in ci_needs(job)]


def ci_step(job: str, step_id: str) -> str:
    """The lines of the step with ``id: step_id`` among the lines of a job."""
    steps = re.split(r"^(?=      - )", job, flags=re.M)
    marker = re.compile(rf"^ {{8}}id: {re.escape(step_id)}$", re.M)
    found = [step for step in steps if marker.search(step)]
    if len(found) != 1:
        raise AssertionError(f"the job has {len(found)} steps with id {step_id}")
    return found[0]


class SelectTest(unittest.TestCase):
    def test_documentation_runs_the_docs_check(self) -> None:
        paths = [
            "CHANGELOG.md",
            "ROADMAP.md",
            "CONTRIBUTING.md",
            "docs/ci.md",
            "docs/architecture.md",
            "LICENSE",
        ]
        self.assertEqual(changes.select(paths), only("docs"))

    def test_no_change_runs_nothing(self) -> None:
        self.assertEqual(changes.select([]), NOTHING)

    def test_rust_source_runs_the_rust_jobs(self) -> None:
        for path in (
            "nails-api/src/exit.rs",
            "nails-base/src/lib.rs",
            "nails-core/src/lib.rs",
            "nails-forensics/src/lib.rs",
            "nails-oracle/src/verdict.rs",
            "nails-platform/src/lib.rs",
            "nails-session/src/lib.rs",
            "nails-teardown/src/lib.rs",
            "nails-cli/tests/cli_integration.rs",
            "nails-core/benches/performance.rs",
            "benches/performance.rs",
            ".cargo/config.toml",
            ".config/nextest.toml",
            ".config/coverage.toml",
            "rust-toolchain.toml",
            "clippy.toml",
            "justfile",
            "scripts/check-line-count.sh",
            "scripts/check-orphan-modules.sh",
        ):
            with self.subTest(path=path):
                self.assertTrue(changes.select([path])["rust"])

    def test_every_workspace_crate_runs_the_rust_jobs(self) -> None:
        # A crate the filter left out would let a pull request that changes
        # only that crate pass without building or testing anything.
        members = workspace_members()
        self.assertTrue(members)
        for member in members:
            with self.subTest(member=member):
                source = changes.select([f"{member}/src/lib.rs"])
                self.assertEqual(source, only("rust"))
                self.assertTrue(changes.select([f"{member}/Cargo.toml"])["rust"])

    def test_files_the_rust_tests_read_run_the_rust_job(self) -> None:
        # The tests read these from outside the crates: a change to one alone
        # must still run them, or it would pass without the test that checks it.
        for path in (
            "copy-lint.toml",
            "nails.1",
            "docs/assets/screenshots/help.txt",
            "docs/schemas/status.schema.json",
            "docs/schemas/config.schema.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("testdata"))
        for path in (
            "README.md",
            "docs/cli.md",
            "docs/configuration.md",
            "docs/decoy-requirements.md",
            "docs/operator-guide.md",
            "docs/threat-model.md",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("testdata", "docs"))
        for path in (
            "nix/e2e-tests/tests/session/session-lifecycle.nix",
            "nix/e2e-tests/fixtures/configs/unknown-key.toml",
            "nix/e2e-tests/fixtures/indicators.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("testdata", "nix"))

    def test_files_no_rust_test_reads_leave_the_rust_job_alone(self) -> None:
        for path in (
            "docs/README.md",
            "docs/ci.md",
            "docs/schemas.md",
            "docs/assets/screenshots/help.svg",
            "docs/assets/screenshots/check.txt",
            "gui/README.md",
            "nix/e2e-tests/README.md",
            "nix/e2e-tests/lib/helper.sh",
            "nix/e2e-tests/fixtures/forensics/fls-sample.txt",
            "nix/e2e-tests/fixtures/indicators.json.orig",
            "fuzz/copy-lint.toml",
            "nails.1.orig",
        ):
            with self.subTest(path=path):
                selected = changes.select([path])
                self.assertFalse(selected["rust"] or selected["testdata"])

    def test_fuzz_crate_runs_its_own_filter(self) -> None:
        for path in (
            "fuzz/fuzz_targets/utab.rs",
            "fuzz/src/libmount.rs",
            "fuzz/Cargo.lock",
            "fuzz/seeds/utab/odd-lines",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("fuzz"))
        self.assertEqual(changes.select(["fuzz/Cargo.toml"]), only("fuzz", "deps"))
        self.assertEqual(changes.select(["docs/fuzz/notes.md"]), only("docs"))

    def test_side_workspaces_run_their_own_filter(self) -> None:
        for path in (
            "setup/nails-setup/src/wordlist.rs",
            "setup/nails-setup/data/eff_large_wordlist.txt",
            "setup/Cargo.lock",
            "gui/nails-gui/src/main.rs",
            "gui/nails-gui/tests/placeholder.rs",
            "gui/.config/coverage.toml",
            "gui/supply-chain/config.toml",
            "gui/supply-chain/imports.lock",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("side"))
        for path in (
            "setup/Cargo.toml",
            "setup/nails-setup/Cargo.toml",
            "gui/Cargo.toml",
            "gui/nails-gui/Cargo.toml",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("side", "deps"))
        self.assertEqual(changes.select(["docs/setup/notes.md"]), only("docs"))

    def test_gui_graph_and_policy_are_dependency_changes(self) -> None:
        # gui/ has a cargo-deny policy of its own, which the advisory check
        # covers; setup/ has none, so its lock above is no dependency change.
        for path in ("gui/Cargo.lock", "gui/deny.toml"):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("side", "deps"))

    def test_source_file_is_not_a_dependency_change(self) -> None:
        self.assertEqual(changes.select(["nails-core/src/state.rs"]), only("rust"))

    def test_manifests_and_lockfile_are_dependency_changes(self) -> None:
        for path in ("Cargo.toml", "Cargo.lock", "nails-core/Cargo.toml"):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("rust", "deps", "sbom"))

    def test_deny_policy_is_only_a_dependency_change(self) -> None:
        self.assertEqual(changes.select(["deny.toml"]), only("deps"))
        for path in ("docs/deny.toml", "setup/deny.toml"):
            with self.subTest(path=path):
                self.assertFalse(changes.select([path])["deps"])

    def test_nix_files_run_the_nix_jobs(self) -> None:
        for path in (
            "flake.nix",
            "flake.lock",
            "nix/checks.nix",
            "nix/e2e-tests/README.md",
            ".github/actions/setup-nix/cache_plan.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(changes.select([path])["nix"])
        self.assertEqual(changes.select(["flake.lock"]), only("nix", "sbom"))

    def test_ci_tooling_runs_the_tooling_checks(self) -> None:
        for path in (
            ".github/workflows/e2e.yml",
            ".github/zizmor.yml",
            ".github/actions/report-status/report_status.py",
            "ci/e2e/plan.py",
            "scripts/run-e2e-tests.sh",
            "pyproject.toml",
            "nix/e2e-tests/lib/helper.sh",
            "justfile",
        ):
            with self.subTest(path=path):
                self.assertTrue(changes.select([path])["workflows"])
        self.assertEqual(changes.select(["ci/e2e/plan.py"]), only("workflows"))
        # scripts/tests checks the stub `just new-fuzz-target` writes against
        # the fuzz-target check, so a change to it must run them.
        self.assertEqual(changes.select(["justfile"]), only("rust", "workflows"))

    def test_lookalike_paths_match_only_docs(self) -> None:
        paths = ["docs/Cargo.toml.md", "docs/nails-core/notes.md", "docs/flake.nix.md"]
        self.assertEqual(changes.select(paths), only("docs"))

    def test_ci_workflow_or_this_filter_runs_everything(self) -> None:
        for path in (".github/workflows/ci.yml", "ci/changes.py"):
            with self.subTest(path=path):
                self.assertEqual(changes.select(["docs/ci.md", path]), EVERYTHING)

    def test_filters_combine_over_several_paths(self) -> None:
        paths = ["docs/ci.md", "nails-cli/src/main.rs", "flake.nix"]
        self.assertEqual(changes.select(paths), only("rust", "nix", "docs", "sbom"))

    def test_what_the_sbom_is_made_from_runs_the_sbom_check(self) -> None:
        for path in (
            "Cargo.lock",
            "Cargo.toml",
            "nails-cli/Cargo.toml",
            "nails-session/Cargo.toml",
            "rust-toolchain.toml",
            "flake.nix",
            "flake.lock",
            "ci/release.py",
            ".github/workflows/release.yml",
            ".github/workflows/sbom.yml",
        ):
            with self.subTest(path=path):
                self.assertTrue(changes.select([path])["sbom"])
        self.assertEqual(changes.select(["ci/release.py"]), only("workflows", "sbom"))
        self.assertEqual(
            changes.select([".github/workflows/sbom.yml"]), only("workflows", "sbom")
        )

    def test_other_changes_leave_the_sbom_alone(self) -> None:
        for path in (
            "nails-cli/src/main.rs",
            "fuzz/Cargo.toml",
            "fuzz/Cargo.lock",
            "deny.toml",
            "gui/Cargo.toml",
            "gui/Cargo.lock",
            "gui/deny.toml",
            "nix/checks.nix",
            "ci/docs_check.py",
            "ci/e2e/plan.py",
            ".github/workflows/e2e.yml",
            ".github/actions/setup-nix/action.yml",
            "docs/flake.nix.md",
            "docs/ci.md",
        ):
            with self.subTest(path=path):
                self.assertFalse(changes.select([path])["sbom"])


class E2EFilterTest(unittest.TestCase):
    """The path filter of e2e.yml covers everything the binary is built from."""

    def setUp(self) -> None:
        relevant = e2e_filter()
        if relevant is None:
            self.fail("e2e.yml has no relevant='...' path filter")
        self.relevant = relevant

    def test_every_workspace_crate_of_the_binary_runs_the_suite(self) -> None:
        members = workspace_members()
        self.assertLessEqual(NOT_IN_THE_BINARY, set(members))
        for member in members:
            with self.subTest(member=member):
                # cargo reads every member's manifest to resolve the workspace,
                # so each one is part of the binary's source.
                self.assertTrue(self.relevant.search(f"{member}/Cargo.toml"))
                source = self.relevant.search(f"{member}/src/lib.rs")
                if member in NOT_IN_THE_BINARY:
                    self.assertIsNone(source)
                else:
                    self.assertTrue(source)

    def test_what_the_binary_is_built_from_runs_the_suite(self) -> None:
        for path in (
            "nails-api/src/exit.rs",
            "nails-oracle/Cargo.toml",
            ".cargo/config.toml",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.relevant.search(path))

    def test_other_rust_sources_leave_the_suite_alone(self) -> None:
        for path in (
            "nails-oracle/src/verdict.rs",
            "setup/nails-setup/src/wordlist.rs",
            "gui/nails-gui/src/main.rs",
            "fuzz/Cargo.toml",
            "docs/ci.md",
        ):
            with self.subTest(path=path):
                self.assertIsNone(self.relevant.search(path))


class WorkflowTest(unittest.TestCase):
    """ci.yml acts on every filter that select() sets, and gate on every job.

    A filter the workflow drops, or a job that no longer reads one, passes the
    tests above and every check of the pull request: the job just never runs.
    """

    def test_the_changes_job_passes_on_every_filter(self) -> None:
        # The step that runs changes.py writes a line per filter to its
        # outputs, and the job passes each one on under its own name. Every
        # work job runs only on these, so a step that is skipped, that may fail
        # or that writes them anywhere else skips every work job, and gate
        # passes with nothing run. So does a BASE that compares HEAD with
        # itself, which no path differs from.
        job = ci_job("changes")
        self.assertNotRegex(job, r"(?m)^ {4}(if|continue-on-error):")
        step = ci_step(job, "filter")
        self.assertNotRegex(step, r"(?m)^ {8}(if|continue-on-error):")
        self.assertEqual(
            re.findall(r"^ {8}run:(.*)$", step, re.M),
            [' python3 -m ci.changes ${BASE:+--base "$BASE"} >> "$GITHUB_OUTPUT"'],
        )
        self.assertEqual(
            re.findall(r"^ {10}BASE:(.*)$", step, re.M),
            [" ${{ github.event_name == 'pull_request' && 'HEAD^1' || '' }}"],
        )
        passed_on = re.findall(
            r"^ {6}(\w+): \$\{\{ steps\.filter\.outputs\.(\w+) \}\}$", job, re.M
        )
        self.assertCountEqual(passed_on, [(name, name) for name in changes.FILTERS])

    def test_each_job_runs_on_its_filters(self) -> None:
        # Only the job's own if: counts. Read over the whole file, the filter a
        # job dropped would still turn up where another job, or one of the
        # job's steps, reads it. Every job before gate but changes is a work
        # job, whatever it needs, so none can escape the table.
        work = [job for job in ci_gated_jobs() if job != "changes"]
        self.assertCountEqual(work, list(JOB_FILTERS))
        for job, filters in JOB_FILTERS.items():
            with self.subTest(job=job):
                self.assertEqual(ci_needs(job), ["changes"])
                condition = re.search(r"^ {4}if: (.+)$", ci_job(job), re.M)
                if condition is None:
                    raise AssertionError(f"ci.yml's {job} job has no if:")
                self.assertCountEqual(
                    [term.strip() for term in condition[1].split("||")],
                    [f"needs.changes.outputs.{name} == 'true'" for name in filters],
                )

    def test_gate_waits_for_every_job(self) -> None:
        # gate never sees the result of a job it does not need, so that job
        # could fail and gate still pass. That holds for every job but those
        # that run after gate, whether it needs changes or not.
        self.assertCountEqual(ci_needs("gate"), ci_gated_jobs())

    def test_gate_always_runs_and_fails_on_what_it_finds(self) -> None:
        # Without always(), gate is skipped as soon as a job it needs was
        # skipped or failed, and a required check that was skipped counts as
        # passed. With continue-on-error, or with its step skipped, gate passes
        # whatever the step finds.
        job = ci_job("gate")
        self.assertEqual(re.findall(r"^ {4}if:(.*)$", job, re.M), [" always()"])
        self.assertNotRegex(job, r"(?m)^ +continue-on-error:")
        self.assertNotRegex(job, r"(?m)^ {8}if:")

    def test_the_jobs_read_the_filters_and_nothing_else(self) -> None:
        # An output that changes.py does not print is empty, so a job or a step
        # gated on it alone would never run. A filter that no job runs on gates
        # nothing.
        text = CI_WORKFLOW.read_text(encoding="utf-8")
        read = set(re.findall(r"\bneeds\.changes\.outputs\.(\w+)", text))
        self.assertLessEqual(read, set(changes.FILTERS))
        runs_on = {name for filters in JOB_FILTERS.values() for name in filters}
        self.assertEqual(runs_on, set(changes.FILTERS))


def gate_needs(
    changes_result: str = "success",
    filters: dict[str, str] | None = None,
    work: str = "success",
) -> dict[str, dict[str, object]]:
    """The needs context of gate, as toJSON(needs) gives it.

    changes has the result ``changes_result`` and the outputs ``filters``, every
    filter true by default, and each work job has the result ``work``.
    """
    if filters is None:
        filters = dict.fromkeys(changes.FILTERS, "true")
    needs: dict[str, dict[str, object]] = {
        "changes": {"result": changes_result, "outputs": filters}
    }
    for job in JOB_FILTERS:
        needs[job] = {"result": work, "outputs": {}}
    return needs


class GateTest(unittest.TestCase):
    """gate passes only when changes set the filters and no job went red.

    The script of gate's step runs here as the runner runs it, with bash and jq.
    """

    NO_FILTERS = "::error::changes did not set the path filters the work jobs run on\n"

    def run_gate(
        self, needs: dict[str, dict[str, object]]
    ) -> subprocess.CompletedProcess[str]:
        if shutil.which("jq") is None:
            self.fail("jq, which gate runs, is not installed")
        found = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", ci_job("gate"), re.M)
        if found is None:
            raise AssertionError("ci.yml's gate job has no run: | script")
        script = textwrap.dedent(found[1])
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        env = {
            **os.environ,
            "NEEDS": json.dumps(needs),
            "GITHUB_STEP_SUMMARY": str(Path(tmp) / "summary.md"),
        }
        # The shell the runner starts for a run: step of shell bash.
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def test_passes_when_every_job_passed(self) -> None:
        result = self.run_gate(gate_needs())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_passes_when_the_filters_skipped_every_job(self) -> None:
        # A change no filter matches, such as an image under docs/assets/.
        filters = dict.fromkeys(changes.FILTERS, "false")
        result = self.run_gate(gate_needs(filters=filters, work="skipped"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fails_when_a_job_failed_or_was_cancelled(self) -> None:
        for red in ("failure", "cancelled"):
            with self.subTest(result=red):
                needs = gate_needs()
                needs["rust"]["result"] = red
                result = self.run_gate(needs)
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error::Failed or cancelled: rust\n", result.stdout)

    def test_fails_when_changes_set_no_filters(self) -> None:
        # Skipped, or passed without writing its outputs: every work job was
        # skipped then, so none could fail. The runner leaves an empty output
        # out of the context, and one it kept fails as well.
        empty = dict.fromkeys(changes.FILTERS, "")
        for result_of_changes, filters in (
            ("skipped", {}),
            ("success", {}),
            ("success", empty),
        ):
            with self.subTest(changes=result_of_changes, filters=filters):
                needs = gate_needs(result_of_changes, filters, work="skipped")
                result = self.run_gate(needs)
                self.assertEqual(result.returncode, 1)
                self.assertIn(self.NO_FILTERS, result.stdout)

    def test_fails_on_a_filter_that_is_neither_true_nor_false(self) -> None:
        filters = {**dict.fromkeys(changes.FILTERS, "false"), "rust": "yes"}
        result = self.run_gate(gate_needs(filters=filters, work="skipped"))
        self.assertEqual(result.returncode, 1)
        self.assertIn(self.NO_FILTERS, result.stdout)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=CI Test",
            "-c",
            "user.email=ci-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def write(repo: Path, path: str, text: str = "x\n") -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class ChangedPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        # A hook or an outer repository must not redirect git in the scratch repo.
        scrubbed = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        env = mock.patch.dict(os.environ, scrubbed, clear=True)
        env.start()
        self.addCleanup(env.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, "init", "--quiet")
        write(self.repo, "nails-core/src/lib.rs", "pub fn old() {}\n")
        write(self.repo, "docs/ci.md")
        git(self.repo, "add", "--all")
        git(self.repo, "commit", "--quiet", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")

    def test_lists_added_modified_and_removed_paths(self) -> None:
        write(self.repo, "docs/ci.md", "changed\n")
        write(self.repo, "deny.toml")
        (self.repo / "nails-core/src/lib.rs").unlink()
        git(self.repo, "add", "--all")
        git(self.repo, "commit", "--quiet", "-m", "change")
        paths = changes.changed_paths(self.base, self.repo)
        self.assertEqual(
            sorted(paths or []), ["deny.toml", "docs/ci.md", "nails-core/src/lib.rs"]
        )

    def test_a_move_counts_at_both_paths(self) -> None:
        git(self.repo, "mv", "nails-core/src/lib.rs", "docs/lib.rs")
        git(self.repo, "commit", "--quiet", "-m", "move")
        paths = changes.changed_paths(self.base, self.repo)
        self.assertEqual(sorted(paths or []), ["docs/lib.rs", "nails-core/src/lib.rs"])
        self.assertTrue(changes.select(paths or [])["rust"])

    def test_unknown_base_is_none(self) -> None:
        self.assertIsNone(changes.changed_paths("no-such-revision", self.repo))

    def test_same_revision_has_no_paths(self) -> None:
        self.assertEqual(changes.changed_paths(self.base, self.repo), [])


class MainTest(unittest.TestCase):
    def run_main(self, *argv: str) -> list[str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(changes.main(list(argv)), 0)
        return out.getvalue().splitlines()

    def test_without_base_every_filter_is_true(self) -> None:
        self.assertEqual(
            self.run_main(),
            [
                "rust=true",
                "testdata=true",
                "fuzz=true",
                "side=true",
                "deps=true",
                "nix=true",
                "workflows=true",
                "docs=true",
                "sbom=true",
            ],
        )

    def test_unknown_base_runs_everything(self) -> None:
        with mock.patch.object(changes, "changed_paths", return_value=None):
            self.assertEqual(
                self.run_main("--base", "HEAD^1"),
                [
                    "rust=true",
                    "testdata=true",
                    "fuzz=true",
                    "side=true",
                    "deps=true",
                    "nix=true",
                    "workflows=true",
                    "docs=true",
                    "sbom=true",
                ],
            )

    def test_prints_github_output_lines(self) -> None:
        with mock.patch.object(changes, "changed_paths", return_value=["deny.toml"]):
            self.assertEqual(
                self.run_main("--base", "HEAD^1"),
                [
                    "rust=false",
                    "testdata=false",
                    "fuzz=false",
                    "side=false",
                    "deps=true",
                    "nix=false",
                    "workflows=false",
                    "docs=false",
                    "sbom=false",
                ],
            )


if __name__ == "__main__":
    unittest.main()
