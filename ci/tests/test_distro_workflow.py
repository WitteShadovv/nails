"""Tests for distro-e2e.yml: its path filter, its choice of suites, its gating
drivers and its result.

The scripts of the workflow's steps run here as the runner runs them, with bash
(and git and python3 for the choice of suites, coreutils and a stand-in for nix
for the drivers, jq for nothing: the result step reads plain values).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from ci.e2e import distro

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "distro-e2e.yml"
DISTRO_TESTS = REPO_ROOT / "nix" / "distro-tests"
# The crates of the root workspace that the nails binary never links: flake.nix
# builds it from their manifests alone, so their sources cannot change a
# scenario.
NOT_IN_THE_BINARY = frozenset({"nails-oracle"})

# A relative path literal in a Nix file: ./x or ../x, in code or in an
# interpolation such as "${../e2e-tests/py}".
NIX_PATH = re.compile(r"(?<![\w./+-])(\.\.?/[\w./+-]+)")
# A comment: from a # at the start of a line or after a blank to its end.
NIX_COMMENT = re.compile(r"(^|\s)#.*$", re.M)


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


def distro_filter() -> re.Pattern[str]:
    """The path filter of the plan job's select step."""
    found = re.search(
        r"^\s*relevant='([^']+)'$", step(job("plan"), "select"), re.MULTILINE
    )
    if found is None:
        raise AssertionError("distro-e2e.yml has no relevant='...' path filter")
    return re.compile(found[1])


def workspace_members() -> list[str]:
    with (REPO_ROOT / "Cargo.toml").open("rb") as handle:
        members: list[str] = tomllib.load(handle)["workspace"]["members"]
    return members


def nix_inputs() -> dict[str, Path]:
    """What the Nix files of the tier read, by repository path.

    Every relative path literal of every Nix file under nix/distro-tests, and of
    every Nix file outside it that one of them imports, resolved against its
    file. Comments are left out.
    """
    found: dict[str, Path] = {}
    queue = sorted(DISTRO_TESTS.rglob("*.nix"))
    scanned: set[Path] = set()
    while queue:
        nix = queue.pop()
        if nix in scanned:
            continue
        scanned.add(nix)
        code = NIX_COMMENT.sub("", nix.read_text(encoding="utf-8"))
        for literal in NIX_PATH.findall(code):
            target = (nix.parent / literal).resolve()
            path = target.relative_to(REPO_ROOT).as_posix()
            found[path] = nix
            if target.suffix == ".nix":
                if not target.is_file():
                    raise AssertionError(
                        f"{nix.relative_to(REPO_ROOT)} imports {path}, which is "
                        "missing here (outside the ci-python check's files?)"
                    )
                queue.append(target)
    return found


class DistroFilterTest(unittest.TestCase):
    """The path filter covers everything the scenarios and drivers are built from."""

    def setUp(self) -> None:
        self.relevant = distro_filter()

    def covers(self, path: str) -> bool:
        """Whether the filter matches the path, or anything below it."""
        return bool(self.relevant.search(path) or self.relevant.search(f"{path}/x"))

    def test_every_workspace_crate_of_the_binary_runs_the_tier(self) -> None:
        members = workspace_members()
        self.assertLessEqual(NOT_IN_THE_BINARY, set(members))
        for member in members:
            with self.subTest(member=member):
                self.assertTrue(self.relevant.search(f"{member}/Cargo.toml"))
                source = self.relevant.search(f"{member}/src/lib.rs")
                if member in NOT_IN_THE_BINARY:
                    self.assertIsNone(source)
                else:
                    self.assertTrue(source)

    def test_what_the_binary_and_the_vms_are_built_from_runs_the_tier(self) -> None:
        for path in (
            "nails-api/src/exit.rs",
            "nails-oracle/Cargo.toml",
            ".cargo/config.toml",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "flake.nix",
            "flake.lock",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.relevant.search(path))

    def test_the_scan_finds_what_the_tier_reads_outside_it(self) -> None:
        # A scan that found nothing would pass the test below on nothing.
        outside = {
            path for path in nix_inputs() if not path.startswith("nix/distro-tests/")
        }
        self.assertLessEqual(
            {
                "flake.lock",
                "nix/e2e-tests/py",
                "nix/e2e-tests/lib/records.py",
                "nix/e2e-tests/lib/disk-forensics.nix",
                "nix/e2e-tests/lib/disk_forensics.py",
                "nix/e2e-tests/fixtures/indicators.json",
            },
            outside,
        )

    def test_every_file_the_tier_reads_runs_the_tier(self) -> None:
        for path, reader in nix_inputs().items():
            with self.subTest(path=path, reader=reader.name):
                self.assertTrue(self.covers(path))

    def test_the_tier_and_its_wiring_run_the_tier(self) -> None:
        for path in (
            "nix/distro-tests/images.json",
            "nix/distro-tests/py/distro_checks.py",
            "nix/distro-tests/tests/session-records.nix",
            "nix/e2e-tests/py/nails_e2e/session.py",
            "ci/e2e/distro.py",
            ".github/actions/setup-nix/action.yml",
            ".github/workflows/distro-e2e.yml",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.relevant.search(path))

    def test_other_changes_leave_the_tier_alone(self) -> None:
        for path in (
            "nails-oracle/src/verdict.rs",
            "setup/nails-setup/src/wordlist.rs",
            "gui/nails-gui/src/main.rs",
            "fuzz/Cargo.toml",
            "docs/ci.md",
            "README.md",
            "nix/checks.nix",
            "nix/e2e-tests/tests/session/session-lifecycle.nix",
            "nix/e2e-tests/lib/vm-config.nix",
            "nix/e2e-tests/fixtures/indicators.json.orig",
            ".github/workflows/e2e.yml",
            "docs/nix/distro-tests/notes.md",
        ):
            with self.subTest(path=path):
                self.assertIsNone(self.relevant.search(path))


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


class SelectTest(unittest.TestCase):
    """The select step picks the suites by event, and filters pull requests.

    It runs in a scratch repository whose HEAD^1 is the base, as the first
    parent of a pull request's merge commit is.
    """

    def setUp(self) -> None:
        scrubbed = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.environ = scrubbed
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.repo = Path(tmp) / "repo"
        self.repo.mkdir()
        self.output = Path(tmp) / "output"
        git(self.repo, "init", "--quiet")
        write(self.repo, "nails-core/src/lib.rs", "pub fn old() {}\n")
        write(self.repo, "nix/distro-tests/records.nix", "{ }\n")
        write(self.repo, "docs/ci.md")
        git(self.repo, "add", "--all")
        git(self.repo, "commit", "--quiet", "-m", "base")

    def change(self, *paths: str) -> None:
        for path in paths:
            write(self.repo, path, "changed\n")
        git(self.repo, "add", "--all")
        git(self.repo, "commit", "--quiet", "-m", "change")

    def select(self, **env: str) -> tuple[int, dict[str, str], str]:
        defaults = {
            "EVENT_NAME": "pull_request",
            "EVENT_ACTION": "synchronize",
            "EVENT_LABEL": "",
            "LABELLED": "false",
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
            cwd=self.repo,
            env={
                **self.environ,
                **defaults,
                **env,
                "GITHUB_OUTPUT": str(self.output),
            },
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

    def assert_selects(self, suites: str, unchanged: str = "false", **env: str) -> None:
        code, outputs, log = self.select(**env)
        self.assertEqual(code, 0, log)
        self.assertEqual(outputs.get("suites"), suites, log)
        self.assertEqual(outputs.get("unchanged"), unchanged, log)

    def test_a_push_that_changes_the_binary_runs_records_and_refusal(self) -> None:
        self.change("nails-core/src/lib.rs")
        self.assert_selects("records refusal")

    def test_a_push_that_changes_the_tier_runs_records_and_refusal(self) -> None:
        self.change("nix/distro-tests/records.nix")
        self.assert_selects("records refusal", EVENT_ACTION="opened")

    def test_a_push_outside_the_paths_tests_nothing(self) -> None:
        self.change("docs/ci.md")
        self.assert_selects("", unchanged="true")
        self.assert_selects("", unchanged="true", LABELLED="true")

    def test_a_labelled_pull_request_runs_every_suite_on_a_push(self) -> None:
        self.change("nails-core/src/lib.rs")
        self.assert_selects("all", LABELLED="true", EVENT_ACTION="reopened")

    def test_adding_the_label_runs_every_suite_whatever_changed(self) -> None:
        self.change("docs/ci.md")
        self.assert_selects(
            "all", EVENT_ACTION="labeled", EVENT_LABEL="distro-e2e", LABELLED="true"
        )

    def test_a_file_moved_out_of_the_paths_counts_as_a_change(self) -> None:
        git(self.repo, "mv", "nix/distro-tests/records.nix", "docs/records.nix")
        git(self.repo, "commit", "--quiet", "-m", "move")
        self.assert_selects("records refusal")

    def test_a_long_list_of_changes_is_read_in_full(self) -> None:
        # Enough names to fill a pipe, the one that matters sorted first.
        paths = [f"docs/notes/{index:05}-{'x' * 60}.md" for index in range(1500)]
        self.change(".cargo/config.toml", *paths)
        self.assert_selects("records refusal")

    def test_an_unknown_base_runs_the_suites(self) -> None:
        # The base commit has no parent: HEAD^1 does not resolve.
        self.assert_selects("records refusal")

    def test_a_run_that_is_no_pull_request_runs_every_suite(self) -> None:
        self.change("docs/ci.md")
        for event in ("schedule", "workflow_dispatch", "push"):
            with self.subTest(event=event):
                self.assert_selects("all", EVENT_NAME=event)

    def test_an_input_names_the_suite_and_is_not_filtered(self) -> None:
        self.change("docs/ci.md")
        for suite in ("all", "smoke", "records", "refusal", "probe", "staged"):
            with self.subTest(suite=suite):
                self.assert_selects(suite, SUITE_INPUT=suite)
                self.assert_selects(
                    suite, SUITE_INPUT=suite, EVENT_NAME="workflow_dispatch"
                )

    def test_an_unknown_suite_fails(self) -> None:
        code, _, log = self.select(SUITE_INPUT="oracle")
        self.assertEqual(code, 1)
        self.assertIn("::error::suite must be", log)

    def test_the_runner_and_the_ceiling_are_checked(self) -> None:
        self.change("nails-core/src/lib.rs")
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
            "UNCHANGED": "false",
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
        result = self.report(
            SUITES="staged",
            GATING_JOBS="0",
            GATING_RESULT="skipped",
            DISTRO_RESULT="failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("::warning::One or more staged scenarios", result.stdout)

    def test_passes_a_run_that_planned_no_gating_job(self) -> None:
        result = self.report(SUITES="smoke", GATING_JOBS="0", GATING_RESULT="skipped")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_passes_a_pull_request_the_path_filter_skipped(self) -> None:
        result = self.report(
            SUITES="",
            UNCHANGED="true",
            DISTRO_JOBS="0",
            GATING_JOBS="0",
            DISTRO_RESULT="skipped",
            GATING_RESULT="skipped",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("No change under the distro paths", result.stdout)

    def test_passes_a_run_for_another_label(self) -> None:
        result = self.report(
            PLAN_RESULT="skipped",
            SUITES="",
            UNCHANGED="",
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
            {"SUITES": "", "UNCHANGED": ""},
            {"GATING_JOBS": ""},
            {"DISTRO_JOBS": ""},
        ):
            with self.subTest(env=env):
                result = self.report(
                    **env, DISTRO_RESULT="skipped", GATING_RESULT="skipped"
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error::The plan set no suites", result.stdout)


# A stand-in for nix. `nix build --print-build-logs --out-link <link> <attr>`
# logs the attribute and links a copy of the stand-in driver, or fails when
# FAKE_BUILD says so.
FAKE_NIX = """\
set -eu
[ "$1" = build ] || exit 2
shift
link=
attr=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --print-build-logs) ;;
    --out-link) link=$2; shift ;;
    *) attr=$1 ;;
  esac
  shift
done
echo "build $attr" >> "$FAKE_LOG"
[ "${FAKE_BUILD:-pass}" = pass ] || exit 1
mkdir -p "$link/bin"
cp "$FAKE_DRIVER_SCRIPT" "$link/bin/test-driver"
chmod +x "$link/bin/test-driver"
"""

# A stand-in for a driver's bin/test-driver. It logs where it runs and what
# its stdin holds, then passes, fails or hangs as FAKE_DRIVER says.
FAKE_DRIVER = """\
stdin=$(cat)
printf 'run %s %s %s [%s]\\n' "$PWD" "$TMPDIR" "$XDG_RUNTIME_DIR" "$stdin" \\
  >> "$FAKE_LOG"
case "$FAKE_DRIVER" in
  pass) exit 0 ;;
  fail) exit 3 ;;
  *) exec sleep 30 ;;
esac
"""


class GatingStepTest(unittest.TestCase):
    """The gating job's step fails when its driver fails, hangs or is missing.

    That step is all that turns a failed records scenario or refusal into a
    failed job, and so into a red distro-result. It runs here as the runner
    runs it, with coreutils' timeout and a stand-in for nix whose build links
    a stand-in driver.
    """

    def setUp(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.fail("bash, which the step runs in, is not installed")
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runner_temp = tmp / "runner-temp"
        self.runner_temp.mkdir()
        self.log = tmp / "log"
        tools = tmp / "tools"
        tools.mkdir()
        driver = tmp / "test-driver"
        # bash from PATH, not /usr/bin/env, which does not exist in the
        # hermetic Nix build sandbox the ci-python check runs in.
        for path, text in ((tools / "nix", FAKE_NIX), (driver, FAKE_DRIVER)):
            path.write_text(f"#!{bash}\n{text}", encoding="utf-8")
            path.chmod(0o755)
        self.environ = {
            **os.environ,
            "PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}",
            "RUNNER_TEMP": str(self.runner_temp),
            "FAKE_LOG": str(self.log),
            "FAKE_DRIVER_SCRIPT": str(driver),
        }

    def run_step(self, driver: str = "pass", **env: str) -> tuple[int, str, list[str]]:
        """The step's exit status, its output, and what nix and the driver logged."""
        defaults = {
            "TESTS": "ubuntu-24.04-records",
            "DRIVER_SECONDS": "60",
            "FAKE_DRIVER": driver,
        }
        result = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                script(step(job("gating"), "driver")),
            ],
            env={**self.environ, **defaults, **env},
            # The driver must not read the job's stdin.
            input="a line on the step's stdin\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        logged: list[str] = []
        if self.log.exists():
            logged = self.log.read_text(encoding="utf-8").splitlines()
        return result.returncode, result.stdout + result.stderr, logged

    def test_a_driver_that_passes_passes_the_job(self) -> None:
        code, output, logged = self.run_step()
        self.assertEqual(code, 0, output)
        scratch = self.runner_temp / "vm"
        self.assertEqual(
            logged,
            [
                'build .#legacyPackages.x86_64-linux.e2e-distro."ubuntu-24.04-records"',
                f"run {scratch} {scratch} {scratch} []",
            ],
        )

    def test_a_driver_that_fails_fails_the_job_with_its_status(self) -> None:
        code, output, logged = self.run_step("fail")
        self.assertEqual(code, 3, output)
        self.assertEqual(len(logged), 2, logged)
        self.assertNotIn("::error::", output)

    def test_a_driver_past_its_time_limit_fails_the_job(self) -> None:
        code, output, _ = self.run_step("hang", DRIVER_SECONDS="1")
        self.assertEqual(code, 124, output)
        self.assertIn(
            "::error::ubuntu-24.04-records ran past its time limit of 1 s.", output
        )

    def test_a_job_without_a_driver_fails(self) -> None:
        code, output, logged = self.run_step(TESTS="")
        self.assertEqual(code, 1, output)
        self.assertIn("::error::The plan gave this job no driver to run.", output)
        self.assertEqual(logged, [])

    def test_a_driver_that_does_not_build_fails_the_job(self) -> None:
        code, output, logged = self.run_step(FAKE_BUILD="fail")
        self.assertNotEqual(code, 0, output)
        self.assertEqual(len(logged), 1, logged)

    def test_a_job_without_a_time_limit_fails(self) -> None:
        code, output, logged = self.run_step(DRIVER_SECONDS="")
        self.assertNotEqual(code, 0, output)
        self.assertFalse([line for line in logged if line.startswith("run ")])


class WorkflowShapeTest(unittest.TestCase):
    """The jobs are wired so that no gating job escapes distro-result."""

    def test_no_job_or_step_lets_a_failure_pass(self) -> None:
        # continue-on-error would pass a job whose driver failed.
        self.assertNotIn("continue-on-error", workflow_text())

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
