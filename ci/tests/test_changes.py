"""Tests for ci/changes.py, the path filter of ci.yml, and for that of e2e.yml."""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from ci import changes

REPO_ROOT = Path(__file__).resolve().parents[2]
# The crates of the root workspace that the nails binary never links: flake.nix
# builds it from their manifests alone, so their sources cannot change a VM
# test, and a change to them must not boot one.
NOT_IN_THE_BINARY = frozenset({"nails-oracle"})

NOTHING = {
    "rust": False,
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
    "fuzz": True,
    "side": True,
    "deps": True,
    "nix": True,
    "workflows": True,
    "docs": True,
    "sbom": True,
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


class SelectTest(unittest.TestCase):
    def test_documentation_runs_the_docs_check(self) -> None:
        paths = ["README.md", "CHANGELOG.md", "ROADMAP.md", "docs/ci.md", "LICENSE"]
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
            "gui/Cargo.lock",
        ):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("side"))
        for path in ("setup/Cargo.toml", "setup/nails-setup/Cargo.toml"):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("side", "deps"))
        self.assertEqual(changes.select(["docs/setup/notes.md"]), only("docs"))

    def test_source_file_is_not_a_dependency_change(self) -> None:
        self.assertEqual(changes.select(["nails-core/src/state.rs"]), only("rust"))

    def test_manifests_and_lockfile_are_dependency_changes(self) -> None:
        for path in ("Cargo.toml", "Cargo.lock", "nails-core/Cargo.toml"):
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), only("rust", "deps", "sbom"))

    def test_deny_policy_is_only_a_dependency_change(self) -> None:
        self.assertEqual(changes.select(["deny.toml"]), only("deps"))

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
        ):
            with self.subTest(path=path):
                self.assertTrue(changes.select([path])["workflows"])
        self.assertEqual(changes.select(["ci/e2e/plan.py"]), only("workflows"))

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
