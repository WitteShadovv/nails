"""Tests for .github/actions/report-status/report_status.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "report-status"
SCRIPT = ACTION / "report_status.py"

_spec = importlib.util.spec_from_file_location("report_status", SCRIPT)
assert _spec is not None and _spec.loader is not None
report_status = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report_status)


def needs(**results: str) -> str:
    """A toJSON(needs) document with the given job results."""
    return json.dumps({job: {"result": r, "outputs": {}} for job, r in results.items()})


def run_env(**overrides: str) -> dict[str, str]:
    env = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_RUN_ID": "4242",
        "GITHUB_RUN_NUMBER": "17",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW": "Scheduled",
        "GITHUB_REF_NAME": "main",
        # Low entropy on purpose: a realistic hash trips the secret scanner.
        "GITHUB_SHA": "a" * 40,
        "GITHUB_EVENT_NAME": "schedule",
        "LABEL": "ci-red",
        "TITLE": "",
        "NEEDS": needs(build="success"),
    }
    env.update(overrides)
    return env


class FakeGh:
    """Stands in for the gh CLI: canned listings, recorded calls."""

    def __init__(
        self,
        issues: list[dict[str, Any]] | None = None,
        labels: list[str] | None = None,
    ) -> None:
        self.issues = issues or []
        self.labels = labels if labels is not None else ["ci-red", "advisory"]
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str) -> str:
        self.calls.append(args)
        if args[:2] == ("issue", "list"):
            label = args[args.index("--label") + 1]
            return json.dumps(
                [i for i in self.issues if label in i.get("labels", [label])]
            )
        if args[:2] == ("label", "list"):
            return json.dumps([{"name": name} for name in self.labels])
        if args[:2] == ("issue", "create"):
            return "https://github.com/owner/repo/issues/99\n"
        return ""

    def writes(self) -> list[tuple[str, ...]]:
        """Every call that changes something on GitHub."""
        return [c for c in self.calls if c[1] not in ("list", "view")]


class ClassifyTests(unittest.TestCase):
    def test_a_failed_job_makes_the_run_red(self) -> None:
        verdict = report_status.classify(needs(lint="success", test="failure"))
        self.assertEqual(verdict, ("red", [("test", "failure")]))

    def test_a_cancelled_job_makes_the_run_red(self) -> None:
        # A job that hit its timeout is cancelled; that must not read as green.
        verdict = report_status.classify(needs(stress="cancelled"))
        self.assertEqual(verdict.kind, "red")

    def test_red_wins_over_skipped(self) -> None:
        verdict = report_status.classify(needs(a="skipped", b="failure"))
        self.assertEqual(verdict, ("red", [("b", "failure")]))

    def test_every_job_passing_is_green(self) -> None:
        verdict = report_status.classify(needs(a="success", b="success"))
        self.assertEqual(verdict, ("green", []))

    def test_a_skipped_job_without_failures_is_partial(self) -> None:
        verdict = report_status.classify(needs(a="success", b="skipped"))
        self.assertEqual(verdict, ("partial", [("b", "skipped")]))

    def test_malformed_needs_are_rejected(self) -> None:
        for bad in ("", "not json", "[]", "{}", '{"a": {}}', '{"a": "success"}'):
            with self.subTest(needs=bad), self.assertRaises(ValueError):
                report_status.classify(bad)


class ReportTests(unittest.TestCase):
    def test_first_red_run_opens_one_issue(self) -> None:
        gh = FakeGh()
        env = run_env(NEEDS=needs(canary="failure", warm="success"))
        outcome = report_status.report(env, gh)

        creates = [c for c in gh.writes() if c[:2] == ("issue", "create")]
        self.assertEqual(len(creates), 1)
        self.assertEqual(gh.writes(), creates)
        args = creates[0]
        self.assertEqual(args[args.index("--title") + 1], "CI red: Scheduled")
        self.assertEqual(args[args.index("--label") + 1], "ci-red")
        body = args[args.index("--body") + 1]
        self.assertIn("https://github.com/owner/repo/actions/runs/4242", body)
        self.assertIn("- `canary`: failure", body)
        self.assertIn("on `main` at aaaaaaaaaaaa, triggered by `schedule`", body)
        self.assertNotIn("warm", body)
        self.assertIn("issues/99", outcome)

    def test_a_missing_label_is_created_before_the_issue(self) -> None:
        gh = FakeGh(labels=["bug"])
        report_status.report(run_env(NEEDS=needs(a="failure")), gh)
        self.assertEqual(
            [c[:3] for c in gh.writes()],
            [("label", "create", "ci-red"), ("issue", "create", "--title")],
        )

    def test_second_red_run_comments_on_the_open_issue(self) -> None:
        gh = FakeGh(issues=[{"number": 7, "title": "CI red: Scheduled"}])
        outcome = report_status.report(run_env(NEEDS=needs(a="failure")), gh)
        self.assertEqual(len(gh.writes()), 1)
        self.assertEqual(gh.writes()[0][:3], ("issue", "comment", "7"))
        self.assertIn("#7", outcome)

    def test_an_issue_with_another_title_is_left_alone(self) -> None:
        gh = FakeGh(issues=[{"number": 7, "title": "CI red: Release"}])
        report_status.report(run_env(NEEDS=needs(a="failure")), gh)
        self.assertEqual([c[:2] for c in gh.writes()], [("issue", "create")])

    def test_green_run_closes_the_open_issue(self) -> None:
        gh = FakeGh(issues=[{"number": 7, "title": "CI red: Scheduled"}])
        outcome = report_status.report(run_env(NEEDS=needs(a="success")), gh)
        self.assertEqual(len(gh.writes()), 1)
        close = gh.writes()[0]
        self.assertEqual(close[:3], ("issue", "close", "7"))
        self.assertIn("actions/runs/4242", close[close.index("--comment") + 1])
        self.assertIn("closed #7", outcome)

    def test_green_run_without_an_issue_changes_nothing(self) -> None:
        gh = FakeGh()
        report_status.report(run_env(NEEDS=needs(a="success")), gh)
        self.assertEqual(gh.writes(), [])

    def test_partial_run_never_touches_github(self) -> None:
        gh = FakeGh(issues=[{"number": 7, "title": "CI red: Scheduled"}])
        env = run_env(NEEDS=needs(a="success", b="skipped"))
        outcome = report_status.report(env, gh)
        self.assertEqual(gh.calls, [])
        self.assertIn("b (skipped)", outcome)

    def test_advisory_label_never_sees_the_ci_red_issue(self) -> None:
        gh = FakeGh(
            issues=[
                {"number": 7, "title": "Dependency advisories", "labels": ["ci-red"]},
                {"number": 8, "title": "Dependency advisories", "labels": ["advisory"]},
            ]
        )
        env = run_env(
            LABEL="advisory",
            TITLE="Dependency advisories",
            NEEDS=needs(advisories="failure"),
        )
        report_status.report(env, gh)
        self.assertEqual(gh.writes()[0][:3], ("issue", "comment", "8"))
        listing = gh.calls[0]
        self.assertEqual(listing[listing.index("--label") + 1], "advisory")

    def test_a_rerun_names_its_attempt(self) -> None:
        gh = FakeGh()
        env = run_env(GITHUB_RUN_ATTEMPT="2", NEEDS=needs(a="failure"))
        report_status.report(env, gh)
        body = gh.writes()[0][gh.writes()[0].index("--body") + 1]
        self.assertIn("run #17 (attempt 2)", body)

    def test_an_empty_label_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            report_status.report(run_env(LABEL=""), FakeGh())


class MainTests(unittest.TestCase):
    def run_main(self, env: dict[str, str], gh: object) -> tuple[int, str]:
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, env, clear=True),
            contextlib.redirect_stdout(out),
        ):
            code = report_status.main(gh)
        return code, out.getvalue()

    def test_outcome_lands_in_the_step_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            env = run_env(GITHUB_STEP_SUMMARY=str(summary))
            code, _ = self.run_main(env, FakeGh())
            self.assertEqual(code, 0)
            self.assertIn("report-status: All jobs passed", summary.read_text())

    def test_a_failing_gh_call_is_reported_as_an_error(self) -> None:
        def broken(*args: str) -> str:
            raise subprocess.CalledProcessError(
                1, ["gh", *args], stderr="HTTP 403: Resource not accessible\n"
            )

        code, out = self.run_main(run_env(NEEDS=needs(a="failure")), broken)
        self.assertEqual(code, 1)
        self.assertIn("::error title=report-status::gh issue list failed", out)
        self.assertIn("HTTP 403", out)

    def test_bad_input_is_reported_as_an_error(self) -> None:
        code, out = self.run_main(run_env(NEEDS="{}"), FakeGh())
        self.assertEqual(code, 1)
        self.assertIn("::error title=report-status::", out)


class ActionTests(unittest.TestCase):
    def test_the_action_runs_this_script(self) -> None:
        action = (ACTION / "action.yml").read_text(encoding="utf-8")
        self.assertIn('"$GITHUB_ACTION_PATH/report_status.py"', action)


if __name__ == "__main__":
    unittest.main()
