"""Keep one tracking issue in step with a workflow's unattended runs.

action.yml runs this as the last job of the runs nobody watches: pushes to
main and next, schedules and releases. It reads the calling job's `needs`
context (NEEDS, as JSON) and decides:

red
    A needed job failed or was cancelled. The open issue with LABEL and TITLE
    gets a comment naming the run and the red jobs; without one, it is
    created.
green
    Every needed job passed. That issue, if open, is closed.
partial
    Nothing failed, but some jobs were skipped (a single dispatched task, a
    condition that excluded them). A skipped job proves nothing, so the issue
    stays as it is.

Issues are matched on label and exact title, so the ci-red issue of one
workflow and the advisory issue of another never touch each other.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import NamedTuple

RED_RESULTS = ("failure", "cancelled")
GREEN_RESULT = "success"

# Colour and description of the labels this action may have to create.
KNOWN_LABELS = {
    "ci-red": ("B60205", "An unattended CI run (main, schedule, release) is red"),
    "advisory": ("FBCA04", "A dependency advisory or policy finding to triage"),
}
OTHER_LABEL = ("EDEDED", "Tracked by the report-status action")

Gh = Callable[..., str]


class Verdict(NamedTuple):
    kind: str
    # (job, result) pairs: the red jobs for "red", the skipped ones for
    # "partial", nothing for "green".
    jobs: list[tuple[str, str]]


def classify(needs_json: str) -> Verdict:
    """Sort a `toJSON(needs)` document into red, green or partial."""
    try:
        needs = json.loads(needs_json)
    except json.JSONDecodeError as error:
        raise ValueError(f"needs is not JSON: {error}") from None
    if not isinstance(needs, dict) or not needs:
        raise ValueError("needs must be the non-empty needs context of the job")
    results: list[tuple[str, str]] = []
    for job, entry in needs.items():
        result = entry.get("result") if isinstance(entry, dict) else None
        if not isinstance(result, str):
            raise ValueError(f"needs.{job} has no result")
        results.append((job, result))
    red = [(job, result) for job, result in results if result in RED_RESULTS]
    if red:
        return Verdict("red", red)
    other = [(job, result) for job, result in results if result != GREEN_RESULT]
    if other:
        return Verdict("partial", other)
    return Verdict("green", [])


def run_gh(*args: str) -> str:
    completed = subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True
    )
    return completed.stdout


def find_issue(gh: Gh, label: str, title: str) -> int | None:
    fields = ("--json", "number,title", "--limit", "100")
    listed = gh("issue", "list", "--state", "open", "--label", label, *fields)
    for issue in json.loads(listed or "[]"):
        if issue.get("title") == title:
            return int(issue["number"])
    return None


def ensure_label(gh: Gh, label: str) -> None:
    listed = gh("label", "list", "--search", label, "--json", "name", "--limit", "100")
    if any(entry.get("name") == label for entry in json.loads(listed or "[]")):
        return
    colour, description = KNOWN_LABELS.get(label, OTHER_LABEL)
    gh("label", "create", label, "--color", colour, "--description", description)


def describe_run(env: Mapping[str, str]) -> str:
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    url = f"{server}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    attempt = env.get("GITHUB_RUN_ATTEMPT", "1")
    run = f"run #{env.get('GITHUB_RUN_NUMBER', '?')}"
    if attempt != "1":
        run += f" (attempt {attempt})"
    sha = env.get("GITHUB_SHA", "")[:12]
    return (
        f"[{env.get('GITHUB_WORKFLOW', 'workflow')} {run}]({url}) "
        f"on `{env.get('GITHUB_REF_NAME', '?')}` at {sha}, "
        f"triggered by `{env.get('GITHUB_EVENT_NAME', '?')}`"
    )


def report(env: Mapping[str, str], gh: Gh = run_gh) -> str:
    """Apply the verdict for this run; returns what was done, for the log."""
    label = env.get("LABEL", "")
    if not label:
        raise ValueError("label must not be empty")
    title = env.get("TITLE") or f"CI red: {env.get('GITHUB_WORKFLOW', 'workflow')}"
    verdict = classify(env.get("NEEDS", ""))
    run = describe_run(env)

    if verdict.kind == "partial":
        skipped = ", ".join(f"{job} ({result})" for job, result in verdict.jobs)
        return f"No failures, but not every job ran ({skipped}); left '{title}' as is"

    issue = find_issue(gh, label, title)
    if verdict.kind == "green":
        if issue is None:
            return f"All jobs passed; no open '{title}' issue"
        gh("issue", "close", str(issue), "--comment", f"Green again: {run}.")
        return f"All jobs passed; closed #{issue}"

    red = "\n".join(f"- `{job}`: {result}" for job, result in verdict.jobs)
    body = f"Red: {run}.\n\n{red}\n"
    if issue is not None:
        gh("issue", "comment", str(issue), "--body", body)
        return f"Red; commented on #{issue}"
    ensure_label(gh, label)
    created = gh("issue", "create", "--title", title, "--label", label, "--body", body)
    return f"Red; opened {created.strip() or 'a new issue'}"


def main(gh: Gh = run_gh) -> int:
    try:
        outcome = report(os.environ, gh)
    except ValueError as error:
        print(f"::error title=report-status::{error}")
        return 1
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip().replace("\n", " ")
        args = error.cmd if isinstance(error.cmd, list) else [error.cmd]
        command = " ".join(str(arg) for arg in args[:3])
        print(f"::error title=report-status::{command} failed: {detail}")
        return 1
    print(outcome)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"report-status: {outcome}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
