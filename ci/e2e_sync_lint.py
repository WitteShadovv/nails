"""Flag the E2E synchronisation patterns that made tests flaky or hang.

Each rule names a pattern that has cost a real failure in the suite's history
(see docs/e2e-performance.md, "Robustness"):

* ``sleep``: a fixed ``time.sleep(...)`` or ``<machine>.sleep(...)`` used to
  wait for something. A sleep inside a bounded polling loop (a ``while`` on a
  deadline, or a ``for _ in range(...)`` with a give-up branch) is fine and is
  recognised from the lines above it.
* ``console-wait``: ``wait_for_console_text`` or ``wait_for_console_log``.
  The emergency teardown restarts journald, which severs a unit's
  journal+console stream, so a console regex can miss a line that was printed.
  Wait on a result file under ``/run``, the unit's state or a mountpoint.
* ``tmp-capture``: command output redirected into ``/tmp``. Activation overlays
  ``/tmp`` and the forensic tests image the disk it lives on, so a capture
  there lands in the hidden upper or on the decoy image depending on timing.
  Capture under ``/run``.
* ``unbounded-shutdown``: the driver's ``wait_for_shutdown()`` has no
  deadline; wait on ``machine.process`` with a timeout first (as
  ``canonical_deactivate`` does), so a power-off that never comes fails with
  diagnostics instead of holding the test until its global timeout.

A justified exception carries a marker on the same line or the line above:
``sync-lint: allow <rule> -- <reason>``. A marker without a reason is itself a
finding.

Usage: ``python3 -m ci.e2e_sync_lint [PATH ...]`` (defaults to the E2E tests and
their helper library). Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATHS = (
    REPO_ROOT / "nix" / "e2e-tests" / "tests",
    REPO_ROOT / "nix" / "e2e-tests" / "lib",
)
# How far above a sleep or a wait_for_shutdown() to look for the loop or the
# bounded process wait that makes it safe.
CONTEXT_LINES = 15

SLEEP = re.compile(r"\b(?:time|[A-Za-z_][A-Za-z0-9_]*)\.sleep\(")
BOUNDED_LOOP = re.compile(
    r"\bwhile\b.*(?:deadline|time\.(?:time|monotonic)\(\))"
    r"|\bfor\s+\w+\s+in\s+range\("
    r"|\bdeadline\b"
)
CONSOLE_WAIT = re.compile(r"\b(?:wait_for_console_text|wait_for_console_log)\(")
CONSOLE_WAIT_DEF = re.compile(r"^\s*def\s+wait_for_console_log\(")
TMP_CAPTURE = re.compile(
    r"(?:^|[\s;'\"])[12&]?>>?\s*/tmp/[^\s'\"]*\.(?:stdout|stderr|rc|out|err|log|json)\b"
)
SHUTDOWN = re.compile(r"\.wait_for_shutdown\(\)")
BOUNDED_WAIT = re.compile(r"\.wait\(\s*timeout\s*=")
MARKER = re.compile(r"sync-lint:\s*allow\s+(?P<rule>[\w-]+)(?P<rest>.*)")
RULES = ("sleep", "console-wait", "tmp-capture", "unbounded-shutdown")


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str
    text: str

    def format(self, root: Path) -> str:
        try:
            shown = self.path.relative_to(root)
        except ValueError:
            shown = self.path
        return f"{shown}:{self.line}: [{self.rule}] {self.text.strip()}"


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#")


def _allowed(lines: Sequence[str], index: int, rule: str) -> bool:
    for candidate in (lines[index], lines[index - 1] if index else ""):
        match = MARKER.search(candidate)
        if match and match["rule"] == rule:
            return True
    return False


def _context(lines: Sequence[str], index: int) -> Iterable[str]:
    return lines[max(0, index - CONTEXT_LINES) : index]


def lint_text(path: Path, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []

    def flag(index: int, rule: str) -> None:
        if not _allowed(lines, index, rule):
            findings.append(Finding(path, index + 1, rule, lines[index]))

    for index, line in enumerate(lines):
        marker = MARKER.search(line)
        if marker is not None:
            reason = marker["rest"].strip()
            if (
                marker["rule"] not in RULES
                or not reason.startswith("--")
                or not (reason.removeprefix("--").strip())
            ):
                findings.append(Finding(path, index + 1, "marker", line))
        if _is_comment(line) and marker is None:
            continue
        code = line.split("#", 1)[0] if _is_comment(line) else line
        if SLEEP.search(code) and not any(
            BOUNDED_LOOP.search(above) for above in _context(lines, index)
        ):
            flag(index, "sleep")
        if CONSOLE_WAIT.search(code) and not CONSOLE_WAIT_DEF.match(code):
            flag(index, "console-wait")
        if TMP_CAPTURE.search(code):
            flag(index, "tmp-capture")
        if SHUTDOWN.search(code) and not any(
            BOUNDED_WAIT.search(above) for above in _context(lines, index)
        ):
            flag(index, "unbounded-shutdown")
    return findings


def lint_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in paths:
        files = sorted(root.rglob("*.nix")) if root.is_dir() else [root]
        for file in files:
            findings += lint_text(file, file.read_text(encoding="utf-8"))
    return findings


def main(argv: Sequence[str]) -> int:
    paths = [Path(arg) for arg in argv] or list(DEFAULT_PATHS)
    findings = lint_paths(paths)
    for finding in findings:
        print(finding.format(REPO_ROOT))
    if findings:
        print(
            f"\n{len(findings)} E2E synchronisation finding(s). Wait on the real "
            "completion signal (a /run result file, the unit's state, a "
            "mountpoint) with a bounded timeout, capture under /run, or mark a "
            "justified case with 'sync-lint: allow <rule> -- <reason>'. See "
            "ci/e2e_sync_lint.py.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
