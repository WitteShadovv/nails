"""Run a guest command and capture its result, for the NixOS test driver.

This runs inside the test *driver* (the Python the driver execs), not inside the
guest. It drives a machine through the node object the driver injects as a
global, but takes that node as its first argument instead of reading a module
global, so a multi-node test passes whichever node it means and single-node
tests just pass ``machine``.
"""

from __future__ import annotations

import shlex
from typing import Protocol, TypedDict


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    def succeed(self, *commands: str) -> str: ...


class CommandResult(TypedDict):
    """The one shape every caller reads.

    ``combined`` is ``stdout + stderr`` and the ``*_path`` fields name the files
    the streams were captured to, so a caller can re-read or diff them in the
    guest after the fact.
    """

    rc: int
    stdout: str
    stderr: str
    combined: str
    stdout_path: str
    stderr_path: str


def run_command_capture(machine: Machine, label: str, command: str) -> CommandResult:
    """Run ``command`` in a login shell on ``machine`` and capture its result.

    The command's exit status is recorded rather than asserted, so a command
    that is expected to fail is still inspected field by field. Output is
    redirected to files under ``/run`` named after ``label`` (which must be
    unique within a test) and read back afterwards.
    """
    prefix = f"/run/{label}"
    stdout_path = f"{prefix}.stdout"
    stderr_path = f"{prefix}.stderr"
    rc_path = f"{prefix}.rc"
    machine.succeed(
        "bash -lc "
        + shlex.quote(
            "set +e; "
            + command
            + f" > {shlex.quote(stdout_path)} 2> {shlex.quote(stderr_path)}; "
            + f'printf "%s" "$?" > {shlex.quote(rc_path)}'
        )
    )
    stdout = machine.succeed(f"cat {shlex.quote(stdout_path)} || true")
    stderr = machine.succeed(f"cat {shlex.quote(stderr_path)} || true")
    return {
        "rc": int(machine.succeed(f"cat {shlex.quote(rc_path)}").strip()),
        "stdout": stdout,
        "stderr": stderr,
        "combined": stdout + stderr,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
    }
