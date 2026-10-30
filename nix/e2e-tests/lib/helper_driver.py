# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive the window's root helper as the window does, inside a test VM.

    helper_driver.py OUT ERR [PREFIX] STEP... -- HELPER-COMMAND...

The driver starts HELPER-COMMAND (the engine's `helper --stdio`, through
`su` and `sudo` as the operator starts it), takes its hello, answers with the
same versions, and then sends the requests of each STEP in order, each one
only once the last is answered:

- `activate`: an activation plan (`--overlay-only`), then its apply;
- `plans`: a deactivation plan for each ending, then a status request,
  which withdraws the second plan unapplied;
- `deactivate`: a deactivation plan, then its apply.

Every frame the helper writes goes to OUT as one line, PREFIX and a space
before it when given (the serial console carries other lines too), flushed
and synced as it arrives: an activation's frames must reach the hidden
volume before the switch, and a deactivation's the console, which outlives
it. The helper's stderr goes to ERR. The driver ignores SIGTERM and SIGHUP:
the window's pipe stays open until the answer, as the switch that an apply
enqueues stops this process too, and a window that went away before the
point of no return would cancel the activation. It exits 0 once the last
answer is in and every answer but the status has exit 0, and 1 otherwise.
"""

import json
import os
import signal
import subprocess
import sys
from typing import IO, Any

PROTOCOL = 1
STEPS = ("activate", "plans", "deactivate")

Frame = dict[str, Any]


class Driver:
    """The window's end of one helper's pipe."""

    def __init__(
        self, out: IO[str], prefix: str, command: list[str], err: IO[bytes]
    ) -> None:
        self.out = out
        self.prefix = f"{prefix} " if prefix else ""
        self.next_id = 1
        self.helper = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err
        )

    def frame(self) -> Frame:
        """The helper's next frame, written to OUT first."""
        assert self.helper.stdout is not None
        line = self.helper.stdout.readline()
        if not line:
            raise SystemExit(f"the helper ended (exit {self.helper.wait()})")
        text = line.decode().rstrip("\n")
        self.out.write(f"{self.prefix}{text}\n")
        self.out.flush()
        try:
            os.fsync(self.out.fileno())
        except OSError:
            pass  # a terminal or a pipe has nothing to sync
        frame: Frame = json.loads(text)
        return frame

    def ask(self, op: Any) -> Frame:
        """Send `op` and return its answer, the events before it written out."""
        assert self.helper.stdin is not None
        request = {"v": PROTOCOL, "id": self.next_id, "op": op}
        self.next_id += 1
        self.helper.stdin.write((json.dumps(request) + "\n").encode())
        self.helper.stdin.flush()
        while True:
            frame = self.frame()
            if "event" not in frame:
                return frame

    def result(self, op: Any) -> Frame:
        """The result frame answering `op`; anything else ends the driver."""
        answer = self.ask(op)
        if "result" not in answer:
            raise SystemExit(f"{op!r} was answered with {answer!r}")
        result: Frame = answer["result"]
        return result

    def succeeds(self, op: Any) -> bool:
        """Whether `op` is answered with exit 0."""
        return bool(self.result(op)["exit"] == 0)

    def plan_and_apply(self, plan: Any, apply: str) -> bool:
        """Make the plan `plan`, then apply it with its token."""
        planned = self.result(plan)
        token = planned["envelope"].get("data", {}).get("token")
        if planned["exit"] != 0 or token is None:
            return False
        return self.succeeds({apply: {"token": token}})


def run(driver: Driver, steps: list[str]) -> bool:
    """Run `steps` after the handshake; whether every answer had exit 0."""
    hello = driver.frame()
    ok = driver.succeeds({"hello": hello["hello"]})
    plan: Frame
    for step in steps:
        if step == "activate":
            plan = {"activate_plan": {"overlay_only": True}}
            ok = driver.plan_and_apply(plan, "activate_apply") and ok
        elif step == "plans":
            for poweroff in (False, True):
                plan = {"deactivate_plan": {"poweroff": poweroff}}
                ok = driver.succeeds(plan) and ok
            driver.result("status")
        else:
            plan = {"deactivate_plan": {}}
            ok = driver.plan_and_apply(plan, "deactivate_apply") and ok
    return ok


def main() -> int:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    split = sys.argv.index("--")
    head, command = sys.argv[1:split], sys.argv[split + 1 :]
    out_path, err_path, steps = head[0], head[1], head[2:]
    prefix = ""
    if steps and steps[0] not in STEPS:
        prefix, steps = steps[0], steps[1:]
    unknown = [step for step in steps if step not in STEPS]
    if unknown:
        raise SystemExit(f"no such step: {unknown}")
    with open(out_path, "a", buffering=1) as out, open(err_path, "ab") as err:
        return 0 if run(Driver(out, prefix, command, err), steps) else 1


if __name__ == "__main__":
    sys.exit(main())
