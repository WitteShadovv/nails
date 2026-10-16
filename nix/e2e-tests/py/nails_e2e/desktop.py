"""The operator's session in the alert tests: a console login, and what the
notification server on the operator's bus received.

A test node imports ``nix/e2e-tests/lib/notification-server.nix``: a user
service of testuser that owns ``org.freedesktop.Notifications`` and appends
every call to ``$XDG_RUNTIME_DIR/notifications.jsonl``. NAILS alerts the
operator: the account that ran sudo, or for the session watcher the owner of
the active session on seat0, which a login on tty1 makes testuser.
"""

from __future__ import annotations

import json
import shlex
from typing import Any, Protocol

#: The notification server's user unit (see notification-server.nix).
RECORDER_UNIT = "notification-recorder.service"

#: Its records, in the user's runtime directory.
RECORDS = "notifications.jsonl"


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    def succeed(self, *commands: str, timeout: int | None = None) -> str: ...

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]: ...

    def wait_for_unit(
        self, unit: str, user: str | None = None, timeout: int = 900
    ) -> None: ...

    def wait_until_succeeds(self, command: str, timeout: int = 900) -> str: ...

    def wait_until_tty_matches(
        self, tty: str, regexp: str, timeout: int = 900
    ) -> None: ...

    def send_chars(self, chars: str, delay: float | None = 0.01) -> None: ...


def records_path(uid: int) -> str:
    """Where the notification server of ``uid`` keeps its records."""
    return f"/run/user/{uid}/{RECORDS}"


def login_on_console(
    machine: Machine, user: str = "testuser", password: str = "test"
) -> int:
    """Log ``user`` in on tty1 and return their uid, once theirs is the active
    session on seat0 and the notification server on their bus is running."""
    machine.wait_for_unit("getty@tty1.service")
    # Clear tty1 first, so a "Password:" left by an earlier phase cannot
    # match; wait for login's own prompt before typing the password (login
    # flushes typeahead when it turns echo off).
    machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
    machine.send_chars(f"{user}\n")
    machine.wait_until_tty_matches("1", "Password: ", timeout=60)
    machine.send_chars(f"{password}\n")
    uid = int(machine.succeed(f"id -u {shlex.quote(user)}").strip())
    active_owner = (
        "loginctl show-seat seat0 -p ActiveSession --value"
        " | xargs -r loginctl show-session -p User --value"
    )
    machine.wait_until_succeeds(f'test "$({active_owner})" = {uid}', timeout=60)
    machine.wait_until_succeeds(
        f"systemctl --user --machine={shlex.quote(user)}@ is-active {RECORDER_UNIT}",
        timeout=60,
    )
    return uid


def parse_records(text: str) -> list[dict[str, Any]]:
    """The records in the server's JSON-lines file, oldest first."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def received(machine: Machine, uid: int) -> list[dict[str, Any]]:
    """Every notification the server on ``uid``'s bus received so far."""
    status, text = machine.execute(f"cat {records_path(uid)}")
    return parse_records(text) if status == 0 else []


def wait_for(
    machine: Machine, uid: int, summary: str, timeout: int = 60
) -> list[dict[str, Any]]:
    """The notifications titled ``summary``, once at least one has arrived."""
    needle = shlex.quote(json.dumps({"summary": summary})[1:-1])
    machine.wait_until_succeeds(
        f"grep -qF -- {needle} {records_path(uid)}", timeout=timeout
    )
    return [record for record in received(machine, uid) if record["summary"] == summary]
