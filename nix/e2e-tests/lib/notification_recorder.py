"""A notification server that records every call, for the alert tests.

It runs as the operator, owns ``org.freedesktop.Notifications`` on the
operator's session bus and answers the calls a desktop's notification daemon
answers. Every ``Notify`` is appended to the file named on the command line as
one JSON line: the call's arguments, and what the bus and ``/proc`` report
for the process that made the call: its uid, command name, group ids,
supplementary groups, effective capabilities, ``no_new_privs``, session and
controlling terminal. The reply waits for those, so the caller is still alive
when they are looked up.

Run inside the guest: ``python3 -P notification_recorder.py <records file>``.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dbus_fast import BusType, Message, MessageType
from dbus_fast.aio import MessageBus

NAME = "org.freedesktop.Notifications"
OBJECT_PATH = "/org/freedesktop/Notifications"
NOTIFY_SIGNATURE = "susssasa{sv}i"
DBUS = "org.freedesktop.DBus"


async def connection_facts(bus: MessageBus, sender: str) -> dict[str, Any]:
    """The uid, pid and command name of the bus connection ``sender``."""
    facts: dict[str, Any] = {}
    for member, key in (
        ("GetConnectionUnixUser", "uid"),
        ("GetConnectionUnixProcessID", "pid"),
    ):
        reply = await bus.call(
            Message(
                destination=DBUS,
                path="/org/freedesktop/DBus",
                interface=DBUS,
                member=member,
                signature="s",
                body=[sender],
            )
        )
        if reply is not None and reply.message_type == MessageType.METHOD_RETURN:
            facts[key] = reply.body[0]
    if "pid" in facts:
        facts.update(process_facts(int(facts["pid"])))
    return facts


def process_facts(pid: int) -> dict[str, Any]:
    """What ``/proc`` says about ``pid``: its command name, group ids,
    supplementary groups, effective capabilities, ``no_new_privs``, session
    and controlling terminal. Whatever cannot be read is left out."""
    facts: dict[str, Any] = {}
    proc = Path(f"/proc/{pid}")
    try:
        facts["comm"] = (proc / "comm").read_text().strip()
        lines = (proc / "status").read_text().splitlines()
        pairs = (line.partition(":") for line in lines)
        fields = {key: value for key, _, value in pairs}
        facts["gids"] = fields["Gid"].split()
        facts["groups"] = fields["Groups"].split()
        facts["cap_eff"] = int(fields["CapEff"].strip(), 16)
        facts["no_new_privs"] = int(fields["NoNewPrivs"].strip())
        # The command name may hold spaces: the fields after it start with
        # the state (field 3), so the session (6) and the terminal (7)
        # follow three and four places later.
        after_comm = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        facts["sid"] = int(after_comm[3])
        facts["tty_nr"] = int(after_comm[4])
    except (OSError, KeyError, IndexError, ValueError):
        pass
    return facts


def plain(value: Any) -> Any:
    """A hint value as JSON can hold it: numbers, strings and booleans as
    they are, anything else (image data) only by its type."""
    if isinstance(value, (bool, int, float, str)):
        return value
    return type(value).__name__


async def answer(bus: MessageBus, call: Message, ids: Iterator[int], log: Path) -> None:
    """Record ``call`` when it is a notification, then reply to it."""
    if call.member == "Notify" and call.signature == NOTIFY_SIGNATURE:
        app_name, replaces_id, icon, summary, body, actions, hints, timeout = call.body
        record = {
            "app_name": app_name,
            "replaces_id": replaces_id,
            "icon": icon,
            "summary": summary,
            "body": body,
            "actions": actions,
            "hints": {key: plain(variant.value) for key, variant in hints.items()},
            "expire_timeout": timeout,
            **await connection_facts(bus, call.sender or ""),
        }
        with log.open("a", encoding="utf-8") as records:
            records.write(json.dumps(record) + "\n")
        reply = Message.new_method_return(call, "u", [next(ids)])
    elif call.member == "GetServerInformation":
        reply = Message.new_method_return(
            call, "ssss", ["recorder", "test", "1", "1.2"]
        )
    elif call.member == "GetCapabilities":
        reply = Message.new_method_return(call, "as", [["body"]])
    elif call.member == "CloseNotification":
        reply = Message.new_method_return(call)
    else:
        reply = Message.new_error(
            call,
            "org.freedesktop.DBus.Error.UnknownMethod",
            f"{call.interface}.{call.member} is not implemented",
        )
    bus.send(reply)


async def serve(log: Path) -> None:
    bus = await MessageBus(bus_type=BusType.SESSION).connect()
    ids = itertools.count(1)
    pending: set[asyncio.Task[None]] = set()

    def handle(message: Message) -> bool | None:
        if (
            message.message_type != MessageType.METHOD_CALL
            or message.path != OBJECT_PATH
        ):
            return None
        task = asyncio.ensure_future(answer(bus, message, ids, log))
        pending.add(task)
        task.add_done_callback(pending.discard)
        return True

    bus.add_message_handler(handle)
    await bus.request_name(NAME)
    await bus.wait_for_disconnect()


def main() -> None:
    asyncio.run(serve(Path(sys.argv[1])))


if __name__ == "__main__":
    main()
