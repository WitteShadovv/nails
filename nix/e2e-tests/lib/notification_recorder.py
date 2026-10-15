"""A notification server that records every call, for the alert tests.

It runs as the operator, owns ``org.freedesktop.Notifications`` on the
operator's session bus and answers the calls a desktop's notification daemon
answers. Every ``Notify`` is appended to the file named on the command line as
one JSON line: the call's arguments, and the uid and the command name of the
process that made the call, which the bus reports for its connection. The reply
waits for those, so the caller is still alive when they are looked up.

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
        try:
            facts["comm"] = Path(f"/proc/{facts['pid']}/comm").read_text().strip()
        except OSError:
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
