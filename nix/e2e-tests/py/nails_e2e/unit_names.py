"""The names PID 1 gives the mount units of mount points NAILS must name.

The way back waits until PID 1 holds the unit of each mount its ``/run``
scrub detached down, asking for each unit by name (``systemctl is-active``),
so the name must be the one PID 1 gives: every byte of the path escaped, one
that is not valid UTF-8 too, and a name of 256 characters or more shortened
with a hash (systemd's ``unit_name_from_path``). :data:`CASES` are the names
PID 1 gave on systemd 255; nails-teardown's ``unit_name`` tests hold the same
pairs. :func:`check` mounts a tmpfs at each path and asks the VM's PID 1 for
each name, and :func:`plant` leaves two such mounts in ``/run`` while
deactivate reads the mount table.
"""

from __future__ import annotations

from typing import Protocol

#: The folder the cases' paths lie in.
BASE = b"/run/nails-unit-probe/"

#: What every case's unit name starts with: ``BASE`` escaped.
PREFIX = "run-nails\\x2dunit\\x2dprobe-"

#: Each folder of :data:`BASE`, with the name of the unit PID 1 gave a tmpfs
#: mounted there (systemd 255).
CASES: list[tuple[bytes, str]] = [
    (b"a\xff", PREFIX + "a\\xff.mount"),
    (b"x\xfe\xfdy", PREFIX + "x\\xfe\\xfdy.mount"),
    (b"c" * 222, PREFIX + "c" * 222 + ".mount"),
    (b"c" * 223, PREFIX + "c" * 205 + "_6b26d6a749d60614.mount"),
    (b"a" * 250, PREFIX + "a" * 205 + "_01599071334b551b.mount"),
    (b"\xff" + b"a" * 250, PREFIX + "\\xff" + "a" * 201 + "_4512109f26c23c95.mount"),
    (b"\xff" * 70, PREFIX + "\\xff" * 51 + "\\_e4a55aff71ad7547.mount"),
    (b"\xc3\xa4" * 120, PREFIX + "\\xc3\\xa4" * 25 + "\\xc3\\_f920c2364cb45eed.mount"),
    (b"my-disk a\\b", PREFIX + "my\\x2ddisk\\x20a\\x5cb.mount"),
    (b".dot", PREFIX + ".dot.mount"),
]


class Machine(Protocol):
    """The part of the NixOS test driver's machine these helpers use."""

    def succeed(self, *commands: str, timeout: int | None = None) -> str: ...


def shell_path(path: bytes) -> str:
    """A shell word that sets ``p`` to ``path`` byte for byte: ``printf``'s
    ``%b`` reads each byte as a ``\\xHH`` escape, so no byte that is not valid
    UTF-8 passes through the driver."""
    escaped = "".join(f"\\x{byte:02x}" for byte in path)
    return f"printf -v p '%b' '{escaped}'"


def states(machine: Machine, names: list[str]) -> list[str]:
    """What PID 1 answers for the state of each unit of ``names``, as the
    way back asks it."""
    quoted = " ".join(f"'{name}'" for name in names)
    return machine.succeed(f"systemctl is-active -- {quoted} || true").split()


def check(machine: Machine) -> None:
    """Mount a tmpfs at each case's path and require PID 1 to hold each
    case's unit active, then unmount them and require it to hold each down."""
    for folder, _ in CASES:
        machine.succeed(
            f'{shell_path(BASE + folder)}; mkdir -p -- "$p" && '
            'mount -t tmpfs nails-probe -- "$p"'
        )
    names = [name for _, name in CASES]
    machine.succeed("udevadm settle; sleep 1")
    mounted = states(machine, names)
    for folder, _ in CASES:
        machine.succeed(f'{shell_path(BASE + folder)}; umount -- "$p" && rmdir -- "$p"')
    machine.succeed(f"rmdir {BASE.decode()}")
    machine.succeed("sleep 1")
    unmounted = states(machine, names)
    assert mounted == ["active"] * len(names), list(zip(names, mounted, strict=False))
    assert unmounted == ["inactive"] * len(names), list(
        zip(names, unmounted, strict=False)
    )


#: The folders of ``/run`` :func:`plant` mounts a tmpfs at: one whose name is
#: not valid UTF-8, and one whose unit name PID 1 shortens with a hash.
PLANTED: list[bytes] = [b"/run/nails-odd-\xff", b"/run/" + b"l" * 250]


def plant(machine: Machine) -> None:
    """Mount a tmpfs at each folder of :data:`PLANTED`, in the hidden
    session, where deactivate reads the mount table with them in it."""
    for path in PLANTED:
        machine.succeed(
            f'{shell_path(path)}; mkdir -p -- "$p" && '
            'mount -t tmpfs nails-probe -- "$p"'
        )


def planted_gone(machine: Machine) -> None:
    """Require that nothing of :data:`PLANTED` is left after the way back."""
    for path in PLANTED:
        machine.succeed(f'{shell_path(path)}; test ! -e "$p"')
