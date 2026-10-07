"""Run several former single-boot tests as scenarios of one VM boot.

Booting is most of what a single-boot E2E test costs (median 21.8 s per boot,
38% of all script time in a full run), so tests that share an identical node
run as scenarios of one test instead (``lib/batch.nix``). Each scenario keeps its
own subtests and assertions; what this module adds is the isolation the
separate VMs used to give for free:

* before the first scenario it records what the freshly booted guest looks
  like (:func:`capture_state`);
* every scenario starts with a ``starts from a clean guest`` subtest that
  compares the guest against that baseline (:func:`assert_clean`): no mount,
  device-mapper node, loop device or swap area that was not there at boot, no
  NAILS runtime directory or harness capture in ``/run``, no new entry in the
  scratch directories, an unchanged ``/etc/nixos``, a blank hidden-volume disk
  and no ``nails`` process or unit;
* between scenarios :func:`reset_guest` restores that baseline. A scenario
  that left a NAILS overlay, runtime directory or process behind is reset by
  power-cycling the VM (the same disk, a fresh kernel and ``/run``), so the
  harness never depends on the teardown code under test; anything else is
  unmounted, closed and deleted in place. A reset that cannot restore the
  baseline stops the batch, because the next scenario could not be trusted.

A failing scenario does not hide the others: it is reported, the guest is
reset and the batch moves on, and the test fails at the end naming every
scenario that failed or did not run.
"""

from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field

# The hidden-volume disk every E2E VM carries (lib/vm-config.nix).
DATA_DISK = "/dev/disk/by-id/virtio-data"

# Directories scenarios use as scratch space. A new top-level entry in one of
# them is a leftover: the reset deletes it and the clean check fails on it.
SCRATCH_DIRS = ("/tmp", "/var/tmp", "/mnt", "/root", "/home/testuser")
# systemd owns the PrivateTmp directories of services it starts on demand and
# removes them when the service stops; deleting one under a running service
# would break it, and it says nothing about a scenario.
_SYSTEMD_PRIVATE = "systemd-private-"

# Mounts the guest makes or drops on its own (automounts, per-user and
# per-service runtime mounts), which say nothing about a scenario.
_VOLATILE_MOUNT_PREFIXES = ("/proc/", "/sys/", "/run/user/", "/run/credentials/")
_VOLATILE_MOUNTS = frozenset({"/dev/hugepages", "/dev/mqueue"})

# NAILS runtime state in /run: the random runtime root (16 hex digits,
# nails-core/src/runtime_root.rs) and the fixed nails* and overlay-runtime
# names. Harness captures are the files the capture helpers write there, and
# the harness's own nails-tests directory, which is not NAILS state.
_RUNTIME_ENTRY = re.compile(r"^(?:[0-9a-f]{16}|nails(?!-tests$).*|overlay-runtime)$")
_CAPTURE_ENTRY = re.compile(r"\.(?:stdout|stderr|rc|typescript)$")

_SECTION = "### "
_COMMAND_TIMEOUT = 120


@dataclass(frozen=True)
class GuestState:
    """What the clean check compares, as read from the guest."""

    mounts: frozenset[tuple[str, str]]
    mapper: frozenset[str]
    loops: frozenset[str]
    swaps: frozenset[str]
    run: frozenset[str]
    scratch: dict[str, frozenset[str]] = field(default_factory=dict)
    etc_nixos: str = ""
    data_disk_signatures: str = ""
    nails_processes: str = ""
    nails_units: frozenset[str] = frozenset()
    state_files: frozenset[str] = frozenset()

    def runtime_entries(self) -> list[str]:
        return sorted(name for name in self.run if _RUNTIME_ENTRY.match(name))

    def capture_entries(self) -> list[str]:
        return sorted(
            name
            for name in self.run
            if name == "nails-tests" or _CAPTURE_ENTRY.search(name)
        )


def _snapshot_command() -> str:
    parts = [
        f"echo '{_SECTION}mounts'; findmnt -rn -o TARGET,FSTYPE",
        f"echo '{_SECTION}mapper'; ls -1 /dev/mapper | grep -vx control || true",
        f"echo '{_SECTION}loops'; losetup -n -O NAME 2>/dev/null || true",
        f"echo '{_SECTION}swaps'; tail -n +2 /proc/swaps | awk '{{print $1}}'",
        f"echo '{_SECTION}run'; find /run -mindepth 1 -maxdepth 1 -printf '%f\\n'",
        f"echo '{_SECTION}etc-nixos'; "
        "find /etc/nixos -type f -exec sha256sum {} + 2>/dev/null | sort || true",
        f"echo '{_SECTION}data-disk'; "
        f"blkid -p -o export {DATA_DISK} 2>/dev/null || true",
        f"echo '{_SECTION}nails-processes'; pgrep -a -x nails || true",
        f"echo '{_SECTION}state-files'; "
        "ls -d /mnt/data/state.json /mnt/data/state 2>/dev/null || true",
        f"echo '{_SECTION}nails-units'; "
        "systemctl list-units --all --plain --no-legend --no-pager 'nails*' "
        "| awk '{print $1}' || true",
    ]
    for directory in SCRATCH_DIRS:
        quoted = shlex.quote(directory)
        parts.append(
            f"echo '{_SECTION}scratch {directory}'; "
            f"find {quoted} -mindepth 1 -maxdepth 1 -printf '%f\\n' 2>/dev/null || true"
        )
    return "; ".join(parts)


def parse_state(output: str) -> GuestState:
    """Parse the sectioned output of the snapshot command."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in output.splitlines():
        if line.startswith(_SECTION):
            current = sections.setdefault(line[len(_SECTION) :].strip(), [])
        elif current is not None and line.strip():
            current.append(line.rstrip())

    mounts: set[tuple[str, str]] = set()
    for line in sections.get("mounts", []):
        target, _, fstype = line.partition(" ")
        if target in _VOLATILE_MOUNTS or target.startswith(_VOLATILE_MOUNT_PREFIXES):
            continue
        mounts.add((target, fstype))

    scratch = {
        directory: frozenset(
            name
            for name in sections.get(f"scratch {directory}", [])
            if not name.startswith(_SYSTEMD_PRIVATE)
        )
        for directory in SCRATCH_DIRS
    }
    return GuestState(
        mounts=frozenset(mounts),
        mapper=frozenset(sections.get("mapper", [])),
        loops=frozenset(sections.get("loops", [])),
        swaps=frozenset(sections.get("swaps", [])),
        run=frozenset(sections.get("run", [])),
        scratch=scratch,
        etc_nixos="\n".join(sections.get("etc-nixos", [])),
        data_disk_signatures="\n".join(sections.get("data-disk", [])),
        nails_processes="\n".join(sections.get("nails-processes", [])),
        nails_units=frozenset(sections.get("nails-units", [])),
        state_files=frozenset(sections.get("state-files", [])),
    )


def capture_state(machine: object) -> GuestState:
    """Read the guest's current :class:`GuestState`."""
    output = machine.succeed(  # type: ignore[attr-defined]
        _snapshot_command(), timeout=_COMMAND_TIMEOUT
    )
    return parse_state(output)


def leftovers(baseline: GuestState, current: GuestState) -> list[str]:
    """Describe every way ``current`` differs from the clean ``baseline``."""
    found: list[str] = []

    def extra(label: str, now: Iterable[object], then: Iterable[object]) -> None:
        added = sorted(set(now) - set(then), key=str)
        if added:
            found.append(f"{label}: {added}")

    extra("mounts not present at boot", current.mounts, baseline.mounts)
    missing = sorted(baseline.mounts - current.mounts)
    if missing:
        found.append(f"mounts present at boot but gone: {missing}")
    extra("device-mapper nodes", current.mapper, baseline.mapper)
    extra("loop devices", current.loops, baseline.loops)
    extra("swap areas", current.swaps, baseline.swaps)
    runtime = current.runtime_entries()
    if runtime:
        found.append(f"NAILS runtime entries in /run: {runtime}")
    captures = current.capture_entries()
    if captures:
        found.append(f"harness captures in /run: {captures}")
    for directory in SCRATCH_DIRS:
        extra(
            f"new entries in {directory}",
            current.scratch.get(directory, frozenset()),
            baseline.scratch.get(directory, frozenset()),
        )
    if current.etc_nixos != baseline.etc_nixos:
        found.append("/etc/nixos differs from boot")
    if current.data_disk_signatures != baseline.data_disk_signatures:
        found.append(
            f"hidden-volume disk carries signatures: {current.data_disk_signatures!r}"
        )
    if current.nails_processes:
        found.append(f"nails processes running: {current.nails_processes!r}")
    extra("nails units loaded", current.nails_units, baseline.nails_units)
    extra("NAILS state files", current.state_files, baseline.state_files)
    return found


def assert_clean(machine: object, baseline: GuestState) -> None:
    """Fail unless the guest matches the state it booted into."""
    found = leftovers(baseline, capture_state(machine))
    assert not found, "guest is not clean:\n  " + "\n  ".join(found)


def needs_power_cycle(baseline: GuestState, current: GuestState) -> bool:
    """True when a NAILS session (or what is left of one) is still around.

    Overlays, the runtime root and live ``nails`` processes are torn down by
    the product's own deactivation or emergency path. The harness does not run
    that code between scenarios: it power-cycles the VM instead.
    """
    new_overlays = any(
        fstype == "overlay" for _, fstype in current.mounts - baseline.mounts
    )
    return bool(new_overlays or current.runtime_entries() or current.nails_processes)


def _depth_first(targets: Iterable[str]) -> list[str]:
    return sorted(targets, key=lambda target: (-target.count("/"), target))


def _power_cycle(machine: object) -> None:
    machine.crash()  # type: ignore[attr-defined]
    machine.start()  # type: ignore[attr-defined]
    machine.wait_for_unit("multi-user.target")  # type: ignore[attr-defined]


def reset_guest(
    machine: object,
    baseline: GuestState,
    cleanup_paths: Sequence[str] = (),
) -> list[str]:
    """Bring the guest back to ``baseline``; return what had to be undone."""
    actions: list[str] = []

    def run(command: str) -> None:
        machine.succeed(command, timeout=_COMMAND_TIMEOUT)  # type: ignore[attr-defined]

    current = capture_state(machine)
    if needs_power_cycle(baseline, current):
        actions.append("power-cycled the VM (a NAILS session was left behind)")
        _power_cycle(machine)
        current = capture_state(machine)

    for unit in sorted(current.nails_units - baseline.nails_units):
        actions.append(f"stopped {unit}")
        run(f"systemctl stop {shlex.quote(unit)} || true")
    run("systemctl reset-failed")

    for swap in sorted(current.swaps - baseline.swaps):
        actions.append(f"swapoff {swap}")
        run(f"swapoff {shlex.quote(swap)}")
    added_mounts = {target for target, _ in current.mounts - baseline.mounts}
    for target in _depth_first(added_mounts):
        actions.append(f"umount {target}")
        run(f"umount {shlex.quote(target)}")

    # Unmounting releases devices (a loop mount's device autoclears), so the
    # devices still to close are read again.
    current = capture_state(machine)
    for name in sorted(current.mapper - baseline.mapper):
        actions.append(f"closed /dev/mapper/{name}")
        quoted = shlex.quote(name)
        run(
            f"cryptsetup close {quoted} || dmsetup remove {quoted} "
            f"|| [ ! -e /dev/mapper/{quoted} ]"
        )
    for loop in sorted(current.loops - baseline.loops):
        actions.append(f"detached {loop}")
        quoted = shlex.quote(loop)
        # An autoclear loop device may detach on its own in the meantime.
        run(f"losetup -d {quoted} || ! losetup {quoted} >/dev/null 2>&1")
    if current.data_disk_signatures != baseline.data_disk_signatures:
        actions.append(f"wiped the signatures on {DATA_DISK}")
        run(f"wipefs -a {DATA_DISK} && udevadm settle")

    doomed = [f"/run/{name}" for name in current.capture_entries()]
    doomed += [f"/run/{name}" for name in current.runtime_entries()]
    for directory in SCRATCH_DIRS:
        added = current.scratch.get(directory, frozenset()) - baseline.scratch.get(
            directory, frozenset()
        )
        doomed += [f"{directory}/{name}" for name in sorted(added)]
    doomed += list(cleanup_paths)
    if doomed:
        actions.append(f"removed {doomed}")
        run("rm -rf -- " + " ".join(shlex.quote(path) for path in doomed))
    return actions


Scenario = tuple[str, Callable[[], None]]
Subtest = Callable[[str], AbstractContextManager[None]]


def run_scenarios(
    machine: object,
    subtest: Subtest,
    scenarios: Sequence[Scenario],
    cleanup_paths: Sequence[str] = (),
) -> None:
    """Run ``scenarios`` in order on one booted machine, isolated as above.

    Raises at the end when any scenario failed, or immediately (after naming
    the scenarios that will not run) when the guest could not be reset.
    """
    baseline = capture_state(machine)
    failures: list[str] = []
    for index, (name, body) in enumerate(scenarios):
        try:
            with subtest(f"{name}: starts from a clean guest"):
                assert_clean(machine, baseline)
        except Exception as exc:
            skipped = [later for later, _ in scenarios[index:]]
            raise AssertionError(
                f"stopping the batch before {name}: the guest is not clean, so "
                f"{skipped} did not run; failed before that: {failures}"
            ) from exc

        started = time.monotonic()
        try:
            with subtest(name):
                body()
            print(f"batch: {name} passed in {time.monotonic() - started:.1f} s")
        except Exception as exc:  # noqa: BLE001 - reported at the end of the batch
            failures.append(name)
            elapsed = time.monotonic() - started
            print(f"batch: {name} FAILED after {elapsed:.1f} s: {exc}")

        if index + 1 < len(scenarios):
            try:
                with subtest(f"{name}: reset the guest"):
                    for action in reset_guest(machine, baseline, cleanup_paths):
                        print(f"batch: reset after {name}: {action}")
            except Exception as exc:
                skipped = [later for later, _ in scenarios[index + 1 :]]
                raise AssertionError(
                    f"stopping the batch after {name}: the guest could not be "
                    f"reset, so {skipped} did not run; failed scenarios: {failures}"
                ) from exc

    assert not failures, f"failed scenarios: {failures}"
