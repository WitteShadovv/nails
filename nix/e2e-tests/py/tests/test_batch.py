"""Host-side tests for the scenario batch runner.

A fake guest keeps the state the snapshot command reads (mounts, devices,
``/run``, scratch directories, ...) and applies the reset commands to it, so
the clean check, the reset and the scenario loop are exercised without a VM.
"""

from __future__ import annotations

import contextlib
import re
import shlex
import unittest
from collections.abc import Iterator

from nails_e2e import batch
from nails_e2e.batch import DATA_DISK, GuestState, leftovers, parse_state

BOOT_MOUNTS = {
    ("/", "ext4"),
    ("/nix/store", "overlay"),
    ("/run", "tmpfs"),
    ("/proc", "proc"),
    ("/sys/kernel/debug", "debugfs"),
}


class FakeGuest:
    """A guest whose state the batch runner reads and resets."""

    def __init__(self) -> None:
        self.boots = 0
        self.commands: list[str] = []
        self.fail_on: str | None = None
        self.boot()
        self.scratch: dict[str, set[str]] = {
            directory: set() for directory in batch.SCRATCH_DIRS
        }
        self.scratch["/home/testuser"] = {".bashrc"}
        self.etc_nixos = "abc  /etc/nixos/configuration.nix"
        self.data_disk = ""

    def boot(self) -> None:
        self.boots += 1
        self.mounts = set(BOOT_MOUNTS)
        self.mapper: set[str] = set()
        self.loops: set[str] = set()
        self.loop_autoclear: set[str] = set()
        self.swaps: set[str] = set()
        self.run = {"systemd", "wrappers", "current-system"}
        self.processes = ""
        self.units: set[str] = set()
        self.state_files: set[str] = set()

    # --- the driver API the runner uses --------------------------------------

    def crash(self) -> None:
        self.commands.append("<crash>")

    def start(self) -> None:
        self.boot()

    def wait_for_unit(self, unit: str) -> None:
        self.commands.append(f"<wait {unit}>")

    def succeed(self, command: str, timeout: int | None = None) -> str:
        self.commands.append(command)
        if self.fail_on is not None and command.startswith(self.fail_on):
            raise RuntimeError(f"command failed: {command}")
        if command.startswith("echo '### mounts'"):
            return self.snapshot()
        self.apply(command)
        return ""

    # --- behaviour ----------------------------------------------------------

    def snapshot(self) -> str:
        def section(name: str, lines: object) -> str:
            body = "\n".join(sorted(str(line) for line in lines))  # type: ignore[attr-defined]
            return f"### {name}\n{body}\n"

        out = section("mounts", [f"{t} {f}" for t, f in self.mounts])
        out += section("mapper", self.mapper)
        out += section("loops", self.loops)
        out += section("swaps", self.swaps)
        out += section("run", self.run)
        out += section("etc-nixos", [self.etc_nixos])
        out += section("data-disk", [self.data_disk] if self.data_disk else [])
        out += section("nails-processes", [self.processes] if self.processes else [])
        out += section("state-files", self.state_files)
        out += section("nails-units", self.units)
        for directory, names in self.scratch.items():
            out += section(f"scratch {directory}", names)
        return out

    def apply(self, command: str) -> None:
        if command.startswith("umount "):
            target = shlex.split(command)[1]
            self.mounts = {m for m in self.mounts if m[0] != target}
            if target == "/mnt/data":
                self.state_files.clear()
            for loop in list(self.loop_autoclear):
                self.loops.discard(loop)
                self.loop_autoclear.discard(loop)
        elif command.startswith("cryptsetup close "):
            self.mapper.discard(shlex.split(command)[2])
        elif command.startswith("losetup -d "):
            loop = shlex.split(command)[2]
            if loop not in self.loops:
                raise RuntimeError(f"losetup: {loop}: no such device")
            self.loops.discard(loop)
        elif command.startswith("wipefs -a "):
            self.data_disk = ""
        elif command.startswith("swapoff "):
            self.swaps.discard(shlex.split(command)[1])
        elif command.startswith("systemctl stop "):
            self.units.discard(shlex.split(command)[2])
        elif command.startswith("rm -rf -- "):
            for path in shlex.split(command)[3:]:
                self.remove(path)

    def remove(self, path: str) -> None:
        if path.startswith("/run/"):
            self.run.discard(path[len("/run/") :])
            return
        for directory, names in self.scratch.items():
            if path.startswith(directory + "/"):
                names.discard(path[len(directory) + 1 :])


class RecordingSubtest:
    def __init__(self) -> None:
        self.names: list[str] = []

    @contextlib.contextmanager
    def __call__(self, name: str) -> Iterator[None]:
        self.names.append(name)
        yield


def dirty_without_session(guest: FakeGuest) -> None:
    """What a refused activation or an init scenario typically leaves."""
    guest.mounts |= {
        ("/mnt/data", "ext4"),
        ("/etc/nixos", "ext4"),
        ("/mnt/fat", "vfat"),
    }
    guest.mapper.add("data")
    guest.loops.add("/dev/loop0")
    guest.loop_autoclear.add("/dev/loop0")
    guest.swaps.add("/dev/zram0")
    guest.data_disk = "TYPE=crypto_LUKS"
    guest.state_files.add("/mnt/data/state.json")
    guest.run |= {"preflight-x.stdout", "preflight-x.rc", "nails-tests"}
    guest.scratch["/tmp"] |= {"nails-headless.toml", "fat.img"}
    guest.scratch["/mnt"] |= {"data", "fat"}
    guest.units.add("nails-config-emergency.service")


class ParseStateTest(unittest.TestCase):
    def test_drops_volatile_mounts_and_reads_every_section(self) -> None:
        guest = FakeGuest()
        guest.mounts.add(("/run/user/1000", "tmpfs"))
        guest.mounts.add(("/dev/mqueue", "mqueue"))
        state = parse_state(guest.snapshot())
        self.assertIn(("/nix/store", "overlay"), state.mounts)
        self.assertNotIn(("/run/user/1000", "tmpfs"), state.mounts)
        self.assertNotIn(("/dev/mqueue", "mqueue"), state.mounts)
        self.assertNotIn(("/sys/kernel/debug", "debugfs"), state.mounts)
        self.assertEqual(state.scratch["/home/testuser"], frozenset({".bashrc"}))
        self.assertEqual(state.etc_nixos, guest.etc_nixos)

    def test_classifies_run_entries(self) -> None:
        state = GuestState(
            mounts=frozenset(),
            mapper=frozenset(),
            loops=frozenset(),
            swaps=frozenset(),
            run=frozenset(
                {
                    "0123456789abcdef",
                    "nails",
                    "overlay-runtime",
                    "a.stdout",
                    "b.rc",
                    "c.typescript",
                    "nails-tests",
                    "systemd",
                    "deadbeef",
                }
            ),
        )
        self.assertEqual(
            state.runtime_entries(),
            ["0123456789abcdef", "nails", "overlay-runtime"],
        )
        self.assertEqual(
            state.capture_entries(),
            ["a.stdout", "b.rc", "c.typescript", "nails-tests"],
        )


class LeftoversTest(unittest.TestCase):
    def test_a_fresh_guest_is_clean(self) -> None:
        guest = FakeGuest()
        baseline = parse_state(guest.snapshot())
        self.assertEqual(leftovers(baseline, parse_state(guest.snapshot())), [])

    def test_names_every_kind_of_leftover(self) -> None:
        guest = FakeGuest()
        baseline = parse_state(guest.snapshot())
        dirty_without_session(guest)
        guest.etc_nixos = "changed"
        guest.processes = "1234 nails notify-dispatch"
        guest.mounts.discard(("/nix/store", "overlay"))
        found = "\n".join(leftovers(baseline, parse_state(guest.snapshot())))
        for needle in [
            "mounts not present at boot",
            "/mnt/data",
            "mounts present at boot but gone",
            "device-mapper nodes",
            "loop devices",
            "swap areas",
            "harness captures in /run",
            "new entries in /tmp",
            "new entries in /mnt",
            "/etc/nixos differs from boot",
            "hidden-volume disk carries signatures",
            "nails processes running",
            "nails units loaded",
            "NAILS state files",
        ]:
            self.assertIn(needle, found)


class ResetGuestTest(unittest.TestCase):
    def test_restores_the_baseline_in_place(self) -> None:
        guest = FakeGuest()
        baseline = parse_state(guest.snapshot())
        dirty_without_session(guest)

        actions = batch.reset_guest(guest, baseline, cleanup_paths=["/run/extra"])

        self.assertEqual(guest.boots, 1, "no NAILS session, so no power cycle")
        self.assertEqual(leftovers(baseline, parse_state(guest.snapshot())), [])
        # Nested mounts go first, and the autocleared loop is not detached twice.
        umounts = [c for c in guest.commands if c.startswith("umount ")]
        self.assertEqual(umounts[-1], "umount /mnt/fat")
        self.assertFalse(any(c.startswith("losetup -d") for c in guest.commands))
        self.assertTrue(any("wiped the signatures" in a for a in actions))
        self.assertTrue(any("/run/extra" in a for a in actions))

    def test_power_cycles_when_a_session_was_left_behind(self) -> None:
        guest = FakeGuest()
        baseline = parse_state(guest.snapshot())
        guest.mounts |= {("/home", "overlay"), ("/mnt/data", "ext4")}
        guest.run.add("0123456789abcdef")
        guest.scratch["/tmp"].add("nails-headless.toml")
        guest.data_disk = "TYPE=crypto_LUKS"

        actions = batch.reset_guest(guest, baseline)

        self.assertEqual(guest.boots, 2)
        self.assertIn("<crash>", guest.commands)
        self.assertTrue(actions[0].startswith("power-cycled"))
        # The disk survives the power cycle, so its leftovers are still removed.
        self.assertEqual(leftovers(baseline, parse_state(guest.snapshot())), [])

    def test_a_live_nails_process_forces_a_power_cycle(self) -> None:
        guest = FakeGuest()
        baseline = parse_state(guest.snapshot())
        guest.processes = "99 nails watch"
        batch.reset_guest(guest, baseline)
        self.assertEqual(guest.boots, 2)


class RunScenariosTest(unittest.TestCase):
    def test_a_failure_does_not_stop_the_batch_and_is_reported(self) -> None:
        guest = FakeGuest()
        subtest = RecordingSubtest()
        ran: list[str] = []

        def first() -> None:
            ran.append("first")
            dirty_without_session(guest)

        def second() -> None:
            ran.append("second")
            raise AssertionError("boom")

        def third() -> None:
            ran.append("third")

        with self.assertRaisesRegex(AssertionError, re.escape("['second']")):
            batch.run_scenarios(
                guest, subtest, [("first", first), ("second", second), ("third", third)]
            )
        self.assertEqual(ran, ["first", "second", "third"])
        self.assertEqual(
            subtest.names,
            [
                "first: starts from a clean guest",
                "first",
                "first: reset the guest",
                "second: starts from a clean guest",
                "second",
                "second: reset the guest",
                "third: starts from a clean guest",
                "third",
            ],
        )

    def test_no_reset_after_the_last_scenario(self) -> None:
        guest = FakeGuest()

        def leaves_a_session() -> None:
            guest.mounts.add(("/home", "overlay"))

        batch.run_scenarios(guest, RecordingSubtest(), [("only", leaves_a_session)])
        self.assertEqual(guest.boots, 1)

    def test_a_reset_that_fails_stops_the_batch(self) -> None:
        guest = FakeGuest()
        ran: list[str] = []

        def first() -> None:
            ran.append("first")
            guest.mounts.add(("/mnt/busy", "ext4"))
            guest.fail_on = "umount /mnt/busy"

        def second() -> None:
            ran.append("second")

        expected = r"could not be reset.*\['second'\]"
        with self.assertRaisesRegex(AssertionError, expected):
            batch.run_scenarios(
                guest, RecordingSubtest(), [("first", first), ("second", second)]
            )
        self.assertEqual(ran, ["first"])

    def test_a_guest_the_reset_cannot_clean_stops_before_the_next_scenario(
        self,
    ) -> None:
        guest = FakeGuest()
        ran: list[str] = []

        def first() -> None:
            ran.append("first")
            # A boot-time mount that disappears cannot be restored by a reset.
            guest.mounts.discard(("/nix/store", "overlay"))

        def second() -> None:
            ran.append("second")

        with self.assertRaisesRegex(AssertionError, r"not clean.*\['second'\]"):
            batch.run_scenarios(
                guest, RecordingSubtest(), [("first", first), ("second", second)]
            )
        self.assertEqual(ran, ["first"])

    def test_data_disk_constant_is_the_hidden_volume_disk(self) -> None:
        self.assertEqual(DATA_DISK, "/dev/disk/by-id/virtio-data")


if __name__ == "__main__":
    unittest.main()
