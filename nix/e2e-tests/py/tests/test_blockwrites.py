"""Host-side tests for the block-write oracle, with a stand-in for QEMU's QMP."""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest import mock

from nails_e2e import blockwrites

ROOT = {
    "device": "drive1",
    "inserted": {"node-name": "#block100", "file": "/tmp/vm-state/machine.qcow2"},
}
DATA = {
    "device": "drive2",
    "inserted": {"node-name": "#block200", "file": "/tmp/vm-state/empty0.qcow2"},
}
STORE = {
    "device": "drive3",
    "inserted": {"node-name": "#block300", "file": "/tmp/store.img", "ro": True},
}
CDROM = {"device": "ide1-cd0"}


class FakeQmp:
    """QMP as far as the oracle asks it: bitmaps with a dirty count each."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.counts: dict[tuple[str, str], int] = {}
        self.bitmaps: dict[str, list[str]] = {"#block100": [], "#block200": []}
        self.status = "running"

    def send(self, command: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        args = args or {}
        self.sent.append((command, args))
        if command == "query-block":
            out = []
            for block in (ROOT, DATA, STORE, CDROM):
                block = json.loads(json.dumps(block))
                inserted = block.get("inserted")
                if inserted:
                    node = inserted["node-name"]
                    inserted["dirty-bitmaps"] = [
                        {"name": n, "count": self.counts.get((node, n), 0)}
                        for n in self.bitmaps.get(node, [])
                    ]
                out.append(block)
            return {"return": out}
        if command == "transaction":
            for action in args["actions"]:
                data = action["data"]
                if action["type"] == "block-dirty-bitmap-add":
                    self.bitmaps[data["node"]].append(data["name"])
        if command == "block-dirty-bitmap-remove":
            self.bitmaps[args["node"]].remove(args["name"])
        if command == "query-status":
            return {"return": {"status": self.status}}
        return {"return": {}}

    def commands(self) -> list[str]:
        return [c for c, _ in self.sent]


class FakeProcess:
    def __init__(self) -> None:
        self.code: int | None = None

    def poll(self) -> int | None:
        return self.code


class FakeMachine:
    def __init__(self) -> None:
        self.qmp_client = FakeQmp()
        self.process = FakeProcess()
        self.full_console_log: list[str] = []
        self.logged: list[str] = []
        self.ran: list[str] = []
        self.waited = 0
        self.crashed = 0

    def succeed(self, *commands: str, timeout: int | None = None) -> str:
        self.ran.extend(commands)
        return ""

    def log(self, msg: str) -> None:
        self.logged.append(msg)

    def wait_for_shutdown(self) -> None:
        self.waited += 1

    def crash(self) -> None:
        self.crashed += 1


def installed() -> tuple[FakeMachine, blockwrites.Oracle]:
    machine = FakeMachine()
    oracle = blockwrites.install(machine, {"qemu_img": "qemu-img"})
    return machine, oracle


class Drives(unittest.TestCase):
    def test_the_extra_disks_and_read_only_drives_are_no_decoy_drive(self) -> None:
        decoy, other = blockwrites.drives([ROOT, DATA, STORE, CDROM])
        self.assertEqual([d.device for d in decoy], ["drive1"])
        self.assertEqual([d.device for d in other], ["drive2"])

    def test_a_snapshot_drive_is_named_by_its_backing_image(self) -> None:
        block = {
            "device": "ide0-hd0",
            "inserted": {
                "node-name": "#block1",
                "file": "/var/tmp/vl.abc",
                "image": {
                    "filename": "/var/tmp/vl.abc",
                    "backing-image": {"filename": "/nix/store/x-image.qcow2"},
                },
            },
        }
        decoy, other = blockwrites.drives([block])
        self.assertEqual([d.node for d in decoy], ["#block1"])
        self.assertEqual(other, [])


class Ranges(unittest.TestCase):
    MAP = [
        {"start": 0, "length": 4096, "data": True},
        {"start": 4096, "length": 1024, "data": False},
        {"start": 5120, "length": 1 << 20, "data": True},
        {"start": 5120 + (1 << 20), "length": 512, "data": False},
    ]

    def test_the_dirty_ranges_are_the_holes_when_their_total_is_the_count(
        self,
    ) -> None:
        self.assertEqual(
            blockwrites.dirty_ranges(self.MAP, 1536),
            [(4096, 1024), (5120 + (1 << 20), 512)],
        )

    def test_the_dirty_ranges_are_the_data_when_their_total_is_the_count(
        self,
    ) -> None:
        self.assertEqual(
            blockwrites.dirty_ranges(self.MAP, 4096 + (1 << 20)),
            [(0, 4096), (5120, 1 << 20)],
        )

    def test_a_map_that_matches_no_count_raises(self) -> None:
        with self.assertRaises(ValueError):
            blockwrites.dirty_ranges(self.MAP, 7)

    def test_ranges_merge_and_the_allowed_extents_are_cut_out(self) -> None:
        self.assertEqual(
            blockwrites.merge([(10, 5), (0, 10), (30, 2), (31, 4)]), [(0, 15), (30, 5)]
        )
        self.assertEqual(
            blockwrites.outside([(0, 100)], [(10, 10), (50, 60)]), [(0, 10), (20, 30)]
        )
        self.assertEqual(blockwrites.outside([(0, 100)], []), [(0, 100)])
        self.assertEqual(blockwrites.outside([(0, 100)], [(0, 100)]), [])

    def test_sectors_are_named_inclusive(self) -> None:
        self.assertEqual(blockwrites.sector_text([(0, 512), (1024, 4096)]), "0, 2-9")
        self.assertEqual(
            blockwrites.sector_text([(0, 512)] * 3, limit=1), "0 and 2 more"
        )


class Marks(unittest.TestCase):
    def test_the_first_hold_and_the_release_after_it(self) -> None:
        lines = [
            "x",
            "blkstat-mark release",
            "blkstat-mark hold",
            "y",
            "blkstat-mark release",
        ]
        self.assertEqual(blockwrites.hold_and_release(lines), (2, 4))
        self.assertEqual(blockwrites.hold_and_release(["x"]), (None, None))


DUMPE2FS = """\
Block size:               4096
Inodes per group:         8192
Inode size:               256

Group 0: (Blocks 0-32767) csum 0x1234 [ITABLE_ZEROED]
  Primary superblock at 0, Group descriptors at 1-3
  Reserved GDT blocks at 4-1026
  Block bitmap at 1027 (+1027)
  Inode bitmap at 1043 (+1043)
  Inode table at 1059-1570 (+1059)
Group 1: (Blocks 32768-65535) csum 0x5678 [INODE_UNINIT]
  Backup superblock at 32768, Group descriptors at 32769-32771
  Block bitmap at 1028 (bg #0 + 1028)
  Inode bitmap at 1044 (bg #0 + 1044)
  Inode table at 1571-2082 (bg #0 + 1571)
"""


class Ext4(unittest.TestCase):
    def test_the_layout_names_each_metadata_area(self) -> None:
        layout = blockwrites.parse_dumpe2fs(DUMPE2FS)
        assert layout is not None
        self.assertEqual(blockwrites.classify(layout, 0).area, "superblock of group 0")
        self.assertEqual(
            blockwrites.classify(layout, 2).area, "group descriptors of group 0"
        )
        self.assertEqual(
            blockwrites.classify(layout, 32768).area, "superblock of group 1"
        )
        self.assertEqual(
            blockwrites.classify(layout, 1044).area, "inode bitmap of group 1"
        )
        self.assertEqual(blockwrites.classify(layout, 1059).inodes, (1, 16))
        self.assertEqual(blockwrites.classify(layout, 1572).inodes, (8209, 8224))
        self.assertEqual(blockwrites.classify(layout, 40000), blockwrites.BlockKind())

    def test_no_layout_without_the_header(self) -> None:
        self.assertIsNone(blockwrites.parse_dumpe2fs("nothing"))

    def test_icheck_and_ncheck_output(self) -> None:
        self.assertEqual(
            blockwrites.parse_icheck(
                "Block\tInode number\n40000\t12\n40001\t<block not found>\n"
            ),
            {40000: 12, 40001: None},
        )
        self.assertEqual(
            blockwrites.parse_ncheck(
                "Inode\tPathname\n12\t/var/lib/systemd/random-seed\n"
            ),
            {12: "/var/lib/systemd/random-seed"},
        )


class Windows(unittest.TestCase):
    def test_a_window_with_no_write_finds_nothing(self) -> None:
        machine, oracle = installed()
        self.assertTrue(blockwrites.before_switch(machine, "activate"))
        self.assertIn("sync", machine.ran)
        self.assertIn(("set-action", {"shutdown": "pause"}), machine.qmp_client.sent)
        blockwrites.at_hold(machine, opened_here=True)
        machine.full_console_log.append("blkstat-mark release")
        blockwrites.after_switch(machine, "activate", True, 0, 0, hidden=True)
        self.assertTrue(blockwrites.watching(machine))
        self.assertFalse(blockwrites.before_switch(machine, "deactivate"))
        cut = blockwrites.at_hold(machine, opened_here=False)
        blockwrites.after_switch(machine, "deactivate", False, cut, cut, hidden=False)
        self.assertFalse(blockwrites.watching(machine))
        self.assertEqual(oracle.findings, [])
        self.assertEqual(oracle.errors, [])
        oracle.raise_on_findings()
        self.assertEqual(machine.qmp_client.bitmaps, {"#block100": [], "#block200": []})
        self.assertEqual(
            machine.qmp_client.sent[-1], ("set-action", {"shutdown": "poweroff"})
        )

    def test_a_write_in_the_session_is_a_finding_and_the_decoy_start_is_not_read(
        self,
    ) -> None:
        machine, oracle = installed()
        qmp = machine.qmp_client
        blockwrites.before_switch(machine, "activate")
        blockwrites.at_hold(machine, opened_here=True)
        # bw1: the switch, bw2: the session, bw3: the decoy's own start.
        blockwrites.at_hold(machine, opened_here=False)
        qmp.counts[("#block100", "bw2")] = 512
        qmp.counts[("#block100", "bw3")] = 1 << 30
        qmp.counts[("#block200", "bw2")] = 4096
        mapped = json.dumps(
            [
                {"start": 0, "length": 8192, "data": True},
                {"start": 8192, "length": 512, "data": False},
            ]
        )
        data_map = json.dumps([{"start": 0, "length": 4096, "data": False}])
        outputs = iter([mapped, "", data_map])
        with mock.patch.object(
            blockwrites, "_run", side_effect=lambda argv: next(outputs)
        ):
            blockwrites.after_switch(machine, "way back", False, 5, 6, hidden=False)
        decoy = [f for f in oracle.findings if f.decoy]
        self.assertEqual(len(decoy), 1)
        self.assertEqual(decoy[0].phase, blockwrites.SESSION)
        self.assertEqual(decoy[0].ranges, [(8192, 512)])
        self.assertIn("could not tell the writers", decoy[0].writers[0])
        self.assertEqual(
            [(f.drive, f.decoy) for f in oracle.findings if not f.decoy],
            [("drive2", False)],
        )
        with self.assertRaises(AssertionError) as raised:
            oracle.raise_on_findings()
        self.assertIn("sectors 16", str(raised.exception))
        self.assertNotIn(
            "bw3", json.dumps([a for _, a in qmp.sent if _ == "block-export-add"])
        )

    def test_allowed_extents_are_not_findings(self) -> None:
        machine, oracle = installed()
        oracle.allowed["drive1"] = [(8192, 512)]
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.counts[("#block100", "bw1")] = 512
        mapped = json.dumps([{"start": 8192, "length": 512, "data": False}])
        with mock.patch.object(blockwrites, "_run", return_value=mapped):
            oracle.close("test")
        self.assertEqual(oracle.findings, [])

    def test_a_switch_that_never_enters_drops_its_window(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot")
        blockwrites.after_switch(machine, "soft-reboot", True, None, None, hidden=False)
        self.assertFalse(blockwrites.watching(machine))
        self.assertEqual(oracle.findings, [])
        self.assertEqual(oracle.errors, [])

    def test_a_way_back_without_the_hold_line_or_with_a_late_cut_is_an_error(
        self,
    ) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        blockwrites.after_switch(machine, "deactivate", False, None, None, hidden=False)
        self.assertIn("without the mark unit's hold line", oracle.errors[0])
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        blockwrites.after_switch(machine, "activate", True, 9, 3, hidden=True)
        self.assertIn("stopped waiting before the host cut", oracle.errors[0])

    def test_a_power_off_is_read_while_qemu_waits_then_qemu_quits(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.status = "shutdown"

        def quit_exits(command: str, args: dict[str, Any] | None = None) -> Any:
            reply = FakeQmp.send(machine.qmp_client, command, args)
            if command == "quit":
                machine.process.code = 0
            return reply

        machine.qmp_client.send = quit_exits  # type: ignore[method-assign]
        machine.wait_for_shutdown()
        self.assertEqual(machine.waited, 1)
        self.assertIn("quit", machine.qmp_client.commands())
        self.assertFalse(blockwrites.watching(machine))
        self.assertIn("closed at a power-off", " ".join(machine.logged))

    def test_a_crash_reads_the_window_first(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.crash()
        self.assertEqual(machine.crashed, 1)
        self.assertFalse(blockwrites.watching(machine))

    def test_the_end_of_the_test_reads_an_open_window_and_raises(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.counts[("#block100", "bw1")] = 512
        mapped = json.dumps([{"start": 0, "length": 512, "data": False}])
        with (
            mock.patch.object(blockwrites, "_run", return_value=mapped),
            self.assertRaises(AssertionError),
        ):
            blockwrites.finish([machine])

    def test_a_restarted_qemu_is_an_oracle_error(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.process = FakeProcess()
        oracle.close("test")
        self.assertIn("restarted", oracle.errors[0])

    def test_an_unwatched_machine_is_left_alone(self) -> None:
        machine = FakeMachine()
        self.assertFalse(blockwrites.before_switch(machine, "x"))
        self.assertFalse(blockwrites.watching(machine))
        self.assertFalse(blockwrites.paused_at_shutdown(machine))
        self.assertEqual(machine.qmp_client.sent, [])


if __name__ == "__main__":
    unittest.main()
