"""Host-side tests for the block-write oracle, with a stand-in for QEMU's QMP."""

from __future__ import annotations

import datetime
import json
import time
import unittest
from typing import Any
from unittest import mock

from nails_e2e import blockwrites, session

ROOT = {
    "device": "drive1",
    "qdev": "/machine/peripheral/root",
    "inserted": {"node-name": "#block100", "file": "/tmp/vm-state/machine.qcow2"},
}
DATA = {
    "device": "drive2",
    "qdev": "/machine/peripheral/data",
    "inserted": {"node-name": "#block200", "file": "/tmp/vm-state/empty0.qcow2"},
}
#: A drive the extra-disk rule takes as a decoy drive.
HIDDEN = {
    "device": "drive5",
    "qdev": "/machine/peripheral/hid",
    "inserted": {"node-name": "#block500", "file": "/tmp/vm-state/hidden.qcow2"},
}

#: What the guest answers about the hidden volume, by a part of the command:
#: an ext4 filesystem alone on the drive with serial "data".
ON_DATA = {
    "cat /run/overlay-runtime/plan.json": '{"version": 1, "hidden_root": "/mnt/data"}',
    "--target /mnt/data": "/dev/vdb ext4 /mnt/data",
    "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb": "/dev/vdb disk data",
    "lsblk -nrpo PATH,FSTYPE /dev/vdb": "/dev/vdb ext4",
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
        self.serials: dict[str, str] = {
            "/machine/peripheral/root": "root",
            "/machine/peripheral/data": "data",
            "/machine/peripheral/hid": "hid",
        }
        self.fail_transactions = False
        #: Drives besides the usual ones.
        self.extra: list[dict[str, Any]] = []

    def send(self, command: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        args = args or {}
        self.sent.append((command, args))
        if command == "query-block":
            out = []
            for block in (ROOT, DATA, STORE, CDROM, *self.extra):
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
        if command == "transaction" and self.fail_transactions:
            raise RuntimeError("QMP said no")
        if command == "transaction":
            for action in args["actions"]:
                data = action["data"]
                if action["type"] == "block-dirty-bitmap-add":
                    self.bitmaps.setdefault(data["node"], []).append(data["name"])
        if command == "block-dirty-bitmap-remove":
            self.bitmaps[args["node"]].remove(args["name"])
        if command == "query-status":
            return {"return": {"status": self.status}}
        if command == "qom-get":
            return {"return": self.serials.get(args["path"], "")}
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
        self.monitor: list[str] = []
        self.typed: list[str] = []
        #: The guest's answers, by a part of the command: the first that
        #: matches.
        self.answers: dict[str, str] = dict(ON_DATA)
        self.started = 0

    def succeed(self, *commands: str, timeout: int | None = None) -> str:
        self.ran.extend(commands)
        for part, answer in self.answers.items():
            if part in commands[0]:
                return answer
        return ""

    def log(self, msg: str) -> None:
        self.logged.append(msg)

    def start(self) -> None:
        self.started += 1
        self.process = FakeProcess()

    def wait_for_unit(self, unit: str) -> None:
        pass

    def wait_for_shutdown(self, timeout: object = None) -> None:
        self.waited += 1

    def send_console(self, chars: str) -> None:
        self.typed.append(chars)
        if chars == blockwrites.SYNC:
            self.full_console_log.append("blkstat-mark synced")

    def send_monitor_command(self, command: str) -> str:
        self.monitor.append(command)
        if command == "quit":
            self.process.code = 0
        return ""

    def crash(self) -> None:
        self.crashed += 1


def installed() -> tuple[FakeMachine, blockwrites.Oracle]:
    machine = FakeMachine()
    oracle = blockwrites.install(machine, {"qemu_img": "qemu-img"}, watch=False)
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


WRITERS = [
    "sectors 0-7: the whole disk, ext4 blocks 0-0: superblock of group 0",
    "sectors 8-31: disk.raw2, ext4 blocks 1-3: group descriptors of group 0",
    "sectors 100: disk.raw2, ext4 blocks 12-12: data of inode 8 (the journal); "
    "data of inode 12 (no name); data of inode 393227 (//var/lib/systemd/random-seed)",
    "sectors 200: disk.raw2, ext4 blocks 25-25 (first blocks): inode table slots "
    "1-16, in use: 2 /; 11 lost+found; free blocks [7]",
    "sectors 16384: disk.raw1, not ext4 (bad magic): writer not told",
    "sectors 1: outside every partition",
    "could not tell the writers: boom",
]


class Verdicts(unittest.TestCase):
    def test_the_writers_are_compared_by_file_and_metadata_class(self) -> None:
        self.assertEqual(
            blockwrites.items_of(WRITERS),
            {
                "the whole disk: superblock",
                "disk.raw2: group descriptors",
                "disk.raw2: journal",
                "disk.raw2: an unlinked inode",
                "disk.raw2: /var/lib/systemd/random-seed",
                "disk.raw2: inode table",
                "disk.raw2: free blocks",
                "disk.raw1: not ext4",
                "outside every partition",
                "unattributed",
            },
        )

    def finding(self, phase: str, writers: list[str]) -> blockwrites.Finding:
        return blockwrites.Finding(
            "activate", phase, "drive1", True, [(0, 512)], writers
        )

    def test_the_switch_phase_must_be_a_part_of_the_control(self) -> None:
        machine, oracle = installed()
        oracle.findings.append(self.finding(blockwrites.SWITCH, WRITERS[:2]))
        switch, session = oracle.verdict()
        self.assertIn("no plain soft-reboot", switch[0])
        oracle.controls["drive1"] = blockwrites.items_of(WRITERS[:3])
        self.assertEqual(oracle.verdict(), ([], []))
        oracle.findings.append(self.finding(blockwrites.SWITCH, WRITERS[4:5]))
        switch, session = oracle.verdict()
        self.assertIn("disk.raw1: not ext4", switch[0])
        oracle.raise_on_findings()
        with (
            mock.patch.object(blockwrites, "SWITCH_VERDICT", blockwrites.STRICT),
            self.assertRaises(AssertionError),
        ):
            oracle.raise_on_findings()
        with mock.patch.object(blockwrites, "SESSION_VERDICT", blockwrites.STRICT):
            oracle.raise_on_findings()  # the session phase holds

    def test_any_session_phase_write_breaks_the_session_verdict(self) -> None:
        machine, oracle = installed()
        oracle.findings.append(self.finding(blockwrites.SESSION, WRITERS[:1]))
        self.assertEqual(len(oracle.verdict()[1]), 1)

    def test_an_oracle_error_fails_only_where_a_verdict_is_strict(self) -> None:
        machine, oracle = installed()
        oracle.errors.append("boom")
        oracle.raise_on_findings()
        with (
            mock.patch.object(blockwrites, "SESSION_VERDICT", blockwrites.STRICT),
            self.assertRaises(AssertionError),
        ):
            oracle.raise_on_findings()

    def test_a_plain_soft_reboot_is_measured_as_the_control(self) -> None:
        machine, oracle = installed()
        qmp = machine.qmp_client
        self.assertTrue(blockwrites.before_switch(machine, "soft-reboot", control=True))
        cut = blockwrites.at_hold(machine, opened_here=True)
        qmp.counts[("#block100", "bw1")] = 512
        qmp.counts[("#block100", "bw2")] = 1 << 20
        mapped = json.dumps([{"start": 0, "length": 512, "data": False}])
        outputs = iter([mapped, ""])
        with (
            mock.patch.object(blockwrites, "_run", side_effect=lambda a: next(outputs)),
            mock.patch.object(blockwrites, "describe", return_value=WRITERS[2:3]),
        ):
            blockwrites.after_switch(
                machine, "soft-reboot", True, cut, cut, hidden=False
            )
        self.assertFalse(blockwrites.watching(machine))
        self.assertEqual(oracle.findings, [])
        self.assertIn("disk.raw2: journal", oracle.controls["drive1"])
        self.assertFalse(blockwrites.needs_control(oracle))
        # The guest flushed before the cut, and was let go after it.
        self.assertEqual(machine.typed, [blockwrites.SYNC, blockwrites.GO])
        self.assertEqual(oracle.errors, [])

    def test_only_a_plain_soft_reboot_is_a_control(self) -> None:
        self.assertTrue(blockwrites.is_control("systemctl soft-reboot"))
        self.assertFalse(blockwrites.is_control("systemctl reboot"))
        self.assertFalse(blockwrites.is_control("nails --config c activate -y"))
        self.assertFalse(blockwrites.is_control("nails deactivate --soft-reboot"))

    def test_a_flush_that_never_ends_is_an_oracle_error(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot", control=True)
        machine.send_console = machine.typed.append  # type: ignore[method-assign, assignment]
        with mock.patch.object(blockwrites, "SYNC_WAIT", 0.2):
            blockwrites.at_hold(machine, opened_here=True)
        self.assertIn("flush did not end", oracle.errors[0])

    def test_a_control_without_a_cut_is_noted_and_one_that_enters_is_an_error(
        self,
    ) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot", control=True)
        blockwrites.after_switch(machine, "soft-reboot", True, None, None, hidden=False)
        self.assertTrue(oracle.uncut_control)
        blockwrites.before_switch(machine, "x", control=True)
        blockwrites.after_switch(machine, "x", True, None, None, hidden=True)
        self.assertIn("landed in the hidden root", oracle.errors[0])

    def test_a_session_whose_switch_wrote_needs_a_control(self) -> None:
        machine, oracle = installed()
        self.assertFalse(blockwrites.needs_control(oracle))
        oracle.findings.append(self.finding(blockwrites.SWITCH, WRITERS[:1]))
        self.assertTrue(blockwrites.needs_control(oracle))


class HiddenDrives(unittest.TestCase):
    def blocks(self) -> list[dict[str, Any]]:
        root = json.loads(json.dumps(ROOT))
        data = json.loads(json.dumps(DATA))
        extra = {
            "device": "drive4",
            "qdev": "/dev/extra",
            "inserted": {"node-name": "#block400", "file": "/x/empty1.qcow2"},
        }
        data["qdev"] = "/dev/data"
        return [root, data, extra]

    def test_the_hidden_volume_s_serials_leave_every_other_drive_a_decoy_drive(
        self,
    ) -> None:
        serials = {"drive2": "data", "drive4": "extra"}
        decoy, other = blockwrites.drives(self.blocks(), serials, {"data"})
        self.assertEqual([d.device for d in decoy], ["drive1", "drive4"])
        self.assertEqual([d.device for d in other], ["drive2"])
        # Without them, the extra disks are not judged.
        decoy, other = blockwrites.drives(self.blocks(), serials, None)
        self.assertEqual([d.device for d in decoy], ["drive1"])

    def test_the_hidden_start_tells_the_hidden_drives_and_needs_its_hold_line(
        self,
    ) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        assert oracle.window is not None
        # QEMU told each drive's serial.
        self.assertEqual(
            [(d.device, d.serial) for d in oracle.window.decoy + oracle.window.other],
            [("drive1", "root"), ("drive2", "data")],
        )
        blockwrites.after_switch(machine, "activate", True, None, None, hidden=True)
        self.assertEqual(oracle.hidden, {"data"})
        self.assertEqual([d.device for d in oracle.window.other], ["drive2"])
        self.assertIn("without the mark unit's hold line", oracle.errors[0])

    def test_the_open_window_is_sorted_again_by_the_hidden_volume_s_drives(
        self,
    ) -> None:
        machine, oracle = installed()
        machine.qmp_client.extra.append(HIDDEN)
        machine.answers["lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb"] = "/dev/vdb disk hid"
        blockwrites.before_switch(machine, "activate")
        assert oracle.window is not None
        # By the extra-disk rule until the hidden root's start.
        self.assertEqual([d.device for d in oracle.window.decoy], ["drive1", "drive5"])
        blockwrites.at_hold(machine, opened_here=True)
        blockwrites.after_switch(machine, "activate", True, 0, None, hidden=True)
        self.assertEqual(oracle.errors, [])
        # The hidden volume's drive leaves the decoy drives, and the extra
        # disk it does not lie on joins them.
        self.assertEqual([d.device for d in oracle.window.other], ["drive5"])
        self.assertEqual([d.device for d in oracle.window.decoy], ["drive1", "drive2"])
        self.assertIn("lies on the drive with serial hid", " ".join(machine.logged))

    def test_hidden_drives_that_cannot_be_told_are_an_oracle_error(self) -> None:
        machine, oracle = installed()
        machine.answers["lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb"] = "/dev/vdb disk "
        blockwrites.before_switch(machine, "activate")
        blockwrites.after_switch(machine, "activate", True, 0, None, hidden=True)
        self.assertIn(
            "cannot be told (/dev/vdb, below /mnt/data, has no serial)",
            oracle.errors[0],
        )
        self.assertIsNone(oracle.hidden)
        assert oracle.window is not None
        self.assertEqual([d.device for d in oracle.window.other], ["drive2"])

    def test_a_drive_the_hidden_volume_shares_stays_a_decoy_drive(self) -> None:
        machine, oracle = installed()
        machine.answers = {
            "cat /run/overlay-runtime/plan.json": '{"hidden_root": "/mnt/hidden"}',
            "--target /mnt/hidden": "/dev/mapper/hid ext4 /mnt/hidden",
            "lsblk -nrspo PATH,TYPE,SERIAL /dev/mapper/hid": (
                "/dev/mapper/hid crypt \n/dev/loop0 loop "
            ),
            "BACK-FILE --raw /dev/loop0": "254:32 /srv/c.img\n",
            "readlink /sys/dev/block/254:32": "vdc",
            "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdc": "/dev/vdc disk data",
        }
        blockwrites.before_switch(machine, "activate")
        blockwrites.after_switch(machine, "activate", True, 0, None, hidden=True)
        self.assertEqual(oracle.hidden, set())
        self.assertIn(
            "serial data holds the hidden volume beside other data", oracle.errors[0]
        )
        self.assertIn("the file /srv/c.img holds it", oracle.errors[0])
        assert oracle.window is not None
        self.assertEqual([d.device for d in oracle.window.decoy], ["drive1", "drive2"])

    def test_a_plain_soft_reboot_that_lands_hidden_drops_its_window(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot", control=True)
        blockwrites.after_switch(machine, "soft-reboot", True, 5, None, hidden=True)
        self.assertFalse(blockwrites.watching(machine))
        self.assertIn("landed in the hidden root", oracle.errors[0])

    def test_a_failed_cut_is_an_oracle_error_not_a_failure(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.fail_transactions = True
        blockwrites.at_hold(machine, opened_here=True)
        self.assertIn("the cut failed", oracle.errors[0])
        oracle.raise_on_findings()  # report mode

    def test_an_older_hold_and_release_keep_no_answer_back(self) -> None:
        machine, oracle = installed()
        machine.full_console_log += ["blkstat-mark hold", "blkstat-mark release"]
        since = len(machine.full_console_log)
        machine.full_console_log.append("blkstat-mark hold")
        blockwrites.at_hold(machine, opened_here=True, since=since)
        self.assertEqual(machine.typed, [blockwrites.GO])

    def test_a_test_can_ask_for_no_control(self) -> None:
        machine, oracle = installed()
        oracle.findings.append(
            blockwrites.Finding("a", blockwrites.SWITCH, "drive1", True, [(0, 1)], [])
        )
        self.assertTrue(blockwrites.needs_control(oracle))
        blockwrites.skip_control(machine, "its fstab state breaks a soft-reboot")
        self.assertFalse(blockwrites.needs_control(oracle))
        self.assertIn("fstab state", oracle.verdict()[0][0])


class HiddenVolume(unittest.TestCase):
    def volume(self, answers: dict[str, str]) -> blockwrites.HiddenVolume:
        machine = FakeMachine()
        machine.answers = {
            "cat /run/overlay-runtime/plan.json": '{"hidden_root": "/mnt/hidden"}',
            **answers,
        }
        return blockwrites.hidden_volume(machine)

    def test_a_disk_of_its_own(self) -> None:
        volume = self.volume(
            {
                "--target /mnt/hidden": "/dev/dm-0 ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/dm-0": (
                    "/dev/dm-0 crypt \n/dev/vdb disk hid"
                ),
                "lsblk -nrpo PATH,FSTYPE /dev/vdb": (
                    "/dev/vdb crypto_LUKS\n/dev/dm-0 ext4"
                ),
            }
        )
        self.assertEqual((volume.alone, volume.shared), ({"hid"}, {}))

    def test_a_partition_beside_a_decoy_one(self) -> None:
        volume = self.volume(
            {
                "--target /mnt/hidden": "/dev/vdb2 ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb2": (
                    "/dev/vdb2 part \n/dev/vdb disk d"
                ),
                "lsblk -nrpo PATH,FSTYPE /dev/vdb": (
                    "/dev/vdb \n/dev/vdb1 ext4\n/dev/vdb2 ext4"
                ),
            }
        )
        self.assertEqual(volume.alone, set())
        self.assertEqual(volume.shared, {"d": "it also holds /dev/vdb1 (ext4)"})

    def test_a_drive_reached_alone_and_beside_other_data_is_shared(self) -> None:
        # A mapping over vdb and over a file on vdb's own filesystem.
        volume = self.volume(
            {
                "--target /mnt/hidden": "/dev/mapper/hid ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/mapper/hid": (
                    "/dev/mapper/hid lvm \n/dev/vdb disk data\n/dev/loop0 loop "
                ),
                "lsblk -nrpo PATH,FSTYPE /dev/vdb": (
                    "/dev/vdb LVM2_member\n/dev/mapper/hid ext4"
                ),
                "BACK-FILE --raw /dev/loop0": "252:16 /srv/part.img",
                "readlink /sys/dev/block/252:16": "vdb",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb": "/dev/vdb disk data",
            }
        )
        self.assertEqual(volume.alone, set())
        self.assertEqual(volume.shared, {"data": "the file /srv/part.img holds it"})

    def test_a_folder_or_a_subvolume_shares_its_filesystem(self) -> None:
        folder = self.volume(
            {
                "--target /mnt/hidden": "/dev/vda ext4 /",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/vda": "/dev/vda disk root",
            }
        )
        self.assertIn("a folder of the filesystem at /", folder.shared["root"])
        subvolume = self.volume(
            {
                "--target /mnt/hidden": "/dev/vdb[/@hidden] btrfs /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdb": "/dev/vdb disk b",
            }
        )
        self.assertIn("only /@hidden of its btrfs filesystem", subvolume.shared["b"])

    def test_a_hidden_volume_in_ram_lies_on_no_drive(self) -> None:
        for answers in (
            {"--target /mnt/hidden": "tmpfs tmpfs /mnt/hidden"},
            {
                "--target /mnt/hidden": "/dev/zram0 ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/zram0": "/dev/zram0 disk ",
            },
            # The distribution tests' file on a tmpfs, by another path here.
            {
                "--target /mnt/hidden": "/dev/mapper/data ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/mapper/data": (
                    "/dev/mapper/data crypt \n/dev/loop1 loop "
                ),
                "losetup -nO BACK-MAJ:MIN,BACK-FILE --raw /dev/loop1": "0:45 /data.img",
                "findmnt -nro MAJ:MIN,FSTYPE": "0:30 overlay\n0:45 tmpfs",
            },
        ):
            volume = self.volume(answers)
            self.assertEqual((volume.alone, volume.shared), (set(), {}), answers)

    def test_a_file_on_btrfs_is_found_by_its_path(self) -> None:
        volume = self.volume(
            {
                "--target /mnt/hidden": "/dev/loop1 ext4 /mnt/hidden",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/loop1": "/dev/loop1 loop ",
                "BACK-FILE --raw /dev/loop1": "0:52 /srv/h.img",
                "findmnt -nro MAJ:MIN,FSTYPE": "0:52 btrfs",
                "--target /srv/h.img": "/dev/vdc[/@srv] btrfs /srv",
                "lsblk -nrspo PATH,TYPE,SERIAL /dev/vdc": "/dev/vdc disk c",
            }
        )
        self.assertEqual(volume.shared, {"c": "the file /srv/h.img holds it"})

    def test_what_it_cannot_tell_raises(self) -> None:
        for answers, why in (
            ({"--target /mnt/hidden": "overlay overlay /"}, "lies on overlay"),
            (
                {
                    "--target /mnt/hidden": "/dev/loop1 ext4 /mnt/hidden",
                    "lsblk -nrspo PATH,TYPE,SERIAL /dev/loop1": "/dev/loop1 loop ",
                },
                "no backing file",
            ),
            (
                {
                    "--target /mnt/hidden": "/dev/loop1 ext4 /mnt/hidden",
                    "lsblk -nrspo PATH,TYPE,SERIAL /dev/loop1": "/dev/loop1 loop ",
                    "losetup -nO BACK-MAJ:MIN,BACK-FILE --raw /dev/loop1": "0:9 /x",
                    "findmnt -nro MAJ:MIN,FSTYPE": "0:30 overlay",
                },
                "is not mounted here",
            ),
        ):
            with self.assertRaises(ValueError) as raised:
                self.volume(answers)
            self.assertIn(why, str(raised.exception))
        machine = FakeMachine()
        machine.answers = {"cat /run/overlay-runtime/plan.json": "{}"}
        with self.assertRaises(ValueError):
            blockwrites.hidden_volume(machine)


class DecoyMounts(unittest.TestCase):
    def test_a_loop_file_on_a_mount_only_the_decoy_shows_lies_in_ram(self) -> None:
        machine, oracle = installed()
        machine.answers = {
            blockwrites.MOUNT_TYPES: "0:30 ext4\n0:45 tmpfs",
            "cat /run/overlay-runtime/plan.json": '{"hidden_root": "/mnt/data"}',
            "--target /mnt/data": "/dev/mapper/data ext4 /mnt/data",
            "lsblk -nrspo PATH,TYPE,SERIAL /dev/mapper/data": (
                "/dev/mapper/data crypt \n/dev/loop0 loop "
            ),
            "BACK-FILE --raw /dev/loop0": "0:45 /data.img",
        }
        blockwrites.before_switch(machine, "activate")
        self.assertEqual(oracle.mount_types, {"0:30": "ext4", "0:45": "tmpfs"})
        # The hidden root no longer shows the tmpfs.
        machine.answers[blockwrites.MOUNT_TYPES] = "0:31 overlay"
        blockwrites.after_switch(machine, "activate", True, 0, None, hidden=True)
        self.assertEqual(oracle.errors, [])
        self.assertEqual(oracle.hidden, set())
        self.assertIn("lies on no drive", " ".join(machine.logged))


class Arming(unittest.TestCase):
    ARM = f"[ -e {blockwrites.ARM} ] || : > {blockwrites.ARM}"
    DISARM = f"rm -f {blockwrites.ARM}"

    def test_the_mark_unit_is_armed_while_a_window_is_open(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        self.assertEqual(machine.ran.count(self.ARM), 1)
        blockwrites.after_switch(machine, "activate", True, 0, 0, hidden=True)
        self.assertNotIn(self.DISARM, machine.ran)
        # The way back arms it again, and its end disarms it.
        blockwrites.before_switch(machine, "deactivate")
        self.assertEqual(machine.ran.count(self.ARM), 2)
        blockwrites.after_switch(machine, "deactivate", False, None, None, hidden=False)
        self.assertEqual(machine.ran[-1], self.DISARM)

    def test_a_switch_that_never_enters_disarms_and_a_failure_is_an_error(
        self,
    ) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot")
        blockwrites.after_switch(machine, "soft-reboot", True, None, None, hidden=False)
        self.assertEqual(machine.ran[-1], self.DISARM)

        def refuse(*commands: str, timeout: int | None = None) -> str:
            if "blkstat-arm" in commands[0]:
                raise RuntimeError("no shell")
            return ""

        machine, oracle = installed()
        machine.succeed = refuse  # type: ignore[method-assign]
        blockwrites.before_switch(machine, "activate")
        self.assertIn("could not be armed: no shell", oracle.errors[0])
        oracle.discard()
        blockwrites.disarm(machine)
        self.assertIn("could not be disarmed", oracle.errors[1])

    def test_the_first_window_reports_the_boot_s_mark_and_journald(self) -> None:
        machine, oracle = installed()
        machine.answers[blockwrites.BOOT_TIMES] = (
            "InactiveExitTimestampMonotonic=3100000\n"
            "InactiveEnterTimestampMonotonic=3150000\n"
            "ExecMainStartTimestampMonotonic=3300000\n"
        )
        blockwrites.before_switch(machine, "activate")
        oracle.discard()
        blockwrites.before_switch(machine, "again")
        boot = [line for line in machine.logged if "boot:" in line]
        self.assertEqual(
            boot,
            [
                "block-write oracle: boot: the mark unit ran 0.05 s from 3.10 s; "
                "journald started at 3.30 s"
            ],
        )
        self.assertIn(
            "the mark unit did not run",
            blockwrites.boot_times("InactiveExitTimestampMonotonic=0\n"),
        )


class Control(unittest.TestCase):
    def test_a_test_that_ended_in_the_hidden_root_has_no_control(self) -> None:
        machine, oracle = installed()
        machine.answers["findmnt -no FSTYPE /"] = "overlay"
        with mock.patch.object(session, "follow_soft_reboot") as follow:
            blockwrites._control(machine, oracle)
        follow.assert_not_called()
        self.assertEqual(
            oracle.errors, ["no control: the test ended in the hidden root"]
        )

    def test_the_control_installs_the_mark_unit_first_and_starts_a_machine_off(
        self,
    ) -> None:
        machine, oracle = installed()
        oracle.tools["mark_setup"] = "install the mark unit"
        machine.answers["findmnt -no FSTYPE /"] = "ext4"
        machine.process.code = 0
        seen: list[str] = []
        with mock.patch.object(
            session,
            "follow_soft_reboot",
            side_effect=lambda m, trigger, label: seen.extend(m.ran),
        ) as follow:
            blockwrites._control(machine, oracle)
        follow.assert_called_once_with(
            machine, blockwrites.CONTROL_TRIGGER, "oracle-control"
        )
        self.assertEqual(machine.started, 1)
        self.assertIn("install the mark unit", seen)
        self.assertEqual(oracle.errors, [])

    def test_a_failed_control_is_an_oracle_error(self) -> None:
        machine, oracle = installed()
        machine.answers["findmnt -no FSTYPE /"] = "ext4"
        with mock.patch.object(
            session, "follow_soft_reboot", side_effect=RuntimeError("boom")
        ):
            blockwrites._control(machine, oracle)
        self.assertEqual(oracle.errors, ["the control soft-reboot failed: boom"])

    def test_qemu_gone_at_the_end_with_a_window_open_is_an_oracle_error(
        self,
    ) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.process.code = 0
        blockwrites.finish([machine])
        self.assertEqual(oracle.errors, ["activate: QEMU ended without the oracle"])
        self.assertFalse(blockwrites.watching(machine))


class Evidence(unittest.TestCase):
    def test_an_error_about_a_cut_shows_the_switch_s_console_lines(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.full_console_log += ["old line", "blkstat-mark hold"]
        since = 1
        machine.full_console_log += [
            "noise",
            "blkstat-mark release",
            "x Starting Boot marker",
        ]
        blockwrites.after_switch(
            machine, "deactivate", False, None, None, hidden=False, since=since
        )
        self.assertIn("without the mark unit's hold line", oracle.errors[0])
        shown = [line for line in machine.logged if ": console " in line]
        self.assertEqual(
            shown,
            [
                "block-write oracle: deactivate: console 1: blkstat-mark hold",
                "block-write oracle: deactivate: console 3: blkstat-mark release",
                "block-write oracle: deactivate: console 4: x Starting Boot marker",
            ],
        )

    def test_a_switch_without_an_error_shows_none_and_each_cut_says_where(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.full_console_log += ["blkstat-mark hold"]
        cut = blockwrites.at_hold(machine, opened_here=True, since=0)
        self.assertIn(
            f"block-write oracle: activate: cut at console line {cut}, "
            "hold at 0, answered",
            machine.logged,
        )
        blockwrites.after_switch(
            machine, "activate", True, cut, None, hidden=True, since=0
        )
        self.assertFalse([line for line in machine.logged if ": console " in line])

    def test_a_flush_that_never_ends_shows_the_console_from_the_hold(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "soft-reboot", control=True)
        machine.full_console_log += ["blkstat-mark hold"]
        machine.send_console = machine.typed.append  # type: ignore[method-assign, assignment]
        with mock.patch.object(blockwrites, "SYNC_WAIT", 0.2):
            blockwrites.at_hold(machine, opened_here=True, since=0)
        self.assertIn("typed at console line 1", oracle.errors[0])
        self.assertIn(
            "block-write oracle: soft-reboot: console 0: blkstat-mark hold",
            machine.logged,
        )


class BackdoorFirst(unittest.TestCase):
    def test_a_switch_reads_on_past_the_backdoor_for_the_hold_line_a_while(
        self,
    ) -> None:
        machine, oracle = installed()
        now = time.monotonic()
        self.assertFalse(blockwrites.hold_pending(machine, None, now), "no window")
        blockwrites.before_switch(machine, "activate")
        self.assertTrue(blockwrites.hold_pending(machine, None, now))
        self.assertFalse(blockwrites.hold_pending(machine, 7, now), "cut already")
        self.assertFalse(
            blockwrites.hold_pending(machine, None, now - blockwrites.HOLD_GRACE - 1)
        )


class Threads(unittest.TestCase):
    def test_the_watch_thread_finishes_a_paused_power_off(self) -> None:
        machine = FakeMachine()
        oracle = blockwrites.install(machine, {"qemu_img": "qemu-img"})
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.status = "shutdown"
        deadline = time.monotonic() + 10
        while blockwrites.watching(machine) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(blockwrites.watching(machine))
        self.assertEqual(machine.monitor, ["quit"])
        self.assertEqual(oracle.errors, [])

    def test_every_qmp_command_is_sent_under_one_lock(self) -> None:
        machine, oracle = installed()
        inside: list[bool] = []
        send = machine.qmp_client.send

        def probe(command: str, args: dict[str, Any] | None = None) -> Any:
            got = blockwrites._QMP_LOCK.acquire(blocking=False)
            inside.append(got)
            if got:
                blockwrites._QMP_LOCK.release()
            return send(command, args)

        machine.qmp_client.send = probe  # type: ignore[method-assign]
        oracle._qmp("query-status")
        self.assertEqual(inside, [True])
        self.assertTrue(getattr(machine.qmp_client, "_nails_serialized", False))


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


STATS = """\
Block size:               4096
Inodes per group:         8192
Inode size:\t          256
First block:              0
Blocks per group:         32768
Reserved GDT blocks:      1023
Group descriptor size:    64
Inode blocks per group:   512
Directories:              2
 Group  0: block bitmap at 1027, inode bitmap at 1043, inode table at 1059
           5318 free blocks, 2036 free inodes, 2 used directories
 Group  1: block bitmap at 1028, inode bitmap at 1044, inode table at 1571
           [Inode not init, Checksum 0x0e58]
 Group  2: block bitmap at 1029, inode bitmap at 1045, inode table at 2083
 Group  3: block bitmap at 1030, inode bitmap at 1046, inode table at 2595
"""


class Ext4(unittest.TestCase):
    def test_the_layout_names_each_metadata_area(self) -> None:
        layout = blockwrites.parse_stats(STATS)
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
        self.assertEqual(
            blockwrites.classify(layout, 98304).area, "superblock of group 3"
        )
        self.assertEqual(
            blockwrites.classify(layout, 1024).area, "group descriptors of group 0"
        )
        self.assertEqual(blockwrites.classify(layout, 65536), blockwrites.BlockKind())
        self.assertEqual(blockwrites.classify(layout, 1059).inodes, (1, 16))
        self.assertEqual(blockwrites.classify(layout, 1572).inodes, (8209, 8224))
        self.assertEqual(blockwrites.classify(layout, 40000), blockwrites.BlockKind())

    def test_no_layout_without_the_header(self) -> None:
        self.assertIsNone(blockwrites.parse_stats("nothing"))

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
    def test_the_hold_is_answered_after_the_cut_unless_it_ended(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.full_console_log += ["x", "blkstat-mark hold"]
        cut = blockwrites.at_hold(machine, opened_here=True)
        self.assertEqual(cut, 2)
        assert oracle.window is not None
        self.assertEqual(machine.typed, ["blkstat-go\n"])
        self.assertEqual([p.name for p in oracle.window.phases], ["switch", "session"])
        machine.full_console_log += ["blkstat-mark hold", "blkstat-mark release"]
        blockwrites.at_hold(machine, opened_here=False)
        self.assertEqual(machine.typed, ["blkstat-go\n"])

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
        oracle.raise_on_findings()  # the report mode fails no test
        self.assertIn("sectors 16", " ".join(machine.logged))
        with (
            mock.patch.object(blockwrites, "SESSION_VERDICT", blockwrites.STRICT),
            self.assertRaises(AssertionError) as raised,
        ):
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

    def test_the_wait_for_a_power_off_keeps_the_caller_s_timeout(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        with mock.patch.object(blockwrites, "wait_for_exit", return_value=True) as w:
            machine.wait_for_shutdown(timeout=datetime.timedelta(seconds=7))
            w.assert_called_once_with(machine, 7.0)
            machine.wait_for_shutdown(9)
            w.assert_called_with(machine, 9)
        self.assertEqual(machine.waited, 2)
        # A wait that ran out raises at once, without the driver's own wait.
        with (
            mock.patch.object(blockwrites, "wait_for_exit", return_value=False),
            self.assertRaises(TimeoutError),
        ):
            machine.wait_for_shutdown(timeout=3)
        self.assertEqual(machine.waited, 2)

    def test_a_power_off_is_read_while_qemu_waits_then_qemu_quits(self) -> None:
        machine, oracle = installed()
        blockwrites.before_switch(machine, "activate")
        machine.qmp_client.status = "shutdown"
        machine.wait_for_shutdown()
        self.assertEqual(machine.waited, 1)
        self.assertEqual(machine.monitor, ["quit"])
        self.assertNotIn("quit", machine.qmp_client.commands())
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
            mock.patch.object(blockwrites, "_control") as control,
            mock.patch.object(blockwrites, "SWITCH_VERDICT", blockwrites.STRICT),
            self.assertRaises(AssertionError),
        ):
            blockwrites.finish([machine])
        control.assert_called_once()

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
