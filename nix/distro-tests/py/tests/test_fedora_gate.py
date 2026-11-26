"""Tests for the judgments of fedora_gate, the gate scenario of an enforcing
Fedora decoy, that run without a VM."""

from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
import zlib
from typing import Any

import fedora_gate as fg
import selinux_gate as sg

# The update state of a decoy whose /etc and /var follow /usr.
CURRENT = "/etc current; /var current"


def settled(run: fg.Gate) -> fg.Gate:
    """``run`` with every switch of its disk and /run listings taken in one
    update state, and the same names before and after each."""
    labels = {*run.disk, *run.runs}
    run.update_states = dict.fromkeys(labels, CURRENT)
    run.names = {label: ({"/etc"}, {"/etc"}) for label in labels}
    return run


# The folder every gate of these tests writes its results in, removed when
# the tests end.
SCRATCH = tempfile.TemporaryDirectory(prefix="gate-test-")


def gate(**settings: Any) -> fg.Gate:
    return fg.Gate(
        None,
        None,
        None,
        None,
        {"image": "fedora-44", **settings},
        tempfile.mkdtemp(prefix="gate-test-", dir=SCRATCH.name),
    )


def quiet(call: Any, *args: Any) -> Any:
    """``call`` with what it prints kept off the test's output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args)


class SocketIdentityTest(unittest.TestCase):
    BOOT = (
        "socket /run/systemd/journal/dev-log inode=11 label=u:r:kernel_t:s0\n"
        "socket /run/systemd/journal/socket inode=12 label=u:r:kernel_t:s0\n"
        "socket audit inode=13 label=u:r:kernel_t:s0\n"
        "\n"
        "unit systemd-journald.socket active since=1000\n"
    )

    def test_the_boot_s_sockets_are_the_same(self) -> None:
        boot = fg.socket_identity(self.BOOT)
        self.assertEqual(len(boot), 4)
        self.assertTrue(fg.same_sockets(boot, fg.socket_identity(self.BOOT)))

    def test_a_socket_made_anew_differs(self) -> None:
        boot = fg.socket_identity(self.BOOT)
        for change in (
            ("inode=12", "inode=99"),
            ("kernel_t:s0\nsocket audit", "syslogd_t:s0\nsocket audit"),
            ("since=1000", "since=2000"),
            ("socket audit inode=13 label=u:r:kernel_t:s0\n", ""),
        ):
            now = fg.socket_identity(self.BOOT.replace(*change))
            self.assertFalse(fg.same_sockets(boot, now), change)

    def test_without_the_native_socket_nothing_is_judged_the_same(self) -> None:
        self.assertFalse(fg.same_sockets([], []))
        unit = ["unit systemd-journald.socket active since=1"]
        self.assertFalse(fg.same_sockets(unit, unit))


class PrepareTest(unittest.TestCase):
    def test_every_start_takes_the_gate_s_kernel_log_settings(self) -> None:
        for key, value in sg.KMSG_SETTINGS:
            self.assertIn(f"'{key} = {value}'", fg.PREPARE_DECOY)
        self.assertIn("/etc/sysctl.d/", fg.PREPARE_DECOY)

    def test_the_next_boots_keep_a_larger_kernel_log_buffer(self) -> None:
        # Fedora's kernel keeps 256 KiB, the records of about two switches
        # in the variant without dontaudit rules.
        args = '--args="init_on_free=1 log_buf_len=$LOG_BUF_LEN"'
        self.assertIn(f"LOG_BUF_LEN={fg.LOG_BUF_LEN}\n", fg.PREPARE_DECOY)
        self.assertIn(args, fg.PREPARE_DECOY)


def part(*seqs: int) -> str:
    """One part of the kernel log as the reader prints it, whole."""
    body = "".join(f"6,{seq},{seq * 1000},-;record {seq}\n" for seq in seqs)
    digest = hashlib.sha256(body.encode()).hexdigest()
    return f"{body}{sg.WHOLE} {len(seqs)} {digest}\n"


class FakeVm:
    """A guest whose commands give the outputs queued for them, in turn."""

    def __init__(self, *outputs: str) -> None:
        self.outputs = list(outputs)
        self.commands: list[str] = []

    def execute(self, command: str, timeout: int = 0) -> tuple[int, str]:
        self.commands.append(command)
        return 0, self.outputs.pop(0)


class MountsVm(FakeVm):
    """A :class:`FakeVm` whose decoy has no other mounts."""

    def succeed(self, command: str, timeout: int = 0) -> str:
        self.commands.append(command)
        return ""


def whole_out(body: str) -> str:
    """``body`` as the gate's guest commands print it, whole."""
    digest = hashlib.sha256(body.encode()).hexdigest()
    return f"{body}\n{sg.WHOLE} {len(body.encode())} {digest}\n"


class WholeOutputTest(unittest.TestCase):
    def test_a_torn_part_of_the_kernel_log_is_read_again(self) -> None:
        whole = part(1, 2, 3)
        # The part that came torn: bytes missing from its middle.
        torn = whole[:20] + whole[45:]
        run = gate()
        run.vm = FakeVm(torn, whole)
        run.new_boot("first")
        run.read_kmsg()
        boot = run.boots[0]
        self.assertEqual(sorted(boot["records"]), [1, 2, 3])
        self.assertEqual((boot["retried"], boot["torn"]), (1, 0))
        self.assertEqual(len(run.vm.commands), 2)

    def test_a_part_that_never_comes_whole_fails_the_run(self) -> None:
        whole = part(1, 2, 3)
        torn = whole[:20] + whole[45:]
        run = gate()
        run.vm = FakeVm(*[torn] * fg.KMSG_TRIES)
        run.new_boot("first")
        run.read_kmsg()
        self.assertEqual(run.boots[0]["torn"], 1)
        self.assertEqual(run.boots[0]["records"], {})
        quiet(run.judge_denials)
        judged = {c["name"]: c["passed"] for c in run.checks}
        self.assertFalse(judged["every read of the kernel log reached the gate whole"])

    def test_the_log_is_read_part_by_part(self) -> None:
        full = list(range(1, sg.KMSG_PART + 1))
        run = gate()
        run.vm = FakeVm(part(*full), part(sg.KMSG_PART, sg.KMSG_PART + 1))
        run.new_boot("first")
        run.read_kmsg()
        self.assertEqual(len(run.boots[0]["records"]), sg.KMSG_PART + 1)
        self.assertIn(f"python3 - {sg.KMSG_PART} ", run.vm.commands[1])

    def test_a_read_that_comes_torn_is_read_again(self) -> None:
        body = "a big read\n"
        digest = hashlib.sha256(body.encode()).hexdigest()
        whole = f"{body}\n{sg.WHOLE} {len(body)} {digest}\n"
        torn = f"a bi\n\n{sg.WHOLE} {len(body)} {digest}\n"
        run = gate()
        run.vm = FakeVm(torn, whole, *[torn] * fg.KMSG_TRIES)
        run.new_boot("first")
        self.assertEqual(quiet(run.sh, "read", "cat x", 300, True), (0, body))
        self.assertEqual((run.read_again, run.torn), (["0001.b0.read"], []))
        quiet(run.sh, "again", "cat x", 300, True)
        self.assertEqual(run.torn, ["0002.b0.again"])
        self.assertEqual(len(run.vm.commands), 2 + fg.KMSG_TRIES)

    def test_an_output_that_is_not_whole_fails_the_run(self) -> None:
        body = "the output\n"
        digest = hashlib.sha256(body.encode()).hexdigest()
        run = gate()
        run.vm = FakeVm(
            f"{body}\n{sg.WHOLE} {len(body)} {digest}\n",
            f"the outp\n\n{sg.WHOLE} {len(body)} {digest}\n",
        )
        run.new_boot("first")
        self.assertEqual(quiet(run.sh, "first", "echo the output"), (0, body))
        quiet(run.sh, "second", "echo the output")
        self.assertEqual(run.torn, ["0002.b0.second"])
        self.assertIn("python3 -c", run.vm.commands[0])


class RowTest(unittest.TestCase):
    def test_a_row_is_judged_only_with_a_verdict(self) -> None:
        rows = {
            "decoy-persistence": {"status": "warn"},
            # Refused for another reason: still a row check printed.
            "x": {"status": "fail"},
            "y": {"message": "no verdict"},
        }
        self.assertTrue(fg.judged_row(rows, "decoy-persistence"))
        self.assertTrue(fg.judged_row(rows, "x"))
        self.assertFalse(fg.judged_row(rows, "y"))
        # check printed no report: no row, nothing it could no longer name.
        self.assertFalse(fg.judged_row({}, "decoy-persistence"))


class FailedUnitsTest(unittest.TestCase):
    def test_sorts_the_failed_units(self) -> None:
        found = fg.failed_units_problems(
            [
                "overlay-runtime-boot.service",
                "systemd-remount-fs.service",
                "systemd-zram-setup@zram0.service",
                "chronyd.service",
            ],
            {"systemd-zram-setup@zram0.service": "known"},
        )
        self.assertEqual(
            found,
            {
                "nails": ["overlay-runtime-boot.service"],
                "masked": ["systemd-remount-fs.service"],
                "known": ["systemd-zram-setup@zram0.service"],
                "other": ["chronyd.service"],
            },
        )


class DecoyZramFailuresTest(unittest.TestCase):
    """A zram setup unit failed in a hidden session counts as the decoy's own
    run only with the invocation ID it had in the decoy before the entry."""

    UNIT = "systemd-zram-setup@zram0.service"
    BEFORE = f"Id={UNIT}\nInvocationID=0f3a9c\n"

    def test_the_decoy_s_run_failed_at_its_stop_is_allowed(self) -> None:
        # Fedora 45: the decoy's stop at the switch failed to reset zram0, and
        # the hidden session shows the decoy's run failed.
        found = fg.decoy_zram_failures([self.UNIT], self.BEFORE, self.BEFORE)
        self.assertEqual(list(found), [self.UNIT])
        problems = fg.failed_units_problems([self.UNIT], found)
        self.assertEqual(problems["other"], [])

    def test_a_run_of_the_hidden_session_is_not(self) -> None:
        hidden = f"Id={self.UNIT}\nInvocationID=77e01b\n"
        self.assertEqual(fg.decoy_zram_failures([self.UNIT], self.BEFORE, hidden), {})
        problems = fg.failed_units_problems([self.UNIT], {})
        self.assertEqual(problems["other"], [self.UNIT])

    def test_without_an_invocation_on_either_side_nothing_is_allowed(self) -> None:
        none = f"Id={self.UNIT}\nInvocationID=\n"
        for before, hidden in (("", self.BEFORE), (self.BEFORE, ""), (none, none)):
            self.assertEqual(fg.decoy_zram_failures([self.UNIT], before, hidden), {})

    def test_only_zram_setup_units_and_only_failed_ones(self) -> None:
        other = "chronyd.service"
        both = self.BEFORE + f"\nId={other}\nInvocationID=0f3a9c\n"
        self.assertEqual(
            list(fg.decoy_zram_failures([other, self.UNIT], both, both)), [self.UNIT]
        )
        self.assertEqual(fg.decoy_zram_failures([], both, both), {})


class ZramTest(unittest.TestCase):
    COLD = "\n".join(
        (
            "zram0 initstate=1 disksize=3103784960 backing=none "
            "mm_stat=4096 74 12288 0 12288 0 0 0 0",
            "/dev/zram0 partition 3103780864 0 100",
            "Id=systemd-zram-setup@zram0.service",
            "LoadState=loaded",
            "ActiveState=active",
            "Result=success",
            "",
            "Id=dev-zram0.swap",
            "LoadState=loaded",
            "ActiveState=active",
            "Result=success",
        )
    )

    def test_use_does_not_change_the_shape(self) -> None:
        used = self.COLD.replace("mm_stat=4096 74", "mm_stat=9999 99").replace(
            "3103780864 0 100", "3103780864 2621440 100"
        )
        self.assertEqual(fg.zram_shape(used), fg.zram_shape(self.COLD))

    def test_a_device_left_set_up_without_its_swap_differs(self) -> None:
        # The setup failed: the device keeps its size, no swap is on, and the
        # units are failed and inactive.
        failed = "\n".join(
            (
                "zram0 initstate=1 disksize=3103784960 backing=none mm_stat=0 0 0",
                "Id=systemd-zram-setup@zram0.service",
                "LoadState=loaded",
                "ActiveState=failed",
                "Result=exit-code",
                "Id=dev-zram0.swap",
                "LoadState=loaded",
                "ActiveState=inactive",
                "Result=success",
            )
        )
        self.assertNotEqual(fg.zram_shape(failed), fg.zram_shape(self.COLD))
        # A device of another size, or none, differs as well.
        other = self.COLD.replace("disksize=3103784960", "disksize=1")
        self.assertNotEqual(fg.zram_shape(other), fg.zram_shape(self.COLD))
        self.assertNotEqual(fg.zram_shape(""), fg.zram_shape(self.COLD))

    def test_the_marker_counts(self) -> None:
        probe = "\n".join(
            (
                "VmSwap:\t   20480 kB",
                "held:",
                "/dev/zram0=4021",
                "stopped:",
                "/dev/zram0=0",
                "/dev/zram1=grep: /dev/zram1: Permission denied",
            )
        )
        self.assertEqual(
            fg.zram_marker_counts(probe),
            {
                "held /dev/zram0": 4021,
                "stopped /dev/zram0": 0,
                "stopped /dev/zram1": None,
            },
        )
        self.assertEqual(fg.zram_marker_counts("/dev/zram0=0"), {"/dev/zram0": 0})
        self.assertEqual(fg.zram_marker_counts(""), {})


class DecoyDiskTest(unittest.TestCase):
    def test_the_record_files_are_left_to_the_records_checks(self) -> None:
        listing = "\n".join(
            (
                "/var/log/wtmp",
                "/var/lib/lastlog",
                "/var/lib/lastlog/lastlog2.db",
                "/var/lib/lastlogger",
                "/var/lib/systemd/random-seed",
                "find: '/proc/1': no such file",
                "",
            )
        )
        self.assertEqual(
            fg.changed_paths(listing),
            {"/var/lib/lastlogger", "/var/lib/systemd/random-seed"},
        )

    def test_a_unit_s_private_folder_is_named_by_its_unit(self) -> None:
        boot = "ab" * 16  # a boot id: 32 hex digits
        listing = "\n".join(
            (
                f"/var/tmp/systemd-private-{boot}-chronyd.service-WSgY0s",
                f"/var/tmp/systemd-private-{boot}-chronyd.service-WSgY0s/tmp",
                f"/var/tmp/systemd-private-{boot}-dbus-broker.service-nf0Nj1/tmp/x",
            )
        )
        self.assertEqual(
            fg.changed_paths(listing),
            {
                "/var/tmp/systemd-private-*-chronyd.service-*",
                "/var/tmp/systemd-private-*-chronyd.service-*/tmp",
                "/var/tmp/systemd-private-*-dbus-broker.service-*/tmp/x",
            },
        )

    def test_a_control_of_another_boot_explains_a_unit_s_private_folder(
        self,
    ) -> None:
        # The control before the cold power cycle ran under another boot ID
        # than the way back after it (seen on Fedora 45: hostnamed's folder).
        control = fg.changed_paths(
            f"/var/tmp/systemd-private-{'b5' * 16}-systemd-hostnamed.service-Ab12Cd"
        )
        way_back = fg.changed_paths(
            f"/var/tmp/systemd-private-{'21' * 16}-systemd-hostnamed.service-Zz98Yy\n"
            "/etc/x"
        )
        self.assertEqual(fg.decoy_disk_residue(way_back, [control]), ["/etc/x"])

    def test_another_filesystem_s_mount_point_is_left_out(self) -> None:
        listing = "/\n/nix/.ro-store\n/nix/store\n/etc/x\n/run"
        self.assertEqual(
            fg.changed_paths(listing, ["/nix/.ro-store", "/nix/store", "/run"]),
            {"/", "/etc/x"},
        )

    def test_a_way_back_may_change_what_a_control_changes(self) -> None:
        way_back = {"/var/lib/NetworkManager", "/etc/x", "/var/lib/chrony/drift"}
        controls = [{"/var/lib/NetworkManager"}, {"/var/lib/chrony/drift"}]
        self.assertEqual(fg.decoy_disk_residue(way_back, controls), ["/etc/x"])
        self.assertEqual(fg.decoy_disk_residue(way_back, []), sorted(way_back))

    def test_no_control_judges_no_way_back(self) -> None:
        run = gate()
        run.disk = {"way-back-1": {"/etc/x"}}
        quiet(run.judge_disk)
        judged = [c for c in run.checks if "decoy disk changed" in c["name"]]
        self.assertEqual([c["passed"] for c in judged], [False])
        self.assertIn("no control", judged[0]["detail"])

    @staticmethod
    def judged(
        disk: dict[str, set[str]],
        states: dict[str, str],
        names: dict[str, tuple[set[str] | None, set[str] | None]] | None = None,
    ) -> fg.Gate:
        run = gate()
        run.disk = disk
        run.update_states = states
        run.names = (
            names
            if names is not None
            else {label: ({"/etc"}, {"/etc"}) for label in disk}
        )
        quiet(run.judge_disk)
        run.checks = [c for c in run.checks if "decoy disk changed" in c["name"]]
        return run

    def test_judges_each_way_back_against_every_control(self) -> None:
        run = self.judged(
            {
                "control-1": {"/var/a"},
                "way-back-1": {"/var/a", "/var/b"},
                "control-2": {"/var/b"},
                "way-back-2": {"/var/a", "/etc/label"},
            },
            dict.fromkeys(
                ("control-1", "way-back-1", "control-2", "way-back-2"), CURRENT
            ),
        )
        self.assertEqual(
            [(c["name"].split(":")[0], c["passed"]) for c in run.checks],
            [("way back 1", True), ("way back 2", False)],
        )
        self.assertIn("/etc/label", run.checks[1]["detail"])

    def test_a_control_of_another_update_state_excuses_nothing(self) -> None:
        # As on arch-boxes before the fix: pacman left an update pending
        # right before the first plain soft-reboot, which brought /etc and
        # /var up to date; the way back's entry had none pending.
        update = {"/etc", "/etc/ld.so.cache", "/etc/.updated", "/var", "/var/.updated"}
        disk = {
            "control-1": {"/var/lib/systemd/random-seed", *update},
            "way-back-1": {"/var/lib/systemd/random-seed", *update},
            "control-2": {"/var/lib/systemd/random-seed"},
        }
        states = {
            "control-1": "/etc pending; /var pending",
            "way-back-1": CURRENT,
            "control-2": CURRENT,
        }
        run = self.judged(disk, states)
        self.assertFalse(run.checks[0]["passed"])
        for path in update:
            self.assertIn(path, run.checks[0]["detail"])
        # In the same state, the control's changes count.
        run = self.judged(disk, {**states, "way-back-1": states["control-1"]})
        self.assertTrue(run.checks[0]["passed"])
        # No control of the way back's state judges nothing.
        run = self.judged(
            {"control-1": disk["control-1"], "way-back-1": disk["way-back-1"]},
            {"control-1": states["control-1"], "way-back-1": CURRENT},
        )
        self.assertFalse(run.checks[0]["passed"])
        self.assertIn("update state", run.checks[0]["detail"])

    def test_an_unknown_update_state_matches_none(self) -> None:
        self.assertFalse(
            fg.same_state("/etc unknown; /var current", "/etc unknown; /var current")
        )
        self.assertFalse(fg.same_state(None, CURRENT))
        self.assertTrue(fg.same_state(CURRENT, CURRENT))
        self.assertEqual(
            fg.update_state("/etc pending\n/var current\n"),
            "/etc pending; /var current",
        )
        self.assertEqual(fg.update_state("/etc pending"), "/etc pending; /var unknown")
        self.assertEqual(fg.update_state("oops"), "/etc unknown; /var unknown")
        self.assertIn("ConditionNeedsUpdate=$d", fg.NEEDS_UPDATE)

    def test_a_deletion_shows_where_its_folder_s_times_do_not(self) -> None:
        # A plain soft-reboot changes /var's own times, so a file deleted
        # directly in /var shows only as a name gone.
        disk = {"control-1": {"/var"}, "way-back-1": {"/var"}}
        states = dict.fromkeys(disk, CURRENT)
        names: dict[str, tuple[set[str] | None, set[str] | None]] = {
            "control-1": ({"/var", "/var/a", "/var/tmp/x"}, {"/var", "/var/a"}),
            "way-back-1": ({"/var", "/var/a", "/var/tmp/x"}, {"/var", "/var/tmp/x"}),
        }
        run = self.judged(disk, states, names)
        self.assertFalse(run.checks[0]["passed"])
        self.assertIn("/var/a", run.checks[0]["detail"])
        # A name a plain soft-reboot also takes away is no sign of the session.
        names["way-back-1"] = ({"/var", "/var/a", "/var/tmp/x"}, {"/var", "/var/a"})
        self.assertTrue(self.judged(disk, states, names).checks[0]["passed"])
        # Names the gate could not read judge nothing.
        names["way-back-1"] = (None, {"/var"})
        run = self.judged(disk, states, names)
        self.assertFalse(run.checks[0]["passed"])
        self.assertIn("names not read", run.checks[0]["detail"])

    def test_reads_the_names_packed(self) -> None:
        listing = "/\n/etc\n/etc/x\n/nix/store\n/var/log/wtmp\nfind: gone\n"
        packed = base64.b64encode(gzip.compress(listing.encode())).decode()

        class Vm:
            def __init__(self, out: str, status: int = 0) -> None:
                self.out, self.status = out, status

            def execute(self, cmd: str, timeout: int = 900) -> tuple[int, str]:
                return self.status, self.out

            def succeed(self, cmd: str) -> str:
                return "/ btrfs\n/nix/store 9p\n"

        run = gate()
        run.vm = Vm(packed + "\n")
        self.assertEqual(run.disk_names("before-1"), {"/", "/etc", "/etc/x"})
        self.assertEqual(run.facts["disk-names-before-1"], 3)
        for vm in (Vm(packed[:-8]), Vm("not base64!"), Vm(packed, 1)):
            run.vm = vm
            self.assertIsNone(run.disk_names("after-1"))

    def test_a_name_another_state_s_control_took_away_still_counts(self) -> None:
        disk = {"control-1": {"/var"}, "control-2": {"/var"}, "way-back-1": {"/var"}}
        states = {
            "control-1": "/etc pending; /var pending",
            "control-2": CURRENT,
            "way-back-1": CURRENT,
        }
        names: dict[str, tuple[set[str] | None, set[str] | None]] = {
            "control-1": ({"/var", "/var/a"}, {"/var"}),
            "control-2": ({"/var"}, {"/var"}),
            "way-back-1": ({"/var", "/var/a"}, {"/var"}),
        }
        run = self.judged(disk, states, names)
        self.assertFalse(run.checks[0]["passed"])
        self.assertIn("/var/a", run.checks[0]["detail"])

    def test_a_corrupt_payload_is_read_again(self) -> None:
        good = gzip.compress(b"/\n/etc\n")
        corrupt = None
        for at in range(10, len(good) - 8):
            data = bytearray(good)
            data[at] ^= 0xFF
            try:
                gzip.decompress(bytes(data))
            except zlib.error:
                corrupt = bytes(data)
                break
            except Exception:  # noqa: BLE001 - only a zlib.error is wanted
                continue
        assert corrupt is not None
        outs = [base64.b64encode(corrupt).decode(), base64.b64encode(good).decode()]

        class Vm:
            def execute(self, cmd: str, timeout: int = 900) -> tuple[int, str]:
                return 0, outs.pop(0)

            def succeed(self, cmd: str) -> str:
                return "/ btrfs\n"

        run = gate()
        run.vm = Vm()
        self.assertEqual(run.disk_names("before-1"), {"/", "/etc"})
        self.assertIn("error", str(run.facts["disk-names-before-1"]["failed reads"]))

    def test_a_rerun_whose_quiet_listing_was_not_read_explains_nothing(
        self,
    ) -> None:
        before, rerun, after = fg.RERUN_PARTS
        out = (
            f"{before}\nfg-walk\n{rerun}\n/var/lib/unit/state\n/etc/noise\n"
            f"{after}\n"
        ).replace("fg-walk", f"{fg.WALK_ERROR} /")
        self.assertEqual(fg.rerun_changes(out), [])
        read = out.replace(f"{fg.WALK_ERROR} /", "/etc/noise")
        self.assertEqual(fg.rerun_changes(read), ["/var/lib/unit/state"])

    def test_a_mount_not_read_fails_the_way_back(self) -> None:
        disk = {"control-1": {"/var"}, "way-back-1": {"/var"}}
        run = gate()
        run.disk = disk
        run.update_states = dict.fromkeys(disk, CURRENT)
        run.names = {label: ({"/etc"}, {"/etc"}) for label in disk}
        for failures in ({"control-1": ["/home"]}, {"way-back-1": ["/home"]}):
            run.checks = []
            run.walk_failures = failures
            quiet(run.judge_disk)
            judged = [c for c in run.checks if "decoy disk changed" in c["name"]]
            self.assertEqual([c["passed"] for c in judged], [False], failures)
            self.assertIn("/home", judged[0]["detail"])

    def test_the_listing_records_a_mount_not_read(self) -> None:
        run = gate()
        run.fact = lambda label, cmd, timeout=300, again=False: (  # type: ignore[method-assign]
            "/etc/x\ngate-walk-error /home"
        )
        run.other_mounts = lambda: []  # type: ignore[method-assign]
        self.assertEqual(run.disk_changes("way-back-1", "1"), {"/etc/x"})
        self.assertEqual(run.walk_failures, {"way-back-1": ["/home"]})

    def test_names_gone(self) -> None:
        self.assertEqual(
            fg.gone_names({"/a", "/b", "/c"}, {"/a"}, [({"/b"}, set())]), ["/c"]
        )
        self.assertEqual(fg.gone_names({"/a"}, {"/a", "/new"}, []), [])


# What DECOY_TIMERS printed after a way back on Fedora 45: unbound-anchor's
# daily timer had come due while the session ran and caught up at the decoy's
# start, while fstrim's waited and the gate's own timer caught up too.
TIMERS_AFTER_WAY_BACK = "".join(
    line + "\n"
    for line in (
        "timer=fstrim.timer unit=fstrim.service persistent=yes last=@1794900000 "
        "start= end= state=inactive",
        "timer=unbound-anchor.timer unit=unbound-anchor.service persistent=yes "
        "last=@1794959962 start=@1794959962 end=@1794959964 state=inactive",
        "timer=gate-timer.timer unit=gate-timer.service persistent=yes "
        "last=@1794959962 start=@1794959962 end=@1794959962 state=inactive",
        "now=1794959980.5",
    )
)
ROOT_KEY = "/var/lib/unbound/root.key"
UNBOUND_STAMP = "/var/lib/systemd/timers/stamp-unbound-anchor.timer"
# The entry, the leave mark and the end of the switch's last step of that way
# back, as the gate takes them.
TIMERS_SINCE = 1794959800.0
TIMERS_SWITCH_US = 1794959960_500000


def way_back_timers(**changes: Any) -> dict[str, Any]:
    """What the gate takes of the decoy's timers after the way back above."""
    runs, now = fg.timer_runs(TIMERS_AFTER_WAY_BACK)
    timers: dict[str, Any] = {
        "lower": 1794959960.0,
        "since": TIMERS_SINCE,
        "switch": TIMERS_SWITCH_US / 1_000_000,
        "now": now,
        "runs": runs,
        "times": {
            ROOT_KEY: (1794959963.2, 1794959963.2),
            "/var/lib/unbound": (1794959963.2, 1794959963.2),
            UNBOUND_STAMP: (1794959962.4, 1794959962.0),
            fg.GATE_TIMER_FILE: (1794959962.6, 1794959962.6),
            "/etc/x": (1794959963.0, 1794959963.0),
        },
        "reruns": {
            "unbound-anchor.service": [ROOT_KEY, "/var/lib/unbound"],
            "gate-timer.service": [fg.GATE_TIMER_FILE],
        },
    }
    timers.update(changes)
    return timers


class DecoyTimersTest(unittest.TestCase):
    def test_reads_the_runs_of_this_start_of_pid_1(self) -> None:
        runs, now = fg.timer_runs(TIMERS_AFTER_WAY_BACK)
        self.assertEqual(now, 1794959980.5)
        self.assertEqual(
            [(r["unit"], r["start"], r["end"], r["persistent"]) for r in runs],
            [
                ("unbound-anchor.service", 1794959962.0, 1794959964.0, True),
                ("gate-timer.service", 1794959962.0, 1794959962.0, True),
            ],
        )

    def test_a_run_still_going_ends_at_none(self) -> None:
        runs, _ = fg.timer_runs(
            "timer=a.timer unit=a.service persistent=no last= "
            "start=@200 end=@100 state=activating\n"
        )
        self.assertEqual(
            [(r["start"], r["end"], r["last"]) for r in runs], [(200.0, None, None)]
        )

    def test_explains_what_the_unit_changes_again_and_its_stamp(self) -> None:
        paths = {ROOT_KEY, "/var/lib/unbound", UNBOUND_STAMP, "/etc/x"}
        self.assertEqual(
            fg.timer_explained(paths, way_back_timers()),
            {
                ROOT_KEY: "unbound-anchor.service",
                "/var/lib/unbound": "unbound-anchor.service",
                UNBOUND_STAMP: "unbound-anchor.timer",
            },
        )

    def test_a_change_its_run_by_hand_does_not_make_is_not_explained(self) -> None:
        # /etc/x changed while the unit ran, but the unit did not change it
        # when the gate started it again: a write of something else.
        self.assertEqual(fg.timer_explained({"/etc/x"}, way_back_timers()), {})

    def test_a_change_outside_the_run_is_not_explained(self) -> None:
        early = way_back_timers(times={ROOT_KEY: (1794959950.0, 1794959950.0)})
        self.assertEqual(fg.timer_explained({ROOT_KEY}, early), {})

    def test_a_run_before_the_switch_explains_nothing(self) -> None:
        late = way_back_timers(lower=1794959970.0)
        self.assertEqual(fg.timer_explained({ROOT_KEY, UNBOUND_STAMP}, late), {})

    def test_a_run_the_hidden_root_started_before_the_switch_explains_nothing(
        self,
    ) -> None:
        # unbound-anchor's run started after the leave mark, but before the
        # switch's last step ended, or within TIMER_SLACK of it: the hidden
        # root's PID 1 may have started it.
        paths = {ROOT_KEY, "/var/lib/unbound", UNBOUND_STAMP}
        for switch in (1794959962.5, 1794959961.2):
            self.assertEqual(
                fg.timer_explained(paths, way_back_timers(switch=switch)), {}, switch
            )
        # A way back whose switch's time is unknown has nothing explained.
        self.assertEqual(fg.timer_explained(paths, way_back_timers(switch=None)), {})
        self.assertEqual(len(fg.timer_explained(paths, way_back_timers())), 3)

    def test_a_judged_way_back_is_bounded_by_its_switch(self) -> None:
        # The same changes as test_a_way_back_passes_with_the_decoy_s_timer_runs,
        # with a switch that ended after the timers' runs started, or with no
        # switch's time: both fail the comparison and the positive control.
        for carried in ({"switchUs": 1794959962_500000}, {"switchUs": None}, None):
            run = gate()
            run.disk = {
                "control-1": set(),
                "way-back-1": {ROOT_KEY, UNBOUND_STAMP, fg.GATE_TIMER_FILE},
            }
            run.timers = {"way-back-1": way_back_timers()}
            if carried is not None:
                run.facts["carried-1"] = carried
            quiet(run.judge_disk)
            self.assertEqual(
                [c["passed"] for c in run.checks], [False, False], carried
            )

    def test_contents_changed_in_the_session_are_not_explained(self) -> None:
        # The inode of the key changed while unbound-anchor ran after the way
        # back, but its contents changed during the session, after the entry
        # and before the run: that write stays unexplained.
        session = way_back_timers(
            times={ROOT_KEY: (1794959963.2, TIMERS_SINCE + 30)}
        )
        self.assertEqual(fg.timer_explained({ROOT_KEY}, session), {})
        # Contents last changed before the entry, the inode by the run: the
        # run's.
        older = way_back_timers(times={ROOT_KEY: (1794959963.2, TIMERS_SINCE - 30)})
        self.assertEqual(
            fg.timer_explained({ROOT_KEY}, older),
            {ROOT_KEY: "unbound-anchor.service"},
        )
        # Without the time the listing counts from, only contents changed in
        # the run count.
        unbounded = way_back_timers(
            since=None, times={ROOT_KEY: (1794959963.2, TIMERS_SINCE - 30)}
        )
        self.assertEqual(fg.timer_explained({ROOT_KEY}, unbounded), {})

    def test_a_path_with_no_times_or_no_run_is_not_explained(self) -> None:
        self.assertEqual(fg.timer_explained({"/var/y"}, way_back_timers()), {})
        self.assertEqual(fg.timer_explained({ROOT_KEY}, {}), {})
        self.assertEqual(fg.timer_explained({ROOT_KEY}, way_back_timers(runs=[])), {})

    def test_a_stamp_not_dated_at_the_trigger_is_not_explained(self) -> None:
        moved = way_back_timers(
            times={UNBOUND_STAMP: (1794959962.4, 1794950000.0)}
        )
        self.assertEqual(fg.timer_explained({UNBOUND_STAMP}, moved), {})

    def test_a_run_its_timer_did_not_start_explains_nothing(self) -> None:
        # unbound-anchor.service started once the way back had begun, but its
        # timer last triggered a day before: something else started it.
        runs, _ = fg.timer_runs(
            TIMERS_AFTER_WAY_BACK.replace(
                "last=@1794959962 start=@1794959962 end=@1794959964",
                "last=@1794873562 start=@1794959962 end=@1794959964",
            )
        )
        paths = {ROOT_KEY, "/var/lib/unbound", UNBOUND_STAMP}
        self.assertEqual(fg.timer_explained(paths, way_back_timers(runs=runs)), {})

    def test_a_run_still_going_explains_nothing(self) -> None:
        runs, _ = fg.timer_runs(
            TIMERS_AFTER_WAY_BACK.replace(
                "start=@1794959962 end=@1794959964 state=inactive",
                "start=@1794959962 end=@1794900000 state=active",
            )
        )
        paths = {ROOT_KEY, "/var/lib/unbound", UNBOUND_STAMP}
        self.assertEqual(fg.timer_explained(paths, way_back_timers(runs=runs)), {})

    def test_a_path_changed_in_the_quiet_times_is_not_the_unit_s(self) -> None:
        out = (
            "# before\n/var/lib/other-writer\n"
            "rc=0\n# rerun\n/var/lib/other-writer\n/var/lib/later\n"
            f"{ROOT_KEY}\n/var/lib/unbound\n"
            "# after\n/var/lib/later\n"
        )
        self.assertEqual(fg.rerun_changes(out), ["/var/lib/unbound", ROOT_KEY])
        # Without its quiet times, a start by hand changed nothing of its own.
        self.assertEqual(fg.rerun_changes(f"rc=0\n# rerun\n{ROOT_KEY}\n"), [])

    def test_the_rerun_drops_another_writer_s_change(self) -> None:
        # /var/lib/leaked changed while unbound-anchor ran after the way back,
        # and again while the gate started the unit by hand, but also in the
        # quiet time before that start: another writer's, which stays
        # unexplained.
        times = (
            f"1794959963.2 1794959963.2 {ROOT_KEY}\n"
            "1794959963.5 1794959963.5 /var/lib/leaked\n"
        )
        rerun = (
            "# before\n/var/lib/leaked\nrc=0\n# rerun\n"
            f"/var/lib/leaked\n{ROOT_KEY}\n# after\n"
        )
        timers = TIMERS_AFTER_WAY_BACK.replace(
            "timer=gate-timer.timer unit=gate-timer.service persistent=yes "
            "last=@1794959962 start=@1794959962 end=@1794959962 state=inactive\n",
            "",
        )
        run = gate()
        run.vm = MountsVm(*(whole_out(o) for o in (timers, times, rerun)))
        run.disk = {"control-1": set(), "way-back-1": {ROOT_KEY, "/var/lib/leaked"}}
        quiet(run.decoy_timers, "way-back-1", 1794959960.0, str(TIMERS_SINCE))
        self.assertEqual(
            run.timers["way-back-1"]["reruns"],
            {"unbound-anchor.service": [ROOT_KEY]},
        )
        command = next(c for c in run.vm.commands if "systemctl start" in c)
        self.assertIn(f"sleep {fg.TIMER_QUIET}; echo '# before'", command)
        self.assertIn(f'[ "$d" -ge {fg.TIMER_QUIET} ]', command)
        self.assertEqual(
            fg.timer_explained(run.disk["way-back-1"], run.timers["way-back-1"]),
            {ROOT_KEY: "unbound-anchor.service"},
        )

    def test_the_runs_are_read_again_once_a_run_still_going_ended(self) -> None:
        going = TIMERS_AFTER_WAY_BACK.replace(
            "start=@1794959962 end=@1794959964 state=inactive",
            "start=@1794959962 end=@1794900000 state=activating",
        )
        run = gate()
        run.vm = MountsVm(whole_out(going), "", whole_out(TIMERS_AFTER_WAY_BACK))
        run.disk = {"way-back-1": set()}
        quiet(run.decoy_timers, "way-back-1", 1794959960.0, str(TIMERS_SINCE))
        self.assertIn("unbound-anchor.service", run.vm.commands[1])
        ends = [r["end"] for r in run.timers["way-back-1"]["runs"]]
        self.assertEqual(ends, [1794959964.0, 1794959962.0])

    def test_a_timer_s_chance_run_in_one_control_is_no_reference(self) -> None:
        controls = {
            "control-1": {"/var/lib/chrony/drift", ROOT_KEY},
            "control-2": {"/var/lib/chrony/drift"},
        }
        explained = {
            "control-1": {
                ROOT_KEY: "unbound-anchor.service",
                "/var/lib/chrony/drift": "unbound-anchor.service",
            }
        }
        self.assertEqual(
            fg.decoy_reference(controls, explained),
            [{"/var/lib/chrony/drift"}, {"/var/lib/chrony/drift"}],
        )

    def test_a_way_back_passes_with_the_decoy_s_timer_runs(self) -> None:
        # Seen on Fedora 45: unbound-anchor's catch-up wrote its key and its
        # stamp at the decoy's start after the way back, which no control did.
        run = gate()
        run.disk = {
            "control-1": {"/var/lib/chrony/drift"},
            "way-back-1": {
                "/var/lib/chrony/drift",
                ROOT_KEY,
                "/var/lib/unbound",
                UNBOUND_STAMP,
                fg.GATE_TIMER_FILE,
            },
            "control-2": {"/var/lib/chrony/drift"},
        }
        run.timers = {"way-back-1": way_back_timers()}
        run.facts["carried-1"] = {"switchUs": TIMERS_SWITCH_US}
        quiet(settled(run).judge_disk)
        self.assertEqual([c["passed"] for c in run.checks], [True, True], run.checks)

    def test_a_write_beside_the_timer_runs_still_fails(self) -> None:
        run = gate()
        run.disk = {
            "control-1": {"/var/lib/chrony/drift"},
            "way-back-1": {ROOT_KEY, UNBOUND_STAMP, fg.GATE_TIMER_FILE, "/etc/x"},
        }
        run.timers = {"way-back-1": way_back_timers()}
        run.facts["carried-1"] = {"switchUs": TIMERS_SWITCH_US}
        quiet(settled(run).judge_disk)
        self.assertEqual([c["passed"] for c in run.checks], [False, True])
        self.assertIn("'not in a control': ['/etc/x']", run.checks[0]["detail"])

    def test_the_positive_control_needs_the_gate_s_timer_run(self) -> None:
        run = gate()
        run.disk = {
            "control-1": set(),
            "way-back-1": {fg.GATE_TIMER_FILE},
        }
        quiet(run.judge_disk)
        self.assertEqual([c["passed"] for c in run.checks], [False, False])


ROOT = "/dev/vda4"
BLIND = (
    "the decoy filesystem compresses file contents, so a leaked canary may be "
    "stored compressed, which this raw plaintext scan cannot match"
)


class PartitionTest(unittest.TestCase):
    LISTING = (
        "/dev/vda1 digest-of-vda1\n"
        "/dev/vda2 digest-of-vda2\n"
        "/dev/vda3 mounted\n"
        "/dev/vda4 swap\n"
    )

    def test_reads_each_partition(self) -> None:
        self.assertEqual(
            fg.partition_hashes(self.LISTING + "no disk under x\n"),
            {
                "/dev/vda1": "digest-of-vda1",
                "/dev/vda2": "digest-of-vda2",
                "/dev/vda3": "mounted",
                "/dev/vda4": "swap",
            },
        )

    def test_a_partition_that_changed_or_was_mounted_since(self) -> None:
        before = fg.partition_hashes(self.LISTING)
        self.assertEqual(fg.partition_problems(before, before), [])
        after = {**before, "/dev/vda1": "00", "/dev/vda2": "mounted"}
        del after["/dev/vda4"]
        self.assertEqual(
            fg.partition_problems(before, after),
            [
                "/dev/vda1 holds other bytes than before the entry",
                "/dev/vda2 was not mounted before the entry and is mounted now",
            ],
        )
        self.assertEqual(
            fg.partition_problems(before, {}),
            ["/dev/vda1 is gone", "/dev/vda2 is gone"],
        )


class StreamTest(unittest.TestCase):
    LISTING = (
        "journald 230\n"
        "held 18406\n"
        "held 18759\n"
        "held 2001\n"
        "file 10:18406 systemd-logind.service active\n"
        "file 10:18759 overlay-runtime-boot.service active\n"
        "file 10:1999 dbus-broker.service active\n"
        "file 10:2001 - -\n"
    )

    def test_a_stream_of_a_unit_of_the_decoy_s_that_runs(self) -> None:
        self.assertEqual(
            fg.stream_problems(self.LISTING, ("overlay-runtime",)),
            {
                "f /run/systemd/journal/streams/10:18759": (
                    "it is NAILS's overlay-runtime-boot.service"
                ),
                "f /run/systemd/journal/streams/10:1999": (
                    "the decoy's journald holds no such stream"
                ),
                "f /run/systemd/journal/streams/10:2001": "it names no unit",
            },
        )
        stopped = "held 5\nfile 10:5 gate-late.service inactive\n"
        self.assertEqual(
            list(fg.stream_problems(stopped).values()),
            ["its unit gate-late.service does not run (inactive)"],
        )

    def test_the_shape_of_a_stream_excuses_none(self) -> None:
        streams = "f /run/systemd/journal/streams"
        run = gate()
        run.update_states = {"control-1": CURRENT, "way-back-1": CURRENT}
        run.runs = {
            "control-1": (set(), {f"{streams}/10:1"}),
            "way-back-1": (set(), {f"{streams}/10:2", f"{streams}/10:3"}),
        }
        listed = {f"{streams}/10:2", f"{streams}/10:3"}
        run.streams = {
            1: {"listed": listed, "problems": {f"{streams}/10:3": "it names no unit"}}
        }
        quiet(run.judge_run)
        self.assertFalse(run.checks[0]["passed"])
        self.assertEqual(run.facts["run-residue-way-back-1"], [f"{streams}/10:3"])
        # A stream file the reading did not list is left too.
        run.checks = []
        run.streams = {1: {"listed": {f"{streams}/10:3"}, "problems": {}}}
        quiet(run.judge_run)
        self.assertEqual(run.facts["run-residue-way-back-1"], [f"{streams}/10:2"])
        # Streams the gate could not read are all left.
        run.checks = []
        run.streams = {1: None}
        quiet(run.judge_run)
        self.assertEqual(
            run.facts["run-residue-way-back-1"], [f"{streams}/10:2", f"{streams}/10:3"]
        )


# The bash the stubs run with: the build sandbox has no /usr/bin/env.
BASH = shutil.which("bash") or "/bin/sh"


def guest(script: str, stubs: dict[str, str], tmp: str) -> str:
    """What ``script`` prints under bash with the commands of ``stubs`` (name:
    the body of a bash script) put first on the PATH: a guest command of the
    gate run against a stand-in of the guest."""
    bin_dir = os.path.join(tmp, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    for name, body in stubs.items():
        path = os.path.join(bin_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"#!{BASH}\n{body}\n")
        os.chmod(path, 0o755)
    env = {**os.environ, "PATH": bin_dir + os.pathsep + os.environ["PATH"]}
    done = subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, env=env, timeout=60
    )
    return done.stdout


class GuestCommandTest(unittest.TestCase):
    """The guest commands of the way back's new reads, run against stubs of
    the tools they call, so that a change in what they print shows here."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory(prefix="gate-guest-")
        self.addCleanup(holder.cleanup)
        self.tmp = holder.name

    def test_needs_update_reads_systemd_s_verdict(self) -> None:
        verdict = (
            'case "$2" in *=/etc) echo "Conditions succeeded." >&2 ;; '
            '*=/var) echo "Conditions failed." >&2 ;; esac'
        )
        out = guest(fg.NEEDS_UPDATE, {"systemd-analyze": verdict}, self.tmp)
        self.assertEqual(fg.update_state(out), "/etc pending; /var current")
        swapped = verdict.replace("/etc)", "/x)").replace("/var)", "/etc)")
        out = guest(fg.NEEDS_UPDATE, {"systemd-analyze": swapped}, self.tmp)
        self.assertEqual(fg.update_state(out), "/etc current; /var unknown")
        out = guest(fg.NEEDS_UPDATE, {"systemd-analyze": "echo oops >&2"}, self.tmp)
        self.assertEqual(fg.update_state(out), "/etc unknown; /var unknown")

    def test_partitions_reads_the_bytes_of_one_nothing_mounts(self) -> None:
        parts = [os.path.join(self.tmp, f"vda{i}") for i in (1, 2, 3)]
        for i, part in enumerate(parts):
            with open(part, "wb") as handle:
                handle.write(bytes([i]) * 4096)
        root = parts[2]
        findmnt = (
            f'if [ "$1" = -nvo ]; then echo {root}; exit 0; fi; '
            f'if [ "$2" = -S ]; then [ "$3" = {root} ]; exit; fi'
        )
        lsblk = (
            'case "$1" in -nro) if [ "$2" = PKNAME ]; then echo vda; '
            f'elif [ "$3" = {root} ]; then echo /; fi ;; '
            f'-nrpo) printf "%s part\\n" {" ".join(parts)}; echo /dev/vda disk ;; esac'
        )
        out = guest(fg.PARTITIONS, {"findmnt": findmnt, "lsblk": lsblk}, self.tmp)
        expected = {}
        for part in parts[:2]:
            with open(part, "rb") as handle:
                expected[part] = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(fg.partition_hashes(out), {**expected, root: "mounted"})

    def test_journal_streams_lists_each_stream_with_its_unit(self) -> None:
        streams = os.path.join(self.tmp, "streams")
        fds = os.path.join(self.tmp, "fd")
        os.makedirs(streams)
        os.makedirs(fds)
        os.symlink("socket:[18406]", os.path.join(fds, "3"))
        os.symlink("/dev/null", os.path.join(fds, "4"))
        with open(os.path.join(streams, "10:18406"), "w", encoding="utf-8") as f:
            f.write("PRIORITY=6\nUNIT=systemd-logind.service\n")
        with open(os.path.join(streams, "10:999"), "w", encoding="utf-8") as f:
            f.write("PRIORITY=6\n")
        script = fg.JOURNAL_STREAMS.replace(fg.STREAMS_DIR, streams).replace(
            "/proc/$pid/fd", fds
        )
        systemctl = 'case "$3" in MainPID) echo 77 ;; ActiveState) echo active ;; esac'
        out = guest(script, {"systemctl": systemctl}, self.tmp)
        entry = f"f {fg.STREAMS_DIR}/10:18406"
        other = f"f {fg.STREAMS_DIR}/10:999"
        self.assertEqual(fg.stream_listed(out), {entry, other})
        self.assertEqual(
            fg.stream_problems(out),
            {other: "the decoy's journald holds no such stream"},
        )

    # Mounts of other filesystems named with glob characters, each beside an
    # unmounted folder its pattern would match: the walk must leave out the
    # mount and read the folder. nsub is a btrfs subvolume of its own device
    # that nothing mounts, which "n*" would match.
    OTHERS = ("oth[e]r", "a*", "q?", "[b]", "n*")
    SIBLINGS = ("ab", "qx", "b", "nsub")

    def disk_tree(self) -> tuple[str, dict[str, str]]:
        """A disk mount with a nested folder, a bind of the same filesystem
        and other filesystems mounted below it (:data:`OTHERS`), and the stubs
        that list them: findmnt, stat giving each other filesystem and nsub a
        device of their own, and find writing down how it was called before
        it runs."""
        top = os.path.join(self.tmp, "root")
        folders = ("var/lib/machines/deep", "srv/bind", *self.OTHERS, *self.SIBLINGS)
        for folder in folders:
            os.makedirs(os.path.join(top, folder))
        open(os.path.join(top, "var/lib/machines/deep/file"), "w").close()
        open(os.path.join(top, "srv/bind/kept"), "w").close()
        for name in self.OTHERS:
            open(os.path.join(top, name, "not-mine"), "w").close()
        for name in self.SIBLINGS:
            open(os.path.join(top, name, "file"), "w").close()
        bind = os.path.join(top, "srv/bind")
        others = [os.path.join(top, name) for name in self.OTHERS]
        listed = " ".join(shlex.quote(o) for o in others)
        findmnt = (
            f'if [ "$3" = TARGET ]; then printf "%s\\n" {top} {listed} {bind}; '
            f'else echo "{top} btrfs"; '
            + "".join(f'echo {shlex.quote(o + " tmpfs")}; ' for o in others)
            + f'echo "{bind} btrfs"; fi'
        )
        real_stat, real_find = shutil.which("stat"), shutil.which("find")
        elsewhere = [*others, os.path.join(top, "nsub")]
        stat = (
            'case "$3" in '
            + "|".join(shlex.quote(o) for o in elsewhere)
            + f') echo 999999 ;; *) exec {real_stat} "$@" ;; esac'
        )
        find = f'echo "$@" >> {self.tmp}/find-calls; exec {real_find} "$@"'
        self.bind = bind
        return top, {"findmnt": findmnt, "stat": stat, "find": find}

    def as_gate_bind(self, script: str) -> str:
        """``script`` with the tree's bind as the gate's own bind, which it
        reads only through the mount it binds."""
        return script.replace(fg.UTAB_BIND, self.bind)

    def find_calls(self) -> str:
        with open(f"{self.tmp}/find-calls", encoding="utf-8") as handle:
            return handle.read()

    def test_the_names_reach_every_depth_and_no_other_filesystem(self) -> None:
        top, stubs = self.disk_tree()
        out = guest(self.as_gate_bind(fg.names_command()), stubs, self.tmp)
        names = gzip.decompress(base64.b64decode(out.strip())).decode().split("\n")
        self.assertIn(f"{top}/var/lib/machines/deep/file", names)
        self.assertIn(f"{top}/srv/bind/kept", names)
        self.assertIn(top, names)
        self.assertFalse([n for n in names if n.endswith("/not-mine")], names)
        for sibling in self.SIBLINGS:
            self.assertIn(f"{top}/{sibling}/file", names)
        # The bind is read through its mount alone.
        starts = [line.split()[0] for line in self.find_calls().splitlines()]
        self.assertEqual(starts, [top])
        # find crosses devices itself, as -xdev would stop at a btrfs
        # subvolume nested in the mount.
        self.assertNotIn("-xdev", self.find_calls())

    def test_the_changes_reach_every_depth_and_no_other_filesystem(self) -> None:
        top, stubs = self.disk_tree()
        out = guest(self.as_gate_bind(fg.disk_listing("1")), stubs, self.tmp)
        self.assertIn(f"{top}/var/lib/machines/deep/file", out.splitlines())
        self.assertIn(f"{top}/srv/bind/kept", out.splitlines())
        self.assertNotIn("not-mine", out)
        for sibling in self.SIBLINGS:
            self.assertIn(f"{top}/{sibling}/file", out.splitlines())
        self.assertNotIn("-xdev", self.find_calls())
        self.assertNotIn("-path / ", self.find_calls())

    def test_the_root_is_read_and_other_devices_left_out(self) -> None:
        calls = f"{self.tmp}/find-calls"
        findmnt = (
            'if [ "$3" = TARGET ]; then printf "%s\\n" / /proc /srv/same; '
            'else echo "/ btrfs"; echo "/proc proc"; fi'
        )
        stat = 'case "$3" in /|/srv/same) echo 30 ;; /proc) echo 4 ;; *) exit 1 ;; esac'
        find = f'echo "$@" >> {calls}'
        stubs = {"findmnt": findmnt, "stat": stat, "find": find}
        out = guest(fg.disk_listing("1"), stubs, self.tmp)
        self.assertEqual(fg.walk_errors(out), [])
        with open(calls, encoding="utf-8") as handle:
            args = handle.read().split()
        self.assertEqual(args[0], "/")
        self.assertIn("/proc", args)
        self.assertNotIn("/srv/same", args)
        self.assertEqual(args.count("-path"), 1)

    def test_a_device_it_cannot_read_fails_the_reading(self) -> None:
        top, stubs = self.disk_tree()
        stubs["stat"] = 'case "$3" in *oth*) exit 1 ;; *) echo 7 ;; esac'
        out = guest(self.as_gate_bind(fg.disk_listing("1")), stubs, self.tmp)
        self.assertEqual(fg.walk_errors(out), [f"{top}/oth[e]r"])
        # The names it read of the rest are not taken either.
        packed = guest(self.as_gate_bind(fg.names_command()), stubs, self.tmp)
        listed = gzip.decompress(base64.b64decode(packed.strip())).decode()
        self.assertIn(f"{top}/var/lib/machines/deep/file", listed)
        # Where stat of the mount itself fails, the walk says so and reads
        # nothing of it, its bind included.
        stubs["stat"] = f'[ "$3" = {top} ] && exit 1; echo 7'
        out = guest(self.as_gate_bind(fg.disk_listing("1")), stubs, self.tmp)
        self.assertEqual(fg.walk_errors(out), [top])
        self.assertNotIn(f"{top}/srv/bind/kept", out)

        class Vm:
            def execute(self, cmd: str, timeout: int = 900) -> tuple[int, str]:
                return 0, packed

            def succeed(self, cmd: str) -> str:
                return ""

        run = gate()
        run.vm = Vm()
        self.assertIsNone(run.disk_names("after-1"))

    def test_automounts_looks_up_each_automount_point_of_the_disks(self) -> None:
        calls = f"{self.tmp}/ls-calls"
        findmnt = (
            'if [ "$3" = autofs ]; then printf "%s\\n" /efi /proc/sys/fs/binfmt_misc; '
            'elif [ "$3" = FSTYPE ]; then printf "autofs\\nvfat\\n"; fi'
        )
        ls = f'echo "$@" >> {calls}'
        out = guest(fg.AUTOMOUNTS, {"findmnt": findmnt, "ls": ls}, self.tmp)
        self.assertEqual(fg.automounts_mounted(out), {"/efi": "vfat"})
        with open(calls, encoding="utf-8") as handle:
            self.assertEqual(handle.read().split(), ["/efi"])

    def test_fat_files_hashes_every_file(self) -> None:
        top = os.path.join(self.tmp, "efi")
        os.makedirs(os.path.join(top, "EFI/BOOT"))
        with open(os.path.join(top, "EFI/BOOT/BOOTX64.EFI"), "wb") as handle:
            handle.write(b"loader")
        findmnt = f'echo "{top} vfat"; echo "/ btrfs"'
        found = fg.fat_files(guest(fg.FAT_FILES, {"findmnt": findmnt}, self.tmp))
        self.assertEqual(
            found,
            {
                top: {
                    top: "dir",
                    f"{top}/EFI": "dir",
                    f"{top}/EFI/BOOT": "dir",
                    f"{top}/EFI/BOOT/BOOTX64.EFI": hashlib.sha256(
                        b"loader"
                    ).hexdigest(),
                }
            },
        )

    def test_record_sizes_reads_each_file(self) -> None:
        script = fg.RECORD_SIZES
        for path in fg.RECORD_PATHS:
            script = script.replace(path + " ", self.tmp + path + " ", 1).replace(
                path + ";", self.tmp + path + ";", 1
            )
        os.makedirs(self.tmp + "/var/log")
        os.makedirs(self.tmp + "/var/lib/lastlog")
        with open(self.tmp + "/var/log/wtmp", "wb") as handle:
            handle.write(b"x" * 384)
        with open(self.tmp + "/var/lib/lastlog/lastlog2.db", "wb") as handle:
            handle.write(b"x" * 10)
        self.assertEqual(
            fg.record_sizes(guest(script, {}, self.tmp)),
            {
                self.tmp + "/var/log/wtmp": 384,
                self.tmp + "/var/lib/lastlog/lastlog2.db": 10,
            },
        )


class FatAndRecordsTest(unittest.TestCase):
    def test_a_fat_file_changed_came_or_went(self) -> None:
        before = {"/efi": {"/efi": "dir", "/efi/a": "1", "/efi/b": "2"}}
        self.assertEqual(fg.fat_problems(before, before), [])
        after = {"/efi": {"/efi": "dir", "/efi/a": "9", "/efi/c": "3"}}
        self.assertEqual(
            fg.fat_problems(before, after),
            [
                "/efi/a holds other bytes than before the entry",
                "/efi/b is gone",
                "/efi/c is new",
            ],
        )
        # A mount on one side alone is a change too: its partition was not
        # read byte for byte on the side it was mounted.
        self.assertEqual(
            fg.fat_problems(before, {}), ["/efi is mounted only before the entry"]
        )
        self.assertEqual(
            fg.fat_problems({}, before), ["/efi is mounted only after the way back"]
        )

    def test_a_file_beside_the_records_is_compared(self) -> None:
        listing = "\n".join(
            (
                "/var/lib/lastlog",
                "/var/lib/lastlog/lastlog2.db",
                "/var/lib/lastlog/lastlog2.db-journal",
                "/var/lib/lastlog/planted",
                "/var/lib/wtmpdb/wtmp.db-wal",
                "/var/log/wtmp",
                "/var/log/wtmp.db-journal",
                # Siblings of a record file that are none of SQLite's own.
                "/var/log/wtmp-journal",
                "/var/log/btmp-wal",
                "/var/log/wtmp-20261101",
                "/var/log/btmp-nails",
                "/var/log/lastlog-x",
                "/var/lib/lastlog/lastlog2.db-planted",
                "/var/lib/wtmpdb/wtmp.db-backup",
            )
        )
        self.assertEqual(
            fg.changed_paths(listing),
            {
                "/var/lib/lastlog/planted",
                "/var/log/wtmp-20261101",
                "/var/log/btmp-nails",
                "/var/log/lastlog-x",
                "/var/lib/lastlog/lastlog2.db-planted",
                "/var/lib/wtmpdb/wtmp.db-backup",
                "/var/log/wtmp-journal",
                "/var/log/btmp-wal",
            },
        )

    def test_a_record_file_only_grows(self) -> None:
        before = {"/var/log/btmp": 768, "/var/lib/wtmpdb/wtmp.db-journal": 512}
        self.assertEqual(fg.record_problems(before, {"/var/log/btmp": 1152}), [])
        self.assertEqual(
            fg.record_problems(before, {"/var/log/btmp": 0}),
            ["/var/log/btmp shrank from 768 to 0 bytes"],
        )
        self.assertEqual(fg.record_problems(before, {}), ["/var/log/btmp is gone"])


class WayBackDiskTest(unittest.TestCase):
    FAT = "mount /efi\ndir /efi\nfile d1  /efi/BOOTX64.EFI\n"

    def run_way_back(
        self,
        partitions_before: dict[str, str],
        partitions_after: str,
        fat_before: str = FAT,
        fat_after: str = FAT,
        sizes_before: str = "384 /var/log/wtmp",
        sizes_after: str = "384 /var/log/wtmp",
        automounts_before: str = "/efi vfat",
        automounts_after: str = "/efi vfat",
    ) -> fg.Gate:
        """way_back_disk on fakes of what the guest prints before the entry
        (the state) and after the way back."""
        run = gate()
        read: list[str] = []
        self.order: list[str] = []

        def disk_changes(label: str, since: str) -> set[str]:
            self.order.append("changes")
            return set()

        run.disk_changes = disk_changes  # type: ignore[method-assign]

        def disk_names(label: str) -> set[str]:
            read.append(label)
            return {f"/{label}"}

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            self.order.append(label)
            if cmd == fg.PARTITIONS:
                return partitions_after
            if cmd == fg.RECORD_SIZES:
                return sizes_after
            if cmd == fg.FAT_FILES:
                return fat_after
            if cmd == fg.AUTOMOUNTS:
                return automounts_after
            return ""

        run.disk_names = disk_names  # type: ignore[method-assign]
        run.fact = fact  # type: ignore[method-assign]
        state = {
            "since": "1",
            "automounts": fg.automounts_mounted(automounts_before),
            "names": {"/before-1"},
            "partitions": partitions_before,
            "fat": fg.fat_files(fat_before),
            "records-sizes": fg.record_sizes(sizes_before),
        }
        quiet(run.way_back_disk, 1, state)
        self.assertEqual(read, ["after-1"])
        return run

    @staticmethod
    def passed(run: fg.Gate, name: str) -> list[bool]:
        return [c["passed"] for c in run.checks if c["name"].startswith(name)]

    def test_the_automounts_must_be_mounted_as_before(self) -> None:
        name = "way back 1: each automount point of the decoy's disks"
        part = ({"/dev/vda1": "d1"}, "/dev/vda1 d1")
        run = self.run_way_back(*part)
        self.assertEqual(self.passed(run, name), [True])
        for before, after in (
            ("/efi vfat", "/efi autofs"),
            ("/efi vfat", ""),
            ("", "/efi vfat"),
        ):
            run = self.run_way_back(
                *part, automounts_before=before, automounts_after=after
            )
            self.assertEqual(self.passed(run, name), [False], (before, after))

    def test_the_automount_points_are_looked_up_first(self) -> None:
        self.run_way_back({"/dev/vda1": "d1"}, "/dev/vda1 d1")
        self.assertEqual(self.order[:2], ["automounts-after-1", "changes"])
        run = gate()
        asked: list[str] = []

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            asked.append(cmd)
            return ""

        run.fact = fact  # type: ignore[method-assign]
        run.disk_names = lambda label: asked.append("names") or set()  # type: ignore[method-assign,func-returns-value]
        run.before_disk(1)
        self.assertEqual(asked[:2], [fg.AUTOMOUNTS, "names"])

    def test_the_names_after_are_read_after(self) -> None:
        run = self.run_way_back({"/dev/vda1": "d1"}, "/dev/vda1 d1")
        self.assertEqual(run.names["way-back-1"], ({"/before-1"}, {"/after-1"}))
        self.assertTrue(all(c["passed"] for c in run.checks), run.checks)

    def test_a_partition_must_be_read_byte_for_byte(self) -> None:
        name = "way back 1: the partitions of the decoy's disk"
        for before, after in (
            ({}, ""),
            ({"/dev/vda1": "mounted"}, "/dev/vda1 mounted"),
            ({"/dev/vda1": "d1"}, "/dev/vda1 d2"),
        ):
            run = self.run_way_back(before, after)
            self.assertEqual(self.passed(run, name), [False], (before, after))

    def test_the_fat_files_after_are_read_and_compared(self) -> None:
        name = "way back 1: every file of the decoy's FAT filesystems"
        part = ({"/dev/vda1": "d1"}, "/dev/vda1 d1")
        changed = self.FAT.replace("d1  ", "d2  ")
        for before, after in (
            (self.FAT, changed),
            ("", self.FAT),
            ("", ""),
            (self.FAT, ""),
        ):
            run = self.run_way_back(*part, fat_before=before, fat_after=after)
            self.assertEqual(self.passed(run, name), [False], (before, after))

    def test_the_record_sizes_after_are_read_and_held(self) -> None:
        name = "way back 1: no login or boot record file shrank or went"
        part = ({"/dev/vda1": "d1"}, "/dev/vda1 d1")
        run = self.run_way_back(*part, sizes_after="768 /var/log/wtmp")
        self.assertEqual(self.passed(run, name), [True])
        for before, after in (("384 /var/log/wtmp", "0 /var/log/wtmp"), ("", "")):
            run = self.run_way_back(*part, sizes_before=before, sizes_after=after)
            self.assertEqual(self.passed(run, name), [False], (before, after))

    def test_the_state_before_the_entry_is_read_from_the_guest(self) -> None:
        run = gate()
        answers = {
            fg.PARTITIONS: "/dev/vda1 d1",
            fg.FAT_FILES: self.FAT,
            fg.RECORD_SIZES: "384 /var/log/wtmp",
        }
        run.disk_names = lambda label: {f"/{label}"}  # type: ignore[method-assign]
        run.fact = lambda label, cmd, timeout=300, again=False: answers.get(cmd, "")  # type: ignore[method-assign]
        state = run.before_disk(1)
        self.assertEqual(state["names"], {"/before-1"})
        self.assertEqual(state["partitions"], {"/dev/vda1": "d1"})
        self.assertEqual(state["fat"], fg.fat_files(self.FAT))
        self.assertEqual(state["records-sizes"], {"/var/log/wtmp": 384})
        # What it read before is what the way back is held to.
        run = self.run_way_back(
            state["partitions"], "/dev/vda1 d1", fat_before=self.FAT
        )
        self.assertTrue(all(c["passed"] for c in run.checks), run.checks)

    def test_the_session_files_are_the_gate_s_own(self) -> None:
        cmds: list[str] = []

        class Gate(fg.Gate):
            session_files = ("/efi/gate-efi-1",)

        run = Gate(
            None, None, None, None, {"image": "x"}, tempfile.mkdtemp(dir=SCRATCH.name)
        )

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            cmds.append(cmd)
            return ""

        run.fact = fact  # type: ignore[method-assign]
        quiet(run.session_files_left, 1)
        self.assertIn("/efi/gate-efi-1", cmds[0])
        self.assertNotIn("/etc/gate-new", cmds[0])

    def test_a_dangling_link_of_the_session_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gate-files-") as tmp:
            link, kept = f"{tmp}/link", f"{tmp}/kept"
            os.symlink(f"{tmp}/nowhere", link)

            class Gate(fg.Gate):
                session_files = (link, kept)

            out_dir = tempfile.mkdtemp(dir=SCRATCH.name)
            run = Gate(None, None, None, None, {"image": "x"}, out_dir)
            run.fact = lambda label, cmd, timeout=300, again=False: subprocess.run(  # type: ignore[method-assign]
                [BASH, "-c", cmd], capture_output=True, text=True, timeout=60
            ).stdout.strip()
            quiet(run.session_files_left, 1)
            self.assertFalse(run.checks[0]["passed"])
            self.assertEqual(run.checks[0]["detail"].splitlines()[0], link)


class AuditdTest(unittest.TestCase):
    def test_pid_1_reloads_only_once_auditd_has_exited(self) -> None:
        run = gate()
        ran: list[str] = []
        rows = {
            "decoy-persistence": {
                "status": "fail",
                "message": "auditd runs",
                "remediation": "mask ... auditctl --signal stop",
            }
        }
        run.fact = lambda label, cmd, timeout=300, again=False: (  # type: ignore[method-assign]
            "845" if label == "auditd-before" else "gone"
        )
        run.check_rows = lambda *a: (4, rows)  # type: ignore[method-assign]
        run.read_audit_log = lambda: None  # type: ignore[method-assign]

        def sh(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> tuple[int, str]:
            ran.append(cmd)
            return 0, ""

        run.sh = sh  # type: ignore[method-assign]
        quiet(run.auditd)
        off = ran[0]
        self.assertIn("systemctl --no-reload disable auditd.service", off)
        self.assertIn("systemctl --no-reload mask auditd.service", off)
        self.assertLess(off.index("pgrep -x auditd"), off.index("daemon-reload"))
        self.assertLess(off.index("auditctl --signal stop"), off.index("daemon-reload"))


class AdvisoryTest(unittest.TestCase):
    def test_the_advisory_with_the_lines_below_it(self) -> None:
        log = (
            "[WARN] decoy-nix-trace: x\n"
            "[WARN] package-drift: gate-drift (3-1 on the decoy)\n"
            "In a hidden session (`sudo pacman -U <file>`).\n"
            "[WARN] binary-location: y\n"
        )
        self.assertEqual(
            fg.advisory_text(log, "package-drift"),
            "[WARN] package-drift: gate-drift (3-1 on the decoy)\n"
            "In a hidden session (`sudo pacman -U <file>`).",
        )
        self.assertEqual(
            fg.advisory_text("gate-drift sudo pacman -U", "package-drift"), ""
        )


class RehearseScanTest(unittest.TestCase):
    def scan(self, **root: Any) -> dict[str, Any]:
        device = {"device": ROOT, "hits": [], "bytes_scanned": 10, "blind_spot": BLIND}
        device.update(root)
        boot = {"device": "/dev/vda3", "hits": [], "bytes_scanned": 5}
        return {"devices": [device, boot]}

    def test_a_clean_scan_names_the_compressing_root(self) -> None:
        self.assertEqual(fg.rehearse_scan_problems(9, self.scan(), ROOT), [])

    def test_a_root_without_its_blind_spot_reads_as_clean(self) -> None:
        problems = fg.rehearse_scan_problems(0, self.scan(blind_spot=None), ROOT)
        self.assertEqual(len(problems), 2, problems)

    def test_a_hit_an_error_or_another_device_s_blind_spot_fails(self) -> None:
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(hits=["x"]), ROOT))
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(error="EIO"), ROOT))
        scan = self.scan()
        scan["devices"][1]["blind_spot"] = "x"
        self.assertTrue(fg.rehearse_scan_problems(9, scan, ROOT))

    def test_a_scan_that_read_nothing_fails(self) -> None:
        self.assertEqual(
            fg.rehearse_scan_problems(9, {"devices": []}, ROOT),
            ["the scan read no device"],
        )
        scan = self.scan(bytes_scanned=0)
        scan["devices"][1]["bytes_scanned"] = 0
        self.assertIn("the scan read no byte", fg.rehearse_scan_problems(9, scan, ROOT))
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(), "/dev/vdb1"))


class RunResidueTest(unittest.TestCase):
    BEFORE = {
        "d /run/systemd",
        "f /run/systemd/journal/streams/10:100",
        "f /run/nails-gate.toml",
    }

    def test_an_entry_the_session_left_at_any_depth_is_residue(self) -> None:
        link = "l /run/systemd/system/multi-user.target.wants/overlay-runtime-boot"
        after = {*self.BEFORE, link, "f /run/gate-probe-1"}
        self.assertEqual(
            fg.run_residue(self.BEFORE, after, []), ["f /run/gate-probe-1", link]
        )

    def test_a_shape_a_plain_soft_reboot_adds_is_no_residue(self) -> None:
        # Each start of the decoy opens new journal streams, named by their
        # device and inode.
        control = (
            {"f /run/systemd/journal/streams/10:200"},
            {
                "f /run/systemd/journal/streams/10:200",
                "f /run/systemd/journal/streams/10:345",
            },
        )
        after = {*self.BEFORE, "f /run/systemd/journal/streams/10:29536"}
        self.assertEqual(fg.run_residue(self.BEFORE, after, [control]), [])
        # A folder of the same name is another shape.
        odd = {*self.BEFORE, "d /run/systemd/journal/streams/10:29536"}
        self.assertEqual(
            fg.run_residue(self.BEFORE, odd, [control]),
            ["d /run/systemd/journal/streams/10:29536"],
        )

    def test_the_reconcile_pieces_that_stayed_are_left_to_their_check(
        self,
    ) -> None:
        wants = "/run/systemd/system/multi-user.target.wants"
        pieces = ["/run/overlay-runtime-boot", f"{wants}/overlay-runtime-boot.service"]
        after = {
            *self.BEFORE,
            "d /run/overlay-runtime-boot",
            "f /run/overlay-runtime-boot/control",
            f"d {wants}",
            f"l {wants}/overlay-runtime-boot.service",
            "f /run/left",
        }
        self.assertEqual(
            fg.run_residue(self.BEFORE, after, [], pieces), ["f /run/left"]
        )
        self.assertTrue(fg.of_pieces("l /run/overlay-runtime-boot -> x", pieces))
        self.assertFalse(fg.of_pieces("d /run/overlay-runtime-bootx", pieces))

    def test_the_decoy_s_own_invocation_link_since_the_way_back_is_no_residue(
        self,
    ) -> None:
        # Seen on Fedora 44: hostnamed had exited idle before the second
        # entry, and NetworkManager's start after the way back started it
        # again, while in both plain soft-reboots it ran before and after.
        link = "l /run/systemd/units/invocation:systemd-hostnamed.service"
        ident = "1" * 32
        control = ({link}, {link})
        after = {*self.BEFORE, link}
        self.assertEqual(fg.run_residue(self.BEFORE, after, [control]), [link])
        own = fg.decoy_invocations(
            f"unit=systemd-hostnamed.service link={ident} id={ident} "
            "start=@1795029500 "
            "file=/usr/lib/systemd/system/systemd-hostnamed.service\n",
            1795029400.0,
        )
        self.assertEqual(own, {link})
        self.assertEqual(fg.run_residue(self.BEFORE, after, [control], [], own), [])

    def test_an_invocation_link_of_another_run_stays_residue(self) -> None:
        ident = "1" * 32
        other = "2" * 32
        unit_file = "file=/usr/lib/systemd/system/a.service"
        for line in (
            # The link leads to another run than the one PID 1 runs now.
            f"unit=a.service link={other} id={ident} start=@1795029500 {unit_file}",
            # The run started before the switch.
            f"unit=a.service link={ident} id={ident} start=@1795029300 {unit_file}",
            # The unit no longer runs: no link, and no start.
            f"unit=a.service link= id={ident} start= {unit_file}",
            f"unit=a.service link= id= start=@1795029500 {unit_file}",
        ):
            self.assertEqual(fg.decoy_invocations(line, 1795029400.0), set(), line)

    # The F44 gate of run 45566157861 at its second way back: the leave mark,
    # and the end of the switch's last step a second and a half later.
    LEAVE = 1795591475.0
    SWITCH = 1795591476.572876

    def test_a_run_the_hidden_root_started_before_the_switch_stays_residue(
        self,
    ) -> None:
        # Started after the leave mark, by the hidden root's PID 1 as it shut
        # down, with a link the decoy's PID 1 keeps; and within TIMER_SLACK
        # of the switch, where a start to the second cannot tell.
        ident = "3" * 32
        for start in (int(self.LEAVE) + 1, int(self.SWITCH) + 1):
            line = (
                f"unit=hidden-only.service link={ident} id={ident} start=@{start} "
                "file=/usr/lib/systemd/system/hidden-only.service"
            )
            self.assertEqual(fg.decoy_invocations(line, self.SWITCH), set(), line)
        # Without the switch's time, nothing counts as the decoy's.
        line = (
            f"unit=a.service link={ident} id={ident} start=@{int(self.SWITCH) + 3} "
            "file=/usr/lib/systemd/system/a.service"
        )
        self.assertEqual(fg.decoy_invocations(line, None), set())
        self.assertEqual(
            fg.decoy_invocations(line, self.SWITCH),
            {"l /run/systemd/units/invocation:a.service"},
        )

    def test_a_link_of_nails_s_own_unit_stays_residue(self) -> None:
        # The decoy's PID 1 runs the reconcile unit after the switch, but its
        # link is a trace of NAILS.
        ident = "4" * 32
        line = (
            f"unit=overlay-runtime-boot.service link={ident} id={ident} "
            f"start=@{int(self.SWITCH) + 3} "
            "file=/usr/lib/systemd/system/overlay-runtime-boot.service"
        )
        self.assertEqual(fg.decoy_invocations(line, self.SWITCH), set())

    def test_a_link_of_a_unit_without_a_file_outside_run_stays_residue(
        self,
    ) -> None:
        # A unit file in /run (one the session could have left, or a transient
        # unit's) or no unit file at all.
        ident = "5" * 32
        start = f"start=@{int(self.SWITCH) + 3}"
        for path in (
            "/run/systemd/system/a.service",
            "/run/systemd/transient/a.service",
            "",
            "run/x",
        ):
            line = f"unit=a.service link={ident} id={ident} {start} file={path}"
            self.assertEqual(fg.decoy_invocations(line, self.SWITCH), set(), line)
        line = f"unit=a.service link={ident} id={ident} {start}"
        self.assertEqual(fg.decoy_invocations(line, self.SWITCH), set())

    def test_judge_run_reads_the_links_against_the_switch(self) -> None:
        # The decoy's hostnamed, started after the switch, is its own; a unit
        # the hidden root's PID 1 started between the leave mark and the
        # switch is not, nor is any link once the switch's time is unknown.
        hostnamed = "l /run/systemd/units/invocation:systemd-hostnamed.service"
        hidden = "l /run/systemd/units/invocation:hidden-only.service"
        a, b = "6" * 32, "7" * 32
        reading = (
            f"unit=systemd-hostnamed.service link={a} id={a} "
            f"start=@{int(self.SWITCH) + 2} "
            "file=/usr/lib/systemd/system/systemd-hostnamed.service\n"
            f"unit=hidden-only.service link={b} id={b} start=@{int(self.LEAVE) + 1} "
            "file=/usr/lib/systemd/system/hidden-only.service\n"
        )
        for switch_us, left in (
            (int(self.SWITCH * 1_000_000), [hidden]),
            (None, [hidden, hostnamed]),
        ):
            run = gate()
            run.runs = {
                "control-1": (set(), set()),
                "way-back-2": (set(self.BEFORE), {*self.BEFORE, hostnamed, hidden}),
            }
            run.run_invocations = {"way-back-2": reading}
            run.facts["leave-wall-2"] = self.LEAVE
            run.facts["carried-2"] = {"switchUs": switch_us}
            quiet(settled(run).judge_run)
            self.assertEqual(run.facts["run-residue-way-back-2"], left, switch_us)
            self.assertEqual(
                [c["passed"] for c in run.checks], [False], run.checks
            )
        run = gate()
        run.runs = {
            "control-1": (set(), set()),
            "way-back-2": (set(self.BEFORE), {*self.BEFORE, hostnamed}),
        }
        run.run_invocations = {"way-back-2": reading}
        run.facts["carried-2"] = {"switchUs": int(self.SWITCH * 1_000_000)}
        quiet(settled(run).judge_run)
        self.assertEqual([c["passed"] for c in run.checks], [True], run.checks)

    def test_the_invocation_reading_names_only_invocation_links(self) -> None:
        command = fg.invocation_reading(
            {
                "l /run/systemd/units/invocation:systemd-hostnamed.service",
                "f /run/systemd/units/invocation:odd.service",
                "l /run/gate-link",
            }
        )
        self.assertEqual(command.count("u="), 1)
        self.assertIn(
            "readlink /run/systemd/units/invocation:systemd-hostnamed", command
        )
        self.assertIn('file=$(systemctl show -P FragmentPath "$u")', command)
        self.assertEqual(fg.invocation_reading({"f /run/x"}), "")

    def test_reads_the_listing(self) -> None:
        listing = "d /run/a\nf /run/a/b c\n\nfind: oops\n"
        self.assertEqual(fg.run_entries(listing), {"d /run/a", "f /run/a/b c"})
        self.assertEqual(
            fg.run_shape("f /run/log/journal/0123456789abcdef0123/system@5.journal"),
            "f /run/log/journal/#/system@#.journal",
        )

    def test_judges_each_way_back_against_the_controls(self) -> None:
        run = gate()
        run.runs = {
            "control-1": ({"d /run/a"}, {"d /run/a", "f /run/s/1"}),
            "way-back-1": ({"d /run/a"}, {"d /run/a", "f /run/s/7", "f /run/left"}),
            "way-back-2": ({"d /run/a"}, {"d /run/a", "d /run/overlay-runtime-boot/x"}),
        }
        run.pieces = {2: ["/run/overlay-runtime-boot"]}
        quiet(settled(run).judge_run)
        name = "nothing of the session stays in /run, at any depth"
        self.assertEqual(
            [(c["name"], c["passed"]) for c in run.checks],
            [(f"way back 1: {name}", False), (f"way back 2: {name}", True)],
        )
        self.assertEqual(run.facts["run-residue-way-back-1"], ["f /run/left"])
        # Without a control nothing is judged, so nothing passes, and a
        # control of another update state does not count.
        run = gate()
        run.runs = {"way-back-1": ({"d /run/a"}, {"d /run/a"})}
        quiet(run.judge_run)
        self.assertFalse(run.checks[0]["passed"])
        run = gate()
        run.update_states = {
            "control-1": "/etc pending; /var pending",
            "way-back-1": CURRENT,
        }
        link = "l /run/u/invocation:ldconfig.service"
        run.runs = {
            "control-1": ({"d /run/a"}, {"d /run/a", link}),
            "way-back-1": ({"d /run/a"}, {"d /run/a", link}),
        }
        quiet(run.judge_run)
        self.assertFalse(run.checks[0]["passed"])


def entry(
    transport: str,
    msg: str,
    pid: int | None = 1,
    serial: int | None = None,
    sent: int | None = None,
) -> dict[str, Any]:
    return {
        "transport": transport,
        "pid": pid,
        "who": "x",
        "unit": "",
        "auditId": serial,
        "sent": sent,
        "received": None,
        "msg": msg,
    }


class CarriedTest(unittest.TestCase):
    LATE = "GATELATE-n-1"
    ENTRIES = (
        entry("driver", "Journal started", pid=640),
        # The hidden root's last records, waiting in the sockets.
        entry("audit", "SERVICE_STOP unit=systemd-journald", serial=1272),
        entry("audit", "SERVICE_STOP unit=gate-late-1", serial=1276),
        entry("syslog", f"{LATE}-syslog", pid=12001, sent=733_126_747),
        entry("journal", f"{LATE}-native", pid=12003, sent=733_128_735),
        entry("stdout", f"{LATE}-stdout", pid=12001),
        entry("stdout", "Error: Device or resource busy", pid=12007),
        entry("syslog", "a hidden daemon's last line", pid=11990, sent=733_200_000),
        # The decoy's own start, after the switch.
        entry("audit", "AVC map policy.35", serial=1282),
        entry("journal", "Finished lvm2-monitor.service", sent=734_764_503),
        entry("stdout", "zram0: formatted", pid=650),
    )

    def test_sorts_what_the_hidden_root_sent_after_its_journald_stopped(self) -> None:
        found = fg.carried_records(self.ENTRIES, self.LATE, 1281, 734_000_000, 12000)
        self.assertEqual(len(found["late"]), 3)
        self.assertEqual(
            [line.split(":", 1)[1].strip() for line in found["audit"]],
            ["SERVICE_STOP unit=systemd-journald"],
        )
        self.assertEqual(len(found["datagram"]), 1)
        self.assertIn("a hidden daemon's last line", found["datagram"][0])
        self.assertEqual(len(found["stream"]), 1)
        self.assertIn("resource busy", found["stream"][0])

    def test_a_bound_it_lacks_judges_nothing_of_its_kind(self) -> None:
        found = fg.carried_records(self.ENTRIES, self.LATE, None, None, None)
        self.assertEqual(len(found["late"]), 3)
        self.assertEqual(
            (found["audit"], found["datagram"], found["stream"]), ([], [], [])
        )

    def test_the_late_writer_stops_after_the_hidden_journald(self) -> None:
        stop = "audit: type=1131 audit(1.0:{s}): pid=1 uid=0 msg='unit={u} comm=x'"
        log = [
            kmsg(1, stop.format(s=1, u="systemd-journald")),
            kmsg(2, stop.format(s=2, u="gate-late-1")),
            kmsg(3, "audit: type=1130 audit(1.0:3): msg='unit=gate-late-2 comm=x'"),
        ]
        self.assertIs(fg.stopped_after(log, "systemd-journald", "gate-late-1"), True)
        self.assertIs(fg.stopped_after(log, "gate-late-1", "systemd-journald"), False)
        # A start is no stop.
        self.assertIsNone(fg.stopped_after(log, "systemd-journald", "gate-late-2"))

    def test_journald_s_sockets_opened_after_the_step_are_found(self) -> None:
        listening = "systemd[1]: Listening on {} - {}."
        log = [
            kmsg(10, listening.format("systemd-journald.socket", "Journal Sockets")),
            kmsg(20, listening.format("systemd-journald-audit.socket", "Audit")),
            kmsg(21, listening.format("systemd-journald-dev-log.socket", "Log")),
            kmsg(22, listening.format("systemd-oomd.socket", "OOM Killer Socket")),
        ]
        self.assertEqual(len(fg.reopened_sockets(log, 15)), 2)
        self.assertEqual(fg.reopened_sockets(log, 30), [])

    def test_the_late_writer_logs_through_each_socket(self) -> None:
        stop = fg.LATE_STOP.format(mark="M")
        self.assertIn("logger -t gatelate M-syslog", stop)
        self.assertIn("echo M-stdout", stop)
        self.assertIn("MESSAGE=M-native", stop)
        self.assertIn("logger --journald", stop)
        # systemd reads the line with its own quoting: one argument for sh.
        self.assertTrue(stop.startswith('/bin/sh -c "') and stop.endswith('"'))


def utmp(kind: str, pid: int = 0, line: str = "") -> dict[str, Any]:
    return {"type": kind, "pid": pid, "line": line}


class GettyTest(unittest.TestCase):
    def test_the_power_of_two_range(self) -> None:
        self.assertEqual(fg.pid_range(700), (512, 1023))
        self.assertEqual(fg.pid_range(1024), (1024, 2047))
        self.assertEqual(fg.pid_range(3175), (2048, 4095))
        self.assertEqual(fg.pid_range(0), (0, 0))

    def test_reads_the_consoles_of_the_last_start(self) -> None:
        wtmp = [
            utmp("BOOT_TIME"),
            utmp("INIT_PROCESS", 921, "tty1"),
            utmp("LOGIN_PROCESS", 921, "tty1"),
            utmp("BOOT_TIME"),
            utmp("RUN_LVL"),
            # kmscon on Fedora 45: the unit's record alone.
            utmp("INIT_PROCESS", 644, "tty1"),
            utmp("LOGIN_PROCESS", 671, "hvc0"),
            utmp("USER_PROCESS", 990, "tty1"),
            utmp("DEAD_PROCESS", 644, "tty1"),
            utmp("INIT_PROCESS", 3000, "tty1"),
        ]
        self.assertEqual(fg.getty_logins(wtmp), {"tty1": 644, "hvc0": 671})
        self.assertEqual(fg.getty_logins([utmp("LOGIN_PROCESS", 5, "tty1")]), {})

    def test_a_getty_numbered_from_the_session_fails(self) -> None:
        cold = {"ttyS0": 670}
        self.assertEqual(fg.getty_problems(cold, {"ttyS0": 702}, 12000), [])
        # No set-back: the number continues from the session's.
        self.assertEqual(len(fg.getty_problems(cold, {"ttyS0": 12040}, 12000)), 2)
        # Set back from a soft-reboot's numbers, not a cold boot's.
        soft = fg.getty_problems(cold, {"ttyS0": 3175}, 12000)
        self.assertIn("in (2048, 4095)", soft[0])
        self.assertTrue(fg.getty_problems(cold, {}, 12000))
        self.assertTrue(fg.getty_problems({}, {"ttyS0": 702}, 12000))
        self.assertTrue(fg.getty_problems(cold, {"ttyS0": 702}, None))


SYSCALL = (
    "audit: type=1300 audit(1794705307.950:{serial}): arch=c000003e syscall=59 "
    "success={success} exit=0 items=2 ppid=1 pid=4146 auid=4294967295 uid=0 "
    'comm="{comm}" exe="{exe}" subj=system_u:system_r:{domain}:s0 key="{key}"'
)
EXECVE = "audit: type=1309 audit(1794705307.950:{serial}): argc={argc} {args}"
PATH = (
    "audit: type=1302 audit(1794705307.950:{serial}): item=0 "
    'name="{name}" inode=4311 obj=system_u:object_r:init_var_run_t:s0'
)


def run(
    serial: int,
    exe: str,
    domain: str,
    *args: str,
    key: str = fg.EXEC_RUN_KEY,
    ran: bool = True,
) -> list[str]:
    """The kernel's records of one run: its system call and its arguments."""
    argv = [exe, *args]
    return [
        SYSCALL.format(
            serial=serial,
            success="yes" if ran else "no",
            comm=exe.rsplit("/", 1)[-1],
            exe=exe if ran else "/usr/lib/systemd/systemd-executor",
            domain=domain,
            key=key,
        ),
        EXECVE.format(
            serial=serial,
            argc=len(argv),
            args=" ".join(f'a{i}="{a}"' for i, a in enumerate(argv)),
        ),
        PATH.format(serial=serial, name=exe),
    ]


COPY = "/run/overlay-runtime/control"
BOOT_COPY = "/run/overlay-runtime-boot/control"


def every_step(domain: str = "unconfined_service_t") -> list[str]:
    """A run of each step of NAILS from its copy in /run."""
    lines: list[str] = []
    for serial, step in enumerate(fg.NAILS_STEPS, 100):
        copy = BOOT_COPY if step == "reconcile-records" else COPY
        lines += run(serial, copy, domain, "--config", "/run/x.toml", step)
    return lines


class ExecTest(unittest.TestCase):
    def boot(self, *messages: str) -> dict[str, Any]:
        return {
            "why": "cold",
            "records": {seq: kmsg(seq, m) for seq, m in enumerate(messages, 1)},
        }

    def test_reads_what_the_rules_recorded(self) -> None:
        records = self.boot(
            *run(800, BOOT_COPY, "init_t", "reconcile-records", key=fg.EXEC_KEY),
            *run(801, "/usr/bin/true", "init_t", key="other"),
            *run(802, BOOT_COPY, "init_t", "reconcile-records", ran=False),
            "audit: type=1400 audit(1.0:803): avc:  denied  { map }",
        )["records"].values()
        found = fg.exec_records(records)
        self.assertEqual(
            [(r["key"], r["program"], r["step"], r["ran"]) for r in found],
            [
                (fg.EXEC_KEY, BOOT_COPY, "reconcile-records", True),
                (fg.EXEC_RUN_KEY, BOOT_COPY, "reconcile-records", False),
            ],
        )
        self.assertEqual(found[0]["subj"], "system_u:system_r:init_t:s0")

    def judged(self, *messages: str, probes: tuple[str, ...]) -> list[bool]:
        run_ = gate()
        run_.exec_audit = True
        run_.exec_probes = list(probes)
        run_.boots = [self.boot(*messages)]
        quiet(run_.judge_execs)
        self.judged_facts = run_.facts
        return [c["passed"] for c in run_.checks]

    PROBE = f"{fg.EXEC_PROBE}-hidden-1"

    def probe(self) -> list[str]:
        return run(5, self.PROBE, "unconfined_service_t", key=fg.EXEC_KEY)

    def test_every_step_outside_init_t_passes(self) -> None:
        self.assertEqual(
            self.judged(*self.probe(), *every_step(), probes=(self.PROBE,)),
            [True, True, True, True],
        )
        self.assertEqual(
            self.judged_facts["nails-step-domains"]["guard-device"],
            ["unconfined_service_t"],
        )

    def test_a_copy_labelled_as_runtime_data_fails(self) -> None:
        data = run(6, COPY, "init_t", "watch", key=fg.EXEC_KEY)
        self.assertEqual(
            self.judged(*self.probe(), *every_step(), *data, probes=(self.PROBE,)),
            [True, False, False, True],
        )

    def test_a_step_in_init_t_fails(self) -> None:
        self.assertEqual(
            self.judged(*self.probe(), *every_step("init_t"), probes=(self.PROBE,)),
            [True, True, False, True],
        )

    def test_a_step_the_kernel_never_recorded_fails(self) -> None:
        # The policy refused the reconcile step: it never ran, so its domain
        # is unknown, and the copy it tried was labelled as runtime data.
        steps = [
            line
            for line in every_step()
            if "reconcile-records" not in line and BOOT_COPY not in line
        ]
        steps += run(
            104, BOOT_COPY, "init_t", "reconcile-records", key=fg.EXEC_KEY, ran=False
        )
        self.assertEqual(
            self.judged(*self.probe(), *steps, probes=(self.PROBE,)),
            [True, False, True, False],
        )

    def test_without_the_probe_s_record_nothing_shows_the_rules_work(self) -> None:
        missing = self.judged(*every_step(), probes=(f"{fg.EXEC_PROBE}-after-1",))
        self.assertEqual(missing[0], False)
        self.assertEqual(self.judged(*every_step(), probes=())[0], False)

    def test_the_variant_without_the_rules_judges_nothing(self) -> None:
        run_ = gate(dontaudit=False)
        quiet(run_.judge_execs)
        self.assertEqual(run_.checks, [])

    def test_the_listed_rules_hold_only_with_each_one_there(self) -> None:
        rule = "-a always,exit -F arch=b64 -S execve,execveat"
        listed = [
            f"{rule} -F obj_type={kind} -F key={fg.EXEC_KEY}" for kind in fg.EXEC_TYPES
        ]
        listed.append(f"{rule} -F dir=/run -F key={fg.EXEC_RUN_KEY}")
        self.assertTrue(fg.exec_rules_held("\n".join(listed)))
        self.assertFalse(fg.exec_rules_held("\n".join(listed[1:])))
        self.assertFalse(fg.exec_rules_held("\n".join(listed[:-1])))
        self.assertFalse(fg.exec_rules_held("No rules"))

    def test_the_rules_record_each_runtime_label_and_all_of_run(self) -> None:
        for kind in fg.EXEC_TYPES:
            self.assertIn(f"-F obj_type={kind} -k {fg.EXEC_KEY};", fg.EXEC_RULES)
        self.assertTrue(fg.EXEC_RULES.startswith("auditctl -D;"))
        # The labels' rules come first: the first rule a run matches names it.
        self.assertLess(
            fg.EXEC_RULES.index(fg.EXEC_KEY + ";"),
            fg.EXEC_RULES.index(f"-F dir=/run -k {fg.EXEC_RUN_KEY};"),
        )


def kmsg(seq: int, msg: str) -> dict[str, Any]:
    return {"seq": seq, "us": seq * 1000, "msg": msg, "pri": 6, "dict": []}


def marker(label: str, seq: int, wall: float) -> dict[str, Any]:
    return {"label": label, "seq": seq, "wall": f"{wall:.9f}"}


DENIAL = (
    "audit: type=1400 audit({t}:{s}): avc:  denied  {{ read }} for  pid=9 "
    'comm="{comm}" name="x" dev="vda4" ino=1 '
    "scontext=system_u:system_r:{stype}:s0 "
    "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
)


def denial(t: float, serial: int, comm: str, stype: str = "init_t") -> str:
    return DENIAL.format(t=f"{t:.3f}", s=serial, comm=comm, stype=stype)


class DenialsTest(unittest.TestCase):
    # Each marker's sequence number in the kernel log and its wall clock.
    MARKERS = (
        ("boot-ready", 10, 100.0),
        ("prep-decoy", 20, 110.0),
        ("check-check-journal", 30, 120.0),
        ("prep-after-check-journal", 40, 130.0),
        ("control-1-start", 50, 140.0),
        ("enter-1", 60, 150.0),
        ("prep-drift", 70, 160.0),
    )

    def boot(
        self, placed: dict[int, str], audit_text: str = "", started: bool = True
    ) -> dict[str, Any]:
        """A reference boot whose kernel log runs from 1 to 80 without a gap:
        the first audit record (serial 1), the markers, the first audit record
        after the first marker (serial 2) unless not ``started``, ``placed``
        by their sequence numbers, and filler."""
        records = {}
        for seq in range(1, 81):
            records[seq] = kmsg(seq, "filler")
        records[1] = kmsg(1, "audit: type=2000 audit(0.100:1): state=initialized")
        if started:
            records[11] = kmsg(11, "audit: type=1130 audit(100.500:2): pid=1 res=1")
        for label, seq, _ in self.MARKERS:
            records[seq] = kmsg(seq, sg.marker(label, "n"))
        # Each switch keeps the decoy's policy, as at a plain soft-reboot.
        for seq in (55, 62):
            records[seq] = kmsg(seq, f"systemd[1]: {fg.POLICY_KEPT}")
        for seq, message in placed.items():
            records[seq] = kmsg(seq, message)
        return {
            "why": "reference",
            "records": records,
            "dropped": 0,
            "markers": [marker(*m) for m in self.MARKERS],
            "console": [],
            "audit": sg.audit_log(audit_text, 0),
            "btime": 0,
        }

    def failed(self, boot: dict[str, Any]) -> list[str]:
        run = gate()
        run.boots = [boot]
        quiet(run.judge_denials)
        self.run_checks = run.checks
        return [c["name"] for c in run.checks if not c["passed"]]

    def test_a_clean_boot_passes(self) -> None:
        self.assertEqual(self.failed(self.boot({})), [])

    def test_a_check_phase_judges_what_auditd_logged_of_it(self) -> None:
        # nails check ran while auditd took every record: its denial is only
        # in auditd's log, dated inside the check's phase.
        audit = (
            "type=AVC msg=audit(125.000:3): avc:  denied  { read } for  pid=9 "
            'comm="nails" name="x" dev="vda4" ino=1 '
            "scontext=unconfined_u:unconfined_r:unconfined_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
        )
        failed = self.failed(self.boot({}, audit))
        self.assertEqual(failed, ["no new denial from marker check-check-journal on"])
        detail = next(c for c in self.run_checks if c["name"] == failed[0])
        self.assertIn("audit log", detail["detail"])

    SERIALS = (
        "every audit record of the boot from its first marker on is in the "
        "kernel log or auditd's log"
    )

    def test_an_audit_record_in_neither_log_fails_the_boot(self) -> None:
        # From the first marker on, 3 is in auditd's log and 5 in the kernel
        # log: 4 reached neither.
        audit = "type=CONFIG_CHANGE msg=audit(105.000:3): op=set res=1"
        late = {25: "audit: type=1130 audit(111.000:5): pid=1 msg='unit=x'"}
        self.assertEqual(self.failed(self.boot(late, audit)), [self.SERIALS])
        audit += "\ntype=CONFIG_CHANGE msg=audit(106.000:4): op=set res=1"
        self.assertEqual(self.failed(self.boot(late, audit)), [])

    def test_what_the_boot_s_start_lost_is_recorded_only(self) -> None:
        # Before the gate lifted printk's rate limit the kernel dropped 2 to
        # 38; auditd took 39 on.
        audit = "type=CONFIG_CHANGE msg=audit(105.000:39): op=set res=1"
        run = gate()
        run.boots = [self.boot({}, audit, started=False)]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(
            run.facts["audit-serials-reference"],
            {"fromFirstMarker": 39, "highest": 39, "lostAtTheBootsStart": [(2, 38)]},
        )

    def test_a_phase_that_lost_records_fails(self) -> None:
        lost = {65: "kauditd_printk_skb: 3 callbacks suppressed"}
        self.assertEqual(
            self.failed(self.boot(lost)), ["the kernel lost no record from enter-1 on"]
        )

    def test_what_the_boot_s_start_dropped_is_recorded_only(self) -> None:
        run = gate()
        run.boots = [self.boot({5: "kauditd_printk_skb: 2 callbacks suppressed"})]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(
            run.facts["lost-at-the-boots-start-reference"],
            ["kauditd_printk_skb: 2 callbacks suppressed"],
        )

    def test_the_baseline_is_the_decoy_before_the_first_entry(self) -> None:
        self.assertEqual(
            fg.Gate.baseline_labels(self.boot({})),
            {"boot-ready", "prep-decoy", "prep-after-check-journal", "control-1-start"},
        )
        # A denial a phase after the first session logs is new unless the
        # decoy logged it before the first entry; one a check logged is no
        # baseline.
        late = denial(161.0, 3, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({75: late})),
            ["no new denial from marker prep-drift on"],
        )
        early = denial(111.0, 4, "rpm", "rpm_t")
        self.assertEqual(self.failed(self.boot({25: early, 75: late})), [])
        in_check = denial(121.0, 4, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({35: in_check, 75: late})),
            [
                "no new denial from marker check-check-journal on",
                "no new denial from marker prep-drift on",
            ],
        )

    def test_without_dontaudit_rules_only_nails_s_new_denials_fail(self) -> None:
        # The policy's quiet denials of other programs show then: recorded.
        late = {75: denial(161.0, 3, "systemd-hwdb", "systemd_hwdb_t")}
        run = gate(dontaudit=False)
        run.boots = [self.boot(late)]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(len(run.facts["noda-other-new"]["marker prep-drift"]), 1)
        nails = {75: denial(161.0, 3, "control")}
        run = gate(dontaudit=False)
        run.boots = [self.boot(nails)]
        quiet(run.judge_denials)
        self.assertEqual(
            [c["name"] for c in run.checks if not c["passed"]],
            ["no new denial from marker prep-drift on"],
        )

    def test_a_nails_denial_before_the_first_entry_still_counts(self) -> None:
        self.assertEqual(
            self.failed(self.boot({25: denial(111.0, 3, "control")})),
            ["no new denial from marker prep-decoy on"],
        )


if __name__ == "__main__":
    unittest.main()
