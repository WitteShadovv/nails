"""Tests for the judgments of arch_gate, the gate scenario of an Arch decoy,
that run without a VM."""

from __future__ import annotations

import contextlib
import io
import shlex
import subprocess
import tempfile
import unittest
from typing import Any

import arch_gate as ag
import fedora_gate as fg


def gate(**settings: Any) -> ag.ArchGate:
    return ag.ArchGate(
        None,
        None,
        None,
        None,
        {"image": "arch-boxes", **settings},
        tempfile.mkdtemp(prefix="arch-gate-test-"),
    )


def quiet(call: Any, *args: Any) -> Any:
    """``call`` with what it prints kept off the test's output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args)


class SecurityStateTest(unittest.TestCase):
    ARCH = (
        "capability,landlock,lockdown,yama,bpf\n"
        "\n"
        "lockdown: [none] integrity confidentiality\n"
        "ptrace_scope: 1\n"
        "no selinuxfs\n"
    )

    def test_reads_the_kernel_s_modules(self) -> None:
        self.assertEqual(
            ag.lsm_list(self.ARCH),
            ["capability", "landlock", "lockdown", "yama", "bpf"],
        )
        self.assertEqual(ag.lsm_list(""), [])

    def test_no_mandatory_access_control_on_the_stock_kernel(self) -> None:
        self.assertEqual(ag.mac_running(ag.lsm_list(self.ARCH), self.ARCH), [])

    def test_selinux_apparmor_or_a_selinuxfs_is_found(self) -> None:
        for lsms, state, found in (
            (["capability", "selinux"], "", ["selinux"]),
            (["capability", "apparmor"], "", ["apparmor"]),
            (["capability"], "x\nselinuxfs\n", ["selinuxfs"]),
        ):
            self.assertEqual(ag.mac_running(lsms, state), found)

    def test_lsm_status_must_name_every_module(self) -> None:
        lsms = ["capability", "landlock", "yama"]
        message = "SELinux does not run. Active LSMs: capability, landlock, yama."
        self.assertEqual(ag.lsm_not_named(message, lsms), [])
        self.assertEqual(
            ag.lsm_not_named("Active LSMs: capability", lsms),
            [
                "landlock",
                "yama",
            ],
        )

    def test_the_gate_asserts_the_modules_where_fedora_s_asserts_enforcing(
        self,
    ) -> None:
        g = gate()
        calls: list[str] = []

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            calls.append(cmd)
            return self.ARCH if len(calls) == 1 else self.ARCH.replace(",bpf", "")

        g.fact = fact  # type: ignore[method-assign]
        quiet(g.enforcing, "on the decoy")
        quiet(g.enforcing, "in hidden session 1")
        by_name = {(c["where"], c["name"]): c["passed"] for c in g.checks}
        where = "decoy before the first entry"
        self.assertTrue(by_name[(where, "no SELinux and no AppArmor run on the decoy")])
        self.assertTrue(
            by_name[
                (
                    where,
                    "the kernel runs the security modules of the first boot "
                    "on the decoy",
                )
            ]
        )
        self.assertFalse(
            by_name[
                (
                    where,
                    "the kernel runs the security modules of the first boot "
                    "in hidden session 1",
                )
            ]
        )
        self.assertEqual(calls, [ag.SECURITY_STATE, ag.SECURITY_STATE])

    def test_the_way_back_names_the_state_it_compares(self) -> None:
        self.assertNotIn("SELinux", ag.ArchGate.security_state_name)
        self.assertIn("SELinux", fg.Gate.security_state_name)


class GateSettingsTest(unittest.TestCase):
    def test_the_arch_gate_s_shares_volume_and_warnings(self) -> None:
        g = gate(python="/nix/store/x-python3/bin/python3")
        self.assertEqual(list(g.shares), [("tools", "/run/tools")])
        self.assertIn("cryptsetup open", g.hidden_root)
        self.assertNotIn("backend-encryption", g.harness_warnings)
        self.assertEqual(g.python, "/nix/store/x-python3/bin/python3")
        self.assertFalse(g.zram)

    def test_fedora_s_gate_keeps_its_own(self) -> None:
        g = fg.Gate(None, None, None, None, {"image": "fedora-44"}, tempfile.mkdtemp())
        self.assertEqual(g.python, "python3")
        self.assertTrue(g.zram)
        self.assertEqual(g.hidden_root, fg.HIDDEN_ROOT)
        self.assertIn("backend-encryption", g.harness_warnings)
        self.assertEqual(len(g.shares), 2)

    def test_the_kernel_log_reader_runs_the_python_it_is_given(self) -> None:
        import selinux_gate as sg

        self.assertTrue(sg.kmsg_command(7).startswith("python3 - 7 "))
        self.assertTrue(
            sg.kmsg_command(7, python="/p/bin/python3").startswith(
                "/p/bin/python3 - 7 "
            )
        )

    def test_the_decoy_is_prepared_for_init_on_free_through_grub(self) -> None:
        self.assertIn("init_on_free=1", ag.PREPARE_DECOY)
        self.assertIn(f"log_buf_len={fg.LOG_BUF_LEN}", ag.PREPARE_DECOY)
        self.assertIn("grub-mkconfig -o /boot/grub/grub.cfg", ag.PREPARE_DECOY)
        for key, value in __import__("selinux_gate").KMSG_SETTINGS:
            self.assertIn(f"'{key} = {value}'", ag.PREPARE_DECOY)


class FstabPolicyTest(unittest.TestCase):
    MESSAGE = (
        "decoy filesystems in the hidden root: /swap/swapfile: masked (swap would "
        "take hidden RAM onto a decoy disk); /efi: read-only; /efi: masked (the "
        "session puts the filesystem behind it in place); /var/lib/machines: "
        "masked (not mounted now; the hidden session would mount it read-write). "
        "Masked and skipped filesystems are not available in the hidden session."
    )

    def test_reads_what_the_warning_names(self) -> None:
        self.assertEqual(
            ag.fstab_items(self.MESSAGE),
            [
                "/efi: masked",
                "/efi: read-only",
                "/swap/swapfile: masked",
                "/var/lib/machines: masked",
            ],
        )
        self.assertEqual(ag.fstab_items(""), [])

    def test_reads_what_the_warning_says_after_its_items(self) -> None:
        self.assertEqual(ag.fstab_notes(self.MESSAGE), ag.FSTAB_NOTE)
        self.assertEqual(ag.fstab_notes("something else. x"), None)
        added = f"{self.MESSAGE} a unit pulls /var/lib/machines by path."
        self.assertEqual(ag.fstab_items(added), ag.fstab_items(self.MESSAGE))
        self.assertNotEqual(ag.fstab_notes(added), ag.FSTAB_NOTE)

    def judged(self, message: str) -> dict[str, bool]:
        g = gate(
            fstabPolicy=[
                "/swap/swapfile: masked",
                "/efi: read-only",
                "/efi: masked",
                "/var/lib/machines: masked",
            ]
        )
        rows = {
            "fstab-policy": {"status": "warn", "message": message},
            "dma-protection": {"status": "warn", "message": "no IOMMU"},
            "swap": {"status": "pass", "message": ""},
        }
        g.check_rows = lambda *args: (9, rows)  # type: ignore[method-assign]
        quiet(g.clean_check)
        return {c["name"]: c["passed"] for c in g.checks}

    def test_the_clean_check_holds_the_warning_to_its_items_and_note(self) -> None:
        name = (
            "fstab-policy names on the prepared decoy what the image's layout "
            "brings, and nothing else"
        )
        found = self.judged(self.MESSAGE)
        self.assertTrue(all(found.values()), found)
        self.assertIn(
            "check warns of nothing on the prepared decoy but what the harness, "
            "the VM, an untested release and, from fstab-policy, the image's own "
            "filesystems bring",
            found,
        )
        for extra in (
            " /efi is masked, as its device /dev/sda1 is not there.",
            " a unit pulls /var/lib/machines by path and may not start.",
        ):
            self.assertFalse(self.judged(self.MESSAGE + extra)[name], extra)
        self.assertFalse(
            self.judged(self.MESSAGE.replace("/efi: read-only", "/efi: read-write"))[
                name
            ]
        )

    def test_the_image_s_layout_is_allowed_only_where_the_settings_name_it(
        self,
    ) -> None:
        self.assertNotIn("fstab-policy", gate().harness_warnings)
        named = gate(fstabPolicy=["/efi: read-only", "/efi: masked"])
        self.assertIn("fstab-policy", named.harness_warnings)
        self.assertEqual(named.fstab_policy, ["/efi: masked", "/efi: read-only"])
        self.assertNotIn("fstab-policy", ag.HARNESS_WARNINGS)


class FakeVm:
    """A guest that answers each command by the first key it contains."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.ran: list[str] = []

    def succeed(self, cmd: str) -> str:
        self.ran.append(cmd)
        for key, out in self.answers.items():
            if key in cmd:
                return out
        return ""

    def wait_for_unit(self, unit: str) -> None:
        self.ran.append(f"wait {unit}")


class SwapTest(unittest.TestCase):
    NAME = "the decoy's disk swap is off, and every swap line of its fstab noauto"
    OFF = "Filename Type Size Used Priority\n"
    LINE = "/swap/swapfile none swap defaults 0 0\n"

    def judged(
        self, fstab: str, swaps: str, torn: int = 0, garble: bool = False
    ) -> tuple[bool, list[str]]:
        """swap_off against a guest whose /etc/fstab holds ``fstab`` and
        /proc/swaps ``swaps``; the first ``torn`` reads of the fstab come torn,
        flagged torn though their text looks whole, and with ``garble`` its
        second read differs from its first. What the
        check said, and every text written to the fstab."""
        g = gate()
        guest: dict[str, Any] = {"fstab": fstab, "reads": 0, "torn": torn}
        written: list[str] = []

        def sh(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> tuple[int, str]:
            if cmd == "cat /etc/fstab":
                guest["reads"] += 1
                if guest["torn"]:
                    guest["torn"] -= 1
                    g.torn.append(label)
                    return 0, guest["fstab"]
                if garble and guest["reads"] == 2:
                    return 0, guest["fstab"] + "x"
                return 0, guest["fstab"]
            if cmd == "cat /proc/swaps":
                return 0, swaps
            return 0, ""

        class Vm:
            def succeed(self, cmd: str) -> str:
                words = shlex.split(cmd)
                if words[:2] == ["printf", "%s"]:
                    written.append(words[2])
                    guest["fstab"] = words[2]
                return ""

        g.vm = Vm()
        g.sh = sh  # type: ignore[method-assign]
        quiet(g.swap_off)
        return {c["name"]: c["passed"] for c in g.checks}[self.NAME], written

    def test_makes_every_swap_line_noauto(self) -> None:
        noauto = self.LINE.replace("defaults", "defaults,noauto")
        self.assertEqual(self.judged(noauto, self.OFF), (True, []))
        self.assertEqual(self.judged(self.LINE, self.OFF), (True, [noauto]))
        # A swap that still runs fails, though every line is noauto.
        running = self.OFF + "/swap/swapfile file 4G 0 -2\n"
        self.assertEqual(self.judged(noauto, running)[0], False)

    def test_writes_back_nothing_read_garbled(self) -> None:
        self.assertEqual(self.judged(self.LINE, self.OFF, torn=1), (False, []))
        self.assertEqual(self.judged(self.LINE, self.OFF, garble=True), (False, []))


class ProcessesTest(unittest.TestCase):
    LINES = ["root 1602 control /run/overlay-runtime/control watch"]

    def test_each_runs_from_the_copy_in_ram(self) -> None:
        self.assertTrue(ag.processes_from_ram(self.LINES, f"1602 {fg.RAM}\n"))
        self.assertFalse(ag.processes_from_ram(self.LINES, "1602 /mnt/data/nails\n"))
        self.assertFalse(
            ag.processes_from_ram(self.LINES, f"1602 {fg.RAM} (deleted)\n")
        )
        self.assertFalse(ag.processes_from_ram(self.LINES, ""))
        self.assertFalse(ag.processes_from_ram([], ""))
        user = ["gate 1602 control /run/overlay-runtime/control watch"]
        self.assertFalse(ag.processes_from_ram(user, f"1602 {fg.RAM}\n"))


class SessionTest(unittest.TestCase):
    def test_no_disk_swap_in_the_session_and_the_esp_probe(self) -> None:
        for swaps, passed in (
            ("Filename Type Size Used Priority\n/dev/zram0 partition 1G 0 100", True),
            ("Filename Type Size Used Priority\n/swap/swapfile file 4G 0 -2", False),
            ("", False),
        ):
            g = gate()
            ran: list[str] = []

            def fact(
                label: str,
                cmd: str,
                timeout: int = 300,
                again: bool = False,
                swaps: str = swaps,
                ran: list[str] = ran,
            ) -> str:
                ran.append(cmd)
                if cmd == "cat /proc/swaps":
                    return swaps
                if cmd.startswith("tail -n1"):
                    return f"# gate\n{fg.UPPER}/etc/gate-new"
                return "rc=1"

            g.fact = fact  # type: ignore[method-assign]
            quiet(g.session_security, 1, "root")
            found = {c["name"]: c["passed"] for c in g.checks}
            self.assertEqual(found["session 1: no swap is on a disk"], passed, swaps)
            self.assertIn(f"touch {ag.EFI_PROBE}-1 2>&1; echo rc=$?", ran)
        self.assertIn(f"{ag.EFI_PROBE}-2", ag.ArchGate.session_files)
        self.assertTrue(set(fg.SESSION_FILES) <= set(ag.ArchGate.session_files))


class UpdateStateTest(unittest.TestCase):
    def test_the_pending_update_is_brought_in_before_the_entry(self) -> None:
        g = gate()
        ran: list[str] = []
        states = iter(["/etc current\n/var current"])

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            if cmd == ag.UPDATE_UNITS:
                return "ldconfig.service\nsystemd-update-done.service"
            return next(states)

        def sh(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> tuple[int, str]:
            ran.append(cmd)
            return 0, ""

        g.fact = fact  # type: ignore[method-assign]
        g.sh = sh  # type: ignore[method-assign]
        quiet(g.up_to_date, "drift", "second")
        self.assertEqual(
            ran, ["systemctl restart ldconfig.service systemd-update-done.service"]
        )
        self.assertEqual(
            [(c["name"], c["passed"]) for c in g.checks],
            [
                (
                    "/etc and /var are up to date with /usr before the second entry, "
                    "as a start of PID 1 leaves them",
                    True,
                )
            ],
        )
        # Still pending afterwards, or no unit to run it: the check fails.
        g.checks = []
        states = iter(["/etc pending\n/var current"])
        quiet(g.up_to_date, "drift", "second")
        self.assertFalse(g.checks[0]["passed"])

    def first_steps(self, reference: str) -> tuple[ag.ArchGate, list[str]]:
        """The run's steps up to the first plain soft-reboot, with
        :data:`fedora_gate.NEEDS_UPDATE` printing ``reference`` after the
        reference boot: the gate and the order its steps ran in."""
        g = gate()
        order: list[str] = []

        class Stop(Exception):
            pass

        g.vm = FakeVm({})
        steps = ("prepare", "attach", "stock", "swap_off", "drift_install", "decoy")
        for name in steps:
            setattr(g, name, lambda *a, name=name: order.append(name))

        def sh(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> tuple[int, str]:
            order.append(label)
            return 0, ""

        def power_cycle(label: str) -> None:
            order.append(f"power-cycle {label}")

        def fact(
            label: str, cmd: str, timeout: int = 300, again: bool = False
        ) -> str:
            order.append(label)
            if label == "cmdline":
                return "init_on_free=1"
            if label == "needs-update-reference":
                return reference
            return "/etc current\n/var current"

        def control(label: str) -> None:
            order.append(label)
            raise Stop

        g.sh = sh  # type: ignore[method-assign]
        g.power_cycle = power_cycle  # type: ignore[method-assign]
        g.mark = lambda label: None  # type: ignore[method-assign]
        g.fact = fact  # type: ignore[method-assign]
        g.control = control  # type: ignore[method-assign]
        with self.assertRaises(Stop):
            quiet(g.flows)
        return g, order

    def test_the_first_control_starts_from_an_update_brought_in(self) -> None:
        # pacman installs the drift control's first version before the
        # reference boot, whose start brings /etc and /var up to date, and so
        # before the first plain soft-reboot.
        g, order = self.first_steps("/etc current\n/var current")
        reference = order.index("power-cycle reference")
        self.assertLess(order.index("drift_install"), reference)
        self.assertLess(reference, order.index("decoy"))
        self.assertEqual(order[-1], "control-1")
        self.assertTrue(all(c["passed"] for c in g.checks), g.checks)

    def test_a_reference_boot_that_left_the_update_pending_fails(self) -> None:
        g, _ = self.first_steps("/etc pending\n/var current")
        found = {c["name"]: c["passed"] for c in g.checks}
        self.assertFalse(
            found[
                "/etc and /var are up to date with /usr after the reference boot, "
                "which ran the units of the update pacman left pending"
            ]
        )

    def test_pacman_leaves_the_update_pending(self) -> None:
        for read, passed in (
            ("/etc pending\n/var pending", True),
            ("/etc current\n/var pending", False),
            ("/etc current\n/var current", False),
        ):
            g = gate()
            g.fact = lambda label, cmd, timeout=300, again=False, read=read: read  # type: ignore[method-assign,misc]
            quiet(g.left_pending, "3")
            self.assertEqual([c["passed"] for c in g.checks], [passed], read)


class DriftTest(unittest.TestCase):
    def test_the_package_info(self) -> None:
        info = ag.pkginfo("2", 1700000000)
        self.assertIn("pkgname = gate-drift\n", info)
        self.assertIn("pkgver = 2-1\n", info)
        self.assertIn("builddate = 1700000000\n", info)
        self.assertIn("arch = any\n", info)
        self.assertEqual(
            ag.drift_file("2"), "/run/gate-pkg/gate-drift-2-1-any.pkg.tar.zst"
        )

    def test_the_build_writes_the_package_info_as_given(self) -> None:
        # The command's printf, run by a shell here, writes .PKGINFO exactly.
        command = ag.drift_package("3", 42)
        start = command.index("printf %s ") + len("printf %s ")
        end = command.index(" > /run/gate-pkg/3/.PKGINFO")
        written = subprocess.run(
            ["sh", "-c", f"printf %s {command[start:end]}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(written, ag.pkginfo("3", 42))
        self.assertIn(
            "bsdtar --zstd -cf /run/gate-pkg/gate-drift-3-1-any.pkg.tar.zst", command
        )

    def test_the_install_checks_no_signature_and_lists_the_package(self) -> None:
        command = ag.pacman_install("1", 5)
        self.assertIn(f"pacman --config {ag.PACMAN_CONF} -U --noconfirm ", command)
        self.assertIn(shlex.quote(ag.PACMAN_CONF_TEXT), command)
        self.assertIn("LocalFileSigLevel = Never", ag.PACMAN_CONF_TEXT)
        self.assertIn("pacman -Q gate-drift", command)

    def test_reads_the_installed_version(self) -> None:
        listing = "...\nrc=0\ngate-drift 2-1\n/var/lib/pacman/local/gate-drift-2-1\n"
        self.assertEqual(ag.installed_version(listing), "2-1")
        self.assertIsNone(
            ag.installed_version("error: package 'gate-drift' was not found\n")
        )


class ZramTest(unittest.TestCase):
    def test_no_device_and_no_generator_runs_no_zram_check(self) -> None:
        cold = (
            "Id=systemd-zram-setup@zram0.service\nLoadState=not-found\n"
            "ActiveState=inactive\nResult=success\n"
        )
        self.assertFalse(ag.zram_applies(cold, False))
        self.assertFalse(ag.zram_applies("", False))

    def test_a_device_a_swap_or_the_generator_runs_them(self) -> None:
        self.assertTrue(ag.zram_applies("", True))
        self.assertTrue(
            ag.zram_applies(
                "zram0 initstate=1 disksize=4294967296 backing=none mm_stat=0\n", False
            )
        )
        self.assertTrue(
            ag.zram_applies("/dev/zram0 partition 4294967296 0 100\n", False)
        )
        self.assertFalse(
            ag.zram_applies(
                "zram0 initstate=0 disksize=0 backing=none mm_stat=0\n", False
            )
        )


class KernelLogTest(unittest.TestCase):
    def boot(self, records: dict[int, str], dropped: int = 0) -> dict[str, Any]:
        marker = next(seq for seq, msg in records.items() if "GATEMARK" in msg)
        return {
            "why": "reference",
            "records": {
                seq: {"seq": seq, "us": seq * 10, "msg": msg}
                for seq, msg in records.items()
            },
            "dropped": dropped,
            "markers": [{"label": "boot-ready", "seq": marker, "wall": "1.0"}],
            "audit": [],
        }

    def judged(self, boot: dict[str, Any]) -> dict[str, bool]:
        g = gate()
        g.boots = [boot]
        quiet(g.judge_denials)
        return {c["name"]: c["passed"] for c in g.checks}

    def test_a_whole_log_passes(self) -> None:
        found = self.judged(
            self.boot(
                {
                    1: "audit: type=1130 audit(1.0:5): pid=1 msg='unit=a'",
                    2: "GATEMARK boot-ready",
                    3: "audit: type=1131 audit(2.0:6): pid=1 msg='unit=a'",
                    4: "audit: type=1130 audit(3.0:7): pid=1 msg='unit=b'",
                }
            )
        )
        self.assertTrue(all(found.values()), found)

    def test_a_lost_record_a_gap_or_a_suppressed_notice_fails(self) -> None:
        records = {
            1: "audit: type=1130 audit(1.0:5): pid=1 msg='unit=a'",
            2: "GATEMARK boot-ready",
            3: "audit: type=1131 audit(2.0:6): pid=1 msg='unit=a'",
            4: "audit: type=1130 audit(3.0:9): pid=1 msg='unit=b'",
        }
        found = self.judged(self.boot(records))
        self.assertFalse(
            found[
                "every audit record of the boot from its first marker on is in the "
                "kernel log"
            ]
        )
        found = self.judged(self.boot({**records, 4: "audit: audit_lost=3"}))
        self.assertFalse(found["the kernel lost no record from boot-ready on"])
        found = self.judged(self.boot({1: records[1], 2: records[2], 5: records[3]}))
        self.assertFalse(found["the kernel log lost no record"])
        found = self.judged(self.boot(records, dropped=1))
        self.assertFalse(found["the kernel log lost no record"])


if __name__ == "__main__":
    unittest.main()
