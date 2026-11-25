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
        self.assertIn("grub-mkconfig -o /boot/grub/grub.cfg", ag.PREPARE_DECOY)
        for key, value in __import__("selinux_gate").KMSG_SETTINGS:
            self.assertIn(f"'{key} = {value}'", ag.PREPARE_DECOY)


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
