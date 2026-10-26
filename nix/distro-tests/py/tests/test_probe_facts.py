"""Unit tests for the distribution probe's queries and their reading.

These run in the fast lane (`python3 -m unittest`, no VM). The samples are
query outputs of the stock Fedora 44 and Arch images as the probe printed them,
so a reading that drifts from what the guest prints shows up here rather than
as a wrong fact in a fixture.
"""

from __future__ import annotations

import json
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path

import probe_facts as pf

# The committed fixtures, nix/distro-tests/probe.
FIXTURES = Path(__file__).resolve().parents[2] / "probe"

FEDORA_OS_RELEASE = """\
NAME="Fedora Linux"
VERSION="44 (Cloud Edition)"
RELEASE_TYPE=stable
ID=fedora
VERSION_ID=44
VERSION_CODENAME=""
PRETTY_NAME="Fedora Linux 44 (Cloud Edition)"
VARIANT="Cloud Edition"
VARIANT_ID=cloud
"""

ARCH_OS_RELEASE = """\
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
"""

FEDORA_SELINUX = """\
Enforcing
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
Current mode:                   enforcing
"""

ARCH_SELINUX = """\
bash: line 1: getenforce: command not found
bash: line 1: sestatus: command not found
"""

FEDORA_BACKDOOR = (
    "system_u:system_r:unconfined_service_t:s0\x00\n"
    "Id=backdoor.service\n"
    "ExecStart={ path=/usr/bin/backdoorScript ; argv[]=/usr/bin/backdoorScript }\n"
)

ARCH_BACKDOOR = """\
cat: /proc/self/attr/current: Invalid argument

Id=backdoor.service
"""

FEDORA_MOUNTS = """\
/ btrfs rw,relatime,seclabel,compress=zstd:1,subvolid=256,subvol=/root
/home btrfs rw,relatime,seclabel,compress=zstd:1,subvolid=258,subvol=/home
/boot btrfs rw,relatime,seclabel,compress=zstd:1,subvolid=257,subvol=/boot
/boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,errors=remount-ro
/var btrfs rw,relatime,seclabel,compress=zstd:1,subvolid=259,subvol=/var
/nix/.ro-store 9p rw,relatime,cache=0xf,access=client,msize=512000,trans=virtio
"""

FEDORA_ROOT = "UUID=15c26993-ac30-424a-9c4b-faec4434d234"

FEDORA_FSTAB = (
    f"{FEDORA_ROOT} / btrfs compress=zstd:1,defaults,subvol=root 0 1\n"
    f"{FEDORA_ROOT} /boot btrfs compress=zstd:1,subvol=boot 0 0\n"
    "UUID=5BCC-12A9 /boot/efi vfat defaults,umask=0077,shortname=winnt 0 0\n"
)

ARCH_FSTAB = """\
# Static information about the filesystems.
# See fstab(5) for details.

# <file system> <dir> <type> <options> <dump> <pass>
/swap/swapfile none swap defaults 0 0
"""

# Some of the mount, swap and automount units of the Fedora image (the padding
# narrowed and two descriptions shortened, which the reading skips), and their
# sources as the query printed them before it passed the unit after `--`: the
# root's unit then read as an option, and its block holds the error instead.
FEDORA_MOUNT_UNITS = """\
boot.automount                 not-found inactive dead    boot.automount
-.mount                        loaded    active   mounted Root Mount
boot-efi.mount                 loaded    active   mounted /boot/efi
nix-.ro\\x2dstore.mount         loaded    active   mounted /nix/.ro-store
sys-kernel-config.mount        loaded    active   mounted Kernel Configuration
tmp.mount                      loaded    active   mounted Temporary Directory /tmp
dev-disk-by\\x2ddiskseq-4.swap  loaded    active   active  /dev/disk/by-diskseq/4
dev-zram0.swap                 loaded    active   active  Compressed Swap on zram0
"""

FEDORA_MOUNT_UNIT_SOURCES = """\
Unit=boot.automount
FragmentPath=
SourcePath=
Unit=-.mount
systemctl: invalid option -- '.'
Hint: to specify units starting with a dash, use "--":
      systemctl [OPTIONS...] COMMAND -- -.mount ...
Unit=boot-efi.mount
FragmentPath=/run/systemd/generator/boot-efi.mount
SourcePath=/etc/fstab
Unit=nix-.ro\\x2dstore.mount
FragmentPath=
SourcePath=/proc/self/mountinfo
Unit=sys-kernel-config.mount
FragmentPath=/usr/lib/systemd/system/sys-kernel-config.mount
SourcePath=/proc/self/mountinfo
Unit=tmp.mount
FragmentPath=/usr/lib/systemd/system/tmp.mount
SourcePath=
Unit=dev-disk-by\\x2ddiskseq-4.swap
FragmentPath=
SourcePath=
Unit=dev-zram0.swap
FragmentPath=/run/systemd/generator/dev-zram0.swap
SourcePath=
"""

FEDORA_TOOLS = """\
systemctl: /usr/bin/systemctl
ip: /usr/bin/ip
cryptsetup:
veracrypt:
kill: /usr/bin/kill
"""

FEDORA_JOURNALD = """\
# /usr/lib/systemd/journald.conf
# /etc/ if the original file is shipped in /usr/), or by creating "drop-ins" in
#Storage=persistent
/run/log/journal
/var/log/journal
"""

FEDORA_MASKED = """\
serial-getty@hvc0.service  masked disabled
serial-getty@ttyS0.service masked disabled
ssh.service                masked disabled
ssh.socket                 masked disabled
"""

ENFORCING_NINEP = """\
TARGET         SOURCE    FSTYPE OPTIONS
/nix/.ro-store nix-store 9p     rw,relatime,cache=0xf,access=client,trans=virtio
find: ‘standard output’: Broken pipe
find: write error
read-ok
"""


class QueriesTest(unittest.TestCase):
    def test_cold_boot_labels_are_unique(self) -> None:
        labels = [label for label, _ in pf.cold_boot_queries("fedora")]
        self.assertEqual(len(labels), len(set(labels)))

    def test_rpm_is_queried_on_fedora_only(self) -> None:
        self.assertIn("rpm", dict(pf.cold_boot_queries("fedora")))
        self.assertNotIn("rpm", dict(pf.cold_boot_queries("arch")))

    def test_soft_reboot_labels_differ_from_the_cold_boot_ones(self) -> None:
        cold = {label for label, _ in pf.cold_boot_queries("fedora")}
        after = [label for label, _ in pf.soft_reboot_queries()]
        self.assertEqual(len(after), len(set(after)))
        self.assertFalse(cold & set(after))

    def test_the_selinux_and_denial_queries_end_the_cold_boot(self) -> None:
        # What the queries after the soft-reboot read beyond these is what the
        # soft-reboot added, so nothing may run between them and it.
        labels = [label for label, _ in pf.cold_boot_queries("fedora")]
        self.assertEqual(labels[-3:], ["selinux-labels", "selinux-policy", "avcs"])

    def test_every_query_is_read(self) -> None:
        class Recorder(Mapping[str, str]):
            def __init__(self) -> None:
                self.read: set[str] = set()

            def __getitem__(self, key: str) -> str:
                self.read.add(key)
                raise KeyError(key)

            def __iter__(self) -> Iterator[str]:
                return iter(())

            def __len__(self) -> int:
                return 0

        blocks = Recorder()
        pf.facts(blocks, "fedora")
        queried = {label for label, _ in pf.cold_boot_queries("fedora")}
        queried |= {label for label, _ in pf.soft_reboot_queries()}
        self.assertEqual(queried, blocks.read)

    def test_probe_name(self) -> None:
        self.assertEqual(pf.probe_name("fedora-44", False), "fedora-44")
        self.assertEqual(pf.probe_name("fedora-44", True), "fedora-44-enforcing")


class SelinuxTest(unittest.TestCase):
    def test_mode(self) -> None:
        self.assertEqual(pf.selinux_mode(FEDORA_SELINUX), "enforcing")
        self.assertEqual(pf.selinux_mode("Permissive\n"), "permissive")
        self.assertIsNone(pf.selinux_mode(ARCH_SELINUX))
        self.assertIsNone(pf.selinux_mode(None))

    def test_backdoor_domain_drops_the_nul_the_kernel_appends(self) -> None:
        self.assertEqual(pf.selinux_type(FEDORA_BACKDOOR), "unconfined_service_t")

    def test_no_domain_without_selinux(self) -> None:
        self.assertIsNone(pf.selinux_type(ARCH_BACKDOOR))

    def test_mls_range_is_not_part_of_the_type(self) -> None:
        context = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\n"
        self.assertEqual(pf.selinux_type(context), "unconfined_t")

    def test_labels(self) -> None:
        # ls right-aligns the labels.
        out = (
            "        system_u:object_r:root_t:s0 /\n"
            "     system_u:object_r:var_run_t:s0 /run\n"
            "system_u:object_r:init_var_run_t:s0 /run/systemd\n"
        )
        self.assertEqual(
            pf.selinux_labels(out),
            {
                "/": "system_u:object_r:root_t:s0",
                "/run": "system_u:object_r:var_run_t:s0",
                "/run/systemd": "system_u:object_r:init_var_run_t:s0",
            },
        )

    def test_unlabelled_path_is_none(self) -> None:
        out = "? /\nls: cannot access '/run/systemd': No such file or directory\n"
        self.assertEqual(
            pf.selinux_labels(out), {"/": None, "/run": None, "/run/systemd": None}
        )

    def test_policy_loads_keep_the_line_and_drop_the_load_time(self) -> None:
        out = (
            "[    4.353519] systemd[1]: Successfully loaded SELinux policy in "
            "105.840ms.\n"
            "[   12.179597] systemd[1]: Failed to load new SELinux policy. "
            "Continuing with old policy.\n"
        )
        loads = pf.policy_loads(out)
        self.assertEqual(
            [message for _, message in loads],
            [
                "systemd[1]: Successfully loaded SELinux policy.",
                "systemd[1]: Failed to load new SELinux policy. "
                "Continuing with old policy.",
            ],
        )
        self.assertTrue(loads[1][0].startswith("[   12.179597]"))

    def test_load_time_in_other_units(self) -> None:
        for took in ("975\u00b5s", "1min 2.345s", "1.2s"):
            line = f"[ 4.1] systemd[1]: Successfully loaded SELinux policy in {took}."
            ((_, message),) = pf.policy_loads(line)
            self.assertEqual(message, "systemd[1]: Successfully loaded SELinux policy.")


class AvcTest(unittest.TestCase):
    # The first denial of the permissive Fedora image after its soft-reboot,
    # as the kernel log and as the audit log print it.
    DENIAL = (
        'avc:  denied  { map } for  pid=1 comm="systemd" '
        'path="/etc/selinux/targeted/policy/policy.35" dev="sda3" ino=2309 '
        "scontext=system_u:system_r:init_t:s0 "
        "tcontext=system_u:object_r:semanage_store_t:s0 tclass=file permissive=1"
    )
    KERNEL = (
        "Oct 26 08:13:34 localhost.localdomain kernel: audit: type=1400 "
        "audit(1793002413.421:137): " + DENIAL
    )
    AUDIT_LOG = "type=AVC msg=audit(1793002413.421:137): " + DENIAL
    USER_AVC = (
        "type=USER_AVC msg=audit(1792831790.001:230): pid=1 uid=0 auid=4294967295 "
        "msg='avc:  denied  { status } for auid=n/a uid=0 gid=0 "
        "scontext=system_u:system_r:a_t:s0 tcontext=system_u:system_r:init_t:s0 "
        "tclass=system permissive=0 exe=\"/usr/lib/systemd/systemd\"'"
        '\x1dUID="root" AUID="unset"'
    )

    def test_a_denial_in_both_logs_is_kept_once(self) -> None:
        events = pf.avc_events("\n".join([self.KERNEL, "----", self.AUDIT_LOG]))
        self.assertEqual(events, [("1793002413.421:137", self.DENIAL)])

    def test_user_avc_loses_the_enrichment_and_the_closing_quote(self) -> None:
        ((_, denial),) = pf.avc_events(self.USER_AVC)
        self.assertTrue(denial.endswith('exe="/usr/lib/systemd/systemd"'))

    def test_no_denial(self) -> None:
        self.assertEqual(pf.avc_events("<no matches>\n"), [])
        missing = "Error opening /var/log/audit/audit.log (No such file or directory)"
        self.assertEqual(pf.avc_events(missing), [])

    def test_only_new_denials_count_after_the_soft_reboot(self) -> None:
        blocks = {
            "selinux": "Enforcing\n",
            "avcs": self.KERNEL,
            "soft-reboot-avcs": "\n".join([self.KERNEL, self.USER_AVC]),
        }
        facts = pf.facts(blocks, "fedora")
        self.assertEqual(len(facts["avcs"]), 1)
        self.assertEqual(len(facts["avcsAfterSoftReboot"]), 1)
        self.assertIn("{ status }", facts["avcsAfterSoftReboot"][0])


class MountTest(unittest.TestCase):
    def test_mounts_are_sorted_and_leave_out_the_harness(self) -> None:
        mounts = pf.parse_mounts(FEDORA_MOUNTS)
        self.assertEqual(
            [mount["target"] for mount in mounts],
            ["/", "/boot", "/boot/efi", "/home", "/var"],
        )
        self.assertEqual(mounts[2]["fstype"], "vfat")
        self.assertTrue(mounts[0]["options"].endswith("subvol=/root"))

    def test_escaped_target_is_decoded(self) -> None:
        mounts = pf.parse_mounts("/mnt/a\\x20b ext4 rw\n")
        self.assertEqual(mounts[0]["target"], "/mnt/a b")

    def test_fstab_entries(self) -> None:
        entries = pf.parse_fstab(FEDORA_FSTAB)
        assert entries is not None
        self.assertEqual(
            [entry["target"] for entry in entries], ["/", "/boot", "/boot/efi"]
        )
        self.assertEqual(
            entries[0],
            {
                "source": "UUID=15c26993-ac30-424a-9c4b-faec4434d234",
                "target": "/",
                "fstype": "btrfs",
                "options": "compress=zstd:1,defaults,subvol=root",
                "dump": 0,
                "pass": 1,
            },
        )

    def test_fstab_comments_and_defaults(self) -> None:
        self.assertEqual(
            pf.parse_fstab(ARCH_FSTAB),
            [
                {
                    "source": "/swap/swapfile",
                    "target": "none",
                    "fstype": "swap",
                    "options": "defaults",
                    "dump": 0,
                    "pass": 0,
                }
            ],
        )
        (entry,) = pf.parse_fstab("tmpfs /scratch tmpfs\n") or []
        self.assertEqual(
            (entry["options"], entry["dump"], entry["pass"]), ("defaults", 0, 0)
        )

    def test_no_fstab(self) -> None:
        self.assertIsNone(
            pf.parse_fstab("cat: /etc/fstab: No such file or directory\n")
        )
        self.assertEqual(pf.parse_fstab("# only comments\n"), [])

    def test_swaps(self) -> None:
        out = "/dev/zram0 partition 2047864832 100\n/swap/swapfile file 536866816 -1\n"
        self.assertEqual(
            pf.parse_swaps(out),
            [
                {
                    "name": "/dev/zram0",
                    "type": "partition",
                    "size": 2047864832,
                    "priority": 100,
                },
                {
                    "name": "/swap/swapfile",
                    "type": "file",
                    "size": 536866816,
                    "priority": -1,
                },
            ],
        )
        self.assertEqual(pf.parse_swaps(""), [])

    def test_unit_path(self) -> None:
        self.assertEqual(pf.unit_path("-.mount"), "/")
        self.assertEqual(pf.unit_path("boot-efi.mount"), "/boot/efi")
        self.assertEqual(pf.unit_path("nix-.ro\\x2dstore.mount"), "/nix/.ro-store")
        self.assertEqual(pf.unit_path("swap-swapfile.swap"), "/swap/swapfile")

    def test_mount_units_with_their_sources(self) -> None:
        units = pf.parse_mount_units(FEDORA_MOUNT_UNITS, FEDORA_MOUNT_UNIT_SOURCES)
        self.assertEqual(
            [unit["unit"] for unit in units],
            [
                "boot.automount",
                "-.mount",
                "boot-efi.mount",
                "sys-kernel-config.mount",
                "tmp.mount",
                "dev-disk-by\\x2ddiskseq-4.swap",
                "dev-zram0.swap",
            ],
        )
        by_name = {unit["unit"]: unit for unit in units}
        self.assertEqual(
            by_name["boot-efi.mount"],
            {
                "unit": "boot-efi.mount",
                "load": "loaded",
                "active": "active",
                "sub": "mounted",
                "fragmentPath": "/run/systemd/generator/boot-efi.mount",
                "sourcePath": "/etc/fstab",
            },
        )
        self.assertEqual(
            (by_name["boot.automount"]["load"], by_name["boot.automount"]["sub"]),
            ("not-found", "dead"),
        )
        self.assertIsNone(by_name["tmp.mount"]["sourcePath"])
        self.assertEqual(
            by_name["dev-zram0.swap"]["fragmentPath"],
            "/run/systemd/generator/dev-zram0.swap",
        )

    def test_a_unit_whose_sources_failed_has_none(self) -> None:
        # The error in the root's block names no file, and the blocks after it
        # still count.
        units = pf.parse_mount_units(FEDORA_MOUNT_UNITS, FEDORA_MOUNT_UNIT_SOURCES)
        root = units[1]
        self.assertEqual(root["unit"], "-.mount")
        self.assertIsNone(root["fragmentPath"])
        self.assertIsNone(root["sourcePath"])
        self.assertEqual(units[2]["sourcePath"], "/etc/fstab")

    def test_the_unit_query_passes_the_unit_after_the_options(self) -> None:
        sources = dict(pf.cold_boot_queries("fedora"))["mount-unit-sources"]
        self.assertIn('-- "$u"', sources)

    def test_generator_listing_is_sorted(self) -> None:
        # The Fedora image's ls sorts by its locale, which puts -.mount among
        # the names that start with a letter.
        facts = pf.facts(
            {
                "generator": "boot.mount\nhome.mount\n-.mount\nvar.mount\n",
                "generator-late": (
                    "ls: cannot access '/run/systemd/generator.late': "
                    "No such file or directory\n"
                ),
            },
            "arch",
        )
        self.assertEqual(
            facts["generatorUnits"],
            {
                "/run/systemd/generator": [
                    "-.mount",
                    "boot.mount",
                    "home.mount",
                    "var.mount",
                ],
                "/run/systemd/generator.late": None,
            },
        )


class ServiceTest(unittest.TestCase):
    def test_states_and_a_missing_unit(self) -> None:
        out = (
            "auditd is-enabled: enabled\n"
            "auditd is-active: active\n"
            "tuned is-enabled: not-found\n"
            "tuned is-active: inactive\n"
            "firewalld is-enabled: Failed to get unit file state for "
            "firewalld.service: No such file or directory\n"
            "firewalld is-active: inactive\n"
        )
        states = pf.parse_services(out)
        self.assertEqual(states["auditd"], {"enabled": "enabled", "active": "active"})
        self.assertEqual(
            states["tuned"], {"enabled": "not-found", "active": "inactive"}
        )
        # An older systemctl fails on a missing unit instead of naming it.
        self.assertEqual(states["firewalld"]["enabled"], "not-found")
        # A service the query printed nothing for.
        self.assertEqual(states["abrtd"], {"enabled": None, "active": None})

    def test_a_failed_answer_is_kept_as_printed(self) -> None:
        # Not a unit that is missing: systemctl could not ask at all.
        error = "Failed to connect to bus: No such file or directory"
        out = (
            f"auditd is-enabled: {error}\n"
            f"auditd is-active: {error}\n"
            # The older systemctl's answer for another unit is not this one's.
            "tuned is-enabled: Failed to get unit file state for "
            "auditd.service: No such file or directory\n"
        )
        states = pf.parse_services(out)
        self.assertEqual(states["auditd"], {"enabled": error, "active": error})
        self.assertEqual(
            states["tuned"]["enabled"],
            "Failed to get unit file state for auditd.service: "
            "No such file or directory",
        )

    def test_refuse_manual_stop(self) -> None:
        self.assertTrue(
            pf.refuse_manual_stop("LoadState=loaded\nRefuseManualStop=yes\n")
        )
        self.assertFalse(
            pf.refuse_manual_stop("RefuseManualStop=no\nLoadState=loaded\n")
        )
        # A unit that is not loaded reports the default, which says nothing.
        self.assertIsNone(
            pf.refuse_manual_stop("LoadState=not-found\nRefuseManualStop=no\n")
        )

    def test_rpm(self) -> None:
        out = (
            "audit-4.1.4-1.fc44.x86_64\n"
            "package tuned is not installed\n"
            "package firewalld is not installed\n"
            "package abrt is not installed\n"
        )
        self.assertEqual(
            pf.parse_rpm(out),
            {
                "audit": "audit-4.1.4-1.fc44.x86_64",
                "tuned": None,
                "firewalld": None,
                "abrt": None,
            },
        )

    def test_a_package_named_after_another_is_not_it(self) -> None:
        out = "audit-libs-4.1.2-1.fc44.x86_64\npackage audit is not installed\n"
        self.assertIsNone(pf.parse_rpm(out)["audit"])

    def test_a_failed_rpm_is_kept_as_printed(self) -> None:
        # No package is absent just because rpm could not be asked.
        error = "bash: line 1: rpm: command not found"
        self.assertEqual(
            pf.parse_rpm(error + "\n"), {name: error for name in pf.RPM_PACKAGES}
        )

    def test_a_package_rpm_did_not_answer_for_holds_the_output(self) -> None:
        out = (
            "audit-4.1.4-1.fc44.x86_64\n"
            "error: rpmdb: damaged header #42 retrieved -- skipping.\n"
            "package firewalld is not installed\n"
            "package abrt is not installed\n"
        )
        packages = pf.parse_rpm(out)
        self.assertEqual(packages["audit"], "audit-4.1.4-1.fc44.x86_64")
        self.assertEqual(packages["tuned"], out.strip())
        self.assertIsNone(packages["firewalld"])
        self.assertIsNone(packages["abrt"])

    def test_packages_only_on_fedora(self) -> None:
        self.assertIsNone(pf.facts({}, "arch")["packages"])
        # A query that has not run reads as no package, not as absent ones.
        self.assertEqual(pf.facts({}, "fedora")["packages"], {})


class ImageFactsTest(unittest.TestCase):
    def test_tools_keep_only_the_ones_present(self) -> None:
        self.assertEqual(
            pf.parse_tools(FEDORA_TOOLS),
            {
                "systemctl": "/usr/bin/systemctl",
                "ip": "/usr/bin/ip",
                "kill": "/usr/bin/kill",
            },
        )

    def test_journald_default_from_the_vendor_comment(self) -> None:
        self.assertEqual(
            pf.parse_journald(FEDORA_JOURNALD),
            {"storage": "persistent", "sources": []},
        )

    def test_journald_setting_wins_with_its_file(self) -> None:
        out = FEDORA_JOURNALD + (
            "# /etc/systemd/journald.conf.d/50-volatile.conf\nStorage=volatile\n"
        )
        self.assertEqual(
            pf.parse_journald(out),
            {
                "storage": "volatile",
                "sources": ["/etc/systemd/journald.conf.d/50-volatile.conf"],
            },
        )

    def test_unit_names(self) -> None:
        self.assertEqual(
            pf.unit_names(FEDORA_MASKED),
            [
                "serial-getty@hvc0.service",
                "serial-getty@ttyS0.service",
                "ssh.service",
                "ssh.socket",
            ],
        )
        failed = "● grub-boot-success.service loaded failed failed Mark\n"
        self.assertEqual(pf.unit_names(failed), ["grub-boot-success.service"])
        self.assertEqual(pf.unit_names(""), [])

    def test_prune_paths(self) -> None:
        out = (
            'PRUNEPATHS = "/afs /media /tmp"\n'
            '# PRUNEPATHS = "/ignored"\n'
            'PRUNEPATHS="/tmp /var/spool"\n'
            "updatedb: /usr/bin/updatedb\n"
        )
        self.assertEqual(
            pf.prune_paths(out), ["/afs", "/media", "/tmp", "/var/spool"]
        )
        self.assertEqual(pf.prune_paths("updatedb:\nplocate:\nlocate:\n"), [])

    def test_nine_p_reads_only_where_enforcing(self) -> None:
        self.assertTrue(pf.nine_p_reads(ENFORCING_NINEP))
        self.assertFalse(pf.nine_p_reads(ENFORCING_NINEP.replace("read-ok", "x")))
        enforcing = pf.facts(
            {"selinux": "Enforcing\n", "ninep": ENFORCING_NINEP}, "fedora"
        )
        self.assertTrue(enforcing["ninePUnderEnforcing"])
        permissive = pf.facts(
            {"selinux": "Permissive\n", "ninep": ENFORCING_NINEP}, "fedora"
        )
        self.assertIsNone(permissive["ninePUnderEnforcing"])

    def test_derivative_os_release(self) -> None:
        self.assertEqual(pf.derivative_os_release(FEDORA_OS_RELEASE, "fedora"), {})
        derivative = 'ID=endeavouros\nID_LIKE="arch"\nNAME="EndeavourOS"\n'
        self.assertEqual(
            pf.derivative_os_release(derivative, "arch"),
            {"ID": "endeavouros", "ID_LIKE": "arch"},
        )

    def test_soft_reboots(self) -> None:
        out = "1a000a8e-fa19-46b8-af38-c098712a40e9\n1\n"
        self.assertEqual(pf.soft_reboots(out), 1)
        self.assertIsNone(pf.soft_reboots(None))


class RecordTest(unittest.TestCase):
    def test_arch_run(self) -> None:
        blocks = {
            "os-release": ARCH_OS_RELEASE,
            "selinux": ARCH_SELINUX,
            "backdoor": ARCH_BACKDOOR,
            "kernel": "7.2.7-arch1-1\n",
            "modules": "7.2.7-arch1-1\n",
            "fstab": ARCH_FSTAB,
            "selinux-labels": "? /\n? /run\n? /run/systemd\n",
            "selinux-policy": "",
            "avcs": "Error opening /var/log/audit/audit.log (No such file)\n",
            "soft-reboot-boot-id": "d96469ba-c50e-4a65-bbc8-be6a8fc3dce6\n1\n",
            "soft-reboot-failed-units": "",
        }
        document = pf.record(
            blocks,
            image="arch-boxes",
            os_id="arch",
            enforcing=False,
            image_file="Arch-Linux-x86_64-basic.qcow2",
        )
        self.assertEqual(
            list(document),
            ["image", "osId", "enforcing", "imageFile", "recorded", "facts"],
        )
        self.assertTrue(document["recorded"])
        facts = document["facts"]
        self.assertIsNone(facts["selinuxMode"])
        self.assertIsNone(facts["selinuxBackdoorDomain"])
        # Without SELinux the SELinux facts are null, not empty.
        for key in (
            "selinuxLabels",
            "selinuxPolicyLoads",
            "selinuxLabelsAfterSoftReboot",
            "selinuxPolicyLoadsAfterSoftReboot",
        ):
            self.assertIsNone(facts[key], key)
        self.assertEqual(facts["kernelRelease"], "7.2.7-arch1-1")
        self.assertEqual(facts["moduleDirs"], ["7.2.7-arch1-1"])
        self.assertEqual(facts["fstab"], pf.parse_fstab(ARCH_FSTAB))
        self.assertEqual(facts["avcs"], [])
        self.assertEqual(facts["softRebootsCount"], 1)
        self.assertEqual(facts["failedUnitsAfterSoftReboot"], [])

    def test_policy_loads_after_the_soft_reboot(self) -> None:
        cold = "[  4.35] systemd[1]: Successfully loaded SELinux policy in 105ms.\n"
        after = cold + (
            "[ 12.17] systemd[1]: Failed to load new SELinux policy. "
            "Continuing with old policy.\n"
        )
        blocks = {
            "selinux": "Enforcing\n",
            "selinux-policy": cold,
            "soft-reboot-selinux-policy": after,
        }
        facts = pf.facts(blocks, "fedora")
        self.assertEqual(
            facts["selinuxPolicyLoads"],
            ["systemd[1]: Successfully loaded SELinux policy."],
        )
        self.assertEqual(
            facts["selinuxPolicyLoadsAfterSoftReboot"],
            [
                "systemd[1]: Failed to load new SELinux policy. "
                "Continuing with old policy."
            ],
        )

    def test_placeholder_has_every_fact(self) -> None:
        placeholder = pf.record(
            {},
            image="fedora-45",
            os_id="fedora",
            enforcing=False,
            image_file=None,
            recorded=False,
        )
        self.assertFalse(placeholder["recorded"])
        self.assertEqual(
            list(placeholder["facts"]),
            list(pf.facts({"selinux": "Enforcing\n"}, "fedora")),
        )

    def test_dumps_ends_with_a_newline(self) -> None:
        text = pf.dumps({"a": [], "b": {}})
        self.assertEqual(text, '{\n  "a": [],\n  "b": {}\n}\n')


class FixtureTest(unittest.TestCase):
    """Every committed fixture is a record the probe could have written."""

    def fixtures(self) -> list[Path]:
        paths = sorted(FIXTURES.glob("*.json"))
        self.assertTrue(paths, f"no fixture in {FIXTURES}")
        return paths

    def test_each_fixture_keeps_the_schema(self) -> None:
        empty = pf.record({}, image="", os_id="", enforcing=False, image_file=None)
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(list(document), list(empty))
                self.assertEqual(list(document["facts"]), list(empty["facts"]))
                self.assertIsInstance(document["enforcing"], bool)
                self.assertIsInstance(document["recorded"], bool)

    def test_each_fixture_is_named_after_its_probe(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                name = pf.probe_name(document["image"], document["enforcing"])
                self.assertEqual(path.name, f"{name}.json")

    def test_each_fixture_is_written_as_the_probe_writes_it(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(text, pf.dumps(json.loads(text)))

    def test_a_recorded_fixture_names_its_image_file(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                if document["recorded"]:
                    self.assertTrue(document["imageFile"])


if __name__ == "__main__":
    unittest.main()
