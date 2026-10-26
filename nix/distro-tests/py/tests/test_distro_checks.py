"""Unit tests for the portable distribution scenarios' distro-aware helpers.

These run in the fast lane (`python3 -m unittest`, no VM) and lock the rules
the scenarios depend on: where a hidden write lands, which boot filesystems to
check, when an overlay's feature options are wrong, and what a refused run
changed. A silent drift here would turn a real leak, a mounted-writable boot
partition or a write before a refusal into a false pass on some distribution.
"""

from __future__ import annotations

import json
import re
import unittest

import distro_checks as dc


class EscapePathTest(unittest.TestCase):
    def test_simple_mount_point(self) -> None:
        self.assertEqual(dc.escape_path("/home"), "home")

    def test_nested_mount_point_uses_dashes(self) -> None:
        self.assertEqual(dc.escape_path("/boot/efi"), "boot-efi")

    def test_dot_and_trailing_slash_are_simplified(self) -> None:
        # Mirrors the Rust layout test: /srv/./share/ -> srv-share.
        self.assertEqual(dc.escape_path("/srv/./share/"), "srv-share")

    def test_root_is_a_single_dash(self) -> None:
        self.assertEqual(dc.escape_path("/"), "-")

    def test_leading_parent_of_absolute_path_is_dropped(self) -> None:
        self.assertEqual(dc.escape_path("/../var"), "var")

    def test_dash_component_is_hex_escaped(self) -> None:
        # A literal dash is not in the kept set, so it is escaped, unlike the
        # separator dash produced from a slash.
        self.assertEqual(dc.escape_path("/a-b"), "a\\x2db")

    def test_leading_dot_component_is_hex_escaped(self) -> None:
        self.assertEqual(dc.escape_path("/.secret"), "\\x2esecret")

    def test_dot_inside_a_component_is_kept(self) -> None:
        self.assertEqual(dc.escape_path("/boot.efi"), "boot.efi")

    def test_non_ascii_byte_is_escaped_per_utf8_byte(self) -> None:
        self.assertEqual(dc.escape_path("/é"), "\\xc3\\xa9")


class CanaryNameTest(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(dc.canary_name("usr"), "nails-canary-usr")


class ParseMountTargetsTest(unittest.TestCase):
    def test_one_target_per_line_blank_lines_dropped(self) -> None:
        out = "/\n/boot/efi\n\n/run/tools\n"
        self.assertEqual(
            dc.parse_mount_targets(out), ["/", "/boot/efi", "/run/tools"]
        )

    def test_empty_output(self) -> None:
        self.assertEqual(dc.parse_mount_targets(""), [])


class ParseFindmntPairsTest(unittest.TestCase):
    def test_target_and_options_split_on_first_space(self) -> None:
        out = "/ rw,lowerdir=/x,upperdir=/u,redirect_dir=nofollow\n"
        self.assertEqual(
            dc.parse_findmnt_pairs(out),
            [("/", "rw,lowerdir=/x,upperdir=/u,redirect_dir=nofollow")],
        )

    def test_missing_options_is_empty_string(self) -> None:
        self.assertEqual(dc.parse_findmnt_pairs("/home\n"), [("/home", "")])

    def test_blank_lines_dropped(self) -> None:
        self.assertEqual(dc.parse_findmnt_pairs("\n\n"), [])


class ContainingMountTest(unittest.TestCase):
    def test_root_when_no_other_mount_contains_it(self) -> None:
        self.assertEqual(dc.containing_mount("/home", ["/", "/boot/efi"]), "/")

    def test_own_mount_wins_over_root(self) -> None:
        self.assertEqual(dc.containing_mount("/home", ["/", "/home"]), "/home")

    def test_deepest_mount_wins(self) -> None:
        mounts = ["/", "/var", "/var/log"]
        self.assertEqual(dc.containing_mount("/var/log/x", mounts), "/var/log")

    def test_prefix_that_is_not_a_path_boundary_does_not_match(self) -> None:
        # /varlib must not be taken to lie on the /var mount.
        self.assertEqual(dc.containing_mount("/varlib", ["/", "/var"]), "/")


class CanaryUpperTest(unittest.TestCase):
    def test_tree_on_the_root_filesystem(self) -> None:
        # The single-root case (Debian/Ubuntu cloud images): byte-identical to
        # the path the scenario checked before it became mount-aware.
        self.assertEqual(
            dc.canary_upper("/mnt/data", "home", ["/", "/boot/efi"]),
            "/mnt/data/root/upper/home/nails-canary-home",
        )

    def test_tree_that_is_a_separate_filesystem(self) -> None:
        # The btrfs case (Fedora/Arch): /home is its own subvolume mount, so its
        # overlay upper is named after the mount unit, matching the Rust layout.
        self.assertEqual(
            dc.canary_upper("/mnt/data", "home", ["/", "/home"]),
            "/mnt/data/root/mounts/home/upper/nails-canary-home",
        )

    def test_hidden_root_trailing_slash_is_normalised(self) -> None:
        self.assertEqual(
            dc.canary_upper("/mnt/data/", "var", []),
            "/mnt/data/root/upper/var/nails-canary-var",
        )

    def test_every_default_tree_on_a_single_root_matches_the_old_paths(self) -> None:
        trees = ("home", "etc", "srv", "opt", "var", "usr", "root")
        for tree in trees:
            self.assertEqual(
                dc.canary_upper("/mnt/data", tree, ["/", "/boot/efi"]),
                f"/mnt/data/root/upper/{tree}/nails-canary-{tree}",
            )


class BootMountsTest(unittest.TestCase):
    def test_subset_in_declaration_order(self) -> None:
        mounts = ["/", "/efi", "/boot", "/home"]
        self.assertEqual(dc.boot_mounts(mounts), ["/boot", "/efi"])

    def test_esp_only(self) -> None:
        self.assertEqual(dc.boot_mounts(["/", "/boot/efi"]), ["/boot/efi"])

    def test_none_mounted(self) -> None:
        self.assertEqual(dc.boot_mounts(["/", "/home"]), [])


class OverlayOptionsTest(unittest.TestCase):
    def test_pinned_off_states_are_clean(self) -> None:
        opts = "rw,lowerdir=/x,upperdir=/u,index=off,metacopy=off,redirect_dir=nofollow"
        self.assertEqual(dc.overlay_option_violations(opts), [])

    def test_the_pin_alone_is_clean_where_index_and_metacopy_default_off(
        self,
    ) -> None:
        # Debian's and Ubuntu's kernels default index and metacopy to off, so
        # only the redirect pin is echoed.
        opts = "rw,lowerdir=/x,upperdir=/u,redirect_dir=nofollow"
        self.assertEqual(dc.overlay_option_violations(opts), [])

    def test_an_overlay_mounted_without_the_pins_is_caught(self) -> None:
        # Without the pins a kernel echoes no feature option at all: its own
        # defaults (follow on Debian and Ubuntu, on for Arch) are in force, and
        # only the missing redirect pin shows it.
        self.assertEqual(
            dc.overlay_option_violations("rw,lowerdir=/x,upperdir=/u,uuid=on"),
            ["missing redirect_dir=nofollow"],
        )

    def test_each_forbidden_on_state_is_reported(self) -> None:
        opts = "rw,index=on,metacopy=on,redirect_dir=follow"
        self.assertEqual(
            dc.overlay_option_violations(opts),
            [
                "index=on",
                "metacopy=on",
                "redirect_dir=follow",
                "missing redirect_dir=nofollow",
            ],
        )

    def test_redirect_dir_on_is_forbidden(self) -> None:
        # Echoed on Debian and Ubuntu, whose default is follow.
        self.assertEqual(
            dc.overlay_option_violations("rw,upperdir=/u,redirect_dir=on"),
            ["redirect_dir=on", "missing redirect_dir=nofollow"],
        )

    def test_substring_of_an_option_does_not_false_match(self) -> None:
        # "redirect_dir=nofollow" must not be read as "redirect_dir=follow".
        self.assertEqual(
            dc.overlay_option_violations("redirect_dir=nofollow"), []
        )

    def test_targets_with_violations_maps_only_the_bad_overlays(self) -> None:
        pairs = [
            ("/", "rw,upperdir=/u,redirect_dir=nofollow"),
            ("/home", "rw,upperdir=/h,index=on,redirect_dir=nofollow"),
        ]
        self.assertEqual(
            dc.overlay_targets_with_violations(pairs), {"/home": ["index=on"]}
        )


class NailsOverlaysTest(unittest.TestCase):
    ROOT = (
        "rw,lowerdir=/run/x,upperdir=/mnt/data/root/upper,"
        "workdir=/mnt/data/root/work"
    )
    HOME = (
        "rw,lowerdir=/run/h,upperdir=/mnt/data/root/mounts/home/upper,"
        "workdir=/mnt/data/root/mounts/home/work"
    )

    def test_the_root_and_per_mount_overlays_are_nails(self) -> None:
        pairs = [
            ("/", self.ROOT),
            ("/home", self.HOME),
            # An overlay of the image's own, such as a store mounted by the
            # test harness: not NAILS's to pin.
            ("/nix/store", "ro,lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/s"),
            ("/srv/ro", "ro,lowerdir=/a:/b"),
        ]
        self.assertEqual(
            dc.nails_overlays(pairs, "/mnt/data/"),
            [("/", self.ROOT), ("/home", self.HOME)],
        )

    def test_an_upper_beside_the_layer_directories_is_not_nails(self) -> None:
        # Only the layer directories count, not anything that shares a prefix.
        pairs = [
            ("/a", "rw,upperdir=/mnt/data/root/upper2"),
            ("/b", "rw,upperdir=/mnt/data/root/mountsx/u"),
            ("/c", "rw,upperdir=/mnt/database/root/upper"),
        ]
        self.assertEqual(dc.nails_overlays(pairs, "/mnt/data"), [])

    def test_upperdir_reads_the_option(self) -> None:
        self.assertEqual(dc.upperdir(self.ROOT), "/mnt/data/root/upper")
        self.assertIsNone(dc.upperdir("ro,lowerdir=/a:/b"))


def listing_line(path: str, *, dev: str = "2049", **fields: str) -> str:
    """One line of listing_command output, with plausible defaults."""
    values = {
        "type": "f",
        "mode": "644",
        "uid": "0",
        "gid": "0",
        "size": "4",
        "inode": "12",
        "mtime": "1700000000.1000000000",
        "ctime": "1700000000.1000000000",
    }
    values.update(fields)
    return "\t".join([dev, *(values[name] for name in dc.LISTING_FIELDS), path])


class ListingCommandTest(unittest.TestCase):
    def test_keeps_to_the_root_filesystem(self) -> None:
        command = dc.listing_command("/mnt/data")
        self.assertTrue(command.startswith("find /mnt/data -xdev -printf '%D\\t%y"))
        self.assertIn("%T@\\t%C@\\t%p\\n'", command)
        # The device of the root itself, the first entry find prints, decides.
        self.assertIn("'NR == 1 { dev = $1 } $1 == dev'", command)
        self.assertNotIn("sha256sum", command)
        self.assertNotIn("|| true", command)

    def test_a_live_listing_tolerates_an_entry_that_goes_away(self) -> None:
        command = dc.listing_command("/var", live=True)
        self.assertTrue(command.startswith("{ find /var -xdev"))
        self.assertIn("|| true; } | awk", command)

    def test_hashes_follow_a_separator(self) -> None:
        command = dc.listing_command("/mnt/data", hashes=True)
        self.assertTrue(
            command.endswith(
                "; echo ---; find /mnt/data -xdev -type f -exec sha256sum -- {} +"
            )
        )

    def test_the_root_is_quoted(self) -> None:
        self.assertIn("find '/a b' -xdev", dc.listing_command("/a b"))


class ParseListingTest(unittest.TestCase):
    def test_entries_by_path_with_their_fields(self) -> None:
        text = "\n".join(
            (
                listing_line("/mnt/data", type="d", mode="755", size="4096"),
                listing_line("/mnt/data/config", type="d", mode="700"),
                "",
            )
        )
        entries = dc.parse_listing(text)
        self.assertEqual(sorted(entries), ["/mnt/data", "/mnt/data/config"])
        self.assertEqual(entries["/mnt/data"]["mode"], "755")
        self.assertEqual(entries["/mnt/data"]["size"], "4096")
        self.assertNotIn("sha256", entries["/mnt/data"])

    def test_hashes_attach_to_their_files(self) -> None:
        text = "\n".join(
            (
                listing_line("/mnt/data", type="d"),
                listing_line("/mnt/data/a"),
                "---",
                "ab12  /mnt/data/a",
            )
        )
        entries = dc.parse_listing(text)
        self.assertEqual(entries["/mnt/data/a"]["sha256"], "ab12")
        self.assertNotIn("sha256", entries["/mnt/data"])

    def test_a_path_with_a_tab_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            dc.parse_listing(listing_line("/mnt/data/a\tb"))

    def test_a_hash_of_an_unlisted_file_is_refused(self) -> None:
        text = "\n".join((listing_line("/mnt/data/a"), "---", "ab12  /mnt/data/b"))
        with self.assertRaises(ValueError):
            dc.parse_listing(text)


class ListingChangesTest(unittest.TestCase):
    BEFORE = {
        "/r": {"type": "d", "mtime": "1", "sha256": ""},
        "/r/kept": {"type": "f", "mtime": "1", "sha256": "aa"},
        "/r/gone": {"type": "f", "mtime": "1", "sha256": "bb"},
    }

    def test_identical_listings_have_no_change(self) -> None:
        self.assertEqual(dc.listing_changes(self.BEFORE, dict(self.BEFORE)), {})

    def test_added_removed_and_changed_paths(self) -> None:
        after = {
            "/r": {"type": "d", "mtime": "2", "sha256": ""},
            "/r/kept": {"type": "f", "mtime": "1", "sha256": "cc"},
            "/r/.lock": {"type": "f", "mtime": "2", "sha256": ""},
        }
        self.assertEqual(
            dc.listing_changes(self.BEFORE, after),
            {
                "/r": "changed: mtime",
                "/r/.lock": "added",
                "/r/gone": "removed",
                "/r/kept": "changed: sha256",
            },
        )

    def test_only_the_fields_asked_for_count(self) -> None:
        # A directory whose entries came and went: its times moved, but it
        # holds the same entries as before.
        after = dict(self.BEFORE)
        after["/r"] = {"type": "d", "mtime": "2", "sha256": ""}
        self.assertEqual(dc.listing_changes(self.BEFORE, after, ("type", "sha256")), {})

    def test_a_renumbered_inode_alone_is_no_change(self) -> None:
        # vfat numbers an inode afresh when it reads it back in; the times
        # still say whether anything was written.
        before = {"/boot/efi/x": {"inode": "7", "ctime": "1", "mtime": "1"}}
        after = {"/boot/efi/x": {"inode": "9", "ctime": "1", "mtime": "1"}}
        self.assertEqual(
            dc.listing_changes(before, after, dc.CHANGE_FIELDS), {}
        )
        self.assertEqual(
            dc.listing_changes(before, after, dc.ALL_FIELDS),
            {"/boot/efi/x": "changed: inode"},
        )

    def test_format_changes_is_one_line_per_path(self) -> None:
        self.assertEqual(
            dc.format_changes({"/r/.lock": "added", "/r": "changed: mtime"}),
            "/r/.lock: added\n/r: changed: mtime",
        )


class DecoyDiskMountsTest(unittest.TestCase):
    def test_fedora_subvolumes_and_its_esp(self) -> None:
        pairs = [
            ("/", "btrfs"),
            ("/proc", "proc"),
            ("/run", "tmpfs"),
            ("/boot", "btrfs"),
            ("/boot/efi", "vfat"),
            ("/home", "btrfs"),
            ("/var", "btrfs"),
            ("/nix/.ro-store", "9p"),
            ("/nix/store", "overlay"),
            ("/run/tools", "9p"),
            ("/mnt/data", "ext4"),
        ]
        self.assertEqual(
            dc.decoy_disk_mounts(pairs, "/mnt/data"),
            ["/", "/boot", "/boot/efi", "/home", "/var"],
        )

    def test_an_automounted_esp_is_left_out(self) -> None:
        # Arch's ESP at /efi: systemd's GPT generator mounts it on demand.
        pairs = [("/", "btrfs"), ("/efi", "autofs"), ("/efi", "vfat")]
        self.assertEqual(dc.decoy_disk_mounts(pairs, "/mnt/data"), ["/"])

    def test_nothing_on_or_below_the_hidden_root(self) -> None:
        pairs = [("/", "ext4"), ("/mnt/data/", "ext4"), ("/mnt/data/x", "ext4")]
        self.assertEqual(dc.decoy_disk_mounts(pairs, "/mnt/data/"), ["/"])

    def test_a_target_mounted_twice_is_listed_once(self) -> None:
        pairs = [("/", "btrfs"), ("/srv", "xfs"), ("/srv", "xfs")]
        self.assertEqual(dc.decoy_disk_mounts(pairs, "/mnt/data"), ["/", "/srv"])


class OutsideBootNoiseTest(unittest.TestCase):
    # The generic boot-noise allowlist of disk_forensics.image_volatile.
    VOLATILE = re.compile(
        r"^(var/|run/|tmp/|etc/machine-id|etc/resolv\.conf|etc/ssh/ssh_host_|"
        r"etc/\.(updated|clean))"
    )

    def test_changes_below_var_are_boot_noise(self) -> None:
        paths = ["/var/log/journal/x/system.journal", "/var/lib/systemd/random-seed"]
        self.assertEqual(dc.outside_boot_noise(paths, self.VOLATILE), [])

    def test_an_allowlisted_tree_covers_its_own_directory(self) -> None:
        self.assertEqual(dc.outside_boot_noise(["/var", "/tmp"], self.VOLATILE), [])

    def test_everything_else_is_left(self) -> None:
        paths = ["/root/nails.log", "/", "/etc/fstab", "/varnish", "/etc/machine-id"]
        self.assertEqual(
            dc.outside_boot_noise(paths, self.VOLATILE),
            ["/", "/etc/fstab", "/root/nails.log", "/varnish"],
        )


class NamedLikeNailsTest(unittest.TestCase):
    NAMES = ("state.json", "nails.log", "reports", ".lock")

    def test_a_registry_name_or_a_name_with_nails_in_it(self) -> None:
        paths = [
            "/var/lib/x/state.json",
            "/var/tmp/.lock",
            "/etc/NAILS-backup",
            "/var/log/journal/x/system.journal",
            "/var/lib/reports/",
            "/var/lib/reportsd",
        ]
        self.assertEqual(
            dc.named_like_nails(paths, self.NAMES),
            [
                "/etc/NAILS-backup",
                "/var/lib/reports/",
                "/var/lib/x/state.json",
                "/var/tmp/.lock",
            ],
        )

    def test_a_directory_on_the_path_does_not_count(self) -> None:
        # Only the last component is the name of what changed.
        self.assertEqual(dc.named_like_nails(["/nails/x"], self.NAMES), [])


class JournalTracesTest(unittest.TestCase):
    @staticmethod
    def entry(**fields: object) -> str:
        return json.dumps(fields)

    def test_the_unit_and_message_of_each_match(self) -> None:
        # systemd names a mount it saw go away by its unit only, the mount
        # point escaped; a process names itself in _EXE whatever it logs.
        unit = "mnt-data-.probe\\x2d1-merged.mount"
        text = "\n".join(
            (
                self.entry(MESSAGE="Started session.", _COMM="systemd"),
                self.entry(UNIT=unit, MESSAGE=f"{unit}: Deactivated successfully."),
                self.entry(
                    SYSLOG_IDENTIFIER="x", MESSAGE="refused", _EXE="/run/tools/nails"
                ),
                "",
            )
        )
        self.assertEqual(
            dc.journal_traces(text, ["nails", "/mnt/data", "mnt-data"]),
            [f"{unit}: {unit}: Deactivated successfully.", "x: refused"],
        )

    def test_case_is_ignored(self) -> None:
        text = self.entry(_COMM="kernel", MESSAGE="NAILS supports NixOS")
        self.assertEqual(
            dc.journal_traces(text, ["nails"]), ["kernel: NAILS supports NixOS"]
        )

    def test_a_field_stored_as_bytes_is_read(self) -> None:
        message = list(b"opened /mnt/data\xff")
        text = self.entry(SYSLOG_IDENTIFIER="y", MESSAGE=message)
        self.assertEqual(
            dc.journal_traces(text, ["/mnt/data"]), ["y: opened /mnt/data\xff"]
        )

    def test_no_match_and_an_empty_token_find_nothing(self) -> None:
        text = self.entry(MESSAGE="Reached target Multi-User System.")
        self.assertEqual(dc.journal_traces(text, ["nails", ""]), [])

    def test_journal_messages_lists_every_entry(self) -> None:
        text = "\n".join(
            (
                self.entry(_COMM="systemd", MESSAGE="Reached target Timers."),
                self.entry(MESSAGE="no process named"),
                "",
            )
        )
        self.assertEqual(
            dc.journal_messages(text),
            ["systemd: Reached target Timers.", "?: no process named"],
        )


class SplitCommTest(unittest.TestCase):
    def test_lines_only_after_holds_come_behind_a_tab(self) -> None:
        old = listing_line("/var/log/x", size="10")
        new = listing_line("/var/log/x", size="20")
        added = listing_line("/var/tmp/new")
        text = f"{old}\n\t{new}\n\t{added}\n"
        self.assertEqual(dc.split_comm(text), (old, f"{new}\n{added}"))

    def test_the_halves_read_back_as_listings(self) -> None:
        text = "\n".join(
            (
                listing_line("/etc/gone"),
                "\t" + listing_line("/var/log/x", size="20"),
                listing_line("/var/log/x", size="10"),
            )
        )
        before, after = (dc.parse_listing(half) for half in dc.split_comm(text))
        self.assertEqual(
            dc.listing_changes(before, after, dc.CHANGE_FIELDS),
            {"/etc/gone": "removed", "/var/log/x": "changed: size"},
        )

    def test_no_difference(self) -> None:
        self.assertEqual(dc.split_comm(""), ("", ""))


class ScanOffsetTest(unittest.TestCase):
    @staticmethod
    def file(size: str, inode: str = "5", kind: str = "f") -> dict[str, str]:
        return {"type": kind, "size": size, "inode": inode}

    def test_a_grown_log_is_read_past_its_old_end(self) -> None:
        before = {"/var/log/audit/audit.log": self.file("1000")}
        after = {"/var/log/audit/audit.log": self.file("1300")}
        self.assertEqual(
            dc.scan_offset(before, after, "/var/log/audit/audit.log"), 1000
        )

    def test_a_new_replaced_or_shrunk_file_is_read_from_the_start(self) -> None:
        after = {"/a": self.file("10")}
        for before in (
            {},
            {"/a": self.file("5", inode="4")},
            {"/a": self.file("50")},
            {"/a": self.file("10")},
        ):
            self.assertEqual(dc.scan_offset(before, after, "/a"), 0, before)

    def test_only_a_regular_file_is_read_from_an_offset(self) -> None:
        before = {"/d": self.file("10", kind="d")}
        after = {"/d": self.file("20", kind="d")}
        self.assertEqual(dc.scan_offset(before, after, "/d"), 0)


# The Ubuntu 26.04 caveat, as nails-platform/src/platform/family.rs words it.
CAVEAT_2604 = (
    "Ubuntu 26.04 is tested, but a known upstream issue affects it: after the"
    " switch into the hidden session, AppArmor blocks chrony (time sync) and CUPS"
    " (printing) from reaching systemd and the journal, so the clock does not sync"
    " and printing times out. After the way back the decoy lists chrony as failed"
    " until its next full reboot, which hints a soft-reboot happened; reboot the"
    " decoy fully after a session to clear it. The fault is upstream, not in NAILS,"
    " and remains until Ubuntu fixes it."
)

NOTIFY_LINE = "Could not send notification to $NOTIFY_SOCKET"

# The Ubuntu 26.04 entry's knownFailedUnits in images.json.
KNOWN_2604 = {
    "hiddenSession": {"chrony.service": NOTIFY_LINE},
    "afterReturn": {"chrony.service": NOTIFY_LINE},
    "notInImage": ["cups.service"],
}

EMPTY_TABLE: dict[str, object] = {
    "hiddenSession": {},
    "afterReturn": {},
    "notInImage": [],
}


class ParseFailedUnitsTest(unittest.TestCase):
    def test_the_first_field_of_each_line(self) -> None:
        # Ubuntu 26.04's first hidden session before GRUB's boot-record unit
        # was masked there, as systemd 259 lists it.
        out = (
            "chrony.service       loaded failed failed chrony, an NTP client/server\n"
            "grub2-common.service loaded failed failed"
            " Record successful boot for GRUB\n"
        )
        self.assertEqual(
            dc.parse_failed_units(out), {"chrony.service", "grub2-common.service"}
        )

    def test_no_failed_unit_prints_nothing(self) -> None:
        self.assertEqual(dc.parse_failed_units(""), set())
        self.assertEqual(dc.parse_failed_units("\n  \n"), set())

    def test_a_status_circle_is_not_a_unit(self) -> None:
        out = (
            "\u25cf chrony.service loaded failed failed chrony\n"
            "* cups.service loaded failed failed CUPS Scheduler\n"
        )
        self.assertEqual(dc.parse_failed_units(out), {"chrony.service", "cups.service"})


class FailedUnitMismatchTest(unittest.TestCase):
    def test_unexpected_and_missing_each_sorted(self) -> None:
        observed = {"z.service", "chrony.service", "a.mount"}
        expected = {
            "chrony.service": NOTIFY_LINE,
            "cups.service": "x",
            "b.service": "y",
        }
        self.assertEqual(
            dc.failed_unit_mismatch(observed, expected),
            (["a.mount", "z.service"], ["b.service", "cups.service"]),
        )

    def test_exactly_the_expected_units(self) -> None:
        self.assertEqual(
            dc.failed_unit_mismatch({"chrony.service"}, KNOWN_2604["hiddenSession"]),
            ([], []),
        )
        self.assertEqual(dc.failed_unit_mismatch(set(), {}), ([], []))


class UnitsNotNamedTest(unittest.TestCase):
    def test_the_stem_without_the_type_suffix(self) -> None:
        self.assertEqual(dc.unit_stem("chrony.service"), "chrony")
        self.assertEqual(dc.unit_stem("run-blk.mount"), "run-blk")
        self.assertEqual(dc.unit_stem("getty@tty1.service"), "getty@tty1")
        self.assertEqual(dc.unit_stem("no-suffix"), "no-suffix")

    def test_the_caveat_names_chrony_and_cups_in_any_case(self) -> None:
        self.assertEqual(
            dc.units_not_named(CAVEAT_2604, ["chrony.service", "cups.service"]), []
        )

    def test_the_units_it_does_not_name_in_their_order(self) -> None:
        self.assertEqual(
            dc.units_not_named(
                CAVEAT_2604, ["cups-browsed.service", "chrony.service", "avahi.socket"]
            ),
            ["cups-browsed.service", "avahi.socket"],
        )


class MessagesSinceTest(unittest.TestCase):
    @staticmethod
    def journal(*entries: tuple[str, str]) -> str:
        return "\n".join(
            json.dumps({"__MONOTONIC_TIMESTAMP": stamp, "MESSAGE": message})
            for stamp, message in entries
        )

    def test_what_the_unit_logged_from_its_latest_start_on(self) -> None:
        # chrony's start on the decoy, its stop at the switch, and its failed
        # start in the hidden session, as Ubuntu 26.04 logs them.
        text = self.journal(
            ("10245501", "Starting chrony.service - chrony, an NTP client/server..."),
            ("23627604", "chrony.service: Deactivated successfully."),
            ("27399638", "Starting chrony.service - chrony, an NTP client/server..."),
            ("27897456", f"Fatal error : {NOTIFY_LINE}"),
            ("27924618", "chrony.service: Failed with result 'exit-code'."),
        )
        self.assertEqual(
            dc.messages_since(text, 27399638),
            [
                "Starting chrony.service - chrony, an NTP client/server...",
                f"Fatal error : {NOTIFY_LINE}",
                "chrony.service: Failed with result 'exit-code'.",
            ],
        )
        self.assertEqual(dc.messages_since(text, 27924619), [])

    def test_an_entry_without_a_time_is_left_out(self) -> None:
        text = json.dumps({"MESSAGE": "no time"}) + "\n"
        self.assertEqual(dc.messages_since(text, 0), [])


class KnownFailureMessagesTest(unittest.TestCase):
    def test_a_gone_failure_asks_to_narrow_the_table_then_the_warning(self) -> None:
        message = dc.known_failure_gone(
            "chrony.service",
            "in the first hidden session",
            "ubuntu-26.04",
            "hiddenSession",
            ["cups.service"],
        )
        self.assertTrue(
            message.startswith(
                "chrony.service no longer fails in the first hidden session on"
                " ubuntu-26.04. The known upstream failure is gone there, probably"
                " fixed in a newer image. Remove it from"
                " knownFailedUnits.hiddenSession in nix/distro-tests/images.json."
                " The release's warning (the caveat in"
                " nails-platform/src/platform/family.rs and"
                " docs/decoy-requirements.md) also covers what this image does not"
                " install: cups.service."
            ),
            message,
        )
        self.assertTrue(
            message.endswith("Remove the warning only when all of it is shown fixed."),
            message,
        )

    def test_with_nothing_out_of_sight_the_warning_is_narrowed_at_once(self) -> None:
        message = dc.known_failure_gone("a.service", "after x", "n", "afterReturn", [])
        self.assertTrue(
            message.endswith(
                "Then narrow the release's warning (the caveat"
                " in nails-platform/src/platform/family.rs and"
                " docs/decoy-requirements.md)."
            ),
            message,
        )
        self.assertNotIn("does not install", message)

    def test_the_known_line_is_found_in_any_message(self) -> None:
        messages = ["Starting chrony.service...", f"Fatal error : {NOTIFY_LINE}"]
        self.assertIsNone(
            dc.failure_not_known("chrony.service", "w", "n", NOTIFY_LINE, messages)
        )

    def test_another_failure_names_what_was_logged(self) -> None:
        problem = dc.failure_not_known(
            "chrony.service",
            "on the decoy after deactivate",
            "ubuntu-26.04",
            NOTIFY_LINE,
            ["Fatal error : Could not open command socket"],
        )
        assert problem is not None
        self.assertIn("so it fails in another way", problem)
        self.assertTrue(
            problem.endswith("It logged:\nFatal error : Could not open command socket"),
            problem,
        )
        problem = dc.failure_not_known("a.service", "w", "n", NOTIFY_LINE, [])
        assert problem is not None
        self.assertTrue(problem.endswith("It logged:\nnothing"), problem)

    def test_a_unit_now_in_the_image(self) -> None:
        self.assertIn(
            "cups.service is now in the ubuntu-26.04 image, so this test can observe"
            " it. Move it from notInImage",
            dc.now_in_image("cups.service", "ubuntu-26.04"),
        )

    def test_unexpected_failures_are_named(self) -> None:
        self.assertTrue(
            dc.unexpected_failures(
                "in the second hidden session",
                "ubuntu-24.04",
                ["a.service", "b.service"],
            ).startswith(
                "units failed in the second hidden session that knownFailedUnits does"
                " not expect on ubuntu-24.04: a.service, b.service."
            )
        )


class PlatformRowProblemTest(unittest.TestCase):
    @staticmethod
    def row(status: str, message: str) -> dict[str, str]:
        return {"name": "platform", "status": status, "message": message}

    def test_the_caveat_covers_the_listed_units(self) -> None:
        self.assertEqual(
            dc.listed_units(KNOWN_2604), ["chrony.service", "cups.service"]
        )
        self.assertIsNone(
            dc.platform_row_problem(
                self.row("warn", CAVEAT_2604), KNOWN_2604, "ubuntu-26.04"
            )
        )

    def test_a_row_that_passes_or_is_missing_does_not(self) -> None:
        for row, it_is in (
            (self.row("pass", "Ubuntu 26.04"), "pass: 'Ubuntu 26.04'"),
            (None, "missing: ''"),
        ):
            with self.subTest(row=row):
                self.assertEqual(
                    dc.platform_row_problem(row, KNOWN_2604, "ubuntu-26.04"),
                    "the platform row on ubuntu-26.04 must warn and name"
                    " chrony.service, cups.service while knownFailedUnits lists"
                    f" them, but it is {it_is}. Keep that part of the caveat until"
                    " the unit is shown fixed and removed from the table.",
                )

    def test_a_warning_that_drops_a_listed_unit_does_not(self) -> None:
        narrowed = CAVEAT_2604.replace(" and CUPS (printing)", "")
        problem = dc.platform_row_problem(
            self.row("warn", narrowed), KNOWN_2604, "ubuntu-26.04"
        )
        assert problem is not None
        self.assertTrue(
            problem.startswith(
                "the platform row on ubuntu-26.04 must warn and name cups.service while"
            ),
            problem,
        )

    def test_a_warning_broader_than_the_table_is_fine(self) -> None:
        # chrony fixed upstream and out of the table, CUPS still unseen: the
        # caveat may still name both.
        known = {"hiddenSession": {}, "afterReturn": {}, "notInImage": ["cups.service"]}
        self.assertIsNone(
            dc.platform_row_problem(self.row("warn", CAVEAT_2604), known, "n")
        )

    def test_an_empty_table_asks_nothing_of_the_row(self) -> None:
        for row in (
            self.row("pass", "Ubuntu 24.04"),
            self.row("warn", "Ubuntu 26.10 is not a release NAILS has been tested on"),
            None,
        ):
            with self.subTest(row=row):
                self.assertIsNone(dc.platform_row_problem(row, EMPTY_TABLE, "n"))


if __name__ == "__main__":
    unittest.main()
