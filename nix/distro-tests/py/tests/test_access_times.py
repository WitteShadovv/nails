"""Unit tests for the access-time scenario's two halves.

``access_times`` decides which reads of the decoy disk are NAILS' own, and
``atime_walk`` ages and lists the disk in the guest. A rule that drifts here
would let a read through as the decoy's own, a false pass, or flag one a plain
soft-reboot makes. ``atime_walk`` runs here on a temporary tree; the
directory's own filesystem decides whether reads update access times, so the
tests set the times themselves.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import access_times as at
import atime_walk as walk

REF = 1_000_000_000_000


def stamp(path: str, atime: int, ctime: int = REF - 5, kind: str = "f") -> at.Stamp:
    return at.Stamp(path=path, atime=atime, ctime=ctime, mtime=0, kind=kind)


class ParseTest(unittest.TestCase):
    def test_a_listing_reads_back_as_its_stamps(self) -> None:
        text = json.dumps(
            {
                "walked": 12,
                "ref": REF,
                "entries": [["/usr/bin/ip", REF + 7, REF - 9, 0, "f"]],
            }
        )
        listing = at.parse_listing(text)
        self.assertEqual(listing.walked, 12)
        self.assertEqual(listing.ref, REF)
        self.assertEqual(listing.stamps, (stamp("/usr/bin/ip", REF + 7, REF - 9),))

    def test_the_shell_clock_reads_with_either_decimal_point(self) -> None:
        self.assertEqual(at.parse_epoch_ns("1731700000.123456\n"), 1731700000123456000)
        self.assertEqual(at.parse_epoch_ns("1731700000,000001"), 1731700000000001000)

    def test_busctl_microseconds_become_nanoseconds(self) -> None:
        self.assertEqual(
            at.parse_busctl_times("t 1731700000123456\nt 7\nx 9\n"),
            [1731700000123456000, 7000],
        )


class ReadsTest(unittest.TestCase):
    def test_only_an_entry_read_and_not_changed_since_the_reference_is_a_read(
        self,
    ) -> None:
        read = stamp("/usr/bin/nft", REF + 1)
        written = stamp("/var/lib/x", REF + 1, ctime=REF + 1)
        before = stamp("/usr/bin/env", REF)
        listing = at.Listing(walked=3, ref=REF, stamps=(read, written, before))
        self.assertEqual(at.reads_since(listing), [read])


class JudgeTest(unittest.TestCase):
    def setUp(self) -> None:
        reads = [
            stamp("/usr/bin/lvm", REF + 10),
            stamp("/usr/lib/systemd/systemd", REF + 19),
            stamp("/usr/lib/systemd/system-generators/g", REF + 30),
        ]
        self.control = at.control_of(reads, userspace=REF + 20)

    def test_a_control_splits_at_its_userspace_start(self) -> None:
        self.assertEqual(
            self.control.stop, {"/usr/bin/lvm", "/usr/lib/systemd/systemd"}
        )
        self.assertEqual(self.control.start, {"/usr/lib/systemd/system-generators/g"})

    def test_every_read_of_check_is_a_finding(self) -> None:
        self.assertEqual(
            at.judge_check([stamp("/usr/bin/busctl", REF + 1)]),
            [at.Finding(at.CHECK, "/usr/bin/busctl", REF + 1, "f")],
        )

    def test_the_way_in_may_read_only_what_the_decoy_s_stop_reads(self) -> None:
        reads = [
            stamp("/usr/bin/lvm", REF + 2),
            stamp("/usr/bin/ip", REF + 3),
            # A generator the decoy's start runs is no stop's read: run before
            # the switch it dates a reload to the activation.
            stamp("/usr/lib/systemd/system-generators/g", REF + 4),
        ]
        self.assertEqual(
            at.judge_flow(reads, way_back=REF + 100, control=self.control),
            [
                at.Finding(at.WAY_IN, "/usr/bin/ip", REF + 3, "f"),
                at.Finding(
                    at.WAY_IN, "/usr/lib/systemd/system-generators/g", REF + 4, "f"
                ),
            ],
        )

    def test_the_way_back_may_read_what_the_decoy_s_stop_or_start_reads(
        self,
    ) -> None:
        reads = [
            stamp("/usr/lib/systemd/systemd", REF + 101),
            stamp("/usr/lib/systemd/system-generators/g", REF + 102),
            stamp("/usr/sbin/nft", REF + 103),
        ]
        self.assertEqual(
            at.judge_flow(reads, way_back=REF + 100, control=self.control),
            [at.Finding(at.WAY_BACK, "/usr/sbin/nft", REF + 103, "f")],
        )

    def test_controls_merge_by_point(self) -> None:
        other = at.Control(stop=frozenset({"/a"}), start=frozenset({"/b"}))
        merged = at.merge([self.control, other])
        self.assertIn("/a", merged.stop)
        self.assertIn("/b", merged.start)
        self.assertNotIn("/a", merged.start)

    def test_links_are_findings_of_their_own(self) -> None:
        link = at.Finding(at.CHECK, "/etc/os-release", REF + 1, "l")
        program = at.Finding(at.WAY_IN, "/usr/bin/nft", REF + 2, "f")
        folder = at.Finding(at.WAY_IN, "/etc/modprobe.d", REF + 3, "d")
        self.assertEqual(
            at.split_links([link, program, folder]), ([program, folder], [link])
        )

    def test_udevd_s_listings_are_findings_of_their_own(self) -> None:
        rules = at.Finding(at.CHECK, "/usr/lib/udev/rules.d", REF + 1, "d")
        links = at.Finding(at.CHECK, "/etc/systemd/network", REF + 1, "d")
        rule = at.Finding(at.CHECK, "/usr/lib/udev/rules.d/60-block.rules", REF, "f")
        other = at.Finding(at.WAY_IN, "/etc/udev", REF + 2, "d")
        self.assertEqual(
            at.split_udevd([rules, links, rule, other]),
            ([rule, other], [rules, links]),
        )

    def test_a_finding_names_the_step_before_it(self) -> None:
        finding = at.Finding(at.WAY_IN, "/usr/bin/ip", REF + 3, "f")
        text = at.describe([finding], [("stop", REF + 9), ("activate", REF + 1)])
        self.assertIn("/usr/bin/ip (f)", text)
        self.assertTrue(text.endswith("after activate"), text)
        self.assertEqual(
            at.as_json([finding]),
            [
                {
                    "window": "way in",
                    "path": "/usr/bin/ip",
                    "atime": REF + 3,
                    "kind": "f",
                }
            ],
        )


class WalkTest(unittest.TestCase):
    def test_mountinfo_fields_are_unescaped(self) -> None:
        line = "36 1 254:1 / /mnt/a\\040b rw,relatime shared:1 - ext4 /dev/vd\\134a1 rw"
        self.assertEqual(
            walk.parse_mountinfo(line + "\nbroken\n"),
            [("/mnt/a b", "ext4", "/dev/vd\\a1")],
        )

    def test_a_walk_lists_its_root_and_stays_out_of_covered_directories(self) -> None:
        with tempfile.TemporaryDirectory() as top:
            os.makedirs(os.path.join(top, "a", "b"))
            os.makedirs(os.path.join(top, "covered", "inside"))
            open(os.path.join(top, "a", "b", "f"), "w").close()
            os.symlink("a", os.path.join(top, "link"))
            seen = {
                path: walk.kind(st.st_mode)
                for path, st in walk.walk(
                    top, frozenset({os.path.join(top, "covered")})
                )
            }
        self.assertEqual(seen[top], "d")
        self.assertEqual(seen[os.path.join(top, "a", "b", "f")], "f")
        self.assertEqual(seen[os.path.join(top, "link")], "l")
        self.assertNotIn(os.path.join(top, "covered"), seen)
        self.assertNotIn(os.path.join(top, "covered", "inside"), seen)

    def test_a_skipped_directory_is_neither_aged_nor_listed(self) -> None:
        with tempfile.TemporaryDirectory() as top:
            tools = os.path.join(top, "tools")
            os.makedirs(tools)
            open(os.path.join(tools, "helper"), "w").close()
            aged = walk.age(2 * 86400, [top], frozenset({tools}))
            self.assertEqual(aged["aged"], 1)
            listed = walk.listing(0, [top], frozenset({tools}))
        self.assertEqual(listed["walked"], 1)

    def test_an_aged_tree_lists_only_what_was_read_after_the_reference(self) -> None:
        with tempfile.TemporaryDirectory() as top:
            old = os.path.join(top, "old")
            new = os.path.join(top, "new")
            for path in (old, new):
                with open(path, "w") as handle:
                    handle.write("x")
            os.symlink("old", os.path.join(top, "link"))
            mtime = os.lstat(old).st_mtime_ns
            aged = walk.age(2 * 86400, [top])
            self.assertEqual((aged["aged"], aged["failed"]), (4, 0))
            self.assertEqual(os.lstat(old).st_mtime_ns, mtime)
            ref = os.lstat(old).st_atime_ns + 1
            os.utime(new, ns=(ref + 5, os.lstat(new).st_mtime_ns))
            listed = at.parse_listing(json.dumps(walk.listing(ref, [top])))
        self.assertEqual(listed.walked, 4)
        self.assertEqual([s.path for s in listed.stamps], [new])


if __name__ == "__main__":
    unittest.main()
