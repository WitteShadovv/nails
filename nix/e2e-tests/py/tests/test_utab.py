"""Host-side tests for the utab checks, on mount tables of the test VMs."""

from __future__ import annotations

import unittest

from nails_e2e import utab

#: The hidden session of a re-entry that hung: the decoy's initrd lines (IDs 62
#: to 85) were carried from before the first entry, and the decoy wrote the
#: line on ID 26 for its /nix/.rw-store after the first way back. The hidden
#: root's /run/wrappers got ID 26 while systemd mounted it, and libmount joined
#: the line to it: systemd took it for an initrd mount and dropped
#: local-fs.target's order on it.
HUNG_UTAB = """\
ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount
ID=65 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount
ID=68 SRC=tmpfs TARGET=/sysroot/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
ID=77 SRC=shared TARGET=/sysroot/tmp/shared ROOT=/ OPTS=x-initrd.mount
ID=80 SRC=xchg TARGET=/sysroot/tmp/xchg ROOT=/ OPTS=x-initrd.mount
ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount
ID=26 SRC=tmpfs TARGET=/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
ID=22 SRC=tmpfs TARGET=/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
"""

HUNG_MOUNTINFO = """\
117 1 0:54 / / rw,relatime shared:1 - overlay overlay rw
291 117 0:57 / /nix/.ro-store rw,relatime shared:2 - overlay overlay rw
300 117 0:60 / /nix/store rw,relatime shared:3 - overlay overlay rw
309 117 0:63 / /tmp/shared rw,relatime shared:4 - overlay overlay rw
318 117 0:66 / /tmp/xchg rw,relatime shared:5 - overlay overlay rw
61 117 254:0 / /mnt/data rw,relatime shared:6 - ext4 /dev/mapper/data rw
325 61 0:30 / /mnt/data/root/decoy/nix-.ro\\134x2dstore ro - virtiofs nix-store ro
329 117 0:25 / /run rw,nosuid,nodev shared:11 - tmpfs tmpfs rw,mode=755
31 117 0:6 / /dev rw,nosuid shared:13 - devtmpfs devtmpfs rw,mode=755
44 31 0:26 / /dev/hugepages rw,relatime shared:16 - hugetlbfs hugetlbfs rw
58 329 0:25 /credentials /run/credentials rw,nosuid,nodev shared:12 - tmpfs tmpfs rw
22 117 0:27 / /nix/.rw-store rw,relatime shared:28 - tmpfs tmpfs rw,mode=755
26 329 0:41 / /run/wrappers rw,nodev,relatime shared:101 - tmpfs tmpfs rw,mode=755
"""

#: The decoy before the first entry: the initrd's lines for the root and the
#: store, the store's read-only bind over its overlay, and /run/wrappers.
DECOY_MOUNTINFO = """\
62 1 253:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
65 62 0:30 / /nix/.ro-store ro,relatime shared:2 - 9p nix-store rw
68 62 0:31 / /nix/.rw-store rw,relatime shared:3 - tmpfs tmpfs rw,mode=755
85 62 0:32 / /nix/store rw,relatime shared:4 - overlay overlay rw
41 85 0:32 / /nix/store ro,nosuid,nodev,relatime shared:4 - overlay overlay rw
26 62 0:41 / /run/wrappers rw,nodev,relatime shared:9 - tmpfs tmpfs rw,mode=755
"""

DECOY_UTAB = """\
ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount
ID=65 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount
ID=68 SRC=tmpfs TARGET=/sysroot/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount
"""

#: The decoy after a way back: its root, /nix/.ro-store and the store are back
#: under new IDs (the session carried them); /nix/.rw-store and /run/wrappers
#: are new filesystems its own start mounted.
BACK_MOUNTINFO = """\
36 1 253:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
58 36 0:30 / /nix/.ro-store ro,relatime shared:2 - 9p nix-store rw
65 36 0:32 / /nix/store ro,nosuid,nodev,relatime shared:4 - overlay overlay rw
32 36 0:50 / /nix/.rw-store rw,relatime shared:28 - tmpfs tmpfs rw,mode=755
44 36 0:51 / /run/wrappers rw,nodev,relatime shared:30 - tmpfs tmpfs rw,mode=755
"""

BACK_UTAB = """\
ID=36 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount
ID=58 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount
ID=65 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount
ID=32 SRC=tmpfs TARGET=/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
"""


class ParseTest(unittest.TestCase):
    def test_a_line_is_read_the_way_libmount_reads_it(self) -> None:
        text = "ID=85 UNIQID=7 SRC=/dev/my\\040disk TARGET=/srv ROOT=/sub"
        line = utab.parse_line(text)
        assert line is not None
        self.assertEqual(line.id, 85)
        self.assertEqual(line.fields["SRC"], "/dev/my disk")
        self.assertFalse(line.joins, "no options: libmount joins it to nothing")
        # An empty ID at the end of the line is none; elsewhere, or a number
        # that runs into the next field, makes libmount skip the line.
        bare = utab.parse_line("SRC=a TARGET=/x ROOT=/ OPTS=o ID=")
        assert bare is not None
        self.assertEqual((bare.id, bare.joins), (0, True))
        for skipped in ("ID= SRC=a", "ID=x", "ID=40 UNIQID=7SRC=a", "  # ID=7", ""):
            self.assertIsNone(utab.parse_line(skipped), skipped)

    def test_mountinfo_paths_are_unescaped(self) -> None:
        mounts = utab.parse_mountinfo(HUNG_MOUNTINFO)
        points = [m.point for m in mounts]
        self.assertIn("/mnt/data/root/decoy/nix-.ro\\x2dstore", points)


class WrongLinesTest(unittest.TestCase):
    def test_the_line_that_hung_the_reentry_is_found(self) -> None:
        # Comparing only the ID, the source and the root, line 26 looks fine:
        # /run/wrappers is a tmpfs with root / too. Its target says otherwise.
        lines = HUNG_UTAB.splitlines()
        self.assertEqual(
            utab.wrong_lines(HUNG_UTAB, HUNG_MOUNTINFO), lines[:6] + [lines[8]]
        )

    def test_lines_of_live_mounts_pass(self) -> None:
        self.assertEqual(utab.wrong_lines(BACK_UTAB, BACK_MOUNTINFO), [])
        self.assertEqual(utab.wrong_lines(DECOY_UTAB, DECOY_MOUNTINFO), [])

    def test_a_line_without_an_id_is_wrong_only_without_its_mount(self) -> None:
        gone = "SRC=tmpfs TARGET=/run/keys ROOT=/ OPTS=x-initrd.mount"
        self.assertEqual(utab.wrong_lines(gone + "\n", HUNG_MOUNTINFO), [gone])
        # Once such a line has joined the mount the next userspace made at its
        # target, it looks right: a test checks that the switch dropped it.
        stale = "SRC=tmpfs TARGET=/run/wrappers ROOT=/ OPTS=x-initrd.mount"
        self.assertEqual(utab.wrong_lines(stale + "\n", HUNG_MOUNTINFO), [])


class NotGivenBackTest(unittest.TestCase):
    def check(self, after: str) -> tuple[list[str], list[str]]:
        return utab.not_given_back(DECOY_UTAB, DECOY_MOUNTINFO, after, BACK_MOUNTINFO)

    def test_the_decoy_has_its_own_lines_again(self) -> None:
        self.assertEqual(self.check(BACK_UTAB), ([], []))

    def test_a_line_of_the_session_is_foreign_even_on_a_restored_mount(self) -> None:
        # Its ID names the restored store, its source, root and target fit;
        # but no decoy line was like it, and the store is no new filesystem.
        hidden = "ID=65 SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount"
        self.assertEqual(utab.wrong_lines(hidden + "\n", BACK_MOUNTINFO), [])
        self.assertEqual(self.check(BACK_UTAB + hidden + "\n"), ([hidden], []))

    def test_a_lost_line_is_found_while_another_still_marks_its_target(self) -> None:
        line = "ID=65 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount"
        after = BACK_UTAB.replace(line + "\n", "")
        self.assertEqual(self.check(after), ([], [line]))

    def test_a_line_kept_as_it_was_names_a_reused_id(self) -> None:
        # Restored verbatim, the root's line names nothing and the store's
        # line names the store under the ID of /nix/.ro-store at entry.
        foreign, lost = self.check(DECOY_UTAB)
        self.assertEqual(foreign, [])
        self.assertIn(
            "ID=36 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount", lost
        )
        self.assertIn(
            "ID=65 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ "
            "OPTS=x-initrd.mount",
            utab.wrong_lines(DECOY_UTAB, BACK_MOUNTINFO),
        )


#: The store of the test VMs after a way back that made both of its layers
#: again: the overlay (152) and the read-only bind of it on top (153).
STACKED_BACK_MOUNTINFO = """\
36 1 253:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
58 36 0:30 / /nix/.ro-store ro,relatime shared:2 - 9p nix-store rw
59 36 0:31 / /nix/.rw-store rw,relatime shared:3 - tmpfs tmpfs rw,mode=755
152 36 0:32 / /nix/store rw,relatime shared:4 - overlay overlay rw
153 152 0:32 / /nix/store ro,nosuid,nodev,relatime shared:5 - overlay overlay rw
"""

STACKED_BACK_UTAB = """\
ID=36 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount
ID=58 SRC=nix-store TARGET=/sysroot/nix/.ro-store ROOT=/ OPTS=x-initrd.mount
ID=59 SRC=tmpfs TARGET=/sysroot/nix/.rw-store ROOT=/ OPTS=x-initrd.mount
ID=152 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=overlay TARGET=/nix/store ROOT=/ OPTS=x-initrd.mount
SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount
"""


class StackedTest(unittest.TestCase):
    def check(self, after: str) -> tuple[list[str], list[str]]:
        return utab.not_given_back(
            DECOY_UTAB, DECOY_MOUNTINFO, after, STACKED_BACK_MOUNTINFO
        )

    def test_each_layer_has_its_own_line_again(self) -> None:
        wrong = utab.wrong_lines(STACKED_BACK_UTAB, STACKED_BACK_MOUNTINFO)
        self.assertEqual(wrong, [])
        self.assertEqual(self.check(STACKED_BACK_UTAB), ([], []))

    def test_the_bottom_s_line_on_the_top_layer_is_lost(self) -> None:
        # By place, source and root the two layers are alike: the line must
        # name the bottom one, as it did before the session.
        on_top = STACKED_BACK_UTAB.replace("ID=152 ", "ID=153 ")
        line = "ID=152 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount"
        self.assertEqual(self.check(on_top), ([], [line]))


if __name__ == "__main__":
    unittest.main()
