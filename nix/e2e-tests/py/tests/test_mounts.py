"""Host-side tests for the mount-table comparison, on tables of the test VMs."""

from __future__ import annotations

import unittest

from nails_e2e import mounts

#: A decoy that boots through a bootloader, before its first entry: its store
#: is a read-only bind of the root's /nix/store, an fstab filesystem at
#: /srv/data has a read-only bind of itself stacked on it, and the hidden
#: volume is mounted at /mnt/data.
BEFORE = """\
36 1 253:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw
69 36 0:26 / /run rw,nosuid,nodev shared:2 - tmpfs tmpfs rw,mode=755
37 36 0:6 / /dev rw,nosuid shared:7 - devtmpfs devtmpfs rw,mode=755
38 37 0:33 / /dev/pts rw,nosuid,noexec,relatime shared:8 - devpts devpts rw
44 36 253:2 /nix/store /nix/store ro,nosuid,nodev,relatime shared:17 - ext4 /dev/vda2 rw
41 69 0:41 / /run/keys rw,nosuid,nodev,relatime shared:22 - ramfs ramfs rw
48 36 253:1 / /boot rw,relatime shared:63 - vfat /dev/vda1 rw
52 36 253:32 / /srv/data rw,relatime shared:91 - ext4 /dev/vdc rw
66 36 254:0 / /mnt/data rw,relatime shared:254 - ext4 /dev/mapper/data rw
112 52 253:32 / /srv/data ro,relatime shared:91 - ext4 /dev/vdc rw
"""

#: After a way back that gave the decoy all of it back: new IDs, new peer
#: groups, /run and the API filesystems after the decoy's mounts, /run
#: without what was below it.
BACK = """\
34 1 253:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw
50 34 253:2 /nix/store /nix/store ro,nosuid,nodev,relatime shared:3 - ext4 /dev/vda2 rw
42 34 253:1 / /boot rw,relatime shared:2 - vfat /dev/vda1 rw
62 34 253:32 / /srv/data rw,relatime shared:4 - ext4 /dev/vdc rw
63 62 253:32 / /srv/data ro,relatime shared:5 - ext4 /dev/vdc rw
287 34 0:26 / /run rw,nosuid,nodev shared:6 - tmpfs tmpfs rw,mode=755
24 34 0:6 / /dev rw,nosuid shared:8 - devtmpfs devtmpfs rw,mode=755
25 24 0:33 / /dev/pts rw,nosuid,noexec,relatime shared:9 - devpts devpts rw
"""

#: The way back before it made the decoy's mounts again, as a VM run showed
#: it: no store bind, and one mount at /srv/data with the top's options.
BACK_BEFORE_THE_FIX = """\
34 1 253:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw
42 34 253:1 / /boot rw,relatime shared:2 - vfat /dev/vda1 rw
62 34 253:32 / /srv/data ro,relatime shared:3 - ext4 /dev/vdc rw
287 34 0:26 / /run rw,nosuid,nodev shared:6 - tmpfs tmpfs rw,mode=755
24 34 0:6 / /dev rw,nosuid shared:8 - devtmpfs devtmpfs rw,mode=755
25 24 0:33 / /dev/pts rw,nosuid,noexec,relatime shared:9 - devpts devpts rw
"""


def leave_out(point: str) -> bool:
    return point.startswith("/run/") or point == "/mnt/data" or point.startswith(
        "/mnt/data/"
    )


def compare(before: str, after: str) -> list[str]:
    return mounts.differences(
        mounts.shape(before, leave_out), mounts.shape(after, leave_out)
    )


def by_place(text: str) -> dict[mounts.Place, mounts.Shape]:
    return {mount.place: mount for mount in mounts.shape(text, leave_out)}


class ShapeTest(unittest.TestCase):
    def test_a_stack_is_told_by_its_layers(self) -> None:
        shapes = by_place(BEFORE)
        bottom = shapes[("/", "/srv/data")]
        top = shapes[("/", "/srv/data", "/srv/data")]
        self.assertEqual((bottom.options, top.options), ("rw,relatime", "ro,relatime"))
        self.assertIn(("/",), shapes)
        self.assertNotIn(("/", "/mnt/data"), shapes)
        self.assertNotIn(("/", "/run", "/run/keys"), shapes)
        self.assertIn(("/", "/run"), shapes)
        self.assertEqual(len(mounts.shape(BEFORE, leave_out)), 8)

    def test_a_mount_hidden_at_another_s_mount_point_keeps_its_own_place(self) -> None:
        # /a/b, then /a over it, then /a/b again on /a: the first is hidden.
        table = (
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n"
            "2 1 0:40 / /a/b rw - tmpfs hidden rw\n"
            "3 1 0:41 / /a rw - tmpfs cover rw\n"
            "4 3 0:42 / /a/b rw - tmpfs visible rw\n"
        )
        shapes = by_place(table)
        self.assertEqual(shapes[("/", "/a/b")].source, "hidden")
        self.assertEqual(shapes[("/", "/a", "/a/b")].source, "visible")
        without_hidden = table.replace("2 1 0:40 / /a/b rw - tmpfs hidden rw\n", "")
        found = compare(table, without_hidden)
        self.assertEqual(len(found), 2, found)
        self.assertTrue(
            found[0].startswith("missing: Shape(place=('/', '/a/b')"), found
        )
        self.assertEqual(found[1], "4 mounts before, 3 after")

    def test_the_propagation_type_comes_from_the_optional_fields(self) -> None:
        self.assertEqual(mounts.propagation([]), "private")
        self.assertEqual(mounts.propagation(["shared:5"]), "shared")
        self.assertEqual(mounts.propagation(["shared:5", "master:2"]), "shared,slave")
        self.assertEqual(mounts.propagation(["master:2"]), "slave")
        self.assertEqual(mounts.propagation(["unbindable"]), "unbindable")


class DifferencesTest(unittest.TestCase):
    def test_a_way_back_that_gave_everything_back_differs_in_nothing(self) -> None:
        self.assertEqual(compare(BEFORE, BACK), [])

    def test_the_lost_store_bind_and_layer_are_found(self) -> None:
        found = compare(BEFORE, BACK_BEFORE_THE_FIX)
        self.assertEqual(len(found), 5, found)
        self.assertTrue(
            found[0].startswith("missing: Shape(place=('/', '/nix/store')"), found
        )
        self.assertTrue(found[1].startswith("missing: Shape(place=('/', '/srv/data')"))
        self.assertTrue(
            found[2].startswith("missing: Shape(place=('/', '/srv/data', '/srv/data')"),
            found,
        )
        # The top's options on the bottom's place.
        self.assertTrue(found[3].startswith("extra: Shape(place=('/', '/srv/data')"))
        self.assertIn("options='ro,relatime'", found[3])
        self.assertEqual(found[4], "8 mounts before, 6 after")

    def test_two_alike_mounts_count_twice(self) -> None:
        # A copy of a mount on the one below a stack, or a second one beside
        # it at its own place: each is one more mount.
        table = (
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n"
            "2 1 8:2 /nix/store /nix/store ro - ext4 /dev/vda2 rw\n"
            "3 2 0:40 / /nix/store/x rw - tmpfs tmpfs rw\n"
        )
        under = table + "4 1 0:40 / /nix/store/x rw - tmpfs tmpfs rw\n"
        found = compare(table, under)
        self.assertEqual(len(found), 2, found)
        self.assertTrue(
            found[0].startswith("extra: Shape(place=('/', '/nix/store/x')"), found
        )
        beside = table + "4 2 0:40 / /nix/store/x rw - tmpfs tmpfs rw\n"
        found = compare(table, beside)
        self.assertEqual(len(found), 2, found)
        self.assertTrue(
            found[0].startswith(
                "extra: Shape(place=('/', '/nix/store', '/nix/store/x')"
            ),
            found,
        )

    def test_a_new_filesystem_or_another_propagation_is_a_difference(self) -> None:
        self.assertEqual(len(compare(BEFORE, BACK.replace("253:1 /", "253:9 /"))), 2)
        self.assertEqual(len(compare(BEFORE, BACK.replace("shared:2 ", ""))), 2)

    def test_the_mounts_the_way_back_makes_keep_their_order(self) -> None:
        lines = BACK.splitlines(keepends=True)
        boot_first = "".join([lines[0], lines[2], lines[1], *lines[3:]])
        found = compare(BEFORE, boot_first)
        self.assertEqual(len(found), 1, found)
        self.assertTrue(found[0].startswith("made in another order:"), found)
        # /run and the API filesystems come back where PID 1 puts them.
        run_last = "".join([*lines[:5], *lines[6:], lines[5]])
        self.assertEqual(compare(BEFORE, run_last), [])


if __name__ == "__main__":
    unittest.main()
