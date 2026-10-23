"""Unit tests for the portable smoke scenario's distro-aware helpers.

These run in the fast lane (`python3 -m unittest`, no VM) and lock the layout
rules the scenario depends on: where a hidden write lands, which boot
filesystems to check, and when an overlay's feature options are wrong. A silent
drift here would turn a real leak or a mounted-writable boot partition into a
false pass on some distribution.
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
