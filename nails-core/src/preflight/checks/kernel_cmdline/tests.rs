// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn kstrtobool_reads_the_classic_spellings_on_every_release() {
    // Linux's lib/kstrtox.c: the first character decides, except for `o`,
    // where the second tells `on` from `off`; case is ignored.
    for spellings in [BoolSpellings::Classic, BoolSpellings::EnableDisable] {
        for truthy in ["y", "Y", "yes", "t", "true", "1", "on", "ON", "On"] {
            assert_eq!(spellings.parse(truthy), Some(true), "{truthy:?}");
        }
        for falsy in ["n", "N", "no", "f", "false", "0", "off", "OFF", "of"] {
            assert_eq!(spellings.parse(falsy), Some(false), "{falsy:?}");
        }
        // A leading `o` that is neither `on` nor `off`, a bare `o`, junk and
        // the empty value are rejected.
        for rejected in ["ouch", "o", "maybe", "2", "", " 1", "ö"] {
            assert_eq!(spellings.parse(rejected), None, "{rejected:?}");
        }
    }
}

#[test]
fn enable_and_disable_count_from_linux_6_16() {
    // Linux 6.16 added `e`/`E` as true and `d`/`D` as false to kstrtobool.
    let current = BoolSpellings::EnableDisable;
    for truthy in ["e", "E", "enable", "enabled", "Enable"] {
        assert_eq!(current.parse(truthy), Some(true), "{truthy:?}");
    }
    for falsy in ["d", "D", "disable", "disabled", "Disable"] {
        assert_eq!(current.parse(falsy), Some(false), "{falsy:?}");
    }
    // An older kernel rejects them, leaving the parameter as it was.
    let classic = BoolSpellings::Classic;
    for rejected in ["e", "enable", "D", "disabled"] {
        assert_eq!(classic.parse(rejected), None, "{rejected:?}");
    }
}

#[test]
fn the_spellings_follow_the_booted_release() {
    for (release, spellings) in [
        ("6.15.11-arch1-1", BoolSpellings::Classic),
        ("6.12.48+deb13-amd64", BoolSpellings::Classic),
        ("6.8.0-45-generic", BoolSpellings::Classic),
        ("5.15.0", BoolSpellings::Classic),
        ("6.16.0", BoolSpellings::EnableDisable),
        ("6.16", BoolSpellings::EnableDisable),
        ("6.17.2-200.fc42.x86_64\n", BoolSpellings::EnableDisable),
        ("7.0.0-14-generic", BoolSpellings::EnableDisable),
        ("10.1", BoolSpellings::EnableDisable),
    ] {
        assert_eq!(
            BoolSpellings::of_release(Some(release)),
            spellings,
            "{release:?}"
        );
    }
    // A release that cannot be read or parsed is taken for a current one.
    for unreadable in [None, Some(""), Some("linux"), Some("6"), Some("6.x")] {
        assert_eq!(
            BoolSpellings::of_release(unreadable),
            BoolSpellings::EnableDisable,
            "{unreadable:?}"
        );
    }
}

#[test]
fn parameters_are_read_as_the_kernel_reads_them() {
    let read: Vec<(String, &str)> =
        parameters("BOOT_IMAGE=/vmlinuz quiet init-on-free=\"1\" iommu.passthrough=0 -- x=1")
            .collect();
    assert_eq!(
        read,
        vec![
            ("BOOT_IMAGE".to_string(), "/vmlinuz"),
            ("init_on_free".to_string(), "1"),
            ("iommu.passthrough".to_string(), "0"),
        ]
    );
}

#[test]
fn the_last_accepted_value_wins() {
    let classic = BoolSpellings::Classic;
    let current = BoolSpellings::EnableDisable;
    assert_eq!(last_bool("x=1 x=0", "x", classic), Some(false));
    assert_eq!(last_bool("x=0 x=1", "x", classic), Some(true));
    // A rejected value leaves the earlier one in place.
    assert_eq!(last_bool("x=1 x=bogus", "x", classic), Some(true));
    assert_eq!(last_bool("x=1 x=disable", "x", classic), Some(true));
    assert_eq!(last_bool("x=1 x=disable", "x", current), Some(false));
    // Nothing accepted, or nothing set.
    assert_eq!(last_bool("x x= x=maybe", "x", current), None);
    assert_eq!(last_bool("quiet", "x", current), None);
    // A similar name does not count, and init's arguments are not read.
    assert_eq!(last_bool("xx=1 y_x=1", "x", current), None);
    assert_eq!(last_bool("quiet -- x=1", "x", current), None);
}
