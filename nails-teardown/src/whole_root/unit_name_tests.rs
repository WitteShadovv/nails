// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::ffi::OsStr;

/// The units PID 1 loaded for a tmpfs mounted at each of these folders of
/// `/run/nails-unit-probe` on systemd 255 (255.4-1ubuntu8.17), read from its
/// bus objects, since `systemctl list-units` fails while a mount point that
/// is not valid UTF-8 exists. The e2e check of the unit names finds the same
/// names on the systemd of the NixOS test VMs.
fn pid_1_names() -> Vec<(Vec<Vec<u8>>, &'static str)> {
    vec![
        (
            vec![b"a\xff".to_vec()],
            "run-nails\\x2dunit\\x2dprobe-a\\xff.mount",
        ),
        (
            vec![b"x\xfe\xfdy".to_vec()],
            "run-nails\\x2dunit\\x2dprobe-x\\xfe\\xfdy.mount",
        ),
        (
            vec![b"c".repeat(222)],
            "run-nails\\x2dunit\\x2dprobe-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.mount",
        ),
        (
            vec![b"c".repeat(223)],
            "run-nails\\x2dunit\\x2dprobe-ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc_6b26d6a749d60614.mount",
        ),
        (
            vec![b"a".repeat(250)],
            "run-nails\\x2dunit\\x2dprobe-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_01599071334b551b.mount",
        ),
        (
            vec![b"\xff".to_vec(), b"a".repeat(250)],
            "run-nails\\x2dunit\\x2dprobe-\\xffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_4512109f26c23c95.mount",
        ),
        (
            vec![b"\xff".repeat(70)],
            "run-nails\\x2dunit\\x2dprobe-\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\_e4a55aff71ad7547.mount",
        ),
        (
            vec![b"\xc3\xa4".repeat(120)],
            "run-nails\\x2dunit\\x2dprobe-\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\xa4\\xc3\\_f920c2364cb45eed.mount",
        ),
        (
            vec![b"my-disk a\\b".to_vec()],
            "run-nails\\x2dunit\\x2dprobe-my\\x2ddisk\\x20a\\x5cb.mount",
        ),
        (
            vec![b".dot".to_vec()],
            "run-nails\\x2dunit\\x2dprobe-.dot.mount",
        ),
    ]
}

#[test]
fn a_mount_unit_is_named_as_pid_1_names_it() {
    for (parts, unit) in pid_1_names() {
        let mut path = b"/run/nails-unit-probe/".to_vec();
        path.extend(parts.concat());
        let path = Path::new(OsStr::from_bytes(&path));
        assert_eq!(mount_unit(path), unit, "{}", path.display());
        assert!(unit.len() < UNIT_NAME_MAX, "{unit}");
    }
}

#[test]
fn a_mount_unit_name_is_simplified_and_escaped_as_systemd_escape_does() {
    assert_eq!(
        mount_unit(Path::new("/run/initramfs")),
        "run-initramfs.mount"
    );
    assert_eq!(
        mount_unit(Path::new("/run//my-disk/./.x/")),
        "run-my\\x2ddisk-.x.mount"
    );
    assert_eq!(mount_unit(Path::new("/.hidden")), "\\x2ehidden.mount");
    assert_eq!(mount_unit(Path::new("/")), "-.mount");
    assert_eq!(mount_unit(Path::new("")), "-.mount");
}

/// The reference vector of the SipHash paper (key 00..0f, the message
/// 00..0e).
#[test]
fn siphash24_gives_the_reference_value() {
    let key: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let message: Vec<u8> = (0..15).collect();
    assert_eq!(siphash24(&message, &key), 0xa129_ca61_49be_45e5);
    assert_eq!(siphash24(&[], &key), 0x726f_db47_dd0e_0e31);
}
