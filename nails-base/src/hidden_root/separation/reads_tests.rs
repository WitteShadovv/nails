// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a crypttab line reads besides its source, as systemd 260.5's
//! crypttab generator wrote its units.

use super::*;
use crate::crypttab::parse_crypttab;

fn line(text: &str) -> CrypttabEntry {
    parse_crypttab(&format!("{text}\n")).remove(0)
}

/// The generator mounted the device after the last `:` (`/dev/sdd` for
/// `none:/dev/sdd`, `/dev/disk/by-label/keys` for `/k:LABEL=keys`, `/dev/sdf`
/// read-write for `header=/hdr:/dev/sdf`), had the line wait for the device a
/// key file or a header names (`/dev/sdb`, by-uuid/abc) and for the mounts of
/// any other path, and handed `systemd-cryptsetup` only the last `header=`.
#[test]
fn the_key_field_and_the_options_name_what_the_line_reads() {
    for (text, reads_of) in [
        ("vault /dev/sdc none luks", vec![]),
        ("vault /dev/sdc - luks", vec![]),
        ("vault /dev/sdc", vec![]),
        (
            "vault /dev/sdc /mnt/key luks",
            vec![(Named::KeyFile, "/mnt/key")],
        ),
        (
            "vault /dev/sdc /key:/dev/mapper/data luks",
            vec![(Named::KeyDevice, "/dev/mapper/data")],
        ),
        (
            "vault /dev/sdc none:/dev/sdd luks",
            vec![(Named::KeyDevice, "/dev/sdd")],
        ),
        (
            "vault /dev/sdc /k:LABEL=keys luks",
            vec![(Named::KeyDevice, "LABEL=keys")],
        ),
        (
            "vault /dev/sdc /k:ID=xyz luks",
            vec![(Named::KeyFile, "/k:ID=xyz")],
        ),
        (
            "vault /dev/sdc /dev/sdb luks",
            vec![(Named::KeyFile, "/dev/sdb")],
        ),
        (
            "vault /dev/sdc UUID=abc luks",
            vec![(Named::KeyFile, "UUID=abc")],
        ),
        // systemd-cryptsetup ignores a key file that is no absolute path.
        ("vault /dev/sdc keys/v.key luks", vec![]),
        (
            "cswap /dev/sdc /dev/urandom swap",
            vec![(Named::KeyFile, "/dev/urandom")],
        ),
        (
            "vault /dev/sdc none luks,header=/mnt/hdr",
            vec![(Named::Header, "/mnt/hdr")],
        ),
        (
            "vault /dev/sdc none luks,header=/hdr:/dev/sdf",
            vec![(Named::HeaderDevice, "/dev/sdf")],
        ),
        (
            "vault /dev/sdc none luks,header=/a,header=/b",
            vec![(Named::Header, "/a"), (Named::Header, "/b")],
        ),
        (
            "vault /dev/sdc none luks,header=UUID=abc",
            vec![(Named::Header, "UUID=abc")],
        ),
        // A header that is none, which systemd-cryptsetup refuses.
        ("vault /dev/sdc none luks,header", vec![]),
        ("vault /dev/sdc none luks,header=", vec![]),
        ("vault /dev/sdc none luks,header=rel/hdr", vec![]),
        (
            "vault /dev/sdc none tcrypt,tcrypt-keyfile=/mnt/tk,tcrypt-keyfile=/etc/tk",
            vec![(Named::KeyFile, "/mnt/tk"), (Named::KeyFile, "/etc/tk")],
        ),
        ("vault /dev/sdc none tcrypt,tcrypt-keyfile=tk", vec![]),
        (
            "vault /dev/sdc /k:/dev/sdd luks,header=/h:/dev/sde,tcrypt-keyfile=/t",
            vec![
                (Named::KeyDevice, "/dev/sdd"),
                (Named::HeaderDevice, "/dev/sde"),
                (Named::KeyFile, "/t"),
            ],
        ),
    ] {
        assert_eq!(reads(&line(text)), reads_of, "{text}");
    }
}

/// The generator handed `systemd-cryptsetup` the key file
/// `<mount>/../../../mnt/key` for `../../../mnt/key:/dev/sdg`, a path out of
/// the mount it made.
#[test]
fn a_path_out_of_a_device_the_boot_mounts_or_a_keyscript_is_not_plain() {
    for (text, why) in [
        (
            "vault /dev/sdc ../../../../mnt/key:/dev/sdg luks",
            vec![Unplain::UpOutOfDevice("key file")],
        ),
        (
            "vault /dev/sdc /keys/../key:/dev/sdg luks",
            vec![Unplain::UpOutOfDevice("key file")],
        ),
        (
            "vault /dev/sdc none luks,header=../../hdr:/dev/sdf",
            vec![Unplain::UpOutOfDevice("header")],
        ),
        (
            "vault UUID=abc /dev/disk/by-uuid/vol:/key luks,keyscript=passdev",
            vec![Unplain::Keyscript],
        ),
        (
            "cryptroot /dev/sda3 none luks,keyscript=decrypt_keyctl",
            vec![Unplain::Keyscript],
        ),
        (
            "vault /dev/sdc ../k:/dev/sdg luks,keyscript",
            vec![Unplain::UpOutOfDevice("key file"), Unplain::Keyscript],
        ),
    ] {
        assert_eq!(unplain(&line(text)), why, "{text}");
    }
    // A `..` in a path that is no path on a mounted device is read where it
    // leads, and a relative key file is none.
    for text in [
        "vault /dev/sdc /keys/../key luks",
        "vault /dev/sdc ../key luks",
        "vault /dev/sdc none luks,header=/a/../hdr",
        "vault /dev/sdc /key:/dev/sdg luks,discard",
        "vault /dev/sdc none luks,keyscriptx=1",
    ] {
        assert_eq!(unplain(&line(text)), [], "{text}");
    }
}
