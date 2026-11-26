// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::whole_root::fence_kernel::{DM_IOCTL_SIZE, DM_TABLE_STATUS};

/// A `DM_TABLE_STATUS` reply as the kernel writes it: the `struct dm_ioctl`,
/// then each `struct dm_target_spec` with its parameters, `next` counted
/// from the first.
fn reply(targets: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = vec![0u8; DM_IOCTL_SIZE];
    buf[16..20].copy_from_slice(&(DM_IOCTL_SIZE as u32).to_ne_bytes());
    buf[20..24].copy_from_slice(&(targets.len() as u32).to_ne_bytes());
    let mut offset = 0usize;
    for (kind, params) in targets {
        let mut spec = vec![0u8; 40];
        spec[24..24 + kind.len()].copy_from_slice(kind.as_bytes());
        let mut body = params.as_bytes().to_vec();
        body.push(0);
        while !(spec.len() + body.len()).is_multiple_of(8) {
            body.push(0);
        }
        offset += spec.len() + body.len();
        spec[20..24].copy_from_slice(&(offset as u32).to_ne_bytes());
        buf.extend(spec);
        buf.extend(body);
    }
    buf
}

#[test]
fn a_table_reply_gives_its_target_types_in_order() {
    assert_eq!(
        parse_targets(&reply(&[
            ("linear", "8:2 2048"),
            (
                "raid",
                "raid1 3 0 region_size 4096 2 254:1 254:2 254:3 254:4"
            ),
            ("crypt", "aes-xts-plain64 :64:logon:cryptsetup:x 0 8:3 4096"),
        ])),
        Ok(vec!["linear".into(), "raid".into(), "crypt".into()])
    );
    assert_eq!(parse_targets(&reply(&[])), Ok(Vec::new()));
    // A 16-byte name fills its field with no NUL.
    assert_eq!(
        parse_targets(&reply(&[("abcdefghijklmnop", "")])),
        Ok(vec!["abcdefghijklmnop".into()])
    );
    assert!(parse_targets(&[0u8; 12]).is_err());
    let mut short = reply(&[("linear", "8:2 0")]);
    short.truncate(DM_IOCTL_SIZE + 30);
    assert!(parse_targets(&short).is_err());
}

#[test]
fn the_table_request_is_the_kernel_s() {
    // _IOWR(0xfd, 12, struct dm_ioctl), struct dm_ioctl being 312 bytes.
    assert_eq!(DM_TABLE_STATUS, 0xC138_FD0C);
    assert_eq!(DM_IOCTL_SIZE, 312);
}

#[test]
fn only_linear_striped_and_crypt_mappings_pass_as_ones_that_write_nothing_of_their_own() {
    for passive in ["linear", "striped", "crypt", "zero", "error"] {
        assert!(PASSIVE_DM_TARGETS.contains(&passive));
    }
    for active in [
        "raid",
        "mirror",
        "cache",
        "writecache",
        "integrity",
        "thin-pool",
        "thin",
        "era",
        "clone",
        "vdo",
        "snapshot",
    ] {
        assert!(!PASSIVE_DM_TARGETS.contains(&active), "{active}");
    }
}
