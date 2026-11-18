// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mask of every `noauto` line of a decoy disk, as what the hidden
//! session keeps off reads it.

use super::*;
use crate::session::fstab::parse_fstab;
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::plan::MaskCause;

const HIDDEN: &str = "/mnt/data";

fn mounts() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n\
         8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    )
}

/// The decisions for the decoy's fstab `fstab`, with every device there or
/// with none.
fn decide_fstab(fstab: &str, there: bool) -> Vec<Decision> {
    decide_all(&parse_fstab(fstab), &mounts(), Path::new(HIDDEN), &|_| {
        there
    })
}

/// The mask of a noauto line yields to a skip of its unit that waits for its
/// device, which starts nothing either: the skip pulls in the line's checkers
/// too, and the unit is not masked. A skip that waits for another device is
/// masked, and recorded as one the lines disagree about.
#[test]
fn a_noauto_mask_yields_to_a_skip_of_its_unit_on_its_device() {
    let noauto = decide_fstab("/dev/vdb1 /srv/x ext4 noauto 0 2\n", true);
    assert!(noauto[0].is_noauto_mask(), "{noauto:?}");
    for (device, yields) in [("/dev/vdb1", true), ("/dev/vdc1", false)] {
        let other = format!("{device} /srv/x ext4 defaults 0 0\n");
        let skip = Decision::Skip {
            target: "/srv/x".into(),
            skip: Skip {
                units: vec!["srv-x.mount".into()],
                pulled: Vec::new(),
                device: Some(device.into()),
            },
            masked: Vec::new(),
            reason: "a unit a target links".into(),
        };
        let decisions = [noauto[0].clone(), skip];
        let fstab = parse_fstab(&format!("/dev/vdb1 /srv/x ext4 noauto 0 2\n{other}"));
        let kept = runtime_units(&fstab, &decisions);
        assert!(
            kept.masks.contains(&"srv-x.automount".to_string()),
            "{kept:?}"
        );
        if yields {
            assert!(!kept.masks.contains(&"srv-x.mount".to_string()), "{kept:?}");
            assert_eq!(
                kept.skips[0].pulled,
                ["systemd-fsck@dev-vdb1.service"],
                "{kept:?}"
            );
            assert!(kept.required_masks.is_empty(), "{kept:?}");
        } else {
            assert!(kept.masks.contains(&"srv-x.mount".to_string()), "{kept:?}");
            assert!(kept.skips.is_empty(), "{kept:?}");
            assert_eq!(kept.required_masks[0].cause, MaskCause::ConflictingLines);
        }
        assert_eq!(
            kept.noauto_masks.contains(&"srv-x.mount".to_string()),
            !yields
        );
    }
}
