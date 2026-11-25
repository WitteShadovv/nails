// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_teardown::mountinfo::parse_mountinfo;

const TABLE: &str = "\
22 1 252:2 / / rw,relatime - ext4 /nonexistent/vda2 rw
23 22 252:1 / /boot rw,relatime - vfat /nonexistent/vda1 rw
24 22 0:21 / /proc rw - proc proc rw
25 22 253:0 / /mnt/data rw,relatime - ext4 /nonexistent/mapper/data rw
26 25 253:0 /root/upper /mnt/data/root/bind rw,relatime - ext4 /nonexistent/mapper/data rw
";

fn dev(text: &str) -> DevNum {
    DevNum::parse(text).unwrap()
}

#[test]
fn the_decoy_is_every_disk_mount_outside_the_hidden_root() {
    let mounts = parse_mountinfo(TABLE);
    assert_eq!(
        decoy_devices(&mounts, Path::new("/mnt/data"), Some(dev("252:2"))),
        [dev("252:1"), dev("252:2")]
    );
    assert_eq!(
        hidden_mount_device(&mounts, Path::new("/mnt/data")),
        Some(dev("253:0"))
    );
}

#[test]
fn a_layout_the_counters_cannot_watch_refuses_the_activation_and_names_the_way_out() {
    let mounts = parse_mountinfo(TABLE);
    let empty = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: empty.path().to_path_buf(),
    };
    let refused = layout(
        &mounts,
        Path::new("/proc"),
        &[],
        Path::new("/nonexistent"),
        &sys,
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("no block device"), "{refused}");
    assert!(refused.contains("write_tripwire = false"), "{refused}");
}

#[test]
fn a_hidden_volume_on_its_own_disk_watches_the_decoy_disks_only() {
    // No sysfs device is known: nothing has hardware below it, so nothing
    // is watched and nothing refuses.
    let mounts = parse_mountinfo(TABLE);
    let empty = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: empty.path().to_path_buf(),
    };
    let watched = layout(
        &mounts,
        Path::new("/mnt/data"),
        &[],
        Path::new("/nonexistent"),
        &sys,
    )
    .unwrap();
    assert!(watched.disks.is_empty());
}
