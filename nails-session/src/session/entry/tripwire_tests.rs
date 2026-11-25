// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_teardown::mountinfo::parse_mountinfo;

const TABLE: &str = "\
22 1 252:2 / / rw,relatime - ext4 /nonexistent/vda2 rw
23 22 252:1 / /boot rw,relatime - vfat /nonexistent/vda1 rw
24 22 0:21 / /proc rw - proc proc rw
27 22 0:40 / /srv rw,relatime - btrfs /nonexistent/vdc rw
25 22 253:0 / /mnt/data rw,relatime - ext4 /nonexistent/mapper/data rw
26 25 253:0 /root/upper /mnt/data/root/bind rw,relatime - ext4 /nonexistent/mapper/data rw
";

fn dev(text: &str) -> DevNum {
    DevNum::parse(text).unwrap()
}

/// A stand-in for the pre-flight's device lookup: a mount's own device
/// number, both devices of the btrfs filesystem at /srv, none for a kernel
/// filesystem.
fn fake_devices(mount: &MountEntry) -> std::result::Result<Option<Vec<DevNum>>, PathBuf> {
    match mount.fstype.as_str() {
        "proc" => Ok(None),
        "btrfs" => Ok(Some(vec![dev("252:32"), dev("252:48")])),
        _ => Ok(Some(vec![dev(&mount.dev)])),
    }
}

#[test]
fn the_decoy_is_every_device_of_every_filesystem_outside_the_hidden_root() {
    let mounts = parse_mountinfo(TABLE);
    assert_eq!(
        decoy_devices(
            &mounts,
            Path::new("/mnt/data"),
            Some(dev("252:2")),
            &fake_devices
        ),
        Ok(vec![
            dev("252:1"),
            dev("252:2"),
            dev("252:32"),
            dev("252:48")
        ])
    );
    assert_eq!(
        hidden_mount_devices(&mounts, Path::new("/mnt/data"), &fake_devices),
        Ok(vec![dev("253:0")])
    );
}

#[test]
fn a_device_that_cannot_be_read_refuses_the_activation() {
    let mounts = parse_mountinfo(TABLE);
    let empty = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: empty.path().to_path_buf(),
    };
    let unread = |mount: &MountEntry| -> std::result::Result<Option<Vec<DevNum>>, PathBuf> {
        if mount.mount_point == Path::new("/srv") {
            Err(PathBuf::from("/sys/fs/btrfs"))
        } else {
            fake_devices(mount)
        }
    };
    let refused = layout(
        &mounts,
        Path::new("/mnt/data"),
        &[],
        Path::new("/nonexistent"),
        &sys,
        &unread,
    )
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("/sys/fs/btrfs cannot be read"),
        "{refused}"
    );
    assert!(
        refused.contains("devices of the decoy's filesystems"),
        "{refused}"
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
        &fake_devices,
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("no block device"), "{refused}");
    assert!(refused.contains("write_tripwire = false"), "{refused}");
}

#[test]
fn a_decoy_on_no_disk_the_counters_know_is_refused_as_nothing_to_watch() {
    // No sysfs device is known: nothing has hardware below it.
    let mounts = parse_mountinfo(TABLE);
    let empty = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: empty.path().to_path_buf(),
    };
    let refused = layout(
        &mounts,
        Path::new("/mnt/data"),
        &[],
        Path::new("/nonexistent"),
        &sys,
        &fake_devices,
    )
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("no decoy filesystem lies on a disk"),
        "{refused}"
    );
}
