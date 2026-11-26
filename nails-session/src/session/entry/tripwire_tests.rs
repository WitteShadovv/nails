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
fn fake_devices(mount: &MountEntry) -> std::result::Result<Option<Vec<DevNum>>, Untold> {
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
    let unread = |mount: &MountEntry| -> std::result::Result<Option<Vec<DevNum>>, Untold> {
        if mount.mount_point == Path::new("/srv") {
            Err(Untold::Unread(PathBuf::from("/sys/fs/btrfs")))
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
fn a_decoy_on_devices_sysfs_does_not_list_is_refused() {
    // No sysfs device is known: the counters cannot follow any of them.
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
        refused.contains("whose writes the counters cannot follow to a disk"),
        "{refused}"
    );
}

#[test]
fn a_decoy_zfs_dataset_refuses_the_activation() {
    let table = format!("{TABLE}28 22 0:50 / /tank rw - zfs tank/home rw\n");
    let mounts = parse_mountinfo(&table);
    let refused = decoy_devices(&mounts, Path::new("/mnt/data"), None, &fake_devices).unwrap_err();
    let Untold::Unwatchable(why) = refused else {
        panic!("{refused:?}");
    };
    assert!(why.contains("zfs dataset tank/home at /tank"), "{why}");
    let empty = tempfile::tempdir().unwrap();
    let sys = Sysfs {
        root: empty.path().to_path_buf(),
    };
    let text = layout(
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
        text.contains("cannot watch the decoy's filesystems"),
        "{text}"
    );
    assert!(text.contains("write_tripwire = false"), "{text}");
}

#[test]
fn a_filesystem_counts_with_its_log_journal_and_realtime_devices() {
    let mounts = parse_mountinfo(TABLE);
    let mut extras = Extras::default();
    extras.devs.insert("vdd".into(), dev("252:48"));
    extras.devs.insert("vde".into(), dev("252:64"));
    // The root's XFS log and realtime devices.
    extras.by_mount.insert(
        "252:2".into(),
        Extra::Devices(vec!["vdd".into(), "vde".into()]),
    );
    let root = &mounts[0];
    assert_eq!(extras.of(root), Ok(vec![dev("252:48"), dev("252:64")]));
    assert_eq!(extras.of(&mounts[1]), Ok(Vec::new()));
    extras
        .by_mount
        .insert("252:2".into(), Extra::Devices(vec!["vdz".into()]));
    assert!(matches!(extras.of(root), Err(Untold::Unwatchable(why)) if why.contains("vdz")));
    extras.by_mount.insert("252:2".into(), Extra::NotFound);
    assert!(matches!(extras.of(root), Err(Untold::Unwatchable(_))));
    extras
        .by_mount
        .insert("252:2".into(), Extra::Unreadable("/proc/fs/jbd2".into()));
    assert_eq!(
        extras.of(root),
        Err(Untold::Unread(PathBuf::from("/proc/fs/jbd2")))
    );
}

/// On the running system, every mount whose device sysfs numbers counts with
/// that device: a lookup that lost one would shrink the watch set.
#[test]
fn every_mount_on_a_device_sysfs_numbers_counts_with_it() {
    let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
    let extras = Extras::read(&mounts);
    let devices = all_devices_of(&extras);
    for mount in &mounts {
        if !Path::new("/sys/dev/block").join(&mount.dev).exists() {
            continue;
        }
        // A mount whose source is the device node of its own number must
        // be found; elsewhere (a node that is gone, a btrfs member sysfs does
        // not list) the lookup may tell nothing, but never too little.
        let own_node = std::fs::metadata(&mount.source).is_ok_and(|m| {
            std::os::unix::fs::FileTypeExt::is_block_device(&m.file_type())
                && DevNum::from_raw(std::os::unix::fs::MetadataExt::rdev(&m)) == dev(&mount.dev)
        });
        let found = match devices(mount) {
            Ok(Some(found)) => found,
            other => {
                assert!(!own_node, "{}: {other:?}", mount.mount_point.display());
                continue;
            }
        };
        assert!(
            found.contains(&dev(&mount.dev)),
            "{} on {}: {found:?}",
            mount.mount_point.display(),
            mount.dev
        );
    }
}
