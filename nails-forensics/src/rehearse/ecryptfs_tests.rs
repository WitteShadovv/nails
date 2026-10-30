// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The devices an eCryptfs mount makes blind spots for a scan: among the
//! mounted devices the filesystem its folder lies on, and for a device named
//! with `--device` every device that holds that filesystem (a whole disk, a
//! device below a mapping), which a mock sysfs shows here.

use super::tests::{TOKEN, ext4_superblock, verdict};
use super::*;
use crate::filesystem::parse_mountinfo;

/// The options the kernel shows for an eCryptfs mount (with made-up key
/// signatures).
const ECRYPTFS_OPTS: &str = "rw,ecryptfs_fnek_sig=bbbbbbbbbbbbbbbb,ecryptfs_sig=aaaaaaaaaaaaaaaa,\
                             ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_unlink_sigs";

/// Where the mock sysfs of [`Sysfs::two_disks`] keeps its devices.
const SDA: &str = "/sys/devices/pci0/block/sda";
const SDA1: &str = "/sys/devices/pci0/block/sda/sda1";
const SDA2: &str = "/sys/devices/pci0/block/sda/sda2";
const SDA3: &str = "/sys/devices/pci0/block/sda/sda3";
const SDB: &str = "/sys/devices/pci0/block/sdb";

/// A mock sysfs, built one device at a time as `nails_base::blockdev` reads
/// it: a device's attributes in its own directory under `/sys/devices`, a
/// partition's in its disk's, and `/sys/class/block/<name>`,
/// `/sys/dev/block/<major:minor>` and every `slaves/` entry a link to it.
struct Sysfs(crate::MockFilesystem);

impl Sysfs {
    /// The disk sda with its partitions sda1 to sda3, and the disk sdb.
    fn two_disks() -> Self {
        let sysfs = Self(crate::MockFilesystem::new());
        sysfs
            .device(SDA, "sda", "8:0")
            .partition(SDA1, "sda1", "8:1", 1)
            .partition(SDA2, "sda2", "8:2", 2)
            .partition(SDA3, "sda3", "8:3", 3)
            .device(SDB, "sdb", "8:16");
        sysfs
    }

    /// The device `name`, numbered `dev`, at `dir`.
    fn device(&self, dir: &str, name: &str, dev: &str) -> &Self {
        self.0
            .mock_set_file_content(&format!("{dir}/dev"), &format!("{dev}\n"));
        self.0
            .mock_set_file_content(&format!("{dir}/uevent"), &format!("DEVNAME={name}\n"));
        self.link(&format!("/sys/class/block/{name}"), dir)
            .link(&format!("/sys/dev/block/{dev}"), dir)
    }

    /// Partition `number` of the disk whose directory holds `dir`.
    fn partition(&self, dir: &str, name: &str, dev: &str, number: u32) -> &Self {
        self.0
            .mock_set_file_content(&format!("{dir}/partition"), &format!("{number}\n"));
        self.device(dir, name, dev)
    }

    /// The device at `dir`, built on the devices at `below` (its `slaves/`).
    fn on(&self, dir: &str, below: &[&str]) -> &Self {
        let slaves = Path::new(dir).join("slaves");
        let mut entries = Vec::new();
        for target in below {
            let entry = slaves.join(Path::new(target).file_name().unwrap());
            self.link(entry.to_str().unwrap(), target);
            entries.push(entry);
        }
        self.0.mock_set_directory_contents(&slaves, entries);
        self
    }

    fn link(&self, link: &str, target: &str) -> &Self {
        crate::Filesystem::create_symlink(&self.0, Path::new(target), Path::new(link)).unwrap();
        self
    }

    /// The blind spot of `device` named for a scan, under `mounts`.
    fn blind_spot(&self, device: &str, mounts: &[crate::filesystem::MountEntry]) -> Option<String> {
        ScanTarget::classified(&self.0, PathBuf::from(device), mounts).blind_spot
    }
}

#[test]
fn an_ecryptfs_mount_marks_the_device_its_folder_lies_on() {
    // An encrypted home as ecryptfs-utils mounts it: /home/alice/.Private on
    // the /home filesystem, mounted over /home/alice. The /home device stores
    // alice's files encrypted; the root device and the hidden volume do not
    // count, and the eCryptfs mount is no device of its own.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         4 2 0:50 / /home/alice rw,nosuid,nodev,relatime - ecryptfs /home/alice/.Private \
         {ECRYPTFS_OPTS}\n"
    ));
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        vec![PathBuf::from("/dev/sda1"), PathBuf::from("/dev/sda2")]
    );
    assert_eq!(targets[0].blind_spot, None);
    assert!(
        targets[1]
            .blind_spot
            .as_deref()
            .is_some_and(|reason| reason.contains("eCryptfs")),
        "{targets:?}"
    );
    assert!(targets.iter().all(|t| t.unread.is_none()), "{targets:?}");

    // `classified` finds it as well, for a device named with --device.
    let sysfs = Sysfs::two_disks();
    assert_eq!(
        sysfs.blind_spot("/dev/sda2", &mounts),
        targets[1].blind_spot
    );
    assert_eq!(sysfs.blind_spot("/dev/sda1", &mounts), None);
}

#[test]
fn an_ecryptfs_folder_lies_on_the_mount_on_top_of_its_path_when_it_was_mounted() {
    // A second filesystem mounted over /home before the eCryptfs mount hides
    // the first: the folder lies on the second. One deeper mount point
    // elsewhere (the hidden volume) does not hold it, nor does the eCryptfs
    // mount on whose mount point its own folder lies.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 8:3 / /home rw,relatime - xfs /dev/sda3 rw\n\
         4 1 253:0 / /mnt/data/deeper rw,relatime - ext4 /dev/mapper/data rw\n\
         5 3 0:50 / /home/alice rw,relatime - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n"
    ));
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data/deeper"));
    let blind = |device: &str| {
        targets
            .iter()
            .find(|t| t.device.as_path() == Path::new(device))
            .unwrap_or_else(|| panic!("{device} is a target: {targets:?}"))
            .blind_spot
            .clone()
    };
    assert_eq!(blind("/dev/sda1"), None);
    assert_eq!(blind("/dev/sda2"), None);
    assert!(
        blind("/dev/sda3").is_some_and(|reason| reason.contains("eCryptfs")),
        "{targets:?}"
    );
}

/// The blind spot of each device `default_scan_targets` lists under `mounts`.
fn default_blind_spots(mounts: &[crate::filesystem::MountEntry]) -> Vec<(PathBuf, Option<String>)> {
    default_scan_targets(mounts, "", Path::new("/mnt/data"))
        .into_iter()
        .map(|target| (target.device, target.blind_spot))
        .collect()
}

#[test]
fn a_filesystem_mounted_over_the_folders_path_later_does_not_hold_it() {
    // The encrypted home on /home (sda2), then another filesystem mounted
    // over /home (sdb1), which the table lists after the eCryptfs mount. The
    // eCryptfs mount keeps the folder it opened on sda2: sda2 and its disk
    // hold the files, sdb1 and the root do not. The later mount sits on sda2,
    // as the kernel records it, or on the root, as a table may name it.
    const SDB1: &str = "/sys/devices/pci0/block/sdb/sdb1";
    let sysfs = Sysfs::two_disks();
    sysfs.partition(SDB1, "sdb1", "8:17", 1);
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    for parent in [2, 1] {
        let mounts = parse_mountinfo(&format!(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
             3 2 0:50 / /home/alice rw,nosuid,nodev,relatime - ecryptfs /home/alice/.Private \
             {ECRYPTFS_OPTS}\n\
             4 {parent} 8:17 / /home rw,relatime - ext4 /dev/sdb1 rw\n"
        ));
        assert_eq!(
            default_blind_spots(&mounts),
            vec![
                (PathBuf::from("/dev/sda1"), None),
                (PathBuf::from("/dev/sda2"), stacked.clone()),
                (PathBuf::from("/dev/sdb1"), None),
            ],
            "parent {parent}"
        );
        for device in ["/dev/sda2", "/dev/sda"] {
            assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
        }
        for device in ["/dev/sdb1", "/dev/sdb", "/dev/sda1"] {
            assert_eq!(sysfs.blind_spot(device, &mounts), None, "{device}");
        }
    }
}

#[test]
fn a_filesystem_moved_over_the_folders_path_later_does_not_hold_it() {
    // sdb1, mounted somewhere else before the encrypted home and moved over
    // /home after it, keeps its place in the table, before the eCryptfs
    // mount and on top of sda2. The eCryptfs mount was made on sda2, so its
    // folder lay there.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 8:17 / /home rw,relatime - ext4 /dev/sdb1 rw\n\
         4 2 0:50 / /home/alice rw,nosuid,nodev,relatime - ecryptfs /home/alice/.Private \
         {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), None),
            (PathBuf::from("/dev/sda2"), stacked),
            (PathBuf::from("/dev/sdb1"), None),
        ]
    );
}

#[test]
fn a_folder_beside_its_mount_point_may_lie_on_each_mount_on_its_own_path() {
    // The folder /srv/.vault is mounted on /home/alice/vault, on /home: up
    // from the mount it was made on to the root, then down the folder's own
    // path, where sda3 is mounted over /srv. The table cannot show whether
    // sda3 was there when the folder was mounted, so the root and sda3 may
    // hold it. /home (sda2), where only its mount point lies, does not.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 0:50 / /home/alice/vault rw,relatime - ecryptfs /srv/.vault {ECRYPTFS_OPTS}\n\
         4 1 8:3 / /srv rw,relatime - ext4 /dev/sda3 rw\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), stacked.clone()),
            (PathBuf::from("/dev/sda2"), None),
            (PathBuf::from("/dev/sda3"), stacked),
        ]
    );
}

#[test]
fn a_folder_with_a_filesystem_of_its_own_may_lie_on_it_or_below_it() {
    // The encrypted files of a Private folder on a partition of their own
    // (sda3), mounted at /home/alice/.Private, with another filesystem stacked
    // on that one (sdb1). Either may have been mounted after the eCryptfs
    // mount, so the folder may lie on /home (sda2), sda3 or sdb1, never on the
    // root.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 8:3 / /home/alice/.Private rw,relatime - ext4 /dev/sda3 rw\n\
         4 2 0:50 / /home/alice/Private rw,relatime - ecryptfs /home/alice/.Private \
         {ECRYPTFS_OPTS}\n\
         5 3 8:17 / /home/alice/.Private rw,relatime - ext4 /dev/sdb1 rw\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), None),
            (PathBuf::from("/dev/sda2"), stacked.clone()),
            (PathBuf::from("/dev/sda3"), stacked.clone()),
            (PathBuf::from("/dev/sdb1"), stacked),
        ]
    );
}

#[test]
fn a_mount_a_copied_namespace_lists_after_the_ecryptfs_mount_may_hold_its_folder() {
    // A mount namespace copied from another (unshare -m, a container, a
    // service with mount sandboxing) lists the mounts it copied in the order
    // of their tree: sdb1 was mounted over /home/.ecryptfs before the
    // encrypted home was mounted on the tmpfs at /home/alice, yet the table
    // lists it after, as the tmpfs came first. The folder may lie on sdb1 or on
    // /home (sda2) below it, so both, and their disks, are not checked; the
    // root's partition is.
    const SDB1: &str = "/sys/devices/pci0/block/sdb/sdb1";
    let sysfs = Sysfs::two_disks();
    sysfs.partition(SDB1, "sdb1", "8:17", 1);
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 0:60 / /home/alice rw,relatime - tmpfs tmpfs rw\n\
         4 3 0:50 / /home/alice/Private rw,relatime - ecryptfs /home/.ecryptfs/alice/.Private \
         {ECRYPTFS_OPTS}\n\
         5 2 8:17 / /home/.ecryptfs rw,relatime - ext4 /dev/sdb1 rw\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), None),
            (PathBuf::from("/dev/sda2"), stacked.clone()),
            (PathBuf::from("/dev/sdb1"), stacked.clone()),
        ]
    );
    for device in ["/dev/sdb1", "/dev/sdb", "/dev/sda2", "/dev/sda"] {
        assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
    }
    assert_eq!(sysfs.blind_spot("/dev/sda1", &mounts), None);
}

#[test]
fn a_mount_a_copied_namespace_lists_before_the_ecryptfs_mount_may_not_have_held_its_folder() {
    // Copied the same way, a mount made after the encrypted home comes before
    // it when its tree does: sdb1, mounted over /srv/vault after the eCryptfs
    // mount, sits on /srv (sda2), which the copy took before /home (sda3). The
    // folder may lie on sda2, sdb1 or the root below them, never on /home.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /srv rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 8:17 / /srv/vault rw,relatime - ext4 /dev/sdb1 rw\n\
         4 1 8:3 / /home rw,relatime - ext4 /dev/sda3 rw\n\
         5 4 0:50 / /home/alice rw,relatime - ecryptfs /srv/vault/.Private {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), stacked.clone()),
            (PathBuf::from("/dev/sda2"), stacked.clone()),
            (PathBuf::from("/dev/sdb1"), stacked),
            (PathBuf::from("/dev/sda3"), None),
        ]
    );
}

#[test]
fn a_folder_in_the_view_of_another_ecryptfs_mount_lies_where_that_ones_folder_does() {
    // Alice's encrypted home keeps its files in /home/.ecryptfs/alice/.Private
    // on /home (sda2), as ecryptfs-utils sets one up, and a second eCryptfs
    // folder inside her home keeps its files in the first one's view: stored
    // encrypted again on sda2, never on the root.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 0:50 / /home/alice rw,relatime - ecryptfs /home/.ecryptfs/alice/.Private \
         {ECRYPTFS_OPTS}\n\
         4 3 0:51 / /home/alice/vault rw,relatime - ecryptfs /home/alice/.vault \
         {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    assert_eq!(
        default_blind_spots(&mounts),
        vec![
            (PathBuf::from("/dev/sda1"), None),
            (PathBuf::from("/dev/sda2"), stacked.clone()),
        ]
    );
    let sysfs = Sysfs::two_disks();
    assert_eq!(sysfs.blind_spot("/dev/sda", &mounts), stacked);
    assert_eq!(sysfs.blind_spot("/dev/sda1", &mounts), None);
}

#[test]
fn an_ecryptfs_mount_the_table_cannot_place_is_not_checked() {
    // The scan cannot tell what the folder lay on when the table does not
    // list the parent the eCryptfs mount names, lists two mounts with that ID
    // (one freed and its ID given to another while the table was read), has
    // parents that run in a circle, or two mounts on one at a place on the
    // folder's path, or stacked in a circle there, or when the folder's path
    // climbs (`..`). The folder is listed unread and not checked, and so is
    // every device named for a scan.
    let tables = [
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/sda2 rw\n\
         3 9 0:50 / /home/alice rw - ecryptfs /home/alice/.Private {opts}\n",
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/sda2 rw\n\
         3 2 0:50 / /home/alice rw - ecryptfs /home/alice/../.Private {opts}\n",
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/sda2 rw\n\
         2 1 8:3 / /srv rw - ext4 /dev/sda3 rw\n\
         3 2 0:50 / /home/alice rw - ecryptfs /home/alice/.Private {opts}\n",
        "5 6 8:2 / /home rw - ext4 /dev/sda2 rw\n\
         6 5 8:3 / /srv rw - ext4 /dev/sda3 rw\n\
         7 5 0:50 / /home/alice rw - ecryptfs /var/.Private {opts}\n",
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /srv rw - ext4 /dev/sda2 rw\n\
         3 1 8:3 / /srv rw - ext4 /dev/sda3 rw\n\
         4 1 0:50 / /home/alice rw - ecryptfs /srv/.Private {opts}\n",
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /srv rw - ext4 /dev/sda2 rw\n\
         3 2 8:3 / /srv rw - ext4 /dev/sda3 rw\n\
         2 3 8:17 / /srv rw - ext4 /dev/sdb1 rw\n\
         4 1 0:50 / /home/alice rw - ecryptfs /srv/.Private {opts}\n",
    ];
    let sysfs = Sysfs::two_disks();
    for table in tables {
        let mounts = parse_mountinfo(&table.replace("{opts}", ECRYPTFS_OPTS));
        let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
        let (folder, devices) = targets.split_last().unwrap();
        assert!(
            devices
                .iter()
                .all(|t| t.blind_spot.is_none() && t.unread.is_none()),
            "{targets:?}"
        );
        assert!(
            folder.device.ends_with(".Private")
                && folder
                    .blind_spot
                    .as_deref()
                    .is_some_and(|reason| reason.contains("eCryptfs"))
                && folder
                    .unread
                    .as_deref()
                    .is_some_and(|why| why.contains("cannot place on a mount the table shows")),
            "{targets:?}"
        );
        for device in ["/dev/sda2", "/dev/sdb"] {
            let reason = sysfs.blind_spot(device, &mounts).unwrap_or_default();
            assert!(
                reason.contains("cannot tell whether this device holds them"),
                "{device}: {reason}"
            );
        }
    }
}

#[test]
fn ecryptfs_folders_that_lie_only_in_each_others_views_are_not_placed() {
    // Each eCryptfs mount sits on the other and keeps its folder in the
    // other's view, which only a table read while it changed shows. No
    // filesystem holds either folder, so neither is placed: both are listed
    // unread and not checked, and so is every device named for a scan.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         3 4 0:50 / /home/alice rw - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n\
         4 3 0:51 / /home/alice rw - ecryptfs /home/alice/.vault {ECRYPTFS_OPTS}\n"
    ));
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    assert_eq!(
        targets
            .iter()
            .map(|t| (t.device.clone(), t.unread.is_some()))
            .collect::<Vec<_>>(),
        vec![
            (PathBuf::from("/dev/sda1"), false),
            (PathBuf::from("/home/alice/.Private"), true),
            (PathBuf::from("/home/alice/.vault"), true),
        ]
    );
    assert_eq!(targets[0].blind_spot, None);
    let reason = Sysfs::two_disks()
        .blind_spot("/dev/sda1", &mounts)
        .unwrap_or_default();
    assert!(
        reason.contains("cannot tell whether this device holds them"),
        "{reason}"
    );
}

#[test]
fn an_ecryptfs_folder_on_the_hidden_volume_marks_no_decoy_device() {
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n\
         3 2 0:50 / /mnt/data/vault rw,relatime - ecryptfs /mnt/data/.vault {ECRYPTFS_OPTS}\n"
    ));
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        vec![PathBuf::from("/dev/sda1")]
    );
    assert_eq!(targets[0].blind_spot, None);
}

#[test]
fn an_ecryptfs_folder_on_no_raw_device_is_listed_unread_and_not_checked() {
    // A folder on a filesystem with no block device of its own (a tmpfs),
    // and one the mount table names by a relative path, which lies on no
    // mount point: neither is dropped, each is listed unread with the
    // eCryptfs blind spot.
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 0:60 / /tmp rw - tmpfs tmpfs rw\n\
         3 2 0:61 / /tmp/private rw - ecryptfs /tmp/.private {ECRYPTFS_OPTS}\n\
         4 1 0:62 / /srv/vault rw - ecryptfs vault {ECRYPTFS_OPTS}\n\
         5 1 253:0 / /mnt/data rw,relatime - ext4 /dev/mapper/data rw\n"
    ));
    let targets = default_scan_targets(&mounts, "", Path::new("/mnt/data"));
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        vec![
            PathBuf::from("/dev/sda1"),
            PathBuf::from("tmpfs"),
            PathBuf::from("vault")
        ]
    );
    assert_eq!(targets[0].blind_spot, None);
    for target in &targets[1..] {
        assert!(
            target
                .blind_spot
                .as_deref()
                .is_some_and(|reason| reason.contains("eCryptfs")),
            "{target:?}"
        );
    }
    assert!(
        targets[1]
            .unread
            .as_deref()
            .is_some_and(|why| why.starts_with("a tmpfs mount, which has no block device")),
        "{targets:?}"
    );
    assert!(
        targets[2]
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("cannot place on a mount the table shows")),
        "{targets:?}"
    );

    let report = scan(TOKEN, &targets[1..], None).unwrap();
    assert!(report.inconclusive() && report.incomplete(), "{report:?}");
}

#[test]
fn a_whole_disk_named_for_a_scan_is_not_checked_when_it_holds_an_ecryptfs_folder() {
    use crate::forensic::layout::tests::{mbr_image, put};
    // The encrypted home above, on /dev/sda2. A whole disk named with
    // --device has no mount entry, and its raw bytes show a plain ext4 in
    // each partition, yet it holds the folder: a blind spot, which the scan
    // keeps over what the bytes show. The other disk, and the partition
    // beside the folder's, hold none.
    let sysfs = Sysfs::two_disks();
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 0:50 / /home/alice rw,nosuid,nodev,relatime - ecryptfs /home/alice/.Private \
         {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    let disk = ScanTarget::classified(&sysfs.0, PathBuf::from("/dev/sda"), &mounts);
    assert!(disk.probe && disk.fstype.is_none(), "{disk:?}");
    assert_eq!(disk.blind_spot, stacked);
    assert_eq!(sysfs.blind_spot("/dev/sda3", &mounts), None);
    assert_eq!(sysfs.blind_spot("/dev/sdb", &mounts), None);

    let dir = tempfile::tempdir().unwrap();
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768), (0x83, 34816, 32768)]);
    put(&mut file, (1 << 20) + 0x400, &ext4_superblock(4096));
    put(&mut file, (17 << 20) + 0x400, &ext4_superblock(4096));
    file.sync_all().unwrap();
    assert_eq!(verdict(path.clone()), None, "the bytes alone read clean");
    let report = scan(
        TOKEN,
        &[ScanTarget {
            device: path,
            ..disk
        }],
        None,
    )
    .unwrap();
    assert!(report.inconclusive() && !report.incomplete(), "{report:?}");
    assert_eq!(report.devices[0].blind_spot, stacked);
}

#[test]
fn an_ecryptfs_folder_marks_every_device_below_its_filesystem() {
    // The root is an LVM volume (dm-1) on a LUKS mapping (dm-0) of /dev/sda3,
    // /srv an md array of sdb1 and sdc1, and each holds an eCryptfs folder:
    // every device below them holds a folder's files, /dev/sda1 none.
    const SDB1: &str = "/sys/devices/pci0/block/sdb/sdb1";
    const SDC: &str = "/sys/devices/pci0/block/sdc";
    const SDC1: &str = "/sys/devices/pci0/block/sdc/sdc1";
    const DM0: &str = "/sys/devices/virtual/block/dm-0";
    const DM1: &str = "/sys/devices/virtual/block/dm-1";
    const MD0: &str = "/sys/devices/virtual/block/md0";
    let sysfs = Sysfs::two_disks();
    sysfs
        .partition(SDB1, "sdb1", "8:17", 1)
        .device(SDC, "sdc", "8:32")
        .partition(SDC1, "sdc1", "8:33", 1)
        .device(DM0, "dm-0", "253:0")
        .on(DM0, &[SDA3])
        .device(DM1, "dm-1", "253:1")
        .on(DM1, &[DM0])
        .device(MD0, "md0", "9:0")
        .on(MD0, &[SDB1, SDC1]);
    let mounts = parse_mountinfo(&format!(
        "1 0 253:1 / / rw,relatime - ext4 /dev/mapper/vg-root rw\n\
         2 1 9:0 / /srv rw,relatime - xfs /dev/md0 rw\n\
         3 1 0:50 / /home/alice rw,relatime - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n\
         4 2 0:51 / /srv/vault rw,relatime - ecryptfs /srv/.vault {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    for device in [
        "/dev/dm-1",
        "/dev/dm-0",
        "/dev/sda3",
        "/dev/sda",
        "/dev/md0",
        "/dev/sdb1",
        "/dev/sdc",
    ] {
        assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
    }
    assert_eq!(sysfs.blind_spot("/dev/sda1", &mounts), None);
}

#[test]
fn an_ecryptfs_folder_in_a_loop_mounted_image_marks_the_image_and_what_holds_it() {
    // A vault image on /home (sda2) is attached to loop0 and mounted at
    // /mnt/vault, with an eCryptfs folder on it. The image named as a file,
    // the loop device, the partition that holds the image and its disk hold
    // the folder's files; another image and the root's partition do not.
    const LOOP0: &str = "/sys/devices/virtual/block/loop0";
    let sysfs = Sysfs::two_disks();
    sysfs.device(LOOP0, "loop0", "7:0");
    let fs = &sysfs.0;
    fs.mock_set_file_content(
        &format!("{LOOP0}/loop/backing_file"),
        "/home/alice/vault.img\n",
    );
    fs.mock_set_device_id(
        Path::new("/home/alice/vault.img"),
        rustix::fs::makedev(8, 2),
    );
    fs.mock_add_file("/home/alice/vault.img", "");
    fs.mock_add_file("/home/alice/other.img", "");
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 1 7:0 / /mnt/vault rw,relatime - ext4 /dev/loop0 rw\n\
         4 3 0:50 / /mnt/vault/alice rw,relatime - ecryptfs /mnt/vault/.Private \
         {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    for device in [
        "/home/alice/vault.img",
        "/dev/loop0",
        "/dev/sda2",
        "/dev/sda",
    ] {
        assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
    }
    for device in ["/home/alice/other.img", "/dev/sda1"] {
        assert_eq!(sysfs.blind_spot(device, &mounts), None, "{device}");
    }
}

#[test]
fn a_device_the_scan_cannot_place_an_ecryptfs_folder_against_is_not_checked() {
    // A folder on a tmpfs, or on no mount at all, lies on no device the scan
    // could name, so it cannot tell whether a device it is given holds the
    // folder's files: each is a blind spot, mounted or not.
    let sysfs = Sysfs::two_disks();
    let unsure = |reason: Option<String>| {
        reason.is_some_and(|reason| reason.contains("cannot tell whether this device holds them"))
    };
    let tmpfs = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 0:60 / /tmp rw - tmpfs tmpfs rw\n\
         3 2 0:61 / /tmp/private rw - ecryptfs /tmp/.private {ECRYPTFS_OPTS}\n"
    ));
    let nowhere = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 0:62 / /srv/vault rw - ecryptfs vault {ECRYPTFS_OPTS}\n"
    ));
    for device in ["/dev/sda1", "/dev/sdb"] {
        assert!(unsure(sysfs.blind_spot(device, &tmpfs)), "{device}");
        assert!(unsure(sysfs.blind_spot(device, &nowhere)), "{device}");
    }

    // Nor can it tell for a path sysfs lists no block device for that is no
    // regular file either, beside a folder it does place. With no eCryptfs
    // mount, none of these is a blind spot.
    let home = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw\n\
         3 2 0:50 / /home/alice rw,relatime - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n"
    ));
    for device in ["/dev/nails-test-unlisted", "/srv/nails-test-no-file"] {
        assert!(unsure(sysfs.blind_spot(device, &home)), "{device}");
        assert_eq!(sysfs.blind_spot(device, &home[..2]), None, "{device}");
    }
}

#[test]
fn a_loop_image_on_storage_sysfs_cannot_place_leaves_the_scan_unable_to_tell() {
    // The vault image of a loop-mounted folder lies on an overlay: stat gives
    // the file the overlay's own anonymous device, which sysfs does not list,
    // and the overlay names no device. Its upper lies on the root partition,
    // but the scan cannot follow an overlay, so it cannot tell whether a disk
    // or partition holds the folder's files, and none is checked. The loop
    // device and the image file hold them.
    const LOOP0: &str = "/sys/devices/virtual/block/loop0";
    let sysfs = Sysfs::two_disks();
    sysfs.device(LOOP0, "loop0", "7:0");
    let fs = &sysfs.0;
    fs.mock_set_file_content(&format!("{LOOP0}/loop/backing_file"), "/srv/ov/vault.img\n");
    fs.mock_set_device_id(Path::new("/srv/ov/vault.img"), rustix::fs::makedev(0, 40));
    fs.mock_add_file("/srv/ov/vault.img", "");
    let table = format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 0:40 / /srv/ov rw,relatime - overlay overlay \
         rw,lowerdir=/srv/l,upperdir=/srv/u,workdir=/srv/w\n\
         3 1 7:0 / /mnt/vault rw,relatime - ext4 /dev/loop0 rw\n\
         4 3 0:50 / /mnt/vault/alice rw,relatime - ecryptfs /mnt/vault/.Private \
         {ECRYPTFS_OPTS}\n"
    );
    fs.mock_set_mount_table(&table);
    let mounts = parse_mountinfo(&table);
    for device in ["/dev/sda", "/dev/sda1", "/dev/sdb"] {
        let reason = sysfs.blind_spot(device, &mounts).unwrap_or_default();
        assert!(
            reason.contains("cannot tell whether this device holds them")
                && reason.contains("an image file stored on one"),
            "{device}: {reason}"
        );
    }
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    for device in ["/dev/loop0", "/srv/ov/vault.img"] {
        assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
    }
}

#[test]
fn every_member_of_a_wide_array_below_an_ecryptfs_folder_holds_it() {
    // /home is an md array of the first partitions of eight disks (sdc to
    // sdj) and holds an encrypted home: with each member's disk, seventeen
    // devices hold its files, all within what the scan follows. Each of
    // them holds the folder, and the disks outside the array do not.
    let sysfs = Sysfs::two_disks();
    let md0 = "/sys/devices/virtual/block/md0";
    let mut members = Vec::new();
    for (n, letter) in ('c'..='j').enumerate() {
        let disk = format!("/sys/devices/pci0/block/sd{letter}");
        let member = format!("{disk}/sd{letter}1");
        let minor = 32 + 16 * n;
        sysfs
            .device(&disk, &format!("sd{letter}"), &format!("8:{minor}"))
            .partition(
                &member,
                &format!("sd{letter}1"),
                &format!("8:{}", minor + 1),
                1,
            );
        members.push(member);
    }
    let below: Vec<&str> = members.iter().map(String::as_str).collect();
    sysfs.device(md0, "md0", "9:0").on(md0, &below);
    let mounts = parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         2 1 9:0 / /home rw,relatime - ext4 /dev/md0 rw\n\
         3 2 0:50 / /home/alice rw,relatime - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n"
    ));
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    for device in ["/dev/md0", "/dev/sdc1", "/dev/sdj1", "/dev/sdc", "/dev/sdj"] {
        assert_eq!(sysfs.blind_spot(device, &mounts), stacked, "{device}");
    }
    for device in ["/dev/sda", "/dev/sda1", "/dev/sdb"] {
        assert_eq!(sysfs.blind_spot(device, &mounts), None, "{device}");
    }
}

#[test]
fn more_devices_below_an_ecryptfs_folder_than_the_scan_follows_leave_it_unable_to_tell() {
    // More mappings stacked on /dev/sdb than the scan follows, the top one
    // holding an eCryptfs folder: the walk down stops before the disk, so the
    // scan cannot tell whether the disk, or any other device, holds the
    // folder, and says why. A mapping it did read still holds it.
    let sysfs = Sysfs::two_disks();
    let mut below = SDB.to_string();
    let top = super::ecryptfs::MAX_HOLDING_DEVICES;
    for n in 0..=top {
        let dir = format!("/sys/devices/virtual/block/dm-{n}");
        sysfs
            .device(&dir, &format!("dm-{n}"), &format!("253:{n}"))
            .on(&dir, &[&below]);
        below = dir;
    }
    let mounts = parse_mountinfo(&format!(
        "1 0 253:{top} / / rw,relatime - ext4 /dev/dm-{top} rw\n\
         2 1 0:50 / /home/alice rw,relatime - ecryptfs /home/alice/.Private {ECRYPTFS_OPTS}\n"
    ));
    for device in ["/dev/sdb", "/dev/dm-0", "/dev/sda"] {
        let reason = sysfs.blind_spot(device, &mounts).unwrap_or_default();
        assert!(
            reason.contains("cannot tell whether this device holds them")
                && reason.contains("than the scan follows"),
            "{device}: {reason}"
        );
    }
    let stacked = Some(ScanBlindSpot::StackedEncryption.reason().to_string());
    let read = format!("/dev/dm-{}", top - 1);
    assert_eq!(sysfs.blind_spot(&read, &mounts), stacked);
}
