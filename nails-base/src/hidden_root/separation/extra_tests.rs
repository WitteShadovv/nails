// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a filesystem keeps data on besides the device it is mounted from (an
//! XFS log or realtime device, an ext3 or ext4 journal on a device of its
//! own, the other devices of a bcachefs filesystem): on the root's own way
//! down, below an image file the root's data reaches, and in the claims of
//! the decoy's filesystems.

use super::*;

/// An XFS root on the separate disk `sdb` at `/mnt` on the plain decoy, whose
/// filesystem keeps data on `extra` too: a disk `sdc` of its own, the network
/// block device `nbd1` or the ZFS volume `zd0`.
fn xfs_on_sdb(extra: Extra) -> World {
    plain_decoy("5 1 8:16 / /mnt rw - xfs /dev/sdb rw,logdev=/dev/x,rtdev=/dev/y\n")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .node("nbd1", "43:1", NodeKind::Served(Served::Network), &[])
        .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
        .extra("8:16", extra)
}

fn devices(names: &[&str]) -> Extra {
    Extra::Devices(names.iter().map(|name| name.to_string()).collect())
}

#[test]
fn a_root_is_judged_with_every_device_its_filesystem_keeps_data_on() {
    // A log on a disk of its own is the root's storage too, and changes
    // nothing.
    assert_eq!(
        xfs_on_sdb(devices(&["sdc"])).verdict("/mnt"),
        Verdict::Separate
    );
    // A realtime device that a program serves holds the files' data.
    assert_eq!(
        xfs_on_sdb(devices(&["sdc", "nbd1"])).verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
    assert_eq!(
        xfs_on_sdb(devices(&["zd0"])).verdict("/mnt"),
        Verdict::UntracedDevice {
            kind: Untraced::ZfsVolume
        }
    );
}

#[test]
fn a_root_whose_other_devices_cannot_be_told_is_refused() {
    assert_eq!(
        xfs_on_sdb(Extra::NotFound).verdict("/mnt"),
        Verdict::UntracedDevice {
            kind: Untraced::NotFound
        }
    );
    let task = PathBuf::from("/sys/fs/ext4/sdb/journal_task");
    assert_eq!(
        xfs_on_sdb(Extra::Unreadable(task.clone())).verdict("/mnt"),
        Verdict::CouldNotJudge {
            unreadable: vec![task]
        }
    );
}

#[test]
fn a_root_whose_journal_lies_in_the_decoys_volume_group_shares_its_storage() {
    // Debian's LVM on LUKS: the root's own disk is separate, its journal is a
    // logical volume beside the decoy's root.
    let world = World::new(
        "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
         5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n",
    )
    .disk("sda", "8:0")
    .part("sda3", "8:3", "sda")
    .crypt("dm-0", "254:0", "cryptroot", &["sda3"])
    .lv("dm-1", "254:1", "vg-root", &["dm-0"])
    .lv("dm-4", "254:4", "vg-journal", &["dm-0"])
    .disk("sdb", "8:16")
    .fstab("/dev/mapper/vg-root / ext4 defaults 0 1\n");
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
    let world = world.extra("8:16", devices(&["dm-4"]));
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::InsideDecoyStorage {
            device: "dm-0".into(),
            holds: Claimed::Mount(PathBuf::from("/")),
            noauto_only: false,
        }
    );
}

#[test]
fn an_entry_that_opens_the_roots_log_device_is_one_for_the_hidden_drive() {
    let world = xfs_on_sdb(devices(&["dm-6"]))
        .crypt("dm-6", "254:6", "logbox", &["sdc"])
        .crypttab("logbox /dev/sdc none luks\n");
    let judgement = world.judge("/mnt");
    assert_eq!(judgement.verdict, Verdict::Separate);
    assert_eq!(judgement.entries.len(), 1, "{:?}", judgement.entries);
    assert_eq!(judgement.entries[0].kind, EntryKind::Blocking);
    assert_eq!(judgement.entries[0].line, "logbox /dev/sdc");
}

#[test]
fn an_image_file_on_a_filesystem_whose_log_a_program_serves_is_refused() {
    let world = |extra: Extra| {
        plain_decoy(
            "3 1 8:32 / /media/x rw - xfs /dev/sdc rw,logdev=/dev/nbd1\n\
             5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
        )
        .disk("sdc", "8:32")
        .node("nbd1", "43:1", NodeKind::Served(Served::Network), &[])
        .loop_file("loop0", "7:0", "/media/x/disk.img")
        .extra("8:32", extra)
    };
    assert_eq!(
        world(devices(&["nbd1"])).verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
    assert_eq!(
        world(Extra::NotFound).verdict("/mnt"),
        Verdict::UntracedDevice {
            kind: Untraced::NotFound
        }
    );
    assert_eq!(world(devices(&[])).verdict("/mnt"), Verdict::Separate);
}

#[test]
fn a_decoy_filesystem_claims_the_devices_it_keeps_data_on() {
    // The decoy's /srv is XFS with its log on a logical volume in a group on
    // sdc, and the root is another volume of that group.
    let world = plain_decoy(
        "3 1 8:17 / /srv rw - xfs /dev/sdb1 rw,logdev=/dev/mapper/vg-log\n\
         5 1 254:5 / /mnt rw - ext4 /dev/mapper/vg-data rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .disk("sdc", "8:32")
    .lv("dm-4", "254:4", "vg-log", &["sdc"])
    .lv("dm-5", "254:5", "vg-data", &["sdc"]);
    assert_eq!(world.verdict("/mnt"), Verdict::Separate);
    let world = world.extra("8:17", devices(&["dm-4"]));
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::InsideDecoyStorage {
            device: "sdc".into(),
            holds: Claimed::Mount(PathBuf::from("/srv")),
            noauto_only: false,
        }
    );
    assert!(world.claimed("/mnt").contains_key("dm-4"));
}

#[test]
fn a_decoy_filesystem_whose_other_devices_cannot_be_told_leaves_every_root_unjudged() {
    // What the decoy claims cannot be told, as with an fstab that cannot be
    // read: the root on a disk of its own is refused too.
    let jbd2 = PathBuf::from("/proc/fs/jbd2");
    let world = plain_decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n")
        .disk("sdb", "8:16")
        .extra("8:2", Extra::Unreadable(jbd2.clone()));
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::CouldNotJudge {
            unreadable: vec![jbd2]
        }
    );
    let world = plain_decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n")
        .disk("sdb", "8:16")
        .extra("8:2", Extra::NotFound);
    assert_eq!(world.verdict("/mnt"), Verdict::ClaimedDeviceNotFound);
}
