// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The session's own storage below the hidden root, told by device
//! ([`Plan::is_hidden_storage`]).

use super::*;
use crate::mountinfo::parse_mountinfo;

/// No mount is on a loop device.
fn no_loop(_: &MountEntry) -> Option<String> {
    None
}

/// The loop device 7:0's backing file lies on the hidden volume (253:0), and
/// 7:1's on a decoy disk.
fn loops(mount: &MountEntry) -> Option<String> {
    match mount.dev.as_str() {
        "7:0" => Some("253:0".to_string()),
        "7:1" => Some("8:3".to_string()),
        _ => None,
    }
}

/// A session with the hidden volume (253:0) at `/mnt`, the decoy's `/home`
/// (8:3) carried at `/mnt/root/decoy/home`.
fn session() -> Plan {
    Plan {
        hidden_root: PathBuf::from("/mnt"),
        hidden_dev: Some("253:0".to_string()),
        upper: PathBuf::from("/mnt/root/upper"),
        work: PathBuf::from("/mnt/root/work"),
        carried: vec![CarriedMount {
            target: PathBuf::from("/home"),
            at: PathBuf::from("/mnt/root/decoy/home"),
            read_only: false,
            dev: Some("8:3".to_string()),
            root: Some(PathBuf::from("/")),
        }],
        ..sample()
    }
}

/// The mount table of that session, with `extra` lines.
fn table(extra: &str) -> Vec<MountEntry> {
    parse_mountinfo(&format!(
        "1 0 0:30 / / rw - overlay overlay rw,upperdir=/mnt/root/upper\n\
         2 1 253:0 / /mnt rw - ext4 /dev/mapper/data rw\n\
         3 2 8:3 / /mnt/root/decoy/home ro - ext4 /dev/vda3 rw\n{extra}"
    ))
}

/// The mount points in `mounts` that `plan` counts as the session's own.
fn own(plan: &Plan, mounts: &[MountEntry], loop_file: LoopFile) -> Vec<String> {
    mounts
        .iter()
        .filter(|mount| plan.is_hidden_storage_with(mount, loop_file))
        .map(|mount| mount.mount_point.display().to_string())
        .collect()
}

#[test]
fn a_disk_below_the_hidden_root_is_not_the_session_s_own() {
    // The hidden volume and the carried decoy /home are the session's own.
    // A USB disk at /mnt/usb, and a mount of the decoy's /home disk made by
    // hand next to it, are disks mounted during the session.
    let mounts = table(
        "4 2 8:33 / /mnt/usb rw - vfat /dev/sdc1 rw\n\
         5 2 8:3 / /mnt/peek rw - ext4 /dev/vda3 rw\n",
    );
    assert_eq!(
        own(&session(), &mounts, no_loop),
        ["/mnt", "/mnt/root/decoy/home"]
    );
}

#[test]
fn the_volume_wherever_a_folder_of_it_is_bound_and_a_loop_on_it_are_its_own() {
    let mounts = table(
        "4 2 253:0 /photos /mnt/photos rw - ext4 /dev/mapper/data rw\n\
         5 2 7:0 / /mnt/vm rw - ext4 /dev/loop0 rw\n\
         6 2 7:1 / /mnt/old rw - ext4 /dev/loop1 rw\n",
    );
    assert_eq!(
        own(&session(), &mounts, loops),
        ["/mnt", "/mnt/root/decoy/home", "/mnt/photos", "/mnt/vm"]
    );
    // Without the loop driver's record, a loop device is a disk like another.
    assert_eq!(
        own(&session(), &mounts, no_loop),
        ["/mnt", "/mnt/root/decoy/home", "/mnt/photos"]
    );
}

#[test]
fn a_disk_over_the_root_or_its_layers_is_not_its_own_and_one_below_them_is() {
    // A disk over the hidden root, or over the layers directory, covers the
    // volume: not the session's own. A mount further below the layers is
    // NAILS's, whatever it is, told by path alone: a carried filesystem the
    // hidden root resolved to another directory there, and so also a disk
    // someone mounts in NAILS's layers, beside them or over a carried one.
    let mounts = table(
        "4 2 8:33 / /mnt rw - vfat /dev/sdc1 rw\n\
         5 2 8:34 / /mnt/root rw - vfat /dev/sdc2 rw\n\
         6 2 8:1 / /mnt/root/decoy/boot ro - vfat /dev/vda1 rw\n\
         7 2 8:35 / /mnt/root/usb rw - vfat /dev/sdc3 rw\n\
         8 3 8:36 / /mnt/root/decoy/home rw - vfat /dev/sdc4 rw\n",
    );
    assert_eq!(
        own(&session(), &mounts, no_loop),
        [
            "/mnt",
            "/mnt/root/decoy/home",
            "/mnt/root/decoy/boot",
            "/mnt/root/usb",
            "/mnt/root/decoy/home"
        ]
    );
    assert!(!session().is_hidden_storage_with(&mounts[3], no_loop));
}

#[test]
fn nothing_outside_the_hidden_root_is_its_own() {
    // A bind of the volume, a loop on it, and a disk elsewhere: outside the
    // root nothing counts, as a root accepted on the decoy's storage can share
    // its device with the decoy's own filesystems.
    let mounts = table(
        "4 1 253:0 /photos /home/alice/photos rw - ext4 /dev/mapper/data rw\n\
         5 1 7:0 / /media/vm rw - ext4 /dev/loop0 rw\n\
         6 1 8:33 / /media/usb rw - vfat /dev/sdc1 rw\n\
         7 1 8:3 / /mnt2 rw - ext4 /dev/vda3 rw\n",
    );
    assert_eq!(
        own(&session(), &mounts, loops),
        ["/mnt", "/mnt/root/decoy/home"]
    );
}

#[test]
fn a_plan_without_the_device_counts_every_mount_below_the_root() {
    let legacy = Plan {
        hidden_dev: None,
        ..session()
    };
    let mounts = table(
        "4 2 8:33 / /mnt/usb rw - vfat /dev/sdc1 rw\n\
         5 1 8:34 / /media/usb rw - vfat /dev/sdc2 rw\n",
    );
    assert_eq!(
        own(&legacy, &mounts, loops),
        ["/mnt", "/mnt/root/decoy/home", "/mnt/usb"]
    );
}

#[test]
fn the_volume_is_shown_by_its_device_or_a_loop_on_it() {
    let mounts = table(
        "4 1 253:0 /photos /home/alice/photos rw - ext4 /dev/mapper/data rw\n\
         5 1 7:0 / /media/vm rw - ext4 /dev/loop0 rw\n\
         6 1 7:1 / /media/old rw - ext4 /dev/loop1 rw\n",
    );
    let shown: Vec<String> = mounts
        .iter()
        .filter(|mount| shows_hidden_volume(mount, "253:0", loops))
        .map(|mount| mount.mount_point.display().to_string())
        .collect();
    assert_eq!(shown, ["/mnt", "/home/alice/photos", "/media/vm"]);
}
