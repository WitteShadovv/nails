// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's own fstab lines for the filesystem a root is part of: the ones
//! its boot mounts at `/` and at the system folders, which a root that
//! `--allow-decoy-storage` accepted lies on by them, and the ones its boot
//! needs.

use super::*;

/// Each entry's line, and the system folder it is the decoy's own line for.
fn entry_folders(judgement: &Judgement) -> Vec<(&str, Option<&Path>)> {
    judgement
        .entries
        .iter()
        .map(|entry| (entry.line.as_str(), entry.system_folder.as_deref()))
        .collect()
}

#[test]
fn the_lines_the_boot_mounts_at_slash_and_the_system_folders_are_the_decoys_own() {
    for at in [
        "/",
        "/usr",
        "/var",
        "/home",
        "/srv",
        "/boot",
        "/efi",
        "/boot/efi",
        "/nix",
        "/opt",
    ] {
        assert!(is_system_folder(Path::new(at), Path::new("/mnt")), "{at}");
    }
    for at in [
        "/pool",
        "/var/log",
        "/home/u",
        "/.snapshots",
        "/mnt",
        "/media/u",
    ] {
        assert!(!is_system_folder(Path::new(at), Path::new("/mnt")), "{at}");
    }
    // A system folder that the hidden root is, or lies above, is the root's.
    assert!(!is_system_folder(Path::new("/srv"), Path::new("/srv")));
    assert!(!is_system_folder(
        Path::new("/boot/efi"),
        Path::new("/boot")
    ));

    // The decoy's lines for the filesystem a bind of a folder of /, or a
    // subvolume beside /home, is part of.
    let bind = plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n").judge("/mnt");
    assert_eq!(
        entry_folders(&bind),
        [("/dev/sda1 / ext4", Some(Path::new("/")))]
    );
    let subvolume = |fstab: &str| {
        World::new(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
             2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvol=/home\n\
             5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvol=/vault\n",
        )
        .disk("sda", "8:0")
        .part("sda1", "8:1", "sda")
        .part("sda2", "8:2", "sda")
        .btrfs(&["sda2"])
        .fstab(fstab)
        .judge("/mnt")
    };
    assert_eq!(
        entry_folders(&subvolume("/dev/sda2 /home btrfs subvol=/home 0 0\n")),
        [("/dev/sda2 /home btrfs", Some(Path::new("/home")))]
    );
    // A line for any other folder, below a system folder too, and one the
    // boot does not mount are none.
    assert_eq!(
        entry_folders(&subvolume(
            "/dev/sda2 /pool btrfs defaults 0 0\n/dev/sda2 /var/log btrfs subvol=/log 0 0\n\
             /dev/sda2 /srv btrfs noauto 0 0\n"
        )),
        [
            ("/dev/sda2 /pool btrfs", None),
            ("/dev/sda2 /var/log btrfs", None),
            ("/dev/sda2 /srv btrfs", None)
        ]
    );
    // Neither is a line for a device below the root's own, nor one for the
    // system folder the hidden root is mounted at.
    let below = plain_decoy("5 1 259:8 /x /mnt rw - ext4 /dev/loop1p1 rw\n")
        .node("loop1", "7:1", NodeKind::Loop { file: None }, &["sda2"])
        .part("loop1p1", "259:8", "loop1")
        .judge("/mnt");
    assert_eq!(entry_folders(&below), [("/dev/sda2 /home ext4", None)]);
    let at_the_root = plain_decoy("5 1 8:17 / /srv rw - ext4 /dev/sdb1 rw\n")
        .disk("sdb", "8:16")
        .part("sdb1", "8:17", "sdb")
        .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /srv ext4 defaults 0 2\n")
        .judge("/srv");
    assert_eq!(entry_folders(&at_the_root), [("/dev/sdb1 /srv ext4", None)]);
}

#[test]
fn the_decoys_line_for_slash_or_a_system_folder_is_one_its_boot_needs_for_a_whole_filesystem() {
    // The decoy's / and its /home partition, each mounted whole at the root
    // as well: the line for / or /home mounts the volume, and the decoy's own
    // boot needs it, so it is never one to remove.
    let whole_root = plain_decoy("5 1 8:1 / /mnt rw - ext4 /dev/sda1 rw\n").judge("/mnt");
    assert_eq!(
        entry_needs(&whole_root),
        [(EntryKind::Blocking, "/dev/sda1 / ext4", true)]
    );
    assert_eq!(whole_root.entries[0].why, "it mounts the volume at /mnt");
    assert_eq!(
        entry_folders(&whole_root),
        [("/dev/sda1 / ext4", Some(Path::new("/")))]
    );
    let whole_home = plain_decoy("5 1 8:2 / /mnt rw - ext4 /dev/sda2 rw\n").judge("/mnt");
    assert_eq!(
        entry_needs(&whole_home),
        [(EntryKind::Blocking, "/dev/sda2 /home ext4", true)]
    );
    // A line for it at any other folder may be the hidden drive's own: it is
    // one the volume alone needs, and goes.
    let elsewhere = plain_decoy(
        "5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n\
         6 1 8:17 / /backup rw - ext4 /dev/sdb1 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /backup ext4 defaults 0 2\n")
    .judge("/mnt");
    assert_eq!(
        entry_needs(&elsewhere),
        [(EntryKind::Blocking, "/dev/sdb1 /backup ext4", false)]
    );
    assert_eq!(
        entry_folders(&elsewhere),
        [("/dev/sdb1 /backup ext4", None)]
    );
}
