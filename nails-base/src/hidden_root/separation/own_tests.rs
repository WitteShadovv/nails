// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The filesystem a root that `--allow-decoy-storage` accepts as a folder or
//! a subvolume of it lies on, where the decoy mounts another part of it at
//! `/` or at a system folder: its devices, by name and number, and the names
//! of the root's own folder and subvolume.

use super::*;

fn device(name: &str, dev: &str) -> OwnDevice {
    OwnDevice {
        name: name.to_string(),
        dev: dev.to_string(),
    }
}

#[test]
fn a_bind_of_a_folder_of_slash_lies_on_the_device_of_slash() {
    let own = plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n")
        .own("/mnt")
        .expect("the filesystem of /");
    assert_eq!(
        own,
        OwnFilesystem {
            how: Sharing::Bind,
            at: PathBuf::from("/"),
            root: PathBuf::from("/mnt"),
            devices: vec![device("sda1", "8:1")],
            folders: vec![PathBuf::from("/srv/x")],
            inside: PathBuf::from("/srv/x"),
            btrfs: false,
            subvolid: None,
        }
    );
}

/// The decoy's / on sda1 and its /home a subvolume of the btrfs on sda2,
/// with the subvolume /vault (id 300) at the root, and `mounts` as well.
fn beside_home(mounts: &str) -> World {
    World::new(&format!(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/home\n\
         5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvolid=300,subvol=/vault\n{mounts}"
    ))
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .part("sda2", "8:2", "sda")
    .btrfs(&["sda2"])
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home btrfs subvol=/home 0 0\n")
}

#[test]
fn a_subvolume_beside_home_lies_on_the_device_of_home_and_is_named_by_its_path_and_id() {
    let own = beside_home("").own("/mnt").expect("the btrfs of /home");
    assert_eq!(
        own,
        OwnFilesystem {
            how: Sharing::Subvolume,
            at: PathBuf::from("/home"),
            root: PathBuf::from("/mnt"),
            devices: vec![device("sda2", "8:2")],
            folders: Vec::new(),
            inside: PathBuf::from("/vault"),
            btrfs: true,
            subvolid: Some(300),
        }
    );
    // The filesystem's top mounted elsewhere shows the subvolume as a
    // folder there, and a mount of a folder inside it shows that folder: both
    // name the root. Another subvolume beside it names none of it.
    let own = beside_home(
        "6 1 0:40 / /media/top rw - btrfs /dev/sda2 rw,subvolid=5,subvol=/\n\
         7 1 0:40 /vault/inner /media/inner rw - btrfs /dev/sda2 rw,subvolid=300,subvol=/vault\n\
         8 1 0:40 /other /media/other rw - btrfs /dev/sda2 rw,subvolid=301,subvol=/other\n",
    )
    .own("/mnt")
    .expect("the btrfs of /home");
    assert_eq!(
        own.folders,
        [
            PathBuf::from("/media/top/vault"),
            PathBuf::from("/media/inner")
        ]
    );
}

#[test]
fn a_bind_of_a_folder_of_a_btrfs_root_subvolume_is_named_by_its_folder_and_path() {
    let world = World::new(
        "1 0 0:30 /@ / rw - btrfs /dev/vda2 rw,subvolid=256,subvol=/@\n\
         5 1 0:30 /@/srv/x /mnt rw - btrfs /dev/vda2 rw,subvolid=256,subvol=/@\n",
    )
    .disk("vda", "253:0")
    .part("vda2", "253:2", "vda")
    .btrfs(&["vda2"])
    .fstab("/dev/vda2 / btrfs subvol=@ 0 0\n");
    let own = world.own("/mnt").expect("the btrfs of /");
    assert_eq!(own.how, Sharing::Bind);
    assert_eq!(own.at, Path::new("/"));
    assert_eq!(own.devices, [device("vda2", "253:2")]);
    assert_eq!(own.folders, [PathBuf::from("/srv/x")]);
    assert_eq!(own.inside, Path::new("/@/srv/x"));
    assert_eq!(own.name(), "x");
    assert!(own.btrfs);
    // A bind has no subvolume id of its own: the id the mount shows is
    // that of the subvolume / shows, the decoy's own.
    assert_eq!(own.subvolid, None);
}

#[test]
fn on_an_encrypted_decoy_the_root_lies_on_the_mapping_and_the_partition_below_it() {
    let world = World::new(
        "1 0 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n\
         5 1 254:0 /srv/x /mnt rw - ext4 /dev/mapper/cryptroot rw\n",
    )
    .disk("nvme0n1", "259:0")
    .part("nvme0n1p3", "259:3", "nvme0n1")
    .crypt("dm-0", "254:0", "cryptroot", &["nvme0n1p3"])
    .spec("UUID=e1", "nvme0n1p3")
    .fstab("/dev/mapper/cryptroot / ext4 defaults 0 1\n")
    .crypttab("cryptroot UUID=e1 none luks\n");
    let own = world.own("/mnt").expect("the filesystem of /");
    assert_eq!(
        own.devices,
        [device("dm-0", "254:0"), device("nvme0n1p3", "259:3")]
    );
    assert_eq!(own.at, Path::new("/"));
}

#[test]
fn no_filesystem_is_the_roots_own_unless_the_decoy_mounts_another_part_of_it_at_a_system_folder() {
    // The whole of /home at the root: the root is the filesystem itself.
    assert_eq!(
        plain_decoy("5 1 8:2 / /mnt rw - ext4 /dev/sda2 rw\n").own("/mnt"),
        None
    );
    // A folder of a drive the fstab mounts at /pool, no system folder.
    let pool = plain_decoy(
        "3 1 8:17 / /pool rw - ext4 /dev/sdb1 rw\n\
         5 1 8:17 /x /mnt rw - ext4 /dev/sdb1 rw\n",
    )
    .disk("sdb", "8:16")
    .part("sdb1", "8:17", "sdb")
    .fstab(
        "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
         /dev/sdb1 /pool ext4 defaults 0 2\n",
    );
    assert!(
        matches!(pool.verdict("/mnt"), Verdict::OnDecoyFilesystem { .. }),
        "{:?}",
        pool.verdict("/mnt")
    );
    assert_eq!(pool.own("/mnt"), None);
    // A volume of its own on another drive.
    assert_eq!(
        plain_decoy("5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n")
            .disk("sdb", "8:16")
            .part("sdb1", "8:17", "sdb")
            .own("/mnt"),
        None
    );
    // Inputs that could not be read: the judge cannot tell.
    assert_eq!(
        plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n")
            .unreadable("/etc/crypttab")
            .own("/mnt"),
        None
    );
    // No device of it known by its number: nothing to tell its names by.
    let mut world = plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n");
    world.devices.by_dev.clear();
    assert_eq!(world.own("/mnt"), None);
}

/// A subvolume whose id the mount table gives as no number could be named
/// by it unseen: nothing is the decoy's own.
#[test]
fn a_subvolume_whose_id_cannot_be_read_is_no_filesystem_of_the_decoys_own() {
    let world = World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 0:40 /home /home rw - btrfs /dev/sda2 rw,subvolid=257,subvol=/home\n\
         5 1 0:40 /vault /mnt rw - btrfs /dev/sda2 rw,subvol=/vault\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .part("sda2", "8:2", "sda")
    .btrfs(&["sda2"])
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home btrfs subvol=/home 0 0\n");
    assert!(
        matches!(
            world.verdict("/mnt"),
            Verdict::OnDecoyFilesystem {
                how: Sharing::Subvolume,
                ..
            }
        ),
        "{:?}",
        world.verdict("/mnt")
    );
    assert_eq!(world.own("/mnt"), None);
}
