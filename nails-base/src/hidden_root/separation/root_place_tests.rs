// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden root's place in a filesystem the decoy uses, for a root the
//! judge makes a folder or a subvolume of it: the folders other mounts show
//! it at, its path inside the filesystem and a subvolume's id.

use super::*;

#[test]
fn a_bind_of_a_folder_of_slash_is_placed_by_its_folder() {
    let place = plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n")
        .place("/mnt")
        .expect("a folder of /");
    assert_eq!(
        place,
        RootPlace {
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
fn a_subvolume_beside_home_is_placed_by_its_path_and_id() {
    let place = beside_home("")
        .place("/mnt")
        .expect("a subvolume of the btrfs of /home");
    assert_eq!(
        place,
        RootPlace {
            folders: Vec::new(),
            inside: PathBuf::from("/vault"),
            btrfs: true,
            subvolid: Some(300),
        }
    );
    // The filesystem's top mounted elsewhere shows the subvolume as a
    // folder there, and a mount of a folder inside it shows that folder: both
    // name the root. Another subvolume beside it names none of it.
    let place = beside_home(
        "6 1 0:40 / /media/top rw - btrfs /dev/sda2 rw,subvolid=5,subvol=/\n\
         7 1 0:40 /vault/inner /media/inner rw - btrfs /dev/sda2 rw,subvolid=300,subvol=/vault\n\
         8 1 0:40 /other /media/other rw - btrfs /dev/sda2 rw,subvolid=301,subvol=/other\n",
    )
    .place("/mnt")
    .expect("a subvolume of the btrfs of /home");
    assert_eq!(
        place.folders,
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
    let place = world.place("/mnt").expect("a folder of the btrfs of /");
    assert_eq!(place.folders, [PathBuf::from("/srv/x")]);
    assert_eq!(place.inside, Path::new("/@/srv/x"));
    assert_eq!(place.name(), "x");
    assert!(place.btrfs);
    // A bind has no subvolume id of its own: the id the mount shows is
    // that of the subvolume / shows, the decoy's own.
    assert_eq!(place.subvolid, None);
}

#[test]
fn on_an_encrypted_decoy_a_folder_of_slash_is_placed_as_well() {
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
    let place = world.place("/mnt").expect("a folder of /");
    assert_eq!(place.folders, [PathBuf::from("/srv/x")]);
}

/// A root that is the whole filesystem, a volume of its own and a root
/// whose storage the judge cannot read have no place; a folder of a drive
/// the decoy mounts at a folder that is no system folder has one, as a
/// folder of `/` has.
#[test]
fn only_a_folder_or_subvolume_of_a_decoy_filesystem_has_a_place() {
    // The whole of /home at the root: the root is the filesystem itself.
    assert_eq!(
        plain_decoy("5 1 8:2 / /mnt rw - ext4 /dev/sda2 rw\n").place("/mnt"),
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
    assert_eq!(
        pool.place("/mnt").map(|place| place.folders),
        Some(vec![PathBuf::from("/pool/x")])
    );
    // A volume of its own on another drive.
    assert_eq!(
        plain_decoy("5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n")
            .disk("sdb", "8:16")
            .part("sdb1", "8:17", "sdb")
            .place("/mnt"),
        None
    );
    // Inputs that could not be read: the judge cannot tell.
    assert_eq!(
        plain_decoy("5 1 8:1 /srv/x /mnt rw - ext4 /dev/sda1 rw\n")
            .unreadable("/etc/crypttab")
            .place("/mnt"),
        None
    );
}

/// A subvolume whose id the mount table gives as no number keeps its place
/// by its path, with no id.
#[test]
fn a_subvolume_whose_id_cannot_be_read_is_placed_without_an_id() {
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
    let place = world
        .place("/mnt")
        .expect("a subvolume of the btrfs of /home");
    assert_eq!(place.inside, Path::new("/vault"));
    assert_eq!(place.subvolid, None);
}
