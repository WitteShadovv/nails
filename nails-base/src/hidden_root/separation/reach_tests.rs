// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the root's data reaches: disks that sysfs shows nothing below,
//! image files below image files, ways down that cannot be followed, and the
//! order of the verdicts that weigh them against the decoy's storage.

use super::*;

/// A logical volume in a group on the ZFS volume `zd0`, opened as `vault`
/// at `/mnt`, beside another one of the decoy's in the same group: `spare`
/// (`dm-2`), mounted by the decoy's fstab `line`, if any.
fn vault_in_a_group_on_a_zfs_volume(root: &str, line: &str) -> World {
    World::new(&format!(
        "{root}5 1 254:4 / /mnt rw - ext4 /dev/mapper/vault rw\n"
    ))
    .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
    .lv("dm-2", "254:2", "vg-spare", &["zd0"])
    .lv("dm-3", "254:3", "vg-vault", &["zd0"])
    .crypt("dm-4", "254:4", "vault", &["dm-3"])
    .fstab(line)
}

#[test]
fn a_zfs_volume_the_decoy_shares_is_refused_as_untraced() {
    // The shared group would be a refusal the override lifts, or with only a
    // noauto entry of the decoy's for it a warning; the ZFS volume below it
    // comes first, whether the decoy's root is the group's other volume or a
    // dataset, perhaps of the same pool.
    for (root, line) in [
        (
            "1 0 254:2 / / rw - ext4 /dev/mapper/vg-spare rw\n",
            "/dev/mapper/vg-spare / ext4 defaults 0 1\n",
        ),
        (
            "1 0 0:40 / / rw - zfs rpool/ROOT rw\n",
            "/dev/mapper/vg-spare /spare ext4 noauto 0 0\n",
        ),
    ] {
        let verdict = vault_in_a_group_on_a_zfs_volume(root, line).verdict("/mnt");
        assert_eq!(
            verdict,
            Verdict::UntracedDevice {
                kind: Untraced::ZfsVolume
            },
            "{line}"
        );
        assert_eq!(verdict.severity(), Severity::Refuse);
    }
}

#[test]
fn a_container_on_the_decoys_home_on_a_zfs_volume_is_refused_as_untraced() {
    // Unlike one on a ZFS dataset at /home, which only warns: the image's
    // filesystem is followed down to the volume.
    let home = World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 230:1 / /home rw - ext4 /dev/zd0p1 rw\n\
         5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
    .part("zd0p1", "230:1", "zd0")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n")
    .loop_file("loop0", "7:0", "/home/op/vault.hc")
    .crypt("dm-8", "254:8", "vault", &["loop0"]);
    assert_eq!(
        home.verdict("/mnt"),
        Verdict::UntracedDevice {
            kind: Untraced::ZfsVolume
        }
    );
    // So is another partition of the same volume.
    let beside = World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 230:1 / /home rw - ext4 /dev/zd0p1 rw\n\
         5 1 230:2 / /mnt rw - ext4 /dev/zd0p2 rw\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
    .part("zd0p1", "230:1", "zd0")
    .part("zd0p2", "230:2", "zd0")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n");
    assert_eq!(
        beside.verdict("/mnt"),
        Verdict::UntracedDevice {
            kind: Untraced::ZfsVolume
        }
    );
}

#[test]
fn a_noauto_entry_sharing_a_device_does_not_hide_a_served_disk() {
    // Sharing a device with a line the decoy never mounts at boot only warns;
    // the network block device below it refuses first.
    let world = plain_decoy("5 1 254:4 / /mnt rw - ext4 /dev/mapper/vault rw\n")
        .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[])
        .lv("dm-2", "254:2", "vg-spare", &["nbd0"])
        .lv("dm-3", "254:3", "vg-vault", &["nbd0"])
        .crypt("dm-4", "254:4", "vault", &["dm-3"])
        .fstab(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n\
             /dev/mapper/vg-spare /spare ext4 noauto 0 0\n",
        );
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
}

#[test]
fn a_partition_of_a_served_disk_the_decoy_uses_shares_nothing_with_another() {
    let world = plain_decoy(
        "4 1 43:2 / /srv rw - ext4 /dev/nbd0p2 rw\n\
         5 1 43:1 / /mnt rw - ext4 /dev/nbd0p1 rw\n",
    )
    .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[])
    .part("nbd0p1", "43:1", "nbd0")
    .part("nbd0p2", "43:2", "nbd0")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/nbd0p2 /srv ext4 defaults 0 2\n");
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
    assert!(!world.claimed("/mnt").contains_key("nbd0"));
}

#[test]
fn another_device_of_a_btrfs_root_is_followed() {
    let world = plain_decoy("5 1 0:60 / /mnt rw - btrfs /dev/sdb rw,subvol=/\n")
        .disk("sdb", "8:16")
        .node("ublkb0", "259:7", NodeKind::Served(Served::Userspace), &[])
        .btrfs(&["sdb", "ublkb0"]);
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Userspace
        }
    );
}

#[test]
fn a_served_disk_does_not_hide_an_image_no_filesystem_holds() {
    // The override lifts the served disk, so the image file below the same
    // array, which no override lifts, decides first.
    let world = plain_decoy("5 1 9:0 / /mnt rw - ext4 /dev/md0 rw\n")
        .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[])
        .loop_file_held("loop0", "7:0", "/media/gone/b.img", FileHolder::Unplaced)
        .node("md0", "9:0", NodeKind::Disk, &["nbd0", "loop0"]);
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::UnplacedImageFile {
            file: PathBuf::from("/media/gone/b.img")
        }
    );
}

#[test]
fn a_container_on_the_decoys_home_does_not_hide_a_served_disk() {
    // A container only warns: the served disk below the same array refuses.
    let world = plain_decoy("5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n")
        .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[])
        .loop_file("loop0", "7:0", "/home/op/a.img")
        .node("md0", "9:0", NodeKind::Disk, &["nbd0", "loop0"])
        .crypt("dm-8", "254:8", "vault", &["md0"]);
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
}

#[test]
fn the_reach_lists_each_device_once_down_to_an_image_files_filesystem() {
    // An md array over a disk and a loop device, whose file a btrfs
    // filesystem of two devices holds: every other device of that filesystem
    // is reached too, and each device once.
    let world = plain_decoy(
        "4 1 0:50 / /data rw - btrfs /dev/sdc rw,subvol=/\n\
         5 1 9:0 / /mnt rw - ext4 /dev/md0 rw\n",
    )
    .disk("sdb", "8:16")
    .disk("sdc", "8:32")
    .disk("sdd", "8:48")
    .btrfs(&["sdc", "sdd"])
    .loop_file("loop0", "7:0", "/data/disk.img")
    .node("md0", "9:0", NodeKind::Disk, &["sdb", "loop0"]);
    let reach = |stops: &[&str]| {
        let stops: BTreeSet<String> = stops.iter().map(|s| s.to_string()).collect();
        world.ask("/mnt", |scene, _| {
            super::super::judge::reach(scene, &["md0".to_string()], &stops)
        })
    };
    assert_eq!(reach(&[]), ["md0", "sdb", "loop0", "sdc", "sdd"]);
    // A device it is told to stop at, and what lies only below it, it does
    // not reach.
    assert_eq!(reach(&["sdc"]), ["md0", "sdb", "loop0"]);
}

#[test]
fn the_reach_goes_into_every_device_of_a_wide_array() {
    // More devices than any bound a walk had: the last one, which a program
    // serves, still refuses the root.
    let names: Vec<String> = (0..300).map(|n| format!("sd{n}")).collect();
    let mut world = plain_decoy("5 1 9:0 / /mnt rw - ext4 /dev/md0 rw\n").node(
        "nbd0",
        "43:0",
        NodeKind::Served(Served::Network),
        &[],
    );
    for (n, name) in names.iter().enumerate() {
        world = world.disk(name, &format!("8:{}", 1000 + n));
    }
    let below: Vec<&str> = names.iter().map(String::as_str).chain(["nbd0"]).collect();
    let world = world.node("md0", "9:0", NodeKind::Disk, &below);
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
}

#[test]
fn a_disk_of_an_unidentified_kind_cannot_be_judged_only_where_the_root_reaches_it() {
    let input = PathBuf::from("/proc/devices");
    let world = |line: &str| {
        plain_decoy(line)
            .node("sdb", "8:16", NodeKind::Unidentified(input.clone()), &[])
            .part("sdb1", "8:17", "sdb")
            .disk("sdc", "8:32")
    };
    // A partition of it is judged with its disk, whose kind decides.
    assert_eq!(
        world("5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n").verdict("/mnt"),
        Verdict::CouldNotJudge {
            unreadable: vec![input.clone()]
        }
    );
    assert_eq!(
        world("5 1 8:32 / /mnt rw - ext4 /dev/sdc rw\n").verdict("/mnt"),
        Verdict::Separate
    );
}

#[test]
fn a_zfs_volume_decides_before_the_decoys_filesystem_on_it() {
    // A root on one of the decoy's filesystems is a refusal the override
    // lifts; on a ZFS volume it is refused first, whether the decoy's fstab
    // mounts the root itself, the root is a bind of a filesystem of the
    // decoy's on the volume, or the fstab names an encrypted mapping on it.
    let zvol = Verdict::UntracedDevice {
        kind: Untraced::ZfsVolume,
    };
    let with_fstab = |world: World, line: &str| {
        world.fstab(&format!(
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n{line}"
        ))
    };
    let itself = with_fstab(
        plain_decoy("5 1 230:0 / /mnt rw - ext4 /dev/zd0 rw\n").node(
            "zd0",
            "230:0",
            NodeKind::Untraced(Untraced::ZfsVolume),
            &[],
        ),
        "/dev/zd0 /mnt ext4 defaults 0 2\n",
    );
    assert_eq!(itself.verdict("/mnt"), zvol);
    let mapping = with_fstab(
        plain_decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n")
            .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
            .crypt("dm-5", "254:5", "data", &["zd0"]),
        "/dev/mapper/data /mnt ext4 defaults 0 2\n",
    );
    assert_eq!(mapping.verdict("/mnt"), zvol);
    let bind = World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 230:0 / /srv rw - ext4 /dev/zd0 rw\n\
         5 1 230:0 /x /mnt rw - ext4 /dev/zd0 rw\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .node("zd0", "230:0", NodeKind::Untraced(Untraced::ZfsVolume), &[])
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/zd0 /srv ext4 defaults 0 2\n");
    assert_eq!(bind.verdict("/mnt"), zvol);

    // On an ordinary disk the same roots are the decoy's filesystem.
    let itself = with_fstab(
        plain_decoy("5 1 8:16 / /mnt rw - ext4 /dev/sdb rw\n").disk("sdb", "8:16"),
        "/dev/sdb /mnt ext4 defaults 0 2\n",
    );
    assert_eq!(
        itself.verdict("/mnt"),
        Verdict::OnDecoyFilesystem {
            how: Sharing::Filesystem,
            at: PathBuf::from("/mnt")
        }
    );
}

/// The hidden root in an image file on `/media/x`, a filesystem in the
/// image file of `loop1`, which `holder` holds, plus `extra` mount lines.
fn an_image_in_an_image(extra: &str, file: &str, holder: Option<FileHolder>) -> World {
    let world = plain_decoy(&format!(
        "{extra}4 1 7:1 / /media/x rw - ext4 /dev/loop1 rw\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n"
    ));
    let world = match holder {
        Some(holder) => world.loop_file_held("loop1", "7:1", file, holder),
        None => world.loop_file("loop1", "7:1", file),
    };
    world.loop_file("loop0", "7:0", "/media/x/root.img")
}

#[test]
fn an_image_file_below_an_image_file_is_judged_as_the_roots_own() {
    // The filesystem that holds the root's image file is in an image file
    // itself: where that file lies decides as if it held the root.
    assert_eq!(
        an_image_in_an_image("", "/media/gone/x.img", Some(FileHolder::Unplaced)).verdict("/mnt"),
        Verdict::UnplacedImageFile {
            file: PathBuf::from("/media/gone/x.img")
        }
    );
    let record = PathBuf::from("/dev/loop1");
    assert_eq!(
        an_image_in_an_image(
            "",
            "/media/y/x.img",
            Some(FileHolder::Unreadable(record.clone()))
        )
        .verdict("/mnt"),
        Verdict::CouldNotJudge {
            unreadable: vec![record]
        }
    );
    let fuse = an_image_in_an_image(
        "3 1 0:70 / /media/y rw - fuse.sshfs host:/srv rw\n",
        "/media/y/x.img",
        None,
    );
    assert_eq!(
        fuse.verdict("/mnt"),
        Verdict::UntracedStorage {
            fstype: "fuse".into()
        }
    );
    let served = an_image_in_an_image(
        "3 1 43:0 / /media/y rw - ext4 /dev/nbd0 rw\n",
        "/media/y/x.img",
        None,
    )
    .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[]);
    assert_eq!(
        served.verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
    // And an image file on the decoy's /home holds the root's data too.
    assert_eq!(
        an_image_in_an_image("", "/home/op/x.img", None).verdict("/mnt"),
        Verdict::ImageFileOnDecoy {
            file: PathBuf::from("/home/op/x.img"),
            at: PathBuf::from("/home")
        }
    );
    // On a disk the decoy does not use, it is separate.
    let apart = an_image_in_an_image(
        "3 1 8:16 / /media/y rw - ext4 /dev/sdb rw\n",
        "/media/y/x.img",
        None,
    )
    .disk("sdb", "8:16");
    assert_eq!(apart.verdict("/mnt"), Verdict::Separate);
}

#[test]
fn an_image_file_that_holds_a_filesystem_of_the_decoys_is_the_decoys_own() {
    // The decoy's /home is a filesystem in an image file on its /: a
    // container on /home only warns, as on any decoy filesystem, and the
    // image file below /home is not the root's.
    let world = World::new(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 7:1 / /home rw - ext4 /dev/loop1 rw\n\
         5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n",
    )
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/var/home.img /home ext4 loop 0 2\n")
    .loop_file("loop1", "7:1", "/var/home.img")
    .loop_file("loop0", "7:0", "/home/op/vault.hc")
    .crypt("dm-8", "254:8", "vault", &["loop0"]);
    assert_eq!(
        world.verdict("/mnt"),
        Verdict::ContainerOnDecoy {
            file: PathBuf::from("/home/op/vault.hc"),
            at: PathBuf::from("/home")
        }
    );
}

/// The decoy, with its `/home` on the network block device `nbd0`, and the
/// hidden root at `/mnt` in the file `/home/op/x.img`, on `loop0` itself or,
/// with `container`, in the encrypted mapping `vault` on it.
fn a_file_on_a_served_home(container: bool) -> World {
    let root = if container {
        "254:8 / /mnt rw - ext4 /dev/mapper/vault"
    } else {
        "7:0 / /mnt rw - ext4 /dev/loop0"
    };
    let world = World::new(&format!(
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
         2 1 43:0 / /home rw - ext4 /dev/nbd0 rw\n\
         5 1 {root} rw\n"
    ))
    .disk("sda", "8:0")
    .part("sda1", "8:1", "sda")
    .node("nbd0", "43:0", NodeKind::Served(Served::Network), &[])
    .fstab("/dev/sda1 / ext4 defaults 0 1\n/dev/nbd0 /home ext4 defaults 0 2\n")
    .loop_file("loop0", "7:0", "/home/op/x.img");
    if container {
        world.crypt("dm-8", "254:8", "vault", &["loop0"])
    } else {
        world
    }
}

#[test]
fn an_image_file_on_a_decoy_filesystem_on_a_served_disk_is_an_image_file_on_the_decoy() {
    // Both are refusals the override lifts; the image file on /home says
    // where the root's data lands, wherever nbd0 keeps it.
    assert_eq!(
        a_file_on_a_served_home(false).verdict("/mnt"),
        Verdict::ImageFileOnDecoy {
            file: PathBuf::from("/home/op/x.img"),
            at: PathBuf::from("/home")
        }
    );
    // An encrypted container there only warns, so the served disk below
    // /home decides: a refusal the override lifts.
    assert_eq!(
        a_file_on_a_served_home(true).verdict("/mnt"),
        Verdict::ServedDevice {
            kind: Served::Network
        }
    );
}

#[test]
fn a_way_down_that_cannot_be_followed_is_refused_wherever_it_is() {
    // A device sysfs does not list below the root's mapping.
    let unlisted = plain_decoy("5 1 254:5 / /mnt rw - ext4 /dev/mapper/data rw\n").crypt(
        "dm-5",
        "254:5",
        "data",
        &["sdq"],
    );
    assert_eq!(
        unlisted.verdict("/mnt"),
        Verdict::CouldNotJudge {
            unreadable: vec![PathBuf::from("/sys/class/block/sdq")]
        }
    );
    // A partition whose disk sysfs does not show, below the filesystem that
    // holds the root's image file.
    let world = plain_decoy(
        "3 1 259:9 / /media/y rw - ext4 /dev/sdz1 rw\n\
         5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n",
    )
    .part("sdz1", "259:9", "sdz")
    .loop_file("loop0", "7:0", "/media/y/x.img");
    assert_eq!(world.verdict("/mnt"), Verdict::DiskNotFound);
}

#[test]
fn a_device_shared_with_the_decoy_counts_however_wide_the_stack() {
    // An md array over forty disks and, last, the decoy's /home partition.
    let names: Vec<String> = (0..40).map(|n| format!("sd{n}")).collect();
    let mut world = plain_decoy("5 1 9:0 / /mnt rw - ext4 /dev/md0 rw\n");
    for (n, name) in names.iter().enumerate() {
        world = world.disk(name, &format!("8:{}", 1000 + n));
    }
    let below: Vec<&str> = names.iter().map(String::as_str).chain(["sda2"]).collect();
    let world = world.node("md0", "9:0", NodeKind::Disk, &below);
    assert!(
        matches!(
            world.verdict("/mnt"),
            Verdict::InsideDecoyStorage { ref device, .. } if device == "sda2"
        ),
        "{:?}",
        world.verdict("/mnt")
    );
}
