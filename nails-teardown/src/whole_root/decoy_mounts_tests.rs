// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The record of the decoy's mounts, against given mount tables.

use super::*;
use crate::mountinfo::parse_mountinfo;

const HIDDEN: &str = "/mnt/data";

/// A carried mount as the entry records it: the filesystem and the
/// directory of it that the carried bind shows.
fn carried(target: &str, dev: &str, root: &str) -> CarriedMount {
    CarriedMount {
        target: PathBuf::from(target),
        at: Path::new("/mnt/data/root/decoy").join(target.trim_start_matches('/')),
        read_only: false,
        dev: Some(dev.to_string()),
        root: Some(PathBuf::from(root)),
    }
}

/// The record's mounts as (mount point, source, directory, options).
fn kept(record: &Record) -> Vec<(String, MountSource, String, String)> {
    record
        .mounts
        .iter()
        .map(|m| {
            (
                m.target.display().to_string(),
                m.source,
                m.path.display().to_string(),
                m.options.clone(),
            )
        })
        .collect()
}

fn lost(record: &Record) -> Vec<(String, Why)> {
    record
        .lost
        .iter()
        .map(|m| (m.target.display().to_string(), m.why))
        .collect()
}

fn entry(
    target: &str,
    source: MountSource,
    path: &str,
    options: &str,
) -> (String, MountSource, String, String) {
    (target.into(), source, path.into(), options.into())
}

/// A NixOS decoy whose store lives on its root disk, as a NixOS VM booted
/// through a bootloader shows it at entry: the store is a read-only bind of the root's
/// `/nix/store`, an fstab filesystem at /srv/data has a read-only bind of
/// itself stacked on top, and the API filesystems, `/run` with its mounts and
/// the hidden volume are there too.
const ON_DISK: &str = "\
36 1 253:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw
69 36 0:26 / /run rw,nosuid,nodev shared:2 - tmpfs tmpfs rw
75 36 0:32 / /tmp/xchg rw,relatime shared:5 - virtiofs xchg rw
37 36 0:6 / /dev rw,nosuid shared:7 - devtmpfs devtmpfs rw
38 37 0:33 / /dev/pts rw,nosuid,noexec,relatime shared:8 - devpts devpts rw
40 36 0:36 / /proc rw,nosuid,nodev,noexec,relatime shared:10 - proc proc rw
44 36 253:2 /nix/store /nix/store ro,nosuid,nodev,relatime shared:17 - ext4 /dev/vda2 rw
41 69 0:41 / /run/wrappers rw,nodev,relatime shared:22 - tmpfs tmpfs rw
48 36 253:1 / /boot rw,relatime shared:63 - vfat /dev/vda1 rw
52 36 253:32 / /srv/data rw,relatime shared:91 - ext4 /dev/vdc rw
66 36 254:0 / /mnt/data rw,relatime shared:254 - ext4 /dev/mapper/data rw
67 66 253:5 / /mnt/data/inner rw,relatime shared:255 - ext4 /dev/vde rw
112 52 253:32 / /srv/data ro,relatime shared:91 - ext4 /dev/vdc rw
";

fn on_disk_carried() -> Vec<CarriedMount> {
    vec![
        carried("/tmp/xchg", "0:32", "/"),
        carried("/boot", "253:1", "/"),
        // The bind of the top mount at /srv/data.
        carried("/srv/data", "253:32", "/"),
    ]
}

#[test]
fn every_mount_of_the_decoy_s_tree_is_kept_in_the_order_it_was_mounted() {
    let record = record(
        &parse_mountinfo(ON_DISK),
        Path::new(HIDDEN),
        &on_disk_carried(),
    );
    assert_eq!(
        kept(&record),
        vec![
            entry("/", MountSource::Root, "", "rw,relatime"),
            entry("/tmp/xchg", MountSource::Carried(0), "", "rw,relatime"),
            // The store bind: a directory of the root filesystem.
            entry(
                "/nix/store",
                MountSource::Root,
                "nix/store",
                "ro,nosuid,nodev,relatime"
            ),
            entry("/boot", MountSource::Carried(1), "", "rw,relatime"),
            // Both layers at /srv/data, the bottom first, from the one carry.
            entry("/srv/data", MountSource::Carried(2), "", "rw,relatime"),
            entry("/srv/data", MountSource::Carried(2), "", "ro,relatime"),
        ]
    );
    let ids: Vec<i32> = record.mounts.iter().map(|m| m.id).collect();
    assert_eq!(ids, [36, 75, 44, 48, 52, 112]);
    // The API filesystems, /run and the hidden volume are not the decoy's
    // tree: nothing of them is kept, and nothing is lost.
    assert!(record.lost.is_empty(), "{:?}", record.lost);
    assert!(record.mounts.iter().all(|m| m.restored.is_none()));
}

/// The test VMs' store: the initrd's overlay at /nix/store and NixOS's
/// read-only bind of it on top, with the reused lower ID 41 listed last, as
/// the kernel lists mounts in the order they were made.
const VM_STORE: &str = "\
62 1 253:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
65 62 0:30 / /nix/.ro-store ro,relatime shared:2 - virtiofs nix-store ro
74 62 0:31 / /nix/.rw-store rw,relatime shared:6 - tmpfs tmpfs rw,mode=755
85 62 0:34 / /nix/store rw,relatime shared:9 - overlay overlay rw,lowerdir=/sysroot/nix/.ro-store
41 85 0:34 / /nix/store ro,nosuid,nodev,relatime shared:10 - overlay overlay rw,lowerdir=/sysroot/nix/.ro-store
";

#[test]
fn a_stack_at_one_place_is_kept_bottom_first_from_the_carried_top() {
    let carried = [
        carried("/nix/.ro-store", "0:30", "/"),
        carried("/nix/.rw-store", "0:31", "/"),
        carried("/nix/store", "0:34", "/"),
    ];
    let record = record(&parse_mountinfo(VM_STORE), Path::new(HIDDEN), &carried);
    let store: Vec<(i32, &str)> = record
        .mounts
        .iter()
        .filter(|m| m.target == Path::new("/nix/store"))
        .map(|m| (m.id, m.options.as_str()))
        .collect();
    assert_eq!(
        store,
        [(85, "rw,relatime"), (41, "ro,nosuid,nodev,relatime")]
    );
    assert_eq!(record.mounts.len(), 5);
    assert!(record.lost.is_empty(), "{:?}", record.lost);
}

#[test]
fn a_mount_the_way_back_cannot_reach_is_lost_with_what_sits_on_it() {
    // /srv/data's own ext4 is covered by a tmpfs: the carried bind shows the
    // tmpfs, and nothing the session holds reaches the ext4. A disk mounted by
    // hand elsewhere is not carried at all.
    let table = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 8:3 / /srv/data rw,relatime - ext4 /dev/vdc rw
3 2 8:3 /sub /srv/data/sub rw,relatime - ext4 /dev/vdc rw
4 2 0:50 / /srv/data rw,relatime - tmpfs tmpfs rw
5 4 0:51 / /srv/data/cache rw,relatime - tmpfs tmpfs rw
6 1 8:33 / /media/usb rw,relatime - vfat /dev/sdb1 rw
7 6 8:2 /srv /media/usb/srv rw,relatime - ext4 /dev/vda2 rw
8 1 0:52 / /home/me/remote rw,nosuid,nodev,relatime - fuse.sshfs me@host: rw
";
    let carried = [carried("/srv/data", "0:50", "/")];
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &carried);
    assert_eq!(
        lost(&record),
        vec![
            ("/srv/data".into(), Why::NoWayBack),
            ("/srv/data/sub".into(), Why::ParentLost),
            ("/srv/data/cache".into(), Why::NoWayBack),
            ("/media/usb".into(), Why::NoWayBack),
            // A directory of the root filesystem, on a mount that is lost.
            ("/media/usb/srv".into(), Why::ParentLost),
            ("/home/me/remote".into(), Why::NoWayBack),
        ]
    );
    // The carried top is put back on what is there.
    assert_eq!(
        kept(&record),
        vec![
            entry("/", MountSource::Root, "", "rw,relatime"),
            entry("/srv/data", MountSource::Carried(0), "", "rw,relatime"),
        ]
    );
    assert!(record.lost.iter().any(Lost::ends_with_its_server));
}

#[test]
fn a_mount_with_a_flag_no_remount_sets_is_lost() {
    let table = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 8:2 /srv /srv rw,relatime,idmapped - ext4 /dev/vda2 rw
3 2 8:2 /srv/a /srv/a rw,relatime - ext4 /dev/vda2 rw
";
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &[]);
    assert_eq!(
        lost(&record),
        vec![
            ("/srv".into(), Why::Options),
            ("/srv/a".into(), Why::ParentLost)
        ]
    );
}

#[test]
fn a_btrfs_root_reaches_its_own_subvolume_alone() {
    // The root is the subvolume /@: a bind of a directory in it comes from
    // the root, the subvolume /@home from its carried mount alone.
    let table = "\
1 0 0:30 /@ / rw,noatime - btrfs /dev/nvme0n1p2 rw,subvol=/@
2 1 0:30 /@/nix/store /nix/store ro,nosuid,nodev,noatime - btrfs /dev/nvme0n1p2 rw,subvol=/@
3 1 0:30 /@home /home rw,noatime - btrfs /dev/nvme0n1p2 rw,subvol=/@home
4 3 0:30 /@home/me/stuff /srv/stuff rw,noatime - btrfs /dev/nvme0n1p2 rw,subvol=/@home
";
    let carried = [carried("/home", "0:30", "/@home")];
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &carried);
    assert_eq!(
        kept(&record),
        vec![
            entry("/", MountSource::Root, "", "rw,noatime"),
            entry(
                "/nix/store",
                MountSource::Root,
                "nix/store",
                "ro,nosuid,nodev,noatime"
            ),
            entry("/home", MountSource::Carried(0), "", "rw,noatime"),
            entry(
                "/srv/stuff",
                MountSource::Carried(0),
                "me/stuff",
                "rw,noatime"
            ),
        ]
    );
}

#[test]
fn a_mount_listed_before_the_one_it_sits_on_comes_after_it() {
    // A mount moved under a later one keeps its place in the table.
    let table = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
3 2 8:2 /x /srv/a/x rw,relatime - ext4 /dev/vda2 rw
2 1 8:2 /a /srv/a rw,relatime - ext4 /dev/vda2 rw
";
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &[]);
    let ids: Vec<i32> = record.mounts.iter().map(|m| m.id).collect();
    assert_eq!(ids, [1, 2, 3]);
}

#[test]
fn without_a_root_nothing_is_recorded() {
    let table = "2 1 8:2 / /srv rw,relatime - ext4 /dev/vda2 rw\n";
    assert_eq!(
        record(&parse_mountinfo(table), Path::new(HIDDEN), &[]),
        Record::default()
    );
}

#[test]
fn the_root_keeps_options_a_remount_sets_and_no_others() {
    let table = "1 0 8:2 / / rw,relatime,idmapped - ext4 /dev/vda2 rw\n";
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &[]);
    assert_eq!(record.mounts[0].options, "");
}

#[test]
fn per_mount_flags_set_exactly_what_the_table_shows() {
    use rustix::mount::MountFlags;
    assert_eq!(
        nextroot::per_mount_flags("ro,nosuid,nodev,relatime"),
        Some(MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::RELATIME)
    );
    // No access-time option is strict access times, set as such.
    assert_eq!(
        nextroot::per_mount_flags("rw,noexec"),
        Some(MountFlags::NOEXEC | MountFlags::STRICTATIME)
    );
    assert_eq!(
        nextroot::per_mount_flags("rw,noatime,nodiratime,nosymfollow"),
        Some(MountFlags::NOATIME | MountFlags::NODIRATIME | MountFlags::NOSYMFOLLOW)
    );
    assert_eq!(nextroot::per_mount_flags("rw,idmapped"), None);
    assert_eq!(nextroot::per_mount_flags("rw,unknown"), None);
}

#[test]
fn a_bind_of_a_file_or_directory_deleted_since_is_lost() {
    // The kernel shows the directory of such a bind as `<path>//deleted`; a
    // lookup of it can only fail. What sits on it goes with it.
    let table = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 8:2 /srv/file//deleted /etc/conf rw,relatime - ext4 /dev/vda2 rw
3 1 8:2 /srv/gone//deleted /mnt/view rw,relatime - ext4 /dev/vda2 rw
4 3 0:50 / /mnt/view/cache rw,relatime - tmpfs tmpfs rw
5 1 8:2 /srv/deleted /srv/kept rw,relatime - ext4 /dev/vda2 rw
";
    let carried = [carried("/mnt/view", "8:2", "/srv/gone//deleted")];
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &carried);
    assert_eq!(
        lost(&record),
        vec![
            ("/etc/conf".into(), Why::Deleted),
            ("/mnt/view".into(), Why::Deleted),
            ("/mnt/view/cache".into(), Why::ParentLost),
        ]
    );
    // A directory that is merely named "deleted" is kept.
    assert_eq!(
        kept(&record),
        vec![
            entry("/", MountSource::Root, "", "rw,relatime"),
            entry("/srv/kept", MountSource::Root, "srv/deleted", "rw,relatime"),
        ]
    );
    assert_eq!(record.lost[0].id, 2);
    assert!(Why::Deleted.to_string().contains("deleted"));
}

#[test]
fn a_filesystem_an_automount_point_mounted_is_left_to_the_decoy_s_start() {
    // An fstab `x-systemd.automount` ESP that an access mounted before the
    // entry: the vfat sits on PID 1's autofs. Put back on the bare mount
    // point, it would keep the decoy's start from setting up the automount,
    // which then fails; the decoy's start sets up both again instead.
    let table = "\
1 0 253:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 0:60 / /boot rw,relatime - autofs systemd-1 rw,fd=50,pgrp=1,timeout=0,direct
3 2 253:1 / /boot rw,relatime - vfat /dev/vda1 rw
4 3 253:1 /EFI /boot/efi-view rw,relatime - vfat /dev/vda1 rw
";
    let carried = [carried("/boot", "253:1", "/")];
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &carried);
    assert_eq!(
        lost(&record),
        vec![
            ("/boot".into(), Why::NoWayBack),
            ("/boot".into(), Why::Automounted),
            ("/boot/efi-view".into(), Why::ParentLost),
        ]
    );
    assert_eq!(record.mounts.len(), 1, "{:?}", record.mounts);
    assert!(record.lost[0].ends_with_its_server());
    assert!(record.lost[1].ends_with_its_server());
    assert!(!record.lost[2].ends_with_its_server());
}

#[test]
fn a_carried_filesystem_whose_mount_point_lies_on_a_lost_mount_is_lost() {
    // /srv/data was mounted on a tmpfs at /srv that the session does not
    // carry: the decoy root has no /srv/data to put it on. Where the lost
    // mount is stacked under the carried one, its mount point lies on the
    // root, and the carried one goes back on what is there.
    let table = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 0:50 / /srv rw,relatime - tmpfs tmpfs rw
3 2 8:3 / /srv/data rw,relatime - ext4 /dev/vdc rw
4 1 8:4 / /home rw,relatime - ext4 /dev/vdd rw
5 4 8:4 / /home rw,relatime - ext4 /dev/vdd rw
6 5 0:51 / /home rw,relatime - tmpfs tmpfs rw
";
    let carried = [
        carried("/srv/data", "8:3", "/"),
        carried("/home", "0:51", "/"),
    ];
    let record = record(&parse_mountinfo(table), Path::new(HIDDEN), &carried);
    assert_eq!(
        lost(&record),
        vec![
            ("/srv".into(), Why::NoWayBack),
            ("/srv/data".into(), Why::ParentLost),
            ("/home".into(), Why::NoWayBack),
            ("/home".into(), Why::ParentLost),
        ]
    );
    assert_eq!(
        kept(&record),
        vec![
            entry("/", MountSource::Root, "", "rw,relatime"),
            entry("/home", MountSource::Carried(1), "", "rw,relatime"),
        ]
    );
}

#[test]
fn a_lost_mount_says_why() {
    let lost = Lost {
        id: 52,
        target: PathBuf::from("/srv/data"),
        fstype: "ext4".into(),
        source: PathBuf::from("/dev/vdc"),
        why: Why::NoWayBack,
    };
    assert!(!lost.ends_with_its_server());
    assert!(
        lost.why.to_string().contains("carries no mount"),
        "{}",
        lost.why
    );
    for fstype in ["fuse", "fuse.sshfs", "autofs"] {
        let served = Lost {
            fstype: fstype.into(),
            ..lost.clone()
        };
        assert!(served.ends_with_its_server(), "{fstype}");
    }
    let automounted = Lost {
        why: Why::Automounted,
        ..lost
    };
    assert!(automounted.ends_with_its_server());
    assert!(automounted.why.to_string().contains("automount"));
}
