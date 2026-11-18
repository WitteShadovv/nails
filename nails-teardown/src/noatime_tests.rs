// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The tests of [`super`].

use super::*;

#[test]
fn the_flag_is_dropped_only_when_the_kernel_refuses_it() {
    let mut tried = Vec::new();
    let opened = with_noatime(|flags| {
        tried.push(flags);
        if flags.contains(OFlags::NOATIME) {
            Err(Errno::PERM)
        } else {
            Ok("plain")
        }
    });
    assert_eq!(opened, Ok("plain"));
    assert_eq!(tried, vec![OFlags::NOATIME, OFlags::empty()]);

    let mut calls = 0;
    assert_eq!(
        with_noatime(|_| {
            calls += 1;
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(calls, 1, "a granted flag needs no second open");

    let mut calls = 0;
    assert_eq!(
        with_noatime(|_| -> Result<()> {
            calls += 1;
            Err(Errno::NOENT)
        }),
        Err(Errno::NOENT)
    );
    assert_eq!(calls, 1, "any other error is the answer");
}

#[test]
fn a_mount_keeps_its_own_access_time_mode() {
    assert_eq!(atime_mode("rw,relatime"), Some(MOUNT_ATTR_RELATIME));
    assert_eq!(
        atime_mode("rw,nosuid,relatime,nodiratime"),
        Some(MOUNT_ATTR_RELATIME)
    );
    assert_eq!(atime_mode("rw"), Some(MOUNT_ATTR_STRICTATIME));
    assert_eq!(atime_mode("ro,nodiratime"), Some(MOUNT_ATTR_STRICTATIME));
    assert_eq!(atime_mode("rw,noatime"), None);
    assert_eq!(atime_mode("rw,noatime,relatime"), None);
}

/// Without the right to change mounts (a test runs unprivileged, or as
/// root of a user namespace of its own) nothing is changed, and a child
/// starts as it is.
#[test]
fn without_the_right_to_change_mounts_nothing_changes() {
    if may_spawn_without_access_times() {
        return;
    }
    let quiet = QuietMounts::open().unwrap();
    assert!(quiet.is_empty());
    assert_eq!(quiet.len(), 0);
    assert!(quiet_copy(std::path::Path::new("/")).is_none());
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", "exit 0"]);
    spawn_without_access_times(&mut command);
    assert!(command.status().unwrap().success());
}

fn source(dev: &str, root: &str, mode: u64) -> Source {
    Source {
        dev: dev.to_string(),
        root: std::path::PathBuf::from(root),
        mode,
    }
}

/// A bind made while the mounts were quiet gets the mode of the mount of
/// its filesystem whose root holds it, the deepest of several; a mount
/// listed before, one that keeps access times, one of another device and
/// one on a filesystem without them on a disk keep theirs.
#[test]
fn a_bind_made_while_quiet_gets_the_mode_of_the_mount_it_copies() {
    let table = "\
20 1 8:1 / / rw,noatime - ext4 /dev/sda1 rw
21 1 0:30 /root / rw,noatime - btrfs /dev/vda4 rw
22 1 0:30 /home /home rw,noatime - btrfs /dev/vda4 rw
30 20 8:1 / /run/nextroot/decoy ro,noatime - ext4 /dev/sda1 rw
31 20 0:30 /home/user /run/nextroot/home ro,noatime - btrfs /dev/vda4 rw
32 20 0:30 /root/var /run/nextroot/var rw,noatime - btrfs /dev/vda4 rw
33 20 8:1 /etc /run/nextroot/etc rw,relatime - ext4 /dev/sda1 rw
34 20 8:2 / /run/nextroot/boot rw,noatime - ext4 /dev/sda2 rw
35 20 0:40 / /run/nextroot/run rw,noatime - tmpfs tmpfs rw
";
    let mounts = crate::mountinfo::parse_mountinfo(table);
    let sources = [
        source("8:1", "/", MOUNT_ATTR_RELATIME),
        source("0:30", "/root", MOUNT_ATTR_STRICTATIME),
        source("0:30", "/home", MOUNT_ATTR_RELATIME),
    ];
    let got: Vec<(i32, u64)> = inherited(&sources, &[20, 21, 22], &mounts)
        .into_iter()
        .map(|(mount, mode)| (mount.mount_id, mode))
        .collect();
    assert_eq!(
        got,
        vec![
            (30, MOUNT_ATTR_RELATIME),
            (31, MOUNT_ATTR_RELATIME),
            (32, MOUNT_ATTR_STRICTATIME),
        ]
    );
}

fn record(id: i32, point: &str, dev: &str, root: &str, relatime: bool) -> QuietRecord {
    QuietRecord {
        mount_id: id,
        mount_point: std::path::PathBuf::from(point),
        dev: dev.to_string(),
        root: std::path::PathBuf::from(root),
        relatime,
    }
}

/// A record gives back its mode only to the mount it names that is still
/// `noatime`: a mount gone, one whose ID another mount took, and one
/// whose mode was changed since are left as they are.
#[test]
fn a_record_restores_only_the_mount_it_names_while_noatime() {
    let table = "\
20 1 8:1 / / rw,noatime - ext4 /dev/sda1 rw
22 1 0:30 /home /home rw,noatime - btrfs /dev/vda4 rw
24 1 8:2 / /boot rw,relatime - ext4 /dev/sda2 rw
25 1 0:31 / /srv rw,noatime - ext4 /dev/sdb1 rw
";
    let mounts = crate::mountinfo::parse_mountinfo(table);
    let records = [
        record(20, "/", "8:1", "/", true),
        record(22, "/home", "0:30", "/home", false),
        // Its mode was changed back since.
        record(24, "/boot", "8:2", "/", true),
        // Another mount took ID 25.
        record(25, "/srv", "8:3", "/", true),
        // Gone.
        record(26, "/data", "8:4", "/", true),
    ];
    let got: Vec<(i32, u64)> = to_restore(&records, &mounts)
        .into_iter()
        .map(|(record, mount)| (mount.mount_id, record.mode()))
        .collect();
    assert_eq!(
        got,
        vec![(20, MOUNT_ATTR_RELATIME), (22, MOUNT_ATTR_STRICTATIME)]
    );
    assert!(restore(&[]).is_empty());
}

/// The record goes into the plan and comes back as it was.
#[test]
fn a_record_reads_back_as_it_was_written() {
    let written = record(20, "/", "8:1", "/", true);
    let text = serde_json::to_string(&written).unwrap();
    assert_eq!(serde_json::from_str::<QuietRecord>(&text).unwrap(), written);
}

fn mount_line(line: &str) -> crate::mountinfo::MountEntry {
    crate::mountinfo::parse_mountinfo(line)
        .pop()
        .expect("a mount table line")
}

/// The mount of `mounts` at `point`, the first one listed there.
fn at<'a>(
    mounts: &'a [crate::mountinfo::MountEntry],
    point: &str,
) -> &'a crate::mountinfo::MountEntry {
    mounts
        .iter()
        .find(|mount| mount.mount_point == std::path::Path::new(point))
        .expect("a mount at the point")
}

/// An error that refuses the quiet mounts names the mount and its type.
#[test]
fn a_refusal_names_the_mount_and_its_type() {
    let mount =
        mount_line("46 30 0:48 / /mnt/data rw,relatime - fuse.sshfs h:/ rw,user_id=0,group_id=0\n");
    let error = naming(&mount, Errno::ACCESS.into());
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    let text = error.to_string();
    assert!(text.starts_with("/mnt/data (fuse.sshfs): "), "{text}");
    assert!(text.contains("os error 13"), "{text}");
}

/// Without a mount it changed, no mount takes a mode from it.
#[test]
fn without_a_changed_mount_no_mode_is_given() {
    let mounts =
        crate::mountinfo::parse_mountinfo("30 20 8:1 / /run/x ro,noatime - ext4 /dev/sda1 rw\n");
    assert!(inherited(&[], &[], &mounts).is_empty());
}

/// The mount ID is read from the kernel's record of a descriptor.
#[test]
fn the_mount_id_is_read_from_the_descriptor_s_record() {
    let text = "pos:\t0\nflags:\t012100000\nmnt_id:\t29\nino:\t2\n";
    assert_eq!(fdinfo_mount_id(text), Some(29));
    assert_eq!(fdinfo_mount_id("pos:\t0\nflags:\t0\n"), None);
    assert_eq!(fdinfo_mount_id("mnt_id:\tx\n"), None);
    assert_eq!(fdinfo_mount_id("my_mnt_id:\t3\n"), None);
}

/// On this kernel, the lookup of `/` reaches the mount there, whose ID the
/// descriptor's record gives as `statx(2)` does and as the mount table lists
/// it. No privilege is needed.
#[test]
fn a_lookup_of_the_root_names_its_mount() {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let mounts = crate::mountinfo::read_mountinfo().expect("read mountinfo");
    // A process whose root is no mount point (a chroot into a directory)
    // finds no mount listed at `/`: nothing to compare with.
    let Some(root) = crate::mountinfo::top_mount_at(&mounts, std::path::Path::new("/")) else {
        return;
    };
    let fd = open_walk(std::path::Path::new("/")).expect("look / up");
    let id = mount_id_of(&fd).expect("the descriptor's mount ID");
    assert_eq!(id, root.mount_id);
    let stat = statx(&fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).expect("statx");
    assert_eq!(i64::try_from(stat.stx_mnt_id).ok(), Some(i64::from(id)));
}

/// The window changes the local disk filesystems alone, and looks up through
/// those and the kernel's own: never FUSE, a network or cluster filesystem,
/// a stacked one, `autofs`, or a type neither list names.
#[test]
fn only_local_filesystems_are_changed_or_crossed() {
    for (fstype, changed, crossed) in [
        ("ext4", true, true),
        ("btrfs", true, true),
        ("xfs", true, true),
        ("vfat", true, true),
        ("f2fs", true, true),
        ("zfs", true, true),
        ("tmpfs", false, true),
        ("proc", false, true),
        ("sysfs", false, true),
        ("devtmpfs", false, true),
        ("squashfs", false, true),
        ("fusectl", false, true),
        ("fuse", false, false),
        ("fuseblk", false, false),
        ("fuse.sshfs", false, false),
        ("fuse.bindfs", false, false),
        ("virtiofs", false, false),
        ("9p", false, false),
        ("nfs", false, false),
        ("nfs4", false, false),
        ("cifs", false, false),
        ("smb3", false, false),
        ("ceph", false, false),
        ("pvfs2", false, false),
        ("orangefs", false, false),
        ("gfs2", false, false),
        ("ocfs2", false, false),
        ("overlay", false, false),
        ("ecryptfs", false, false),
        ("autofs", false, false),
        ("newfs", false, false),
        ("", false, false),
    ] {
        let mount = mount_line(&format!("40 1 0:50 / /mnt rw,relatime - {fstype} x rw\n"));
        assert_eq!(LOCAL_DISK.contains(&fstype), changed, "{fstype:?}");
        assert_eq!(crossable(&mount), crossed, "{fstype:?}");
    }
}

/// A table with FUSE, network and other mounts beside disks, each disk
/// mounted `relatime`:
/// - a user's FUSE mount (`gvfsd-fuse`, no `allow_other`) and a user's
///   `sshfs`;
/// - a `bindfs` everyone may enter (`allow_other`) with an ext4 bind mounted
///   inside it, and another disk inside that one;
/// - a 9p share mounted `cache=loose`, with a disk inside it;
/// - an NFS share with a disk mounted inside it;
/// - a disk at `/home/carol/data`, mounted before a FUSE mount at
///   `/home/carol` that covers it, and a disk at a FUSE mount's own point,
///   below it;
/// - a mount of a type no list names, and a disk inside it;
/// - an overlay and an automount point, each with a disk inside;
/// - disks below the root, `/run` (tmpfs) and each other alone, one at
///   `/home/bobby/data` beside the `bindfs` at `/home/bob`, and a FUSE mount
///   inside a disk;
/// - a disk mounted `noatime`.
const TABLE: &str = "\
1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
2 1 0:20 / /run rw,nosuid,nodev,relatime - tmpfs tmpfs rw
3 1 0:21 / /proc rw,relatime - proc proc rw
10 2 0:47 / /run/user/1000/gvfs rw,nosuid,nodev,relatime - fuse.gvfsd-fuse gvfsd-fuse rw,user_id=1000,group_id=1000
11 1 0:48 / /home/alice/remote rw,nosuid,nodev,relatime - fuse.sshfs alice@h:/ rw,user_id=1000,group_id=1000
20 1 0:49 / /home/bob rw,relatime - fuse.bindfs /srv/bob rw,user_id=0,group_id=0,default_permissions,allow_other
21 20 8:2 / /home/bob/inner rw,relatime - ext4 /dev/sda2 rw
22 21 8:3 / /home/bob/inner/deeper rw,relatime - ext4 /dev/sda3 rw
30 1 0:50 / /mnt/share rw,relatime - 9p host rw,trans=virtio,cache=loose
31 30 8:4 / /mnt/share/disk rw,relatime - ext4 /dev/sda4 rw
40 1 0:51 / /mnt/nfs rw,relatime - nfs4 srv:/export rw,vers=4.2
41 40 8:5 / /mnt/nfs/usb rw,relatime - vfat /dev/sdb1 rw
50 1 8:6 / /home/carol/data rw,relatime - ext4 /dev/sda6 rw
51 1 0:52 / /home/carol rw,nosuid,nodev,relatime - fuse.gocryptfs carol rw,user_id=1001,group_id=1001
52 1 8:7 / /mnt/stack rw,relatime - xfs /dev/sda7 rw
53 52 0:53 / /mnt/stack rw,relatime - fuse.rclone r: rw,user_id=0,group_id=0,allow_other
60 1 0:54 / /mnt/odd rw,relatime - newfs x rw
61 60 8:8 / /mnt/odd/disk rw,relatime - ext4 /dev/sda8 rw
70 1 0:55 / /var/lib/ov rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c
71 70 8:9 / /var/lib/ov/disk rw,relatime - ext4 /dev/sda9 rw
72 1 0:56 / /boot rw,relatime - autofs systemd-1 rw,fd=50,pgrp=1,timeout=0
73 72 8:10 / /boot rw,relatime - vfat /dev/sda10 rw
80 2 8:11 / /run/media/user/usb rw,nosuid,nodev,relatime - exfat /dev/sdc1 rw
81 1 8:12 / /srv rw,relatime - btrfs /dev/sda12 rw
82 81 8:13 / /srv/data rw,relatime - btrfs /dev/sda13 rw
83 1 8:14 / /home/bobby/data rw,relatime - ext4 /dev/sda14 rw
84 81 0:57 / /srv/fuse rw,nosuid,nodev,relatime - fuse.sshfs h:/ rw,user_id=1000,group_id=1000
85 1 8:15 / /var rw,noatime - ext4 /dev/sda15 rw
";

/// The mount points of `table` whose mounts the window changes.
fn window_of(table: &str) -> Vec<String> {
    let mounts = crate::mountinfo::parse_mountinfo(table);
    window(&mounts)
        .into_iter()
        .map(|(mount, _)| mount.mount_point.display().to_string())
        .collect()
}

/// The window takes the local disks a lookup reaches through local mounts
/// alone, decided from the mount table: no FUSE mount, whether a user's or
/// one everyone may enter, no 9p, NFS, overlay, automount or unknown mount,
/// and no disk inside one of them, below the mount point of one, or at its
/// point beneath it. A disk mounted `noatime` has nothing to change.
#[test]
fn the_window_takes_only_local_disks_reached_through_local_mounts() {
    assert_eq!(
        window_of(TABLE),
        [
            "/",
            "/run/media/user/usb",
            "/srv",
            "/srv/data",
            "/home/bobby/data",
        ]
    );
    let mounts = crate::mountinfo::parse_mountinfo(TABLE);
    for point in [
        "/run/user/1000/gvfs",
        "/home/alice/remote",
        "/home/bob",
        "/home/bob/inner",
        "/home/bob/inner/deeper",
        "/mnt/share",
        "/mnt/share/disk",
        "/mnt/nfs",
        "/mnt/nfs/usb",
        "/home/carol/data",
        "/home/carol",
        "/mnt/odd",
        "/mnt/odd/disk",
        "/var/lib/ov/disk",
        "/srv/fuse",
    ] {
        let mount = at(&mounts, point);
        assert!(!in_window(mount, &mounts), "{point} ({})", mount.fstype);
    }
    // At the point of a FUSE or automount mount stacked on it.
    for (point, fstype) in [("/mnt/stack", "xfs"), ("/boot", "vfat")] {
        let mount = mounts
            .iter()
            .find(|m| m.mount_point == std::path::Path::new(point) && m.fstype == fstype)
            .expect("the disk below");
        assert!(!in_window(mount, &mounts), "{point}");
    }
    // In the window but `noatime`: nothing to change.
    assert!(in_window(at(&mounts, "/var"), &mounts));
}

/// Out of the window, a mount is never looked up: [`reach`] answers `None`
/// for it before any lookup. Its mount point here has a name too long for
/// any filesystem, so that a lookup of it would fail with `ENAMETOOLONG`, as
/// it does for the same mount point in the window.
#[test]
fn a_mount_out_of_the_window_is_never_looked_up() {
    let long = "n".repeat(300);
    let table = format!(
        "\
1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
20 1 0:49 / /{long} rw,relatime - fuse.bindfs /x rw,user_id=0,group_id=0,allow_other
21 20 8:2 / /{long}/inner rw,relatime - ext4 /dev/sda2 rw
30 1 0:50 / /{long}-9p rw,relatime - 9p host rw,cache=loose
31 30 8:3 / /{long}-9p/disk rw,relatime - ext4 /dev/sda3 rw
"
    );
    let mounts = crate::mountinfo::parse_mountinfo(&table);
    assert_eq!(mounts.len(), 5);
    for mount in &mounts[1..] {
        assert!(!in_window(mount, &mounts), "{}", mount.fstype);
        assert!(
            matches!(reach(mount, &mounts), Ok(None)),
            "{}",
            mount.fstype
        );
    }
    // In the window, the same mount point is looked up, and the lookup fails.
    let local = crate::mountinfo::parse_mountinfo(&format!(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n21 1 8:2 / /{long}/inner rw,relatime - ext4 /dev/sda2 rw\n"
    ));
    assert!(in_window(&local[1], &local));
    assert!(matches!(reach(&local[1], &local), Err(Errno::NAMETOOLONG)));
}

/// The mounts a mount is mounted inside, up to one the table does not list,
/// without looping on a table whose parents form a ring.
#[test]
fn the_mounts_a_mount_is_inside_follow_its_parents() {
    let mounts = crate::mountinfo::parse_mountinfo(TABLE);
    assert_eq!(
        ancestors(at(&mounts, "/home/bob/inner/deeper"), &mounts),
        [21, 20, 1]
    );
    assert_eq!(ancestors(at(&mounts, "/home/carol/data"), &mounts), [1]);
    assert!(ancestors(&mounts[0], &mounts).is_empty());
    let ring = crate::mountinfo::parse_mountinfo(
        "5 6 8:1 / /a rw - ext4 a rw\n6 7 8:2 / /a/b rw - ext4 b rw\n7 6 8:3 / /a/b/c rw - ext4 c rw\n",
    );
    assert_eq!(ancestors(&ring[0], &ring), [6, 7]);
}

/// A mount inside a FUSE mount by the table's parent chain is out of the
/// window even where its mount point does not lie below the FUSE mount's, as
/// for a process whose root lies inside a mount; and a disk below the mount
/// point of a FUSE mount is out even where the chain does not hold the FUSE
/// mount, as for one the FUSE mount covers.
#[test]
fn either_the_chain_or_the_mount_point_takes_a_mount_out() {
    let mounts = crate::mountinfo::parse_mountinfo(
        "\
1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
20 1 0:49 / /fuse rw,relatime - fuse.bindfs /x rw,user_id=0,group_id=0,allow_other
21 20 8:2 / /elsewhere rw,relatime - ext4 /dev/sda2 rw
30 1 8:3 / /fuse/below rw,relatime - ext4 /dev/sda3 rw
",
    );
    assert!(in_window(at(&mounts, "/"), &mounts));
    assert!(!in_window(at(&mounts, "/elsewhere"), &mounts));
    assert!(!in_window(at(&mounts, "/fuse/below"), &mounts));
}
