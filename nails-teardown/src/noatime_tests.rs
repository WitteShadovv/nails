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

/// A FUSE mount of a user's, without `allow_other`, that root cannot
/// reach is left out of the quiet mounts: the kernel answers PID 1 as it
/// answers root. Any other mount, error, owner or kernel setting is not.
#[test]
fn only_a_fuse_mount_the_kernel_keeps_root_out_of_is_left_out() {
    let gvfs = mount_line(
        "45 30 0:47 / /run/user/1000/gvfs rw,nosuid,nodev,relatime - fuse.gvfsd-fuse gvfsd-fuse rw,user_id=1000,group_id=1000\n",
    );
    let n = Some("N\n");
    assert!(kept_from_root(&gvfs, Errno::ACCESS, n));
    assert!(kept_from_root(&gvfs, Errno::PERM, n));
    for other in [Errno::IO, Errno::NOTCONN, Errno::INTR, Errno::NOMEM] {
        assert!(!kept_from_root(&gvfs, other, n), "{other:?}");
    }
    // The kernel lets CAP_SYS_ADMIN through, or its setting is unknown.
    assert!(!kept_from_root(&gvfs, Errno::ACCESS, Some("Y\n")));
    assert!(!kept_from_root(&gvfs, Errno::ACCESS, None));

    for (line, left_out) in [
        // Plain fuse and fuseblk, and a group that is not root's.
        (
            "46 30 0:48 / /mnt/a rw,relatime - fuse sshfs rw,user_id=1000,group_id=1000",
            true,
        ),
        (
            "47 30 8:3 / /mnt/b rw,relatime - fuseblk /dev/sda3 rw,user_id=0,group_id=100",
            true,
        ),
        // Everyone may read it: what refused root is not the owner check.
        (
            "48 30 0:49 / /mnt/c rw,relatime - fuse.sshfs h:/ rw,user_id=1000,group_id=1000,allow_other",
            false,
        ),
        // Root's own.
        (
            "49 30 0:50 / /mnt/d rw,relatime - fuse.sshfs h:/ rw,user_id=0,group_id=0",
            false,
        ),
        // No owner listed.
        ("50 30 0:51 / /mnt/e rw,relatime - fuse.sshfs h:/ rw", false),
        (
            "51 30 0:52 / /mnt/f rw,relatime - fuse.sshfs h:/ rw,user_id=x,group_id=1000",
            false,
        ),
        // Not FUSE.
        (
            "52 30 8:1 / /mnt/g rw,relatime - ext4 /dev/sda1 rw,user_id=1000,group_id=1000",
            false,
        ),
        (
            "53 30 0:53 / /mnt/h rw,relatime - fusectl fusectl rw,user_id=1000,group_id=1000",
            false,
        ),
        (
            "54 30 0:54 / /mnt/i rw,relatime - fusefs x rw,user_id=1000,group_id=1000",
            false,
        ),
    ] {
        let mount = mount_line(&format!("{line}\n"));
        assert_eq!(kept_from_root(&mount, Errno::ACCESS, n), left_out, "{line}");
    }
}

/// A user's FUSE mount at `/home/bob`, mounted after the disk mount below it
/// at `/home/bob/data`, which it covers.
const BELOW_FUSE: &str = "\
50 30 8:2 / /home/bob/data rw,relatime - ext4 /dev/sda2 rw
60 30 0:47 / /home/bob rw,nosuid,nodev,relatime - fuse.gocryptfs bob rw,user_id=1000,group_id=1000
61 30 8:3 / /home/bobby/data rw,relatime - ext4 /dev/sda3 rw
62 30 8:4 / /srv rw,relatime - ext4 /dev/sda4 rw
63 62 8:5 / /srv/data rw,relatime - ext4 /dev/sda5 rw
";

/// The mount of [`BELOW_FUSE`] at `point`.
fn at<'a>(
    mounts: &'a [crate::mountinfo::MountEntry],
    point: &str,
) -> &'a crate::mountinfo::MountEntry {
    mounts
        .iter()
        .find(|mount| mount.mount_point == std::path::Path::new(point))
        .expect("a mount at the point")
}

/// A mount root cannot reach because a FUSE mount the kernel keeps root out
/// of lies at or above its mount point is covered: PID 1 cannot reach it
/// either. Not for another error, a FUSE mount root may enter, a mount that
/// is not FUSE above it, or a path that only starts with the same letters.
#[test]
fn a_mount_below_a_fuse_mount_kept_from_root_is_covered() {
    let mounts = crate::mountinfo::parse_mountinfo(BELOW_FUSE);
    let data = at(&mounts, "/home/bob/data");
    let fuse = |mount: &crate::mountinfo::MountEntry| mount.fstype.starts_with("fuse");
    assert!(below_kept_fuse(data, Errno::ACCESS, &mounts, fuse));
    assert!(below_kept_fuse(data, Errno::PERM, &mounts, fuse));
    for other in [Errno::IO, Errno::NOTCONN, Errno::NOENT] {
        assert!(!below_kept_fuse(data, other, &mounts, fuse), "{other:?}");
    }
    assert!(!below_kept_fuse(data, Errno::ACCESS, &mounts, |_| false));
    // Not below the FUSE mount: /home/bobby is not /home/bob.
    let bobby = at(&mounts, "/home/bobby/data");
    assert!(!below_kept_fuse(bobby, Errno::ACCESS, &mounts, |_| true));
    // Below a mount that is not FUSE.
    let srv = at(&mounts, "/srv/data");
    assert!(!below_kept_fuse(srv, Errno::ACCESS, &mounts, |_| true));
    // The FUSE mount itself is not below itself.
    let home = at(&mounts, "/home/bob");
    assert!(!below_kept_fuse(home, Errno::ACCESS, &mounts, |_| true));
    // A mount at the FUSE mount's own point, which the FUSE mount covers.
    let under = crate::mountinfo::parse_mountinfo(
        "59 30 8:6 / /home/bob rw,relatime - ext4 /dev/sda6 rw\n",
    );
    let both: Vec<_> = under.iter().chain(&mounts).cloned().collect();
    assert!(below_kept_fuse(&under[0], Errno::ACCESS, &both, fuse));
}

/// How [`judge_unreached`] judges the mount at `point` of [`BELOW_FUSE`],
/// refused with `error`, where FUSE's parameter reads as `parameter` and the
/// FUSE mount refuses root with `fuse_error` (`None`: root reaches it).
fn judged(
    point: &str,
    error: Errno,
    parameter: std::io::Result<String>,
    fuse_error: Option<Errno>,
) -> std::io::Result<()> {
    let mounts = crate::mountinfo::parse_mountinfo(BELOW_FUSE);
    judge_unreached(at(&mounts, point), error, &mounts, &parameter, |other| {
        assert_eq!(
            other.fstype, "fuse.gocryptfs",
            "only a FUSE mount is reached"
        );
        fuse_error
    })
}

/// A user's FUSE mount and a disk mount below it are left out where FUSE lets
/// root no further than its owner check; every other unreached mount is an
/// error naming it.
#[test]
fn an_unreached_mount_is_left_out_only_where_pid_1_cannot_reach_it() {
    let n = || Ok("N\n".to_string());
    let denied = Some(Errno::ACCESS);
    assert!(judged("/home/bob", Errno::ACCESS, n(), denied).is_ok());
    assert!(judged("/home/bob/data", Errno::ACCESS, n(), denied).is_ok());
    assert!(judged("/home/bob/data", Errno::PERM, n(), Some(Errno::PERM)).is_ok());
    for (point, error, parameter, fuse_error) in [
        // Root reaches the FUSE mount: something else keeps it out below.
        ("/home/bob/data", Errno::ACCESS, n(), None),
        // The FUSE mount fails for another reason.
        ("/home/bob/data", Errno::ACCESS, n(), Some(Errno::IO)),
        // The kernel lets CAP_SYS_ADMIN through.
        (
            "/home/bob/data",
            Errno::ACCESS,
            Ok("Y\n".to_string()),
            denied,
        ),
        ("/home/bob", Errno::ACCESS, Ok("Y\n".to_string()), denied),
        // Another error, and a mount below no FUSE mount.
        ("/home/bob/data", Errno::IO, n(), denied),
        ("/srv/data", Errno::ACCESS, n(), denied),
    ] {
        let error = judged(point, error, parameter, fuse_error).expect_err(point);
        let text = error.to_string();
        assert!(text.starts_with(&format!("{point} (")), "{text}");
        assert!(!text.contains("allow_sys_admin_access"), "{text}");
    }
}

/// Where FUSE has no `allow_sys_admin_access`, as before Linux 6.0, a mount
/// the rule would leave out is an error that names the parameter and the
/// kernel NAILS needs; one it cannot read is an error that says so.
#[test]
fn without_the_fuse_parameter_the_refusal_names_it_and_the_kernel_floor() {
    let missing = || Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    let denied = Some(Errno::ACCESS);
    assert_eq!(MIN_LINUX, (6, 1));
    for point in ["/home/bob", "/home/bob/data"] {
        let error = judged(point, Errno::ACCESS, missing(), denied).expect_err(point);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let text = error.to_string();
        assert!(
            text.starts_with(&format!("{point} (")),
            "names the mount: {text}"
        );
        assert!(text.contains("os error 13"), "{text}");
        assert!(text.contains(FUSE_SYS_ADMIN_ACCESS), "{text}");
        assert!(text.contains("Linux 6.0 added it"), "{text}");
        assert!(text.contains("NAILS needs Linux 6.1 or newer"), "{text}");
    }
    let unreadable = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let text = judged("/home/bob", Errno::ACCESS, unreadable, denied)
        .expect_err("refused")
        .to_string();
    assert!(text.contains("cannot be read"), "{text}");
    assert!(!text.contains("Linux 6.1"), "{text}");
    // A mount the rule would not leave out anyway gets the plain error.
    for (point, error) in [("/home/bob", Errno::IO), ("/srv/data", Errno::ACCESS)] {
        let text = judged(point, error, missing(), denied)
            .expect_err(point)
            .to_string();
        assert!(!text.contains("allow_sys_admin_access"), "{text}");
    }
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
