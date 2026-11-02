// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An offline scan of the system subvolume alone, without the subvolumes the
//! decoy mounts inside it, read as complete: a history in `@home` or a sudo
//! log in `@log` beside it was not read, and nothing said so. Every place the
//! decoy mounts something that holds nothing under the root is now listed as
//! not checked, by the scan and by the examiner's view.

use super::Verifier;
use crate::verify::{ExaminerOptions, VerifyResult, VerifyStatus};
use crate::{RealFilesystem, Result};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
                      bob:x:1001:1001:Bob:/srv/bob:/bin/zsh\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";

/// An archinstall layout: the system in `@`, the rest in subvolumes of
/// their own, mounted inside it.
const FSTAB: &str = "UUID=1 / btrfs rw,subvol=/@ 0 0\n\
                     UUID=1 /home btrfs rw,subvol=/@home 0 0\n\
                     UUID=1 /var/log btrfs rw,subvol=/@log 0 0\n\
                     UUID=1 /.snapshots btrfs rw,subvol=/@.snapshots 0 0\n\
                     UUID=2 /boot vfat rw,umask=0077 0 2\n\
                     tmpfs /tmp tmpfs defaults 0 0\n\
                     server:/srv /mnt/share nfs defaults 0 0\n\
                     /swapfile none swap defaults 0 0\n";

/// A decoy root at a temporary folder: `/etc` with `passwd`, the folders
/// `dirs` and the files `files` (path and text).
fn decoy(dirs: &[&str], files: &[(&str, &str)]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/passwd"), PASSWD).unwrap();
    for dir in dirs {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
    }
    for (file, text) in files {
        std::fs::write(root.path().join(file), text).unwrap();
    }
    root
}

fn scan(root: &Path, deep: bool, examiner: bool) -> Result<VerifyResult> {
    let mut verifier = Verifier::new(RealFilesystem).offline_under(root.to_path_buf());
    if examiner {
        verifier = verifier.with_examiner(ExaminerOptions::default());
    }
    verifier.run(deep)
}

/// The areas the scan lists for the places the decoy mounts something at.
fn unmounted(result: &VerifyResult) -> Vec<&str> {
    result
        .areas_not_checked
        .iter()
        .map(String::as_str)
        .filter(|area| area.contains("missing or empty under the root"))
        .collect()
}

fn home_of(user: &str, home: &str) -> String {
    format!(
        "{home}, the home of {user} in the decoy's /etc/passwd (missing or empty under the root: \
         mount what holds it there before the scan)"
    )
}

fn mount_point(point: &str) -> String {
    format!(
        "{point}, which the decoy's /etc/fstab mounts (missing or empty under the root: mount it \
         there before the scan)"
    )
}

#[test]
fn a_home_that_is_not_mounted_is_not_checked() {
    // The system subvolume alone: its /home is the empty folder @home is
    // mounted on, and alice's history lies in @home beside it. bob's home is
    // in place; root, daemon and nobody are no login accounts.
    let root = decoy(&["home", "srv/bob"], &[("srv/bob/.bash_history", "ls\n")]);
    for examiner in [false, true] {
        let result = scan(root.path(), true, examiner).unwrap();
        assert_eq!(result.status, VerifyStatus::Secure, "{:?}", result.findings);
        assert_eq!(
            unmounted(&result),
            [home_of("alice", "/home/alice")],
            "{:#?}",
            result.areas_not_checked
        );
        // The examiner's view reads the homes too, and says so as well.
        if let Some(report) = &result.examiner {
            assert!(
                report
                    .not_checked
                    .contains(&home_of("alice", "/home/alice")),
                "{:#?}",
                report.not_checked
            );
        }
    }
    // An empty home is not checked either, and one that holds a file is.
    std::fs::create_dir(root.path().join("home/alice")).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert_eq!(unmounted(&result), [home_of("alice", "/home/alice")]);
    std::fs::write(root.path().join("home/alice/.profile"), "").unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert!(
        unmounted(&result).is_empty(),
        "{:#?}",
        result.areas_not_checked
    );
}

#[test]
fn a_mount_point_of_the_decoys_fstab_that_holds_nothing_is_not_checked() {
    // @home, @log and @.snapshots are not mounted under the root, /boot is,
    // and /tmp, the share, the swap file and / itself hold nothing on the
    // disk scanned. alice's home lies under /home, which is listed already.
    let root = decoy(
        &["home", "var/log", "boot", "tmp", "srv/bob"],
        &[
            ("etc/fstab", FSTAB),
            ("boot/grub.cfg", ""),
            ("srv/bob/.profile", ""),
        ],
    );
    let result = scan(root.path(), false, true).unwrap();
    let listed = [
        mount_point("/.snapshots"),
        mount_point("/home"),
        mount_point("/var/log"),
    ];
    assert_eq!(
        unmounted(&result),
        listed,
        "{:#?}",
        result.areas_not_checked
    );
    let report = result.examiner.as_ref().expect("the examiner's view ran");
    for area in &listed {
        assert!(
            report.not_checked.contains(area),
            "{:#?}",
            report.not_checked
        );
    }

    // With each mounted in place, nothing is listed.
    for place in ["home/alice/.profile", "var/log/wtmp", ".snapshots/1"] {
        let file = root.path().join(place);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "").unwrap();
    }
    let result = scan(root.path(), false, true).unwrap();
    assert!(
        unmounted(&result).is_empty(),
        "{:#?}",
        result.areas_not_checked
    );
}

#[test]
fn a_link_is_not_followed() {
    // NixOS links /etc/fstab into /etc/static, which leads out of the image:
    // it is not read. A mount point or a home that is a link is not followed
    // either.
    let root = decoy(&["data", "home", "srv"], &[("etc/fstab.real", FSTAB)]);
    std::os::unix::fs::symlink("fstab.real", root.path().join("etc/fstab")).unwrap();
    std::os::unix::fs::symlink("/nonexistent", root.path().join("home/alice")).unwrap();
    std::os::unix::fs::symlink("../data", root.path().join("srv/bob")).unwrap();
    let result = scan(root.path(), false, false).unwrap();
    assert!(
        unmounted(&result).is_empty(),
        "{:#?}",
        result.areas_not_checked
    );
}

/// The access time of `path`, to the nanosecond.
fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Set the access time of `path` well behind its modification time, so that
/// `relatime` updates it on the next plain read.
fn backdate_atime(path: &Path) {
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    std::fs::File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(old))
        .unwrap();
}

#[test]
fn looking_for_the_unmounted_places_moves_no_access_time() {
    let root = decoy(
        &["home", "var/log", "boot", "srv/bob"],
        &[("etc/fstab", FSTAB), ("boot/grub.cfg", "")],
    );
    // Unless a plain read moves an access time here, keeping it proves
    // nothing.
    let probe = root.path().join("boot/grub.cfg");
    backdate_atime(&probe);
    let before = atime(&probe);
    let _ = std::fs::read(&probe).unwrap();
    if atime(&probe) == before {
        eprintln!("skipping: the temp filesystem does not record access times");
        return;
    }

    let read = [
        "etc/fstab",
        "etc/passwd",
        "home",
        "var/log",
        "boot",
        "srv/bob",
    ]
    .map(|place| root.path().join(place));
    for path in &read {
        backdate_atime(path);
    }
    let before: Vec<_> = read.iter().map(|path| atime(path)).collect();
    let areas = Verifier::new(RealFilesystem)
        .offline_under(root.path().to_path_buf())
        .unmounted_areas();
    assert!(!areas.is_empty(), "the places were looked at");
    let after: Vec<_> = read.iter().map(|path| atime(path)).collect();
    assert_eq!(after, before, "an access time moved: {read:?}");
}
