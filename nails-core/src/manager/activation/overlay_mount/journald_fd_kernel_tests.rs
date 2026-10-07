// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The journald re-home check against a real overlayfs, in a private user +
//! mount namespace (see `crate::test_support`).
//!
//! The unit tests in `fdinfo_tests` feed the classifier hand-made mount ids. This
//! one lets the kernel produce them: it mounts a base `/var`, opens a "journal"
//! there the way journald holds its file before the restart, mounts the overlay
//! on `/var` with the production mount code, reopens the journal through it, and
//! runs the real `/proc/<pid>/fd` + `fdinfo` + `mountinfo` inspection on this
//! process. It also pins down the kernel fact the first version of the check got
//! wrong: a file opened through an overlay does not report its upper layer's
//! `st_dev`.

use super::{
    JournalFdSite, JournaldFdCheck, classify_journald_fd_mounts, fdinfo_is_writable,
    inspect_journal_fds_of, parse_fdinfo_mnt_id, parse_main_pid,
};
use crate::filesystem::{Filesystem, RealFilesystem};
use crate::test_support::{Rerun, ScratchTmpfs};
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const JOURNAL: &str = "/var/log/journal/0123abcd/system.journal";

fn open_journal_for_append() -> std::fs::File {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(JOURNAL)
        .expect("open the journal for append")
}

#[test]
fn reopened_journal_fd_is_judged_by_mount_id_not_st_dev() {
    let _ = Rerun::new(crate::test_path!(
        reopened_journal_fd_is_judged_by_mount_id_not_st_dev
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy's base /var, private to this namespace.
        nix::mount::mount(
            Some("tmpfs"),
            "/var",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Some("mode=0755"),
        )
        .expect("mount a base tmpfs on /var");
        std::fs::create_dir_all(Path::new(JOURNAL).parent().unwrap()).unwrap();
        // journald's fd from before the restart: on the base /var.
        let stale = open_journal_for_append();

        // The /var overlay, mounted with the production options.
        let layers = ScratchTmpfs::new("");
        let lower = layers.mkdir("lower");
        let upper = layers.mkdir("upper");
        let work = layers.mkdir("work");
        RealFilesystem
            .mount_overlay(&[lower.as_path()], &upper, &work, Path::new("/var"))
            .expect("mount the /var overlay");
        std::fs::create_dir_all(Path::new(JOURNAL).parent().unwrap()).unwrap();
        // journald's fd after the restart: through the overlay.
        let rehomed = open_journal_for_append();

        // The fact the device comparison got wrong: the overlay reports its own
        // anonymous device, not the device of the upper file it wrote to.
        let upper_journal = upper.join(JOURNAL.trim_start_matches("/var/"));
        let upper_dev = std::fs::metadata(&upper_journal)
            .expect("the write was copied up")
            .dev();
        let overlay_dev = rehomed.metadata().unwrap().dev();
        assert_ne!(
            overlay_dev, upper_dev,
            "an overlay file's st_dev is not its upper layer's device"
        );

        let pid = std::process::id();
        let (verdict, detail) = inspect_journal_fds_of(pid, &upper);
        assert_eq!(
            verdict,
            JournaldFdCheck::NotInOverlay,
            "the fd still open on the base /var is a leak"
        );
        let detail = detail.expect("a leak names its fds");
        assert_eq!(
            detail.matches(JOURNAL).count(),
            1,
            "only the stale fd is named: {detail}"
        );

        drop(stale);
        assert_eq!(
            inspect_journal_fds_of(pid, &upper),
            (JournaldFdCheck::InOverlay, None),
            "with only the reopened fd left, the journal is re-homed"
        );
        drop(rehomed);
        assert_eq!(
            inspect_journal_fds_of(pid, Path::new("/nonexistent-upper")).0,
            JournaldFdCheck::Indeterminate,
            "a foreign upper dir matches no /var overlay"
        );
    });
}

/// Captured by `scripts/capture-kernel-fixtures.sh userns` (see the fixture
/// README): one scene, so the mount ids in the fdinfo files match the mountinfo.
const FIXTURES: [(&str, &str); 4] = [
    (
        "mountinfo",
        include_str!("../../../../tests/fixtures/kernel/userns/mountinfo-overlay-scene.txt"),
    ),
    (
        "append-base",
        include_str!("../../../../tests/fixtures/kernel/userns/fdinfo-append-base.txt"),
    ),
    (
        "append-overlay",
        include_str!("../../../../tests/fixtures/kernel/userns/fdinfo-append-overlay.txt"),
    ),
    (
        "readonly-overlay",
        include_str!("../../../../tests/fixtures/kernel/userns/fdinfo-readonly-overlay.txt"),
    ),
];

#[test]
fn captured_fdinfo_and_mountinfo_classify_like_the_live_check() {
    let fixture = |name: &str| FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
    let overlay = crate::filesystem::parse_mountinfo(fixture("mountinfo"))
        .into_iter()
        .find(|e| e.fstype == "overlay" && e.mount_point == Path::new("/fixture/var"))
        .expect("the captured overlay");
    assert_eq!(
        crate::filesystem::parse_overlay_opts(&overlay.super_opts).upperdir,
        Some(Path::new("/fixture/upper\\dir").to_path_buf())
    );

    assert!(!fdinfo_is_writable(fixture("readonly-overlay")));
    let site = |name: &str| {
        let fdinfo = fixture(name);
        assert!(fdinfo_is_writable(fdinfo), "{name} is an O_APPEND fd");
        JournalFdSite {
            target: name.into(),
            mnt_id: parse_fdinfo_mnt_id(fdinfo),
            dev: None,
        }
    };
    let both = [site("append-base"), site("append-overlay")];
    assert_eq!(
        classify_journald_fd_mounts(overlay.mount_id, &both).0,
        JournaldFdCheck::NotInOverlay
    );
    assert_eq!(
        classify_journald_fd_mounts(overlay.mount_id, &both[1..]),
        (JournaldFdCheck::InOverlay, None)
    );
}

/// The real daemon, captured as root in the decoy-journal-leak VM test right
/// after activation (fixture README): `systemctl show -p MainPID` names the
/// journald whose stat was captured, and its writable journal fds, judged
/// against the `/var` overlay in its own mountinfo, have been re-homed.
#[test]
fn captured_journald_was_rehomed_onto_the_var_overlay() {
    use crate::kernel_fixtures::vm;
    let (Some(main_pid), Some(stat), Some(mountinfo), Some(fds)) = (
        vm("systemctl-show-journald-mainpid.txt"),
        vm("proc-stat-journald.txt"),
        vm("mountinfo-journald.txt"),
        vm("journald-fds.txt"),
    ) else {
        return;
    };
    let pid = parse_main_pid(&main_pid).expect("journald runs");
    assert_eq!(stat.split(' ').next(), Some(pid.to_string().as_str()));

    let overlay = crate::filesystem::parse_mountinfo(&mountinfo)
        .into_iter()
        .rfind(|e| e.fstype == "overlay" && e.mount_point == Path::new("/var"))
        .expect("journald sees the /var overlay");
    let writable: Vec<JournalFdSite> = fds
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(_, target)| target.starts_with("/var/log/journal/"))
        .filter_map(|(fd, target)| {
            let fdinfo = vm(&format!("fdinfo-journald-{fd}.txt"))?;
            fdinfo_is_writable(&fdinfo).then(|| JournalFdSite {
                target: target.into(),
                mnt_id: parse_fdinfo_mnt_id(&fdinfo),
                dev: None,
            })
        })
        .collect();
    assert!(!writable.is_empty(), "journald writes a persistent journal");
    assert_eq!(
        classify_journald_fd_mounts(overlay.mount_id, &writable),
        (JournaldFdCheck::InOverlay, None)
    );
}
