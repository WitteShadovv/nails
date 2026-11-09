// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::test_support::{CHILD_ENV, Outcome, Rerun};
use nix::fcntl::{FcntlArg, fcntl};
use nix::libc;
use rustix::fs::{FlockOperation, fcntl_lock};
use std::path::PathBuf;

/// A write lock over the whole file, as `F_SETLK` and `F_GETLK` take it.
fn whole_file(l_type: libc::c_int) -> libc::flock {
    libc::flock {
        l_type: l_type as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    }
}

/// The kind of error the query of `path` fails with.
fn error_kind(path: &Path) -> Option<std::io::ErrorKind> {
    record_lock_holder(path)
        .expect_err("the query fails")
        .io_kind()
}

#[test]
fn a_file_nobody_locks_has_no_holder() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unattended-upgrades.lock");
    std::fs::write(&path, "").unwrap();
    assert_eq!(record_lock_holder(&path).unwrap(), None);
}

#[test]
fn another_processs_posix_lock_names_that_process() {
    // apt's lock as unattended-upgrade takes it (GetLock(): F_SETLK, a write
    // lock over the whole file), held by this process while a child process
    // asks. The parent's pid names a file both find.
    fn shared(pid: u32) -> PathBuf {
        std::env::temp_dir().join(format!("nails-record-lock-{pid}"))
    }
    let in_child = std::env::var_os(CHILD_ENV).is_some();
    let held = (!in_child).then(|| {
        let path = shared(std::process::id());
        let file = std::fs::File::create(&path).unwrap();
        fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
        (path, file)
    });
    let outcome = Rerun::new(crate::test_path!(
        another_processs_posix_lock_names_that_process
    ))
    .run(|| {
        let parent = std::os::unix::process::parent_id();
        assert_eq!(
            record_lock_holder(&shared(parent)).unwrap(),
            Some(i32::try_from(parent).unwrap())
        );
    });
    if let Some((path, file)) = held {
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }
    assert_eq!(outcome, Outcome::Ran);
}

#[test]
fn an_open_file_description_lock_has_no_process() {
    // An open file description owns its lock, not the process, so even the
    // process that took it meets it; a read lock conflicts with a write lock
    // as a write lock does. Each lock needs its file open for its kind.
    for l_type in [libc::F_WRLCK, libc::F_RDLCK] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("unattended-upgrades.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fcntl(&file, FcntlArg::F_OFD_SETLK(&whole_file(l_type))).unwrap();
        assert_eq!(record_lock_holder(&path).unwrap(), Some(-1), "{l_type}");
        drop(file);
        assert_eq!(record_lock_holder(&path).unwrap(), None, "{l_type}");
    }
}

#[test]
fn the_callers_own_posix_lock_is_no_conflict_and_the_close_releases_it() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unattended-upgrades.lock");
    let file = std::fs::File::create(&path).unwrap();
    fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
    // An open file description lock's query meets the process's own POSIX
    // lock; it stays open, as closing it would release that lock.
    let probe = std::fs::File::open(&path).unwrap();
    let ofd_view = || {
        let mut lock = whole_file(libc::F_WRLCK);
        fcntl(&probe, FcntlArg::F_OFD_GETLK(&mut lock)).unwrap();
        (i32::from(lock.l_type), lock.l_pid)
    };
    let pid = i32::try_from(std::process::id()).unwrap();
    assert_eq!(ofd_view(), (libc::F_WRLCK, pid));
    assert_eq!(record_lock_holder(&path).unwrap(), None);
    // The query's close released it, as the close of any descriptor of the
    // file releases the process's POSIX locks on it.
    assert_eq!(ofd_view().0, libc::F_UNLCK);
    drop(probe);
    drop(file);
}

#[test]
fn what_is_no_regular_file_is_an_error_and_a_fifo_does_not_block() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("file");
    std::fs::write(&file, "").unwrap();
    // A link is not followed, not even to a regular file.
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(record_lock_holder(&link).is_err());
    // A directory opens, and is no regular file.
    assert_eq!(
        error_kind(tmp.path()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    // A FIFO with no writer would block a plain open for reading.
    let fifo = tmp.path().join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    assert_eq!(error_kind(&fifo), Some(std::io::ErrorKind::InvalidInput));
    assert_eq!(
        error_kind(&tmp.path().join("missing")),
        Some(std::io::ErrorKind::NotFound)
    );
}

#[test]
fn a_file_the_caller_may_not_read_is_an_error_but_to_root() {
    use std::os::unix::fs::PermissionsExt;
    // unattended-upgrade's lock file is root's, mode 0640.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unattended-upgrades.lock");
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if nix::unistd::geteuid().is_root() {
        assert_eq!(record_lock_holder(&path).unwrap(), None);
    } else {
        assert_eq!(
            error_kind(&path),
            Some(std::io::ErrorKind::PermissionDenied)
        );
    }
}
