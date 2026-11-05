// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mock's lookup errors (`mock_set_lookup_error`).

use super::{MockFilesystem, MockOp, PathKind};
use crate::NailsError;
use crate::filesystem::Filesystem;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// A directory whose lookups fail with `kind`, with a file below it and a
/// file beside it that a test also set up.
fn failing(kind: ErrorKind) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/srv/data", PathKind::Dir);
    fs.mock_add_file("/srv/data/file", "x");
    fs.mock_add_file("/srv/database", "y");
    fs.mock_set_lookup_error("/srv/data", kind);
    fs
}

/// The path and the kind of an error a lookup failed with.
fn failure<T: std::fmt::Debug>(result: crate::Result<T>) -> (PathBuf, ErrorKind) {
    match result {
        Err(NailsError::IoError { path, source }) => (path, source.kind()),
        other => panic!("expected the lookup to fail, got {other:?}"),
    }
}

/// Every read that looks the path up, or a path below it, fails with the
/// error set, naming the path asked.
#[test]
fn every_read_of_the_path_or_below_it_fails_naming_the_path() {
    let fs = failing(ErrorKind::PermissionDenied);
    for asked in ["/srv/data", "/srv/data/file", "/srv/data/a/b"] {
        let path = Path::new(asked);
        let reads: Vec<(&str, crate::Result<()>)> = vec![
            ("path_exists", fs.path_exists(path).map(drop)),
            ("is_directory", fs.is_directory(path).map(drop)),
            ("is_regular_file", fs.is_regular_file(path).map(drop)),
            ("is_symlink", fs.is_symlink(path).map(drop)),
            ("inode", fs.inode(path).map(drop)),
            ("record_lock_holder", fs.record_lock_holder(path).map(drop)),
            ("mount_root", fs.mount_root(path).map(drop)),
            ("canonicalize", fs.canonicalize(path).map(drop)),
            ("read_link", fs.read_link(path).map(drop)),
            ("read_file_content", fs.read_file_content(path).map(drop)),
            ("read_file_bytes", fs.read_file_bytes(path).map(drop)),
            ("read_file_range", fs.read_file_range(path, 0, 1).map(drop)),
            ("list_directory", fs.list_directory(path).map(drop)),
            ("file_size", fs.file_size(path).map(drop)),
            ("modified_time", fs.modified_time(path).map(drop)),
            ("change_time", fs.change_time(path).map(drop)),
            ("device_id", fs.device_id(path).map(drop)),
            ("get_permissions", fs.get_permissions(path).map(drop)),
            ("disk_usage", fs.disk_usage(path).map(drop)),
        ];
        for (read, result) in reads {
            assert_eq!(
                failure(result),
                (path.to_path_buf(), ErrorKind::PermissionDenied),
                "{read} of {asked}"
            );
        }
    }
}

/// A path beside it, one whose name only starts the same way among them, is
/// looked up as before.
#[test]
fn a_path_beside_it_is_looked_up() {
    let fs = failing(ErrorKind::PermissionDenied);
    fs.mock_set_path_type("/srv", PathKind::Dir);
    let beside = Path::new("/srv/database");
    assert!(fs.path_exists(beside).unwrap());
    assert!(fs.is_regular_file(beside).unwrap());
    assert_eq!(fs.read_file_content(beside).unwrap(), "y");
    assert_eq!(fs.canonicalize(beside).unwrap(), beside);
    // So is the directory that holds it.
    assert!(fs.is_directory(Path::new("/srv")).unwrap());
}

/// The kinds that say nothing is there: the four lookups that answer whether
/// something is there answer no, `inode` none for a missing path only, and
/// every other read fails as for a path that is not there.
#[test]
fn a_kind_that_says_nothing_is_there_answers_no() {
    for kind in [ErrorKind::NotFound, ErrorKind::NotADirectory] {
        let fs = failing(kind);
        let path = Path::new("/srv/data/file");
        assert!(!fs.path_exists(path).unwrap(), "{kind:?}");
        assert!(!fs.is_directory(path).unwrap(), "{kind:?}");
        assert!(!fs.is_regular_file(path).unwrap(), "{kind:?}");
        assert!(!fs.is_symlink(path).unwrap(), "{kind:?}");
        assert_eq!(failure(fs.read_file_content(path)), (path.into(), kind));
        assert_eq!(failure(fs.mount_root(path)), (path.into(), kind));
    }
    assert_eq!(
        failing(ErrorKind::NotFound)
            .inode(Path::new("/srv/data/x"))
            .unwrap(),
        None
    );
    // A lookup through a file is an error, not a missing path.
    assert_eq!(
        failure(failing(ErrorKind::NotADirectory).inode(Path::new("/srv/data/x"))),
        (PathBuf::from("/srv/data/x"), ErrorKind::NotADirectory)
    );
}

/// The reads that answer no on any error, as the real ones do, answer no.
#[test]
fn the_reads_that_answer_no_on_any_error_answer_no() {
    let fs = failing(ErrorKind::Other);
    fs.mock_set_whiteout("/srv/data/whiteout");
    fs.mock_set_writable("/srv/data/file", true);
    let file = Path::new("/srv/data/file");
    assert!(!fs.is_readable(file).unwrap());
    assert!(!fs.is_writable(file).unwrap());
    assert!(
        !fs.is_overlay_whiteout(Path::new("/srv/data/whiteout"))
            .unwrap()
    );
    // The write probe was still tried, as the real one tries it.
    assert!(
        fs.mock_ops()
            .contains(&MockOp::WritableProbe { path: file.into() })
    );
}

/// The first directory on the way that fails decides, as a real lookup
/// stops there.
#[test]
fn the_first_failing_directory_on_the_way_decides() {
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/srv/data/inner", ErrorKind::NotFound);
    fs.mock_set_lookup_error("/srv", ErrorKind::PermissionDenied);
    let path = Path::new("/srv/data/inner/file");
    assert_eq!(
        failure(fs.path_exists(path)),
        (path.to_path_buf(), ErrorKind::PermissionDenied)
    );
}

/// Writes are not affected: the error stands for a failed lookup, and only
/// the reads ask.
#[test]
fn writes_are_not_affected() {
    let fs = failing(ErrorKind::PermissionDenied);
    fs.write_file_content(Path::new("/srv/data/new"), "z")
        .unwrap();
    fs.create_directory(Path::new("/srv/data/dir")).unwrap();
    assert_eq!(
        fs.get_written_content(Path::new("/srv/data/new"))
            .as_deref(),
        Some("z")
    );
}

/// The lookups the mock follows through its links fail where a link leads
/// them to a failing path; the link itself is looked up as before.
#[test]
fn a_link_that_leads_there_fails_the_lookups_that_follow_it() {
    let fs = failing(ErrorKind::PermissionDenied);
    let link = Path::new("/etc/data");
    fs.create_symlink(Path::new("/srv/data/file"), link)
        .unwrap();
    assert_eq!(
        failure(fs.is_regular_file(link)),
        (link.to_path_buf(), ErrorKind::PermissionDenied)
    );
    assert_eq!(
        failure(fs.canonicalize(&link.join("x"))),
        (link.join("x"), ErrorKind::PermissionDenied)
    );
    assert!(fs.is_symlink(link).unwrap());
    assert_eq!(fs.read_link(link).unwrap(), Path::new("/srv/data/file"));
    // A link set on a failing directory is not reached at all.
    fs.create_symlink(Path::new("/etc"), Path::new("/srv/data/up"))
        .unwrap();
    assert_eq!(
        failure(fs.canonicalize(Path::new("/srv/data/up/passwd"))),
        (
            PathBuf::from("/srv/data/up/passwd"),
            ErrorKind::PermissionDenied
        )
    );
}

#[test]
fn reset_clears_the_lookup_errors() {
    let fs = failing(ErrorKind::PermissionDenied);
    fs.reset();
    assert!(!fs.path_exists(Path::new("/srv/data/file")).unwrap());
}
