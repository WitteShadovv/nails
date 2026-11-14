// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mock's lookup errors (`mock_set_lookup_error`) and
//! `Filesystem::entry_exists`.

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
            ("entry_exists", fs.entry_exists(path).map(drop)),
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
        assert!(!fs.entry_exists(path).unwrap(), "{kind:?}");
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
    assert!(fs.entry_exists(link).unwrap());
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

/// A lookup made to fail alone fails as it was told, an I/O error naming the
/// path or a lookup the guard did not make, while the other lookups of the
/// path and a path below it answer as set; reset clears it.
#[test]
fn a_lookup_made_to_fail_alone_leaves_the_others_of_its_path_as_they_are() {
    use super::{MockFailure, MockLookup};
    let fs = MockFilesystem::new();
    let file = Path::new("/srv/data");
    fs.mock_add_file("/srv/data", "x");
    fs.mock_fail_only(
        file,
        MockLookup::Read,
        MockFailure::Io(ErrorKind::PermissionDenied),
    );
    assert!(fs.is_regular_file(file).unwrap());
    assert!(fs.path_exists(file).unwrap());
    assert_eq!(
        failure(fs.read_file_content(file)),
        (file.to_path_buf(), ErrorKind::PermissionDenied)
    );
    assert_eq!(
        failure(fs.read_file_bytes(file)),
        (file.to_path_buf(), ErrorKind::PermissionDenied)
    );
    for lookup in [
        MockLookup::PathExists,
        MockLookup::IsDirectory,
        MockLookup::Canonicalize,
    ] {
        fs.mock_fail_only(file, lookup, MockFailure::Io(ErrorKind::Other));
    }
    assert_eq!(
        failure(fs.path_exists(file)),
        (file.to_path_buf(), ErrorKind::Other)
    );
    assert_eq!(
        failure(fs.is_directory(file)),
        (file.to_path_buf(), ErrorKind::Other)
    );
    assert_eq!(
        failure(fs.canonicalize(file)),
        (file.to_path_buf(), ErrorKind::Other)
    );
    assert!(fs.is_regular_file(file).unwrap());
    assert!(!fs.path_exists(Path::new("/srv/data/below")).unwrap());

    let point = PathBuf::from("/srv");
    fs.mock_fail_only(
        file,
        MockLookup::Read,
        MockFailure::NotLookedUp(point.clone()),
    );
    let error = fs.read_file_content(file).unwrap_err();
    assert_eq!(
        error.not_looked_up(),
        Some((file, &crate::error::Skip::Automount { point }))
    );
    fs.reset();
    fs.mock_add_file("/srv/data", "x");
    assert_eq!(fs.read_file_content(file).unwrap(), "x");
}

/// is_symlink and is_regular_file made to fail alone fail as they were told,
/// while the other lookups of the path answer as set, mount_root and the
/// lock query among them, which ask the same of the path on their own.
#[test]
fn a_link_or_file_lookup_made_to_fail_alone_leaves_the_others_as_they_are() {
    use super::{MockFailure, MockLookup};
    use crate::filesystem::MountRoot;
    let fs = MockFilesystem::new();
    let file = Path::new("/srv/data");
    fs.mock_add_file("/srv/data", "x");
    fs.mock_fail_only(
        file,
        MockLookup::IsSymlink,
        MockFailure::Io(ErrorKind::Other),
    );
    assert_eq!(
        failure(fs.is_symlink(file)),
        (file.to_path_buf(), ErrorKind::Other)
    );
    assert!(fs.is_regular_file(file).unwrap());
    assert!(fs.path_exists(file).unwrap());
    assert_eq!(fs.mount_root(file).unwrap(), MountRoot::Entry(None));
    fs.mock_fail_only(
        file,
        MockLookup::IsRegularFile,
        MockFailure::Io(ErrorKind::PermissionDenied),
    );
    assert_eq!(
        failure(fs.is_regular_file(file)),
        (file.to_path_buf(), ErrorKind::PermissionDenied)
    );
    assert!(fs.path_exists(file).unwrap());
    assert!(!fs.is_directory(file).unwrap());
    assert_eq!(fs.read_file_content(file).unwrap(), "x");
    assert_eq!(fs.record_lock_holder(file).unwrap(), None);
    let below = Path::new("/srv/data/below");
    assert!(!fs.is_symlink(below).unwrap());
    assert!(!fs.is_regular_file(below).unwrap());
}

/// An entry is there when the path itself is something, a link to nothing
/// included, and a link counts without its target being looked up.
#[test]
fn an_entry_is_whatever_is_at_the_path_itself() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/file", "x");
    fs.create_symlink(Path::new("/nowhere"), Path::new("/etc/dangling"))
        .unwrap();
    fs.create_symlink(Path::new("/etc/looped"), Path::new("/etc/looped"))
        .unwrap();
    fs.mock_set_lookup_error("/srv", ErrorKind::PermissionDenied);
    fs.create_symlink(Path::new("/srv/x"), Path::new("/etc/unreachable"))
        .unwrap();
    for present in [
        "/etc/file",
        "/etc/dangling",
        "/etc/looped",
        "/etc/unreachable",
    ] {
        assert!(fs.entry_exists(Path::new(present)).unwrap(), "{present}");
    }
    assert!(!fs.entry_exists(Path::new("/etc/missing")).unwrap());
    assert_eq!(
        failure(fs.entry_exists(Path::new("/srv/x"))),
        (PathBuf::from("/srv/x"), ErrorKind::PermissionDenied)
    );
}

/// Each read records the path it was asked about, in order; the mount
/// queries and the writes record none, and clearing forgets what was
/// recorded.
#[test]
fn every_read_records_the_path_it_was_asked_about() {
    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    fs.mock_set_directory_contents(Path::new("/etc"), vec![PathBuf::from("/etc/passwd")]);
    let path = Path::new("/etc/passwd");
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
        (
            "is_overlay_whiteout",
            fs.is_overlay_whiteout(path).map(drop),
        ),
        ("read_file_content", fs.read_file_content(path).map(drop)),
        ("read_file_bytes", fs.read_file_bytes(path).map(drop)),
        ("read_file_range", fs.read_file_range(path, 0, 1).map(drop)),
        ("file_size", fs.file_size(path).map(drop)),
        ("modified_time", fs.modified_time(path).map(drop)),
        ("change_time", fs.change_time(path).map(drop)),
        ("device_id", fs.device_id(path).map(drop)),
        ("loop_record", fs.loop_record(path).map(drop)),
        ("get_permissions", fs.get_permissions(path).map(drop)),
        ("disk_usage", fs.disk_usage(path).map(drop)),
        ("is_readable", fs.is_readable(path).map(drop)),
        ("is_writable", fs.is_writable(path).map(drop)),
        ("supports_symlinks", fs.supports_symlinks(path).map(drop)),
        (
            "list_directory",
            fs.list_directory(Path::new("/etc")).map(drop),
        ),
        (
            "find_files_with_pattern",
            fs.find_files_with_pattern(Path::new("/etc"), "pass")
                .map(drop),
        ),
        (
            "scan_files_with_pattern",
            fs.scan_files_with_pattern(Path::new("/etc"), "pass")
                .map(drop),
        ),
    ];
    let mut expected: Vec<PathBuf> = reads
        .iter()
        .map(|(read, _)| match *read {
            "list_directory" | "find_files_with_pattern" | "scan_files_with_pattern" => {
                PathBuf::from("/etc")
            }
            _ => path.to_path_buf(),
        })
        .collect();
    assert_eq!(fs.mock_lookups(), expected);

    // The reads a default method makes through another are recorded once.
    fs.read_file_in_root(Path::new("/"), path).unwrap();
    expected.push(path.to_path_buf());
    assert_eq!(fs.mock_lookups(), expected);

    let _ = fs.is_mounted(path);
    let _ = fs.get_filesystem_type(path);
    let _ = fs.mount_source(path);
    let _ = fs.is_mount_read_only(path);
    let _ = fs.mount_table();
    fs.write_file_content(Path::new("/etc/new"), "x").unwrap();
    let _ = fs.create_directory(Path::new("/etc/dir"));
    assert_eq!(fs.mock_lookups(), expected);

    fs.mock_clear_lookups();
    assert!(fs.mock_lookups().is_empty());
    fs.path_exists(path).unwrap();
    assert_eq!(fs.mock_lookups(), vec![path.to_path_buf()]);
    fs.reset();
    assert!(fs.mock_lookups().is_empty());
}

/// A read passes where the links on its way lead, and where the link at its
/// end leads unless it reads the link itself: the path asked alone does not
/// show that a lookup of `/etc/nixos/x` passes bob's home when `/etc/nixos`
/// links there.
#[test]
fn a_read_reaches_where_the_links_on_its_way_lead() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new("/home/bob/nixos"), Path::new("/etc/nixos"))
        .unwrap();
    fs.create_symlink(
        Path::new("../bob/nixos/flake.nix"),
        Path::new("/home/x/flake.nix"),
    )
    .unwrap();
    let bob = Path::new("/home/bob");

    // The link read itself passes no further.
    let _ = fs.is_symlink(Path::new("/etc/nixos"));
    let _ = fs.read_link(Path::new("/etc/nixos"));
    let _ = fs.mount_root(Path::new("/etc/nixos"));
    let _ = fs.is_overlay_whiteout(Path::new("/etc/nixos"));
    let _ = fs.change_time(Path::new("/etc/nixos"));
    let _ = fs.record_lock_holder(Path::new("/etc/nixos"));
    assert!(!fs.mock_reached(bob), "{:?}", fs.mock_lookups());
    assert!(fs.mock_reached(Path::new("/etc/nixos")));

    // A read that follows it, at the end or on the way, passes bob's home.
    for path in ["/etc/nixos", "/etc/nixos/configuration.nix"] {
        fs.mock_clear_lookups();
        let _ = fs.path_exists(Path::new(path));
        assert!(fs.mock_reached(bob), "{path}");
        assert_eq!(fs.mock_lookups(), [PathBuf::from(path)]);
    }
    // A relative target, from the directory that holds the link.
    fs.mock_clear_lookups();
    let _ = fs.read_file_content(Path::new("/home/x/flake.nix"));
    assert!(fs.mock_reached(bob));

    fs.mock_clear_lookups();
    let _ = fs.path_exists(Path::new("/etc/hostname"));
    assert!(!fs.mock_reached(bob));
    assert!(!fs.mock_reached(Path::new("/etc/nixos")));
}
