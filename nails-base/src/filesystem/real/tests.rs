// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for `RealFilesystem`.
//!
//! Every test here runs unprivileged: it drives `RealFilesystem` against plain
//! temporary directories or uses `MockFilesystem`, so the behaviour stays
//! inspectable and runnable in the normal test suite without root.
//!
//! The mount counterparts — real overlay mounts, bind and tmpfs submounts, and
//! their teardown — run in a user + mount namespace: the shared mount contract
//! in `nails-core/tests/filesystem_contract.rs` (tmpfs sizes, idempotent
//! unmounts) and `nails-core/tests/privileged_mounts.rs`.

use super::RealFilesystem;
use crate::NailsError;
use crate::filesystem::{Filesystem, MockFilesystem};
use std::fs;
use std::path::Path;

// ========================================================================
// Tests for Tmpfs Operations for Extended Overlays
// ========================================================================

// ========== enumerate_root_directories() Tests ==========

// ========== Symlink Edge Case Tests ==========

#[test]
fn test_real_is_mounted_returns_false_for_plain_tempdir() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let plain = temp_dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();

    assert!(!fs.is_mounted(&plain).unwrap());
}

#[test]
fn test_real_get_filesystem_type_returns_none_for_plain_tempdir() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let plain = temp_dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();

    assert_eq!(fs.get_filesystem_type(&plain).unwrap(), None);
}

#[test]
fn test_real_supports_symlinks_returns_true_and_cleans_probe() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let probe = temp_dir.path().join(".nails_symlink_probe");

    assert!(fs.supports_symlinks(temp_dir.path()).unwrap());
    assert!(!probe.exists());
}

#[test]
fn test_real_create_symlink_is_idempotent_for_same_target() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target.txt");
    let link = temp_dir.path().join("link.txt");
    fs::write(&target, "data").unwrap();

    assert!(fs.create_symlink(&target, &link).is_ok());
    assert!(fs.create_symlink(&target, &link).is_ok());
    assert!(link.is_symlink());
    assert_eq!(fs::read_link(&link).unwrap(), target);
}

#[test]
fn test_real_create_symlink_existing_symlink_to_different_target_errors() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target_a = temp_dir.path().join("target-a.txt");
    let target_b = temp_dir.path().join("target-b.txt");
    let link = temp_dir.path().join("link.txt");
    fs::write(&target_a, "a").unwrap();
    fs::write(&target_b, "b").unwrap();
    std::os::unix::fs::symlink(&target_a, &link).unwrap();

    let err = fs.create_symlink(&target_b, &link).unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
            assert!(io.to_string().contains("different target"));
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_create_symlink_existing_non_symlink_errors() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("target.txt");
    let link = temp_dir.path().join("link.txt");
    fs::write(&target, "data").unwrap();
    fs::write(&link, "not a symlink").unwrap();

    let err = fs.create_symlink(&target, &link).unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
            assert!(io.to_string().contains("not a symlink"));
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_is_regular_file_follows_links_and_refuses_special_files() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let dir = temp_dir.path();
    fs::write(dir.join("file"), "data").unwrap();
    fs::create_dir(dir.join("dir")).unwrap();
    nix::unistd::mkfifo(
        &dir.join("fifo"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    for (link, target) in [
        ("to-file", "file"),
        ("to-dir", "dir"),
        ("to-fifo", "fifo"),
        ("dangling", "missing"),
    ] {
        std::os::unix::fs::symlink(target, dir.join(link)).unwrap();
    }

    for (name, regular) in [
        ("file", true),
        ("to-file", true),
        ("dir", false),
        ("to-dir", false),
        ("fifo", false),
        ("to-fifo", false),
        ("dangling", false),
        ("missing", false),
    ] {
        assert_eq!(
            fs.is_regular_file(&dir.join(name)).unwrap(),
            regular,
            "{name}"
        );
    }
    // A device node is none either.
    assert!(!fs.is_regular_file(Path::new("/dev/null")).unwrap());
}

#[test]
fn test_real_write_file_content_replaces_contents_and_removes_tmp_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("data.txt");
    fs::write(&file, "old content").unwrap();

    fs.write_file_content(&file, "new content").unwrap();

    assert_eq!(fs::read_to_string(&file).unwrap(), "new content");
    assert!(!file.with_extension("tmp").exists());
}

#[test]
fn test_real_read_file_content_missing_file_wraps_path_in_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing.txt");

    let err = fs.read_file_content(&missing).unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            assert!(
                io.to_string()
                    .contains(&format!("Failed to read file {}", missing.display()))
            );
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_find_files_with_pattern_recurses_and_matches_case_insensitively() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let nested = temp_dir.path().join("nested");
    fs::create_dir_all(&nested).unwrap();
    let match_a = temp_dir.path().join("NAILS.conf");
    let match_b = nested.join("app.nails.log");
    let non_match = nested.join("other.txt");
    fs::write(&match_a, "a").unwrap();
    fs::write(&match_b, "b").unwrap();
    fs::write(&non_match, "c").unwrap();

    let mut matches = fs
        .find_files_with_pattern(temp_dir.path(), "nAiLs")
        .unwrap();
    matches.sort();

    assert_eq!(matches, vec![match_a, match_b]);
}

#[test]
fn test_real_write_file_content_returns_contextual_error_when_parent_missing() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("missing-parent/data.txt");

    let err = fs.write_file_content(&file, "data").unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            assert!(io.to_string().contains("Failed to create temp file"));
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_find_files_with_pattern_returns_empty_for_missing_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    assert!(
        fs.find_files_with_pattern(&missing, "nails")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn test_real_set_permissions_and_get_permissions_round_trip_mode_bits() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("mode.txt");
    fs::write(&file, "data").unwrap();

    fs.set_permissions(&file, 0o764).unwrap();

    assert_eq!(fs.get_permissions(&file).unwrap(), 0o764);
}

#[test]
fn test_real_is_writable_returns_true_for_directory_and_cleans_probe_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let probe = temp_dir.path().join(".nails_write_test");

    assert!(fs.is_writable(temp_dir.path()).unwrap());
    assert!(!probe.exists());
}

#[test]
fn test_real_is_writable_returns_true_for_appendable_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("append.txt");
    fs::write(&file, "data").unwrap();

    assert!(fs.is_writable(&file).unwrap());
}

#[test]
fn test_real_is_writable_returns_false_for_missing_file_path() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("missing.txt");

    assert!(!fs.is_writable(&file).unwrap());
}

#[test]
fn test_real_copy_tree_copies_contents_not_source_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let src = temp_dir.path().join("src");
    let dst = temp_dir.path().join("dst");
    fs::create_dir_all(src.join("nested")).unwrap();
    fs::create_dir_all(&dst).unwrap();
    fs::write(src.join("a.txt"), "a").unwrap();
    fs::write(src.join("nested/b.txt"), "b").unwrap();

    fs.copy_tree(&src, &dst).unwrap();

    assert!(dst.join("a.txt").exists());
    assert!(dst.join("nested/b.txt").exists());
    assert!(!dst.join("src").exists());
}

#[test]
fn test_real_copy_tree_returns_error_for_missing_source() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let src = temp_dir.path().join("missing-src");
    let dst = temp_dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();

    let err = fs.copy_tree(&src, &dst).unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert!(io.to_string().contains("atime-safe copy"))
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_list_directory_returns_created_entries() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("entry.txt");
    let subdir = temp_dir.path().join("subdir");
    fs::write(&file, "data").unwrap();
    fs::create_dir_all(&subdir).unwrap();

    let mut entries = fs.list_directory(temp_dir.path()).unwrap();
    entries.sort();

    assert_eq!(entries, vec![file, subdir]);
}

#[test]
fn test_real_create_directory_and_path_queries_work() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let dir = temp_dir.path().join("nested/dir");

    fs.create_directory(&dir).unwrap();

    assert!(fs.path_exists(&dir).unwrap());
    assert!(fs.is_directory(&dir).unwrap());
    assert!(!fs.is_symlink(&dir).unwrap());
}

#[test]
fn test_real_path_exists_and_is_directory_for_missing_path() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    assert!(!fs.path_exists(&missing).unwrap());
    assert!(!fs.is_directory(&missing).unwrap());
    assert!(!fs.is_symlink(&missing).unwrap());
}

#[test]
fn test_real_is_readable_returns_true_for_existing_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("readable.txt");
    fs::write(&file, "data").unwrap();

    assert!(fs.is_readable(&file).unwrap());
}

#[test]
fn test_real_is_readable_returns_false_for_missing_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing.txt");

    assert!(!fs.is_readable(&missing).unwrap());
}

#[test]
fn test_real_rename_and_remove_file_round_trip() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let original = temp_dir.path().join("before.txt");
    let renamed = temp_dir.path().join("after.txt");
    fs::write(&original, "data").unwrap();

    fs.rename_file(&original, &renamed).unwrap();

    assert!(!original.exists());
    assert!(renamed.exists());

    fs.remove_file(&renamed).unwrap();
    assert!(!renamed.exists());
}

#[test]
fn test_real_remove_directory_variants_work() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let empty_dir = temp_dir.path().join("empty");
    let nested_dir = temp_dir.path().join("nested");
    fs::create_dir_all(&empty_dir).unwrap();
    fs::create_dir_all(nested_dir.join("child")).unwrap();
    fs::write(nested_dir.join("child/file.txt"), "data").unwrap();

    fs.remove_directory(&empty_dir).unwrap();
    assert!(!empty_dir.exists());

    fs.remove_dir_all(&nested_dir).unwrap();
    assert!(!nested_dir.exists());
}

#[test]
fn test_real_secure_delete_removes_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("secret.txt");
    fs::write(&file, "super secret contents").unwrap();

    fs.secure_delete(&file).unwrap();

    assert!(!file.exists());
}

#[test]
fn test_real_secure_delete_removes_zero_length_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("empty.txt");
    fs::write(&file, "").unwrap();

    fs.secure_delete(&file).unwrap();

    assert!(!file.exists());
}

#[test]
fn test_real_secure_delete_dir_all_removes_nested_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("wipe-me");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("top.txt"), "top").unwrap();
    fs::write(root.join("nested/bottom.txt"), "bottom").unwrap();

    fs.secure_delete_dir_all(&root).unwrap();

    assert!(!root.exists());
}

#[test]
fn test_real_modified_time_returns_timestamp_for_existing_file() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("time.txt");
    fs::write(&file, "data").unwrap();

    let modified = fs.modified_time(&file).unwrap();

    assert!(modified <= std::time::SystemTime::now());
}

// ========================================================================
// Tests for parse_submount_sources (extracted pure function)
// ========================================================================

// ========================================================================
// statvfs / disk_usage tests
// ========================================================================

#[test]
fn test_disk_usage_returns_realistic_values() {
    let fs = RealFilesystem;
    let usage = fs
        .disk_usage(Path::new("/"))
        .expect("disk_usage should succeed on /");
    assert_ne!(usage.available, u64::MAX, "Space should come from statvfs");
    assert!(usage.total > 0, "Total should come from statvfs");
    assert!(usage.available <= usage.total);
}

#[test]
fn canonicalize_resolves_symlinks_and_reports_missing_paths() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let real = base.join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, base.join("link")).unwrap();

    let fs_impl = RealFilesystem;
    assert_eq!(fs_impl.canonicalize(&base.join("link")).unwrap(), real);
    match fs_impl.canonicalize(&base.join("link/missing")) {
        Err(NailsError::IoError { source: e, .. }) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound)
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn create_hidden_dir_all_creates_nested_dirs_beneath_root() {
    let temp = tempfile::tempdir().unwrap();
    let fs_impl = RealFilesystem;

    fs_impl
        .create_hidden_dir_all(temp.path(), Path::new(".work/home"))
        .unwrap();

    assert!(temp.path().join(".work/home").is_dir());
}

#[test]
fn create_hidden_dir_all_refuses_a_planted_symlink_in_the_path() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    // A link under the root that points clean outside it. The real override
    // resolves with openat2, so the creation must be refused rather than land in
    // `outside`.
    std::os::unix::fs::symlink(outside.path(), temp.path().join("escape")).unwrap();

    let fs_impl = RealFilesystem;
    assert!(
        fs_impl
            .create_hidden_dir_all(temp.path(), Path::new("escape/upper"))
            .is_err()
    );
    assert!(!outside.path().join("upper").exists());
}

#[test]
fn write_hidden_file_atomic_writes_beneath_root_at_requested_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let fs_impl = RealFilesystem;
    fs_impl
        .create_hidden_dir_all(temp.path(), Path::new("reports"))
        .unwrap();

    fs_impl
        .write_hidden_file_atomic(temp.path(), Path::new("reports/r.json"), "{}", 0o600)
        .unwrap();

    let path = temp.path().join("reports/r.json");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "report must be operator-only, got {mode:#o}");
}

#[test]
fn write_hidden_file_atomic_does_not_follow_a_planted_symlink_at_the_target() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    std::fs::write(&victim, "original").unwrap();

    // A link under the root whose name is the write target but which points off
    // the volume. `write_file_content` on the joined absolute path would follow
    // it and clobber `victim`. The contained write stages a temp file and renames
    // it over the name, which replaces the link itself (rename never follows the
    // final component) rather than writing through it.
    let target = temp.path().join("report.json");
    std::os::unix::fs::symlink(&victim, &target).unwrap();

    let fs_impl = RealFilesystem;
    fs_impl
        .write_hidden_file_atomic(temp.path(), Path::new("report.json"), "payload", 0o600)
        .unwrap();

    // The off-volume target is untouched; the entry is now a real file on the
    // volume carrying the payload, not a symlink.
    assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
    assert!(!target.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read_to_string(&target).unwrap(), "payload");
}

// ========================================================================
// Tests for in-place overwrite (same inode)
// ========================================================================

#[test]
fn test_real_overwrite_file_in_place_preserves_inode() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join(".bash_history");
    fs::write(&path, "ls\nnails activate\npwd\n").unwrap();
    let inode_before = fs::metadata(&path).unwrap().ino();
    let mode_before = fs::metadata(&path).unwrap().mode();

    let realfs = RealFilesystem;
    realfs.overwrite_file_in_place(&path, "ls\npwd\n").unwrap();

    let meta_after = fs::metadata(&path).unwrap();
    assert_eq!(
        inode_before,
        meta_after.ino(),
        "in-place overwrite must keep the same inode"
    );
    assert_eq!(
        mode_before,
        meta_after.mode(),
        "in-place overwrite must preserve mode"
    );
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, "ls\npwd\n");
}

#[test]
fn test_real_overwrite_file_in_place_missing_file_errors() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("does-not-exist");
    let realfs = RealFilesystem;
    // The parent exists but the file does not. In-place overwrite opens
    // `O_RDWR` without `O_CREAT`, so a missing file is a NotFound error rather
    // than being created: the opt-in decoy edit never plants a history file that
    // was not already there. This matches the MockFilesystem contract.
    let err = realfs.overwrite_file_in_place(&path, "x\n").unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("expected NotFound IoError, got {other:?}"),
    }
    assert!(!path.exists(), "a missing file must not be created");
}

#[test]
fn test_mock_overwrite_file_in_place_records_distinct_op() {
    use crate::filesystem::MockOp;

    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/home/op/.bash_history", "a\nb\n");
    fs.overwrite_file_in_place(Path::new("/home/op/.bash_history"), "a\n")
        .unwrap();

    assert_eq!(
        fs.get_written_content(Path::new("/home/op/.bash_history"))
            .as_deref(),
        Some("a\n")
    );
    assert!(fs.mock_ops().iter().any(|op| matches!(
        op,
        MockOp::OverwriteInPlace { path } if path == Path::new("/home/op/.bash_history")
    )));
}

#[test]
fn test_mock_overwrite_file_in_place_missing_file_is_not_found() {
    let fs = MockFilesystem::new();
    let err = fs
        .overwrite_file_in_place(Path::new("/home/op/.missing"), "x")
        .unwrap_err();
    match err {
        NailsError::IoError { source: io, .. } => {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("expected NotFound IoError, got {other:?}"),
    }
}

// ========================================================================
// Tests for refused file operations
// ========================================================================

/// The path and I/O error of a refused operation.
fn io_error<T: std::fmt::Debug>(result: crate::Result<T>) -> (std::path::PathBuf, std::io::Error) {
    match result {
        Err(NailsError::IoError { path, source }) => (path, source),
        other => panic!("expected an IoError, got {other:?}"),
    }
}

/// Run `body` with `dir` set to `mode`, restoring 0o700 afterwards so the
/// temporary directory can be removed. `None` when running as root, which
/// bypasses directory permissions and so cannot observe the refusal.
fn with_mode<T>(dir: &Path, mode: u32, body: impl FnOnce() -> T) -> Option<T> {
    use std::os::unix::fs::PermissionsExt;
    if nix::unistd::geteuid().is_root() {
        return None;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
    let result = body();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    Some(result)
}

#[test]
fn device_id_names_the_filesystem_of_the_resolved_path() {
    use std::os::unix::fs::MetadataExt;

    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("probe");
    fs::write(&file, "x").unwrap();
    let link = temp_dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();

    let expected = fs::metadata(&file).unwrap().dev();
    assert_eq!(fs.device_id(&file).unwrap(), expected);
    // A symlink reports the device of its target, not of the link inode.
    assert_eq!(fs.device_id(&link).unwrap(), expected);

    let missing = temp_dir.path().join("missing");
    let (path, err) = io_error(fs.device_id(&missing));
    assert_eq!(path, missing);
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn inode_names_the_file_a_path_leads_to_and_none_where_nothing_is() {
    use std::os::unix::fs::MetadataExt;

    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("probe");
    fs::write(&file, "x").unwrap();
    let link = temp_dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let hard = temp_dir.path().join("hard");
    fs::hard_link(&file, &hard).unwrap();

    let expected = fs::metadata(&file).unwrap().ino();
    assert_eq!(fs.inode(&file).unwrap(), Some(expected));
    // A symlink is followed, and a hard link is the same file.
    assert_eq!(fs.inode(&link).unwrap(), Some(expected));
    assert_eq!(fs.inode(&hard).unwrap(), Some(expected));
    assert_eq!(fs.inode(&temp_dir.path().join("missing")).unwrap(), None);

    // A namespace file names its namespace, which a thread shares with its
    // process.
    let mnt = fs.inode(Path::new("/proc/self/ns/mnt")).unwrap();
    assert!(mnt.is_some());
    assert_eq!(
        fs.inode(Path::new("/proc/thread-self/ns/mnt")).unwrap(),
        mnt
    );

    // A lookup through a file is an error, not a missing path.
    let below_file = file.join("child");
    let (path, err) = io_error(fs.inode(&below_file));
    assert_eq!(path, below_file);
    assert_eq!(err.kind(), std::io::ErrorKind::NotADirectory);
}

#[test]
fn supports_symlinks_reports_a_missing_directory_as_an_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    let (path, err) = io_error(fs.supports_symlinks(&missing));

    assert_eq!(path, missing.join(".nails_symlink_probe"));
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn is_writable_is_false_for_a_read_only_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let locked = temp_dir.path().join("locked");
    fs::create_dir(&locked).unwrap();

    let Some(writable) = with_mode(&locked, 0o500, || fs.is_writable(&locked).unwrap()) else {
        return;
    };

    assert!(!writable);
    assert!(!locked.join(".nails_write_test").exists());
}

#[test]
fn write_file_content_over_a_directory_fails_the_rename() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("occupied");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("inside"), "keep").unwrap();

    let (path, err) = io_error(fs.write_file_content(&target, "data"));

    assert_eq!(path, target.with_extension("tmp"));
    assert!(
        err.to_string().starts_with(&format!(
            "Failed to rename {} to {}",
            target.with_extension("tmp").display(),
            target.display()
        )),
        "{err}"
    );
    assert_eq!(fs::read_to_string(target.join("inside")).unwrap(), "keep");
}

/// The atomic write fails while writing the temp file on a full filesystem
/// and leaves the original content in place.
#[test]
fn write_file_content_on_a_full_filesystem_keeps_the_original() {
    use crate::test_support::{Rerun, ScratchTmpfs};

    let _ = Rerun::new(crate::test_path!(
        write_file_content_on_a_full_filesystem_keeps_the_original
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("size=16k");
        let file = scratch.path().join("data.txt");
        fs::write(&file, "original").unwrap();

        let (path, err) =
            io_error(RealFilesystem.write_file_content(&file, &"x".repeat(256 * 1024)));

        assert_eq!(path, file.with_extension("tmp"));
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
        assert!(
            err.to_string().starts_with("Failed to write to temp file"),
            "{err}"
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "original");
    });
}

#[test]
fn overwrite_file_in_place_refuses_a_path_without_a_parent_or_a_file_name() {
    let fs = RealFilesystem;

    let (path, err) = io_error(fs.overwrite_file_in_place(Path::new("/"), "x"));
    assert_eq!(path, Path::new("/"));
    assert!(err.to_string().contains("no parent directory"), "{err}");

    let temp_dir = tempfile::tempdir().unwrap();
    let dotdot = temp_dir.path().join("sub/..");
    let (path, err) = io_error(fs.overwrite_file_in_place(&dotdot, "x"));
    assert_eq!(path, dotdot);
    assert!(err.to_string().contains("no file name"), "{err}");
}

#[test]
fn overwrite_file_in_place_on_a_full_filesystem_reports_the_failed_rewrite() {
    use crate::test_support::{Rerun, ScratchTmpfs};

    let _ = Rerun::new(crate::test_path!(
        overwrite_file_in_place_on_a_full_filesystem_reports_the_failed_rewrite
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("size=16k");
        let root = scratch.path().canonicalize().unwrap();
        let file = root.join(".bash_history");
        fs::write(&file, "ls\n").unwrap();

        let (path, err) =
            io_error(RealFilesystem.overwrite_file_in_place(&file, &"x".repeat(256 * 1024)));

        assert_eq!(path, file);
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
        assert!(err.to_string().starts_with("Failed to rewrite"), "{err}");
    });
}

#[test]
fn find_files_with_pattern_fails_on_an_unreadable_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let locked = temp_dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("nails.log"), "x").unwrap();

    let Some(result) = with_mode(&locked, 0o000, || {
        fs.find_files_with_pattern(temp_dir.path(), "nails")
    }) else {
        return;
    };

    let (path, err) = io_error(result);
    assert_eq!(path, locked);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string()
            .starts_with(&format!("Failed to read directory {}", locked.display())),
        "{err}"
    );
}

#[test]
fn scan_files_with_pattern_recurses_skips_links_and_records_unreadable_directories() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path();
    fs::create_dir_all(root.join("nested/deeper")).unwrap();
    fs::write(root.join("nested/deeper/App.NAILS.log"), "x").unwrap();
    fs::write(root.join("nested/other.txt"), "x").unwrap();
    // Neither a link to a matching file nor a link to a directory counts.
    std::os::unix::fs::symlink(
        root.join("nested/deeper/App.NAILS.log"),
        root.join("nails-link"),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("nested"), root.join("dir-link")).unwrap();
    let locked = root.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("nails.hidden"), "x").unwrap();

    let Some(scan) = with_mode(&locked, 0o000, || {
        fs.scan_files_with_pattern(root, "Nails").unwrap()
    }) else {
        return;
    };

    assert_eq!(scan.matches, vec![root.join("nested/deeper/App.NAILS.log")]);
    assert_eq!(scan.unreadable, vec![locked]);

    let missing = fs
        .scan_files_with_pattern(&root.join("missing"), "nails")
        .unwrap();
    assert!(missing.matches.is_empty());
    assert!(missing.unreadable.is_empty());
}

#[test]
fn path_operations_on_a_missing_path_name_it_in_the_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");
    let elsewhere = temp_dir.path().join("elsewhere");

    let cases: Vec<(&str, crate::Result<()>)> = vec![
        (
            "Failed to get file size for",
            fs.file_size(&missing).map(drop),
        ),
        ("Failed to rename", fs.rename_file(&missing, &elsewhere)),
        ("Failed to remove file", fs.remove_file(&missing)),
        ("Failed to remove directory", fs.remove_dir_all(&missing)),
    ];
    for (prefix, result) in cases {
        let (path, err) = io_error(result);
        assert_eq!(path, missing, "{prefix}");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{prefix}");
        assert!(
            err.to_string()
                .starts_with(&format!("{prefix} {}", missing.display())),
            "{err}"
        );
    }
    assert!(!elsewhere.exists());
}

#[test]
fn remove_directory_refuses_a_non_empty_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let dir = temp_dir.path().join("full");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("keep"), "x").unwrap();

    let (path, err) = io_error(fs.remove_directory(&dir));

    assert_eq!(path, dir);
    assert_eq!(err.kind(), std::io::ErrorKind::DirectoryNotEmpty);
    assert_eq!(fs::read_to_string(dir.join("keep")).unwrap(), "x");
}

// ========================================================================
// Tests for refused secure deletion
// ========================================================================

#[test]
fn secure_delete_of_a_missing_file_reports_the_size_lookup() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing");

    let (path, err) = io_error(fs.secure_delete(&missing));

    assert_eq!(path, missing);
    assert!(
        err.to_string().starts_with("Failed to get file size"),
        "{err}"
    );
}

#[test]
fn secure_delete_of_a_read_only_file_leaves_it_intact() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("secret.txt");
    fs::write(&file, "secret").unwrap();

    let Some(result) = with_mode(&file, 0o400, || fs.secure_delete(&file)) else {
        return;
    };

    let (path, err) = io_error(result);
    assert_eq!(path, file);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string()
            .starts_with("Failed to open file for secure deletion"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "secret");
}

/// A sparse file larger than the filesystem cannot be overwritten: the first
/// pass fails with the filesystem full, and the file is not unlinked as if the
/// wipe had succeeded.
#[test]
fn secure_delete_that_cannot_overwrite_keeps_the_file() {
    use crate::test_support::{Rerun, ScratchTmpfs};

    let _ = Rerun::new(crate::test_path!(
        secure_delete_that_cannot_overwrite_keeps_the_file
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("size=64k");
        let file = scratch.path().join("sparse");
        fs::File::create(&file)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();

        let (path, err) = io_error(RealFilesystem.secure_delete(&file));

        assert_eq!(path, file);
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
        assert!(
            err.to_string()
                .starts_with("Failed to overwrite file with zeros"),
            "{err}"
        );
        assert_eq!(fs::metadata(&file).unwrap().len(), 1024 * 1024);
    });
}

#[test]
fn secure_delete_dir_all_fails_on_an_unlistable_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let locked = temp_dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("secret"), "secret").unwrap();

    // Search and write, but no read: the entries cannot be listed.
    let Some(result) = with_mode(&locked, 0o300, || fs.secure_delete_dir_all(&locked)) else {
        return;
    };

    let (path, err) = io_error(result);
    assert_eq!(path, locked);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string().starts_with("Failed to read directory"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(locked.join("secret")).unwrap(), "secret");
}

#[test]
fn secure_delete_dir_all_wipes_the_contents_even_when_the_directory_stays() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let parent = temp_dir.path().join("parent");
    let dir = parent.join("wipe-me");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("secret"), "secret").unwrap();

    // The parent is read-only, so the emptied directory cannot be unlinked.
    let Some(result) = with_mode(&parent, 0o500, || fs.secure_delete_dir_all(&dir)) else {
        return;
    };

    let (path, err) = io_error(result);
    assert_eq!(path, dir);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string().starts_with("Failed to remove directory"),
        "{err}"
    );
    assert!(dir.is_dir());
    assert!(!dir.join("secret").exists());
}

#[test]
fn a_range_of_a_file_is_read_without_its_access_time_or_a_link() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rpmdb.sqlite");
    fs::write(&path, b"0123456789").unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    fs::File::open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_accessed(old))
        .unwrap();
    let atime = || {
        let meta = fs::metadata(&path).unwrap();
        (meta.atime(), meta.atime_nsec())
    };
    let before = atime();

    let real = RealFilesystem;
    assert_eq!(real.read_file_range(&path, 2, 3).unwrap(), b"234");
    // A range past the end gives what the file holds of it.
    assert_eq!(real.read_file_range(&path, 8, 10).unwrap(), b"89");
    assert_eq!(real.read_file_range(&path, 20, 1).unwrap(), b"");
    assert_eq!(atime(), before);

    // A link is not followed.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let error = real.read_file_range(&link, 0, 1).unwrap_err();
    assert!(error.to_string().contains("Failed to read file"), "{error}");
}

#[test]
fn the_kernel_says_a_plain_directory_is_no_mount_point() {
    let dir = tempfile::tempdir().unwrap();
    let real = RealFilesystem;
    // A kernel without the attribute (before 5.8) does not say.
    assert!(matches!(
        real.is_mount_root(dir.path()).unwrap(),
        Some(false) | None
    ));
    assert!(matches!(
        real.is_mount_root(Path::new("/")).unwrap(),
        Some(true) | None
    ));
    assert!(real.is_mount_root(&dir.path().join("missing")).is_err());
}

#[test]
fn a_link_to_a_mount_point_is_no_mount_point_itself() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("root");
    std::os::unix::fs::symlink("/", &link).unwrap();
    assert!(matches!(
        RealFilesystem.is_mount_root(&link).unwrap(),
        Some(false) | None
    ));
}
