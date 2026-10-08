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
