//! Tests for `RealFilesystem`.
//!
//! This module intentionally keeps one opt-in ignored integration test for a
//! real overlay mount. It is ignored because it must run as root against a real
//! overlayfs-capable kernel, so it is not safe or portable for normal CI.
//! Every remaining `#[ignore]` in this workspace is expected to carry this kind
//! of explicit environment/host constraint inline.
//!
//! The rest of this module uses `MockFilesystem` or plain temporary
//! directories so the behavior stays inspectable and runnable in normal tests.

use super::RealFilesystem;
use crate::NailsError;
use crate::filesystem::{Filesystem, MockFilesystem};
use std::fs;
use std::path::{Path, PathBuf};

// ========================================================================
// Integration Tests for RealFilesystem that require root + real overlayfs
// ========================================================================

#[test]
#[ignore = "Requires root privileges and a real overlayfs-capable kernel; excluded from normal CI runs"]
fn test_real_overlay_mount_creates_merged_view() {
    // AC4 Integration test: Verify actual overlay filesystem merge
    // Ignored intentionally: this performs a real overlay mount and therefore
    // needs root privileges, an overlayfs-capable kernel, and manual/isolated
    // execution outside hermetic CI.
    // Run with: cargo test test_real_overlay_mount_creates_merged_view -- --ignored
    //
    // Test verifies:
    // 1. Files from lower directory are visible in target
    // 2. Files from upper directory overlay correctly in target
    // 3. Modifications in upper don't affect lower

    use crate::filesystem::Filesystem;
    use std::fs;
    use std::io::Write;

    let fs = RealFilesystem;

    // Create test directories in /tmp (requires cleanup on failure)
    let test_dir = std::env::temp_dir().join("nails-overlay-test-XXXXXX");
    fs::create_dir_all(&test_dir).unwrap();

    let lower = test_dir.join("lower");
    let upper = test_dir.join("upper");
    let work = test_dir.join("work");
    let target = test_dir.join("target");

    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&target).unwrap();

    // Create test files in lower
    let lower_file = lower.join("from_lower.txt");
    let mut lower_fh = fs::File::create(&lower_file).unwrap();
    lower_fh.write_all(b"content from lower layer").unwrap();
    lower_fh.sync_all().unwrap();

    // Create test files in upper
    let upper_file = upper.join("from_upper.txt");
    let mut upper_fh = fs::File::create(&upper_file).unwrap();
    upper_fh.write_all(b"content from upper layer").unwrap();
    upper_fh.sync_all().unwrap();

    // Mount overlay
    let result = fs.mount_overlay(&[lower.as_path()], &upper, &work, &target);
    if let Err(e) = result {
        // Clean up on failure
        let _ = fs::remove_dir_all(&test_dir);
        panic!("Overlay mount failed: {:?}", e);
    }

    // Verify merged view: both files should be visible in target
    let target_lower_file = target.join("from_lower.txt");
    let target_upper_file = target.join("from_upper.txt");

    assert!(
        target_lower_file.exists(),
        "File from lower layer should be visible in target"
    );
    assert!(
        target_upper_file.exists(),
        "File from upper layer should be visible in target"
    );

    // Verify content is correct
    let content_from_lower = fs::read_to_string(&target_lower_file).unwrap();
    let content_from_upper = fs::read_to_string(&target_upper_file).unwrap();

    assert_eq!(
        content_from_lower, "content from lower layer",
        "Lower layer content should be readable"
    );
    assert_eq!(
        content_from_upper, "content from upper layer",
        "Upper layer content should be readable"
    );

    // Unmount
    fs.unmount(&target, false).unwrap();

    // Cleanup
    fs::remove_dir_all(&test_dir).unwrap();
}

// ========================================================================
// Tests for Story 4.11: Tmpfs Operations for Extended Overlays
// ========================================================================

#[test]
fn test_mock_mount_tmpfs_success() {
    // AC2: MockFilesystem tracks tmpfs mounts
    let fs = MockFilesystem::new();

    // Set up target directory
    fs.mock_set_path_exists("/run/nails/var-upper", true);

    // Mount tmpfs
    let result = fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G");
    assert!(result.is_ok());

    // Verify mount is tracked
    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
}

#[test]
fn test_mock_mount_tmpfs_validates_size_format() {
    // AC1: Size validation rejects invalid formats
    let fs = MockFilesystem::new();

    // Set up directories as creatable
    fs.mock_set_directory_creatable("/run/nails/test1", true);
    fs.mock_set_directory_creatable("/run/nails/test2", true);
    fs.mock_set_directory_creatable("/run/nails/test3", true);
    fs.mock_set_directory_creatable("/run/nails/invalid", true);

    // Valid sizes should succeed
    assert!(fs.mount_tmpfs(Path::new("/run/nails/test1"), "1G").is_ok());
    assert!(
        fs.mount_tmpfs(Path::new("/run/nails/test2"), "512M")
            .is_ok()
    );
    assert!(
        fs.mount_tmpfs(Path::new("/run/nails/test3"), "1024")
            .is_ok()
    );

    // Invalid size format should fail
    let result = fs.mount_tmpfs(Path::new("/run/nails/invalid"), "invalid");
    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Invalid tmpfs size format"));
        }
        _ => panic!("Expected OverlayError for invalid size"),
    }
}

#[test]
fn test_mock_mount_tmpfs_rejects_already_mounted() {
    // AC2: Cannot mount tmpfs on already-mounted path
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/run/nails/var-upper", true);

    // First mount succeeds
    assert!(
        fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
            .is_ok()
    );

    // Second mount fails
    let result = fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G");
    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::AlreadyMounted { path } => {
            assert_eq!(path, PathBuf::from("/run/nails/var-upper"));
        }
        _ => panic!("Expected AlreadyMounted error"),
    }
}

#[test]
fn test_mock_mount_tmpfs_creates_directory() {
    // AC2: Mount creates target directory if missing
    let fs = MockFilesystem::new();

    // Set parent writable to allow directory creation
    fs.mock_set_directory_creatable("/run/nails/new-dir", true);

    // Target doesn't exist yet
    assert!(!fs.path_exists(Path::new("/run/nails/new-dir")).unwrap());

    // Mount should create it
    let result = fs.mount_tmpfs(Path::new("/run/nails/new-dir"), "512M");
    assert!(result.is_ok());

    // Verify directory was created
    assert!(fs.path_exists(Path::new("/run/nails/new-dir")).unwrap());
}

#[test]
fn test_mock_unmount_tmpfs_success() {
    // AC2: Unmount removes tmpfs mount
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/run/nails/var-upper", true);
    fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
        .unwrap();

    // Verify mounted
    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());

    // Unmount
    let result = fs.unmount_tmpfs(Path::new("/run/nails/var-upper"));
    assert!(result.is_ok());

    // Verify unmounted
    assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
}

#[test]
fn test_mock_unmount_tmpfs_idempotent() {
    // AC2: Unmount succeeds even if not mounted
    let fs = MockFilesystem::new();

    // Unmount without mount should succeed (idempotent)
    let result = fs.unmount_tmpfs(Path::new("/not/mounted"));
    assert!(result.is_ok());
}

#[test]
fn test_mock_tmpfs_multiple_mounts() {
    // AC2: Can mount multiple tmpfs filesystems
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/run/nails/var-upper", true);
    fs.mock_set_path_exists("/run/nails/tmp-upper", true);

    // Mount first tmpfs
    assert!(
        fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
            .is_ok()
    );

    // Mount second tmpfs
    assert!(
        fs.mount_tmpfs(Path::new("/run/nails/tmp-upper"), "512M")
            .is_ok()
    );

    // Both should be mounted
    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    assert!(fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap());

    // Unmount first
    assert!(fs.unmount_tmpfs(Path::new("/run/nails/var-upper")).is_ok());

    // First should be unmounted, second still mounted
    assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    assert!(fs.is_mounted(Path::new("/run/nails/tmp-upper")).unwrap());
}

#[test]
fn test_mock_tmpfs_reset_clears_mounts() {
    // Verify reset() clears tmpfs mounts
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/run/nails/var-upper", true);
    fs.mount_tmpfs(Path::new("/run/nails/var-upper"), "1G")
        .unwrap();

    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());

    // Reset should clear tmpfs mounts
    fs.reset();

    assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
}

// ========== Task 3: enumerate_root_directories() Tests (Story 14.10) ==========

#[test]
fn test_enumerate_root_directories_returns_sorted_list() {
    // AC: Returns all root directories in alphabetical order
    let fs = MockFilesystem::new();

    // Configure mock root directories (unsorted)
    fs.mock_set_root_directories(vec![
        PathBuf::from("/var"),
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/tmp"),
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // Should be sorted alphabetically
    assert_eq!(
        dirs,
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
            PathBuf::from("/var"),
        ]
    );
}

#[test]
fn test_enumerate_root_directories_excludes_symlinks() {
    // AC: Symlinks are skipped (not returned)
    let fs = MockFilesystem::new();

    // Configure mix of real dirs and symlinks
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"), // real dir
        PathBuf::from("/etc"),  // real dir
    ]);

    // Mark /bin as symlink (to /nix/store/...)
    fs.mock_set_root_symlinks(vec![PathBuf::from("/bin"), PathBuf::from("/lib")]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // Symlinks should NOT be included
    assert_eq!(dirs, vec![PathBuf::from("/etc"), PathBuf::from("/home"),]);
    assert!(!dirs.contains(&PathBuf::from("/bin")));
    assert!(!dirs.contains(&PathBuf::from("/lib")));
}

#[test]
fn test_enumerate_root_directories_empty_root() {
    // Edge case: empty root directory
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![]);

    let dirs = fs.enumerate_root_directories().unwrap();

    assert_eq!(dirs, Vec::<PathBuf>::new());
}

#[test]
fn test_enumerate_root_directories_many_directories() {
    // Realistic NixOS scenario with many directories
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/root"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/boot"),
        PathBuf::from("/nix"),
        PathBuf::from("/srv"),
        PathBuf::from("/opt"),
        PathBuf::from("/usr"),
        PathBuf::from("/persistent"),
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // Should have 11 directories, sorted
    assert_eq!(dirs.len(), 11);
    assert_eq!(dirs[0], PathBuf::from("/boot"));
    assert_eq!(dirs[10], PathBuf::from("/var"));

    // Verify sorted order
    for i in 1..dirs.len() {
        assert!(
            dirs[i - 1] < dirs[i],
            "Directories not sorted: {:?} >= {:?}",
            dirs[i - 1],
            dirs[i]
        );
    }
}

// ========== Story 14.10: Symlink Edge Case Tests ==========

#[test]
fn test_enumerate_root_directories_symlink_to_directory_is_excluded() {
    // AC3: Symlinks to directories should be excluded (not overlaid)
    // Common NixOS case: /bin -> /nix/store/... (symlink to directory)
    let fs = MockFilesystem::new();

    // Configure: /bin is a symlink to /nix/store/...
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"), // real directory
        PathBuf::from("/etc"),  // real directory
    ]);
    fs.mock_set_root_symlinks(vec![
        PathBuf::from("/bin"), // symlink (should be excluded)
        PathBuf::from("/lib"), // symlink (should be excluded)
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // Only real directories should be included, not symlinks
    assert_eq!(dirs.len(), 2);
    assert!(dirs.contains(&PathBuf::from("/etc")));
    assert!(dirs.contains(&PathBuf::from("/home")));
    assert!(!dirs.contains(&PathBuf::from("/bin")));
    assert!(!dirs.contains(&PathBuf::from("/lib")));
}

#[test]
fn test_enumerate_root_directories_all_symlinks_returns_empty() {
    // Edge case: If all entries under / are symlinks, return empty list
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![]); // No real directories
    fs.mock_set_root_symlinks(vec![
        PathBuf::from("/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/sbin"),
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    assert_eq!(dirs.len(), 0);
}

#[test]
fn test_enumerate_root_directories_mixed_real_and_symlink() {
    // Realistic scenario: mix of real dirs and symlinks (typical NixOS)
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/root"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/boot"),
        PathBuf::from("/nix"), // Real Nix store directory
        PathBuf::from("/srv"),
        PathBuf::from("/opt"),
    ]);
    fs.mock_set_root_symlinks(vec![
        PathBuf::from("/bin"),   // -> /nix/store/...
        PathBuf::from("/lib"),   // -> /nix/store/...
        PathBuf::from("/lib32"), // -> /nix/store/...
        PathBuf::from("/lib64"), // -> /nix/store/...
        PathBuf::from("/sbin"),  // -> /nix/store/...
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // Should have 9 real directories, 0 symlinks
    assert_eq!(dirs.len(), 9);
    assert!(dirs.contains(&PathBuf::from("/home")));
    assert!(dirs.contains(&PathBuf::from("/nix")));
    assert!(!dirs.contains(&PathBuf::from("/bin")));
    assert!(!dirs.contains(&PathBuf::from("/lib")));
}

#[test]
fn test_enumerate_root_directories_excludes_run_nails() {
    // Issue 6: Verify /run/nails directory is excluded from enumeration
    // This prevents nested overlay filesystem issues
    let fs = MockFilesystem::new();

    // Configure with /run/nails present
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/run"),       // Should be included
        PathBuf::from("/run/nails"), // Should be EXCLUDED
    ]);

    let dirs = fs.enumerate_root_directories().unwrap();

    // /run should be included, /run/nails should be excluded
    assert!(
        dirs.contains(&PathBuf::from("/run")),
        "/run should be included"
    );
    assert!(
        !dirs.contains(&PathBuf::from("/run/nails")),
        "/run/nails should be excluded"
    );
}

#[test]
fn test_real_mount_overlay_empty_lower_returns_overlay_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let upper = temp_dir.path().join("upper");
    let work = temp_dir.path().join("work");
    let target = temp_dir.path().join("target");

    let err = fs.mount_overlay(&[], &upper, &work, &target).unwrap_err();
    match err {
        NailsError::OverlayError(msg) => {
            assert_eq!(msg, "mount_overlay requires at least one lower layer");
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

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
fn test_real_is_overlay_mounted_returns_false_for_plain_tempdir() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let plain = temp_dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();

    assert!(!fs.is_overlay_mounted(&plain).unwrap());
}

#[test]
fn test_real_get_mount_info_returns_none_for_plain_tempdir() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let plain = temp_dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();

    assert!(fs.get_mount_info(&plain).is_none());
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
        NailsError::IoError(io) => {
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
        NailsError::IoError(io) => {
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
        NailsError::IoError(io) => {
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
fn test_real_mount_overlay_returns_missing_lower_precondition_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let lower = temp_dir.path().join("lower");
    let upper = temp_dir.path().join("upper");
    let work = temp_dir.path().join("work");
    let target = temp_dir.path().join("target");
    fs::create_dir_all(&upper).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&target).unwrap();

    let err = fs
        .mount_overlay(&[lower.as_path()], &upper, &work, &target)
        .unwrap_err();
    match err {
        NailsError::OverlayError(msg) => assert!(msg.contains("Lower directory not found")),
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_real_mount_overlay_returns_missing_upper_parent_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let lower = temp_dir.path().join("lower");
    let upper = temp_dir.path().join("missing-parent/upper");
    let work = temp_dir.path().join("work");
    let target = temp_dir.path().join("target");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&target).unwrap();

    let err = fs
        .mount_overlay(&[lower.as_path()], &upper, &work, &target)
        .unwrap_err();
    match err {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Upper directory not found and parent doesn't exist"))
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_real_mount_overlay_returns_missing_work_parent_error() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let lower = temp_dir.path().join("lower");
    let upper = temp_dir.path().join("upper");
    let work = temp_dir.path().join("missing-parent/work");
    let target = temp_dir.path().join("target");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();
    fs::create_dir_all(&target).unwrap();

    let err = fs
        .mount_overlay(&[lower.as_path()], &upper, &work, &target)
        .unwrap_err();
    match err {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Work directory not found and parent doesn't exist"))
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_real_mount_tmpfs_rejects_invalid_size_before_creating_target() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("new-tmpfs-target");

    let err = fs.mount_tmpfs(&target, "bogus-size").unwrap_err();
    match err {
        NailsError::ConfigError(msg) => assert!(msg.contains("Invalid tmpfs size")),
        other => panic!("expected ConfigError, got {other:?}"),
    }
    assert!(!target.exists());
}

#[test]
fn test_real_bind_mount_rejects_missing_source_before_syscall() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let source = temp_dir.path().join("missing-source");
    let target = temp_dir.path().join("target");
    fs::create_dir_all(&target).unwrap();

    let err = fs.bind_mount(&source, &target).unwrap_err();
    match err {
        NailsError::OverlayError(msg) => assert!(msg.contains("Bind mount source not found")),
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_real_unmount_is_idempotent_for_unmounted_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("plain");
    fs::create_dir_all(&target).unwrap();

    assert!(fs.unmount(&target, false).is_ok());
}

#[test]
fn test_real_unmount_tmpfs_is_idempotent_for_unmounted_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("plain");
    fs::create_dir_all(&target).unwrap();

    assert!(fs.unmount_tmpfs(&target).is_ok());
}

#[test]
fn test_real_unmount_bind_is_idempotent_for_unmounted_directory() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let target = temp_dir.path().join("plain");
    fs::create_dir_all(&target).unwrap();

    assert!(fs.unmount_bind(&target).is_ok());
}

#[test]
fn test_real_write_file_content_returns_contextual_error_when_parent_missing() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("missing-parent/data.txt");

    let err = fs.write_file_content(&file, "data").unwrap_err();
    match err {
        NailsError::IoError(io) => {
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
        NailsError::IoError(io) => assert!(io.to_string().contains("cp -a")),
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_real_get_directory_size_returns_nonzero_for_directory_contents() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(temp_dir.path().join("a.txt"), "hello").unwrap();
    fs::write(temp_dir.path().join("b.txt"), "world").unwrap();

    let size = fs.get_directory_size(temp_dir.path()).unwrap();

    assert!(size >= 10);
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
fn test_real_read_directory_returns_created_entries() {
    let fs = RealFilesystem;
    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join("entry.txt");
    let subdir = temp_dir.path().join("subdir");
    fs::write(&file, "data").unwrap();
    fs::create_dir_all(&subdir).unwrap();

    let mut entries: Vec<_> = fs
        .read_directory(temp_dir.path())
        .unwrap()
        .into_iter()
        .map(|entry| entry.path())
        .collect();
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

    assert!(modified <= chrono::Utc::now());
}

// ========================================================================
// Tests for parse_submount_sources (extracted pure function)
// ========================================================================

#[test]
fn test_device_backed_bind_mount_resolved() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
73 42 254:1 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/etc/nixos")
        )]
    );
}

#[test]
fn test_non_device_bind_mount_passthrough() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 0:50 / /etc rw - tmpfs tmpfs rw
99 42 0:50 /nixos /etc/nixos rw - /persist/etc/nixos /persist/etc/nixos rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/etc/nixos")
        )]
    );
}

#[test]
fn test_no_root_mount_for_device_skipped() {
    use super::parse_submount_sources;
    // Device 254:99 has no root mount entry — should be skipped
    let mountinfo = "\
99 42 254:99 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/sda9 rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert!(result.is_empty());
}

#[test]
fn test_multiple_bind_mounts_from_same_device() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
73 42 254:1 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/mapper/persist rw
74 42 254:1 /etc/ssh /etc/ssh rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert_eq!(
        result,
        vec![
            (
                PathBuf::from("/etc/nixos"),
                PathBuf::from("/persist/etc/nixos")
            ),
            (PathBuf::from("/etc/ssh"), PathBuf::from("/persist/etc/ssh")),
        ]
    );
}

#[test]
fn test_direct_partition_mount_under_target_skipped() {
    use super::parse_submount_sources;
    // /home/data is a separate partition mounted directly (fs_root="/"), not a bind mount
    let mountinfo = "\
42 1 254:1 / /home rw - ext4 /dev/sda2 rw
73 1 254:2 / /home/data rw - ext4 /dev/sda3 rw";
    let result = parse_submount_sources(mountinfo, Path::new("/home"));
    assert!(result.is_empty());
}

#[test]
fn test_pseudo_filesystem_mounts_skipped() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 0:50 / /etc rw - tmpfs tmpfs rw
99 42 0:51 / /etc/resolv.conf rw - tmpfs none rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert!(result.is_empty());
}

#[test]
fn test_target_itself_excluded() {
    use super::parse_submount_sources;
    // The target mount itself should not appear in results
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
73 42 254:1 /etc /etc rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert!(result.is_empty());
}

#[test]
fn test_home_bind_mount_from_persist() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 0:50 / /home rw - tmpfs tmpfs rw
73 42 254:1 /home/amnesia /home/amnesia rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/home"));
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/home/amnesia"),
            PathBuf::from("/persist/home/amnesia")
        )]
    );
}

#[test]
fn test_empty_mountinfo() {
    use super::parse_submount_sources;
    let result = parse_submount_sources("", Path::new("/etc"));
    assert!(result.is_empty());
}

#[test]
fn test_malformed_lines_skipped() {
    use super::parse_submount_sources;
    let mountinfo = "\
short line
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw

73 42 254:1 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/etc/nixos")
        )]
    );
}

#[test]
fn test_same_device_submount_skipped_persist() {
    use super::parse_submount_sources;
    // Target /persist is on device 254:1, submount /persist/nix/store is also 254:1.
    // Same device → content already visible → should be skipped to avoid ELOOP.
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
73 42 254:1 /nix/store /persist/nix/store rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/persist"));
    assert!(
        result.is_empty(),
        "Same-device submount should be skipped, got: {:?}",
        result
    );
}

#[test]
fn test_same_device_submount_skipped_nix() {
    use super::parse_submount_sources;
    // Target /nix is itself bind-mounted from /persist/nix (device 254:1).
    // Preserving /nix/store would derive an extra lower of /persist/nix, which
    // is target-equivalent to /nix and causes overlayfs ELOOP on nails-os.
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 254:1 /nix /nix rw,relatime - ext4 /dev/mapper/persist rw
73 50 254:1 /nix/store /nix/store rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/nix"));
    assert!(
        result.is_empty(),
        "Target-equivalent same-device submount should be skipped, got: {:?}",
        result
    );
}

#[test]
fn test_same_device_target_equivalent_path_source_skipped_nix() {
    use super::parse_submount_sources;
    // Some kernels/reporting paths expose bind source as a direct path after
    // '-' in mountinfo. This must still be treated as target-equivalent and skipped.
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 254:1 /nix /nix rw,relatime - ext4 /dev/mapper/persist rw
73 50 254:1 /nix/store /nix/store rw,relatime - ext4 /persist/nix/store rw";
    let result = parse_submount_sources(mountinfo, Path::new("/nix"));
    assert!(
        result.is_empty(),
        "Target-equivalent same-device path source should be skipped, got: {:?}",
        result
    );
}

#[test]
fn test_same_device_self_backed_submount_still_skipped() {
    use super::parse_submount_sources;
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 254:1 /persist /persist rw,relatime - ext4 /dev/mapper/persist rw
73 50 254:1 /nix/store /persist/nix/store rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/persist"));
    assert!(
        result.is_empty(),
        "Self-backed submount should still be skipped, got: {:?}",
        result
    );
}

#[test]
fn test_different_device_submount_not_skipped() {
    use super::parse_submount_sources;
    // Target /etc is on tmpfs (device 0:50), submount /etc/nixos is on persist (254:1).
    // Different devices → should be included (this is the normal impermanence case).
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 0:50 / /etc rw - tmpfs tmpfs rw
73 50 254:1 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/mapper/persist rw";
    let result = parse_submount_sources(mountinfo, Path::new("/etc"));
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/etc/nixos")
        )],
        "Cross-device submount should be included"
    );
}

#[test]
fn test_same_device_mixed_with_cross_device() {
    use super::parse_submount_sources;
    // Target /home is on tmpfs (0:51).
    // /home/amnesia is from persist (254:1) — different device → include.
    // But if we also had a same-device submount, it should be skipped.
    let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
50 1 0:51 / /home rw - tmpfs tmpfs rw
73 50 254:1 /home/amnesia /home/amnesia rw,relatime - ext4 /dev/mapper/persist rw
74 50 0:51 /home/tmp /home/tmp rw - tmpfs tmpfs rw";
    let result = parse_submount_sources(mountinfo, Path::new("/home"));
    // Only the cross-device bind mount should appear; tmpfs submount (same device 0:51)
    // is a pseudo-fs and gets skipped by the pseudo-fs filter, not the same-device filter.
    assert_eq!(
        result,
        vec![(
            PathBuf::from("/home/amnesia"),
            PathBuf::from("/persist/home/amnesia")
        )],
    );
}

// ========================================================================
// statvfs / get_free_space tests
// ========================================================================

#[test]
fn test_get_free_space_returns_realistic_value() {
    let fs = RealFilesystem;
    let free = fs
        .get_free_space(Path::new("/"))
        .expect("get_free_space should succeed on /");
    assert_ne!(free, u64::MAX, "Free space should come from statvfs");
}
