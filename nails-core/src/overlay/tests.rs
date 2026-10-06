// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for overlay filesystem operations

use super::*;
use crate::config::EphemeralOverlayDir;
use crate::filesystem::{Filesystem, MockFilesystem};
use std::path::{Path, PathBuf};

/// Deterministic stand-in for the per-activation random runtime root.
const TEST_RUNTIME_BASE: &str = "/run/0123456789abcdef";

// ========== EphemeralMountInfo Tests ==========

#[test]
fn test_ephemeral_mount_info_creation() {
    let info = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/0123456789abcdef/var-upper"),
        work: PathBuf::from("/run/0123456789abcdef/var-work"),
        lower: PathBuf::from("/var"),
    };

    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.upper, PathBuf::from("/run/0123456789abcdef/var-upper"));
    assert_eq!(info.work, PathBuf::from("/run/0123456789abcdef/var-work"));
    assert_eq!(info.lower, PathBuf::from("/var"));
}

#[test]
fn test_ephemeral_mount_info_clone() {
    let info1 = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/0123456789abcdef/var-upper"),
        work: PathBuf::from("/run/0123456789abcdef/var-work"),
        lower: PathBuf::from("/var"),
    };

    let info2 = info1.clone();
    assert_eq!(info1, info2);
}

// ========== mount_ephemeral_overlay Tests ==========

#[test]
fn test_mount_ephemeral_overlay_success() {
    // Creates tmpfs mounts and overlay
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    // Set up mock filesystem
    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    let result = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    );
    assert!(result.is_ok());

    let info = result.unwrap();
    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.upper, PathBuf::from("/run/0123456789abcdef/var-upper"));
    assert_eq!(info.work, PathBuf::from("/run/0123456789abcdef/var-work"));
    assert_eq!(info.lower, PathBuf::from("/var"));

    // Verify tmpfs mounts created
    assert!(
        fs.is_mounted(Path::new("/run/0123456789abcdef/var-upper"))
            .unwrap()
    );
    assert!(
        fs.is_mounted(Path::new("/run/0123456789abcdef/var-work"))
            .unwrap()
    );

    // Verify overlay mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
}

#[test]
fn test_mount_ephemeral_overlay_creates_directories() {
    // Creates upper and work directories
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    // Directories don't exist yet
    assert!(
        !fs.path_exists(Path::new("/run/0123456789abcdef/var-upper"))
            .unwrap()
    );
    assert!(
        !fs.path_exists(Path::new("/run/0123456789abcdef/var-work"))
            .unwrap()
    );

    let result = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    );
    assert!(result.is_ok());

    // Directories were created
    assert!(
        fs.path_exists(Path::new("/run/0123456789abcdef/var-upper"))
            .unwrap()
    );
    assert!(
        fs.path_exists(Path::new("/run/0123456789abcdef/var-work"))
            .unwrap()
    );
}

#[test]
fn test_mount_ephemeral_overlay_validates_sizes() {
    // Size validation via tmpfs mount
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "invalid".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    let result = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    );
    assert!(result.is_err());
}

#[test]
fn test_mount_ephemeral_overlay_rejects_root_target_without_file_name() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    let result =
        mount_ephemeral_overlay(&fs, Path::new(TEST_RUNTIME_BASE), &config, Path::new("/"));

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid path: /"));
}

#[test]
fn test_mount_ephemeral_overlay_multiple_directories() {
    // Can mount multiple ephemeral overlays
    let fs = MockFilesystem::new();

    let config_var = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    let config_tmp = EphemeralOverlayDir {
        path: PathBuf::from("/tmp"),
        tmpfs_upper_size: "512M".to_string(),
        tmpfs_work_size: "256M".to_string(),
    };

    // Set up mock filesystem for both
    fs.mock_set_path_exists("/var", true);
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/tmp-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/tmp-work", true);

    // Mount first ephemeral overlay
    let result_var = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config_var,
        Path::new("/var"),
    );
    assert!(result_var.is_ok());

    // Mount second ephemeral overlay
    let result_tmp = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config_tmp,
        Path::new("/tmp"),
    );
    assert!(result_tmp.is_ok());

    // Both should be mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
}

// ========== unmount_ephemeral_overlay Tests ==========

#[test]
fn test_unmount_ephemeral_overlay_success() {
    // Unmounts overlay and tmpfs in correct order
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    let info = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    )
    .unwrap();

    // Verify mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(
        fs.is_mounted(Path::new("/run/0123456789abcdef/var-upper"))
            .unwrap()
    );
    assert!(
        fs.is_mounted(Path::new("/run/0123456789abcdef/var-work"))
            .unwrap()
    );

    // Unmount
    let result = unmount_ephemeral_overlay(&fs, &info);
    assert!(result.is_ok());

    // Verify all unmounted
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(
        !fs.is_mounted(Path::new("/run/0123456789abcdef/var-upper"))
            .unwrap()
    );
    assert!(
        !fs.is_mounted(Path::new("/run/0123456789abcdef/var-work"))
            .unwrap()
    );
}

#[test]
fn test_unmount_ephemeral_overlay_best_effort() {
    // Best-effort unmount continues even if some fail
    let fs = MockFilesystem::new();
    let info = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/0123456789abcdef/var-upper"),
        work: PathBuf::from("/run/0123456789abcdef/var-work"),
        lower: PathBuf::from("/var"),
    };

    // No mounts exist, but unmount should still succeed (idempotent)
    let result = unmount_ephemeral_overlay(&fs, &info);
    assert!(result.is_ok());
}

#[test]
fn test_unmount_ephemeral_overlay_reports_all_failures_after_force_fallback() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    let info = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    )
    .unwrap();

    fs.mock_set_unmount_should_fail("/var", true);
    fs.mock_set_unmount_should_fail("/run/0123456789abcdef/var-work", true);
    fs.mock_set_unmount_should_fail("/run/0123456789abcdef/var-upper", true);

    let result = unmount_ephemeral_overlay(&fs, &info);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("overlay /var"));
    assert!(error.contains("work tmpfs /run/0123456789abcdef/var-work"));
    assert!(error.contains("upper tmpfs /run/0123456789abcdef/var-upper"));
}

#[test]
fn test_unmount_ephemeral_overlay_full_cycle() {
    // Full mount/write/unmount cycle
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-upper", true);
    fs.mock_set_directory_creatable("/run/0123456789abcdef/var-work", true);

    // Mount
    let info = mount_ephemeral_overlay(
        &fs,
        Path::new(TEST_RUNTIME_BASE),
        &config,
        Path::new("/var"),
    )
    .unwrap();

    // Simulate writes to /var (would go to tmpfs upper in real system)
    // In mock, just verify mount exists
    assert!(fs.is_mounted(Path::new("/var")).unwrap());

    // Unmount destroys tmpfs data
    let result = unmount_ephemeral_overlay(&fs, &info);
    assert!(result.is_ok());

    // No artifacts remain
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
}
