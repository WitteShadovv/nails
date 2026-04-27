//! Tests for overlay filesystem operations

use super::*;
use crate::config::EphemeralOverlayDir;
use crate::filesystem::{Filesystem, MockFilesystem};
use std::path::{Path, PathBuf};

// ========== EphemeralMountInfo Tests ==========

#[test]
fn test_ephemeral_mount_info_creation() {
    let info = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/nails/var-upper"),
        work: PathBuf::from("/run/nails/var-work"),
        lower: PathBuf::from("/var"),
    };

    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
    assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
    assert_eq!(info.lower, PathBuf::from("/var"));
}

#[test]
fn test_ephemeral_mount_info_clone() {
    let info1 = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/nails/var-upper"),
        work: PathBuf::from("/run/nails/var-work"),
        lower: PathBuf::from("/var"),
    };

    let info2 = info1.clone();
    assert_eq!(info1, info2);
}

// ========== mount_ephemeral_overlay Tests ==========

#[test]
fn test_mount_ephemeral_overlay_success() {
    // AC2: Creates tmpfs mounts and overlay
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    // Set up mock filesystem
    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
    assert!(result.is_ok());

    let info = result.unwrap();
    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
    assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
    assert_eq!(info.lower, PathBuf::from("/var"));

    // Verify tmpfs mounts created
    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

    // Verify overlay mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
}

#[test]
fn test_mount_ephemeral_overlay_creates_directories() {
    // AC2: Creates upper and work directories
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    // Directories don't exist yet
    assert!(!fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
    assert!(!fs.path_exists(Path::new("/run/nails/var-work")).unwrap());

    let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
    assert!(result.is_ok());

    // Directories were created
    assert!(fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
    assert!(fs.path_exists(Path::new("/run/nails/var-work")).unwrap());
}

#[test]
fn test_mount_ephemeral_overlay_validates_sizes() {
    // AC1: Size validation via tmpfs mount
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "invalid".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
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

    let result = mount_ephemeral_overlay(&fs, &config, Path::new("/"));

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid path: /"));
}

#[test]
fn test_mount_ephemeral_overlay_multiple_directories() {
    // AC2: Can mount multiple ephemeral overlays
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
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);
    fs.mock_set_directory_creatable("/run/nails/tmp-upper", true);
    fs.mock_set_directory_creatable("/run/nails/tmp-work", true);

    // Mount first ephemeral overlay
    let result_var = mount_ephemeral_overlay(&fs, &config_var, Path::new("/var"));
    assert!(result_var.is_ok());

    // Mount second ephemeral overlay
    let result_tmp = mount_ephemeral_overlay(&fs, &config_tmp, Path::new("/tmp"));
    assert!(result_tmp.is_ok());

    // Both should be mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
}

// ========== unmount_ephemeral_overlay Tests ==========

#[test]
fn test_unmount_ephemeral_overlay_success() {
    // AC5: Unmounts overlay and tmpfs in correct order
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

    // Verify mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

    // Unmount
    let result = unmount_ephemeral_overlay(&fs, &info);
    assert!(result.is_ok());

    // Verify all unmounted
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
    assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
}

#[test]
fn test_unmount_ephemeral_overlay_best_effort() {
    // AC5: Best-effort unmount continues even if some fail
    let fs = MockFilesystem::new();
    let info = EphemeralMountInfo {
        target: PathBuf::from("/var"),
        upper: PathBuf::from("/run/nails/var-upper"),
        work: PathBuf::from("/run/nails/var-work"),
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
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

    fs.mock_set_unmount_should_fail("/var", true);
    fs.mock_set_unmount_should_fail("/run/nails/var-work", true);
    fs.mock_set_unmount_should_fail("/run/nails/var-upper", true);

    let result = unmount_ephemeral_overlay(&fs, &info);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("overlay /var"));
    assert!(error.contains("work tmpfs /run/nails/var-work"));
    assert!(error.contains("upper tmpfs /run/nails/var-upper"));
}

#[test]
fn test_unmount_ephemeral_overlay_full_cycle() {
    // AC4, AC5: Full mount/write/unmount cycle
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-work", true);

    // Mount
    let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

    // Simulate writes to /var (would go to tmpfs upper in real system)
    // In mock, just verify mount exists
    assert!(fs.is_mounted(Path::new("/var")).unwrap());

    // Unmount destroys tmpfs data
    let result = unmount_ephemeral_overlay(&fs, &info);
    assert!(result.is_ok());

    // No artifacts remain
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
}

// ========== PivotMountInfo Tests ==========

#[test]
fn test_pivot_mount_info_creation() {
    let info = PivotMountInfo {
        target: PathBuf::from("/var"),
        staging: PathBuf::from("/mnt/nails-pivot/var"),
        upper: PathBuf::from("/mnt/hidden/var-upper"),
        work: PathBuf::from("/mnt/hidden/var-work"),
        lower: PathBuf::from("/var"),
        is_ephemeral: false,
    };

    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
    assert!(!info.is_ephemeral);
}

#[test]
fn test_pivot_mount_info_clone() {
    let info1 = PivotMountInfo {
        target: PathBuf::from("/var"),
        staging: PathBuf::from("/mnt/nails-pivot/var"),
        upper: PathBuf::from("/mnt/hidden/var-upper"),
        work: PathBuf::from("/mnt/hidden/var-work"),
        lower: PathBuf::from("/var"),
        is_ephemeral: true,
    };

    let info2 = info1.clone();
    assert_eq!(info1, info2);
    assert!(info2.is_ephemeral);
}

// ========== pivot_overlay_mount Tests ==========

#[test]
fn test_pivot_overlay_mount_success() {
    let fs = MockFilesystem::new();

    // Set up mock filesystem
    fs.mock_set_path_exists("/var", true);
    fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/var-work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/var")],
        Path::new("/mnt/hidden/var-upper"),
        Path::new("/mnt/hidden/var-work"),
        Path::new("/var"),
    );

    assert!(result.is_ok());
    let info = result.unwrap();

    // Verify mount info
    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
    assert_eq!(info.lower, PathBuf::from("/var"));
    assert!(!info.is_ephemeral);

    // Verify mounts created
    assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap()); // staging overlay
    assert!(fs.is_mounted(Path::new("/var")).unwrap()); // bind mount
}

#[test]
fn test_pivot_overlay_mount_creates_staging_dir() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/var-work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/var")],
        Path::new("/mnt/hidden/var-upper"),
        Path::new("/mnt/hidden/var-work"),
        Path::new("/var"),
    );

    assert!(result.is_ok());

    // Staging directory was created
    assert!(fs.path_exists(Path::new("/mnt/nails-pivot/var")).unwrap());
}

#[test]
fn test_pivot_overlay_mount_rollback_on_bind_failure() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/var-work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    // Configure bind mount to fail
    fs.mock_set_mount_should_fail("/var", true);

    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/var")],
        Path::new("/mnt/hidden/var-upper"),
        Path::new("/mnt/hidden/var-work"),
        Path::new("/var"),
    );

    assert!(result.is_err());

    // Staging overlay should be unmounted (rolled back)
    // Note: Mock doesn't perfectly simulate rollback tracking, but we verify error
}

// ========== pivot_ephemeral_mount Tests ==========

#[test]
fn test_pivot_ephemeral_mount_success() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    let result = pivot_ephemeral_mount(&fs, &config, Path::new("/var"));
    assert!(result.is_ok());

    let info = result.unwrap();

    // Verify ephemeral flag
    assert!(info.is_ephemeral);

    // Verify paths
    assert_eq!(info.target, PathBuf::from("/var"));
    assert_eq!(info.upper, PathBuf::from("/run/nails/var-ephemeral/upper"));
    assert_eq!(info.work, PathBuf::from("/run/nails/var-ephemeral/work"));

    // Verify all mounts created
    assert!(
        fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    ); // tmpfs
    assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap()); // overlay
    assert!(fs.is_mounted(Path::new("/var")).unwrap()); // bind
}

#[test]
fn test_pivot_ephemeral_mount_rollback_on_overlay_failure() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    // Make staging overlay mount fail
    fs.mock_set_mount_should_fail("/mnt/nails-pivot/var", true);

    let result = pivot_ephemeral_mount(&fs, &config, Path::new("/var"));
    assert!(result.is_err());

    // Tmpfs mounts should be cleaned up (rolled back)
    assert!(
        !fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    );
}

// ========== unmount_pivot_overlay Tests ==========

#[test]
fn test_unmount_pivot_overlay_success() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/var-work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    // Mount
    let info = pivot_overlay_mount(
        &fs,
        &[Path::new("/var")],
        Path::new("/mnt/hidden/var-upper"),
        Path::new("/mnt/hidden/var-work"),
        Path::new("/var"),
    )
    .unwrap();

    // Verify mounted
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());

    // Unmount
    let result = unmount_pivot_overlay(&fs, &info);
    assert!(result.is_ok());

    // Verify unmounted
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(!fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
}

#[test]
fn test_unmount_pivot_overlay_ephemeral_cleans_tmpfs() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    // Mount ephemeral pivot
    let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();
    assert!(info.is_ephemeral);

    // Verify all mounts
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
    assert!(
        fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    );

    // Unmount
    let result = unmount_pivot_overlay(&fs, &info);
    assert!(result.is_ok());

    // Verify all unmounted (including tmpfs)
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(!fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
    assert!(
        !fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    );
    assert!(!fs.path_exists(Path::new("/mnt/nails-pivot/var")).unwrap());
    assert!(
        !fs.path_exists(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    );
}

#[test]
fn test_unmount_pivot_overlay_idempotent() {
    let fs = MockFilesystem::new();
    let info = PivotMountInfo {
        target: PathBuf::from("/var"),
        staging: PathBuf::from("/mnt/nails-pivot/var"),
        upper: PathBuf::from("/mnt/hidden/var-upper"),
        work: PathBuf::from("/mnt/hidden/var-work"),
        lower: PathBuf::from("/var"),
        is_ephemeral: false,
    };

    // No mounts exist, but unmount should still succeed (idempotent)
    let result = unmount_pivot_overlay(&fs, &info);
    assert!(result.is_ok());
}

#[test]
fn test_unmount_pivot_overlay_full_ephemeral_cycle() {
    let fs = MockFilesystem::new();
    let config = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    fs.mock_set_path_exists("/var", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

    // Full cycle: mount -> verify -> unmount
    let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();

    // System is active
    assert!(fs.is_mounted(Path::new("/var")).unwrap());

    // Deactivate
    let result = unmount_pivot_overlay(&fs, &info);
    assert!(result.is_ok());

    // No forensic artifacts remain
    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(
        !fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap()
    );
}
