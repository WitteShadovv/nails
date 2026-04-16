use super::*;
use crate::filesystem::MockFilesystem;

/// Helper: set up MockFilesystem so pivot_overlay_mount can succeed for a given target.
/// - `lower_path`: the lower directory (must exist)
/// - `upper_path`: the upper directory (must exist)
/// - `work_path`: the work directory (must exist)
///   The staging dir is auto-created under PIVOT_STAGING_BASE.
fn setup_pivot_fs(fs: &MockFilesystem, lower: &str, upper: &str, work: &str) {
    fs.mock_set_path_exists(lower, true);
    fs.mock_set_path_exists(upper, true);
    fs.mock_set_path_exists(work, true);
    // create_directory("/mnt/nails-pivot/{name}") needs grandparent /mnt to exist+be writable
    fs.mock_set_path_exists("/mnt", true);
}

#[test]
fn test_pivot_overlay_mount_success() {
    let fs = MockFilesystem::new();
    setup_pivot_fs(&fs, "/var", "/mnt/hidden/var-upper", "/mnt/hidden/var-work");

    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/var")],
        Path::new("/mnt/hidden/var-upper"),
        Path::new("/mnt/hidden/var-work"),
        Path::new("/var"),
    );

    assert!(
        result.is_ok(),
        "pivot_overlay_mount should succeed: {:?}",
        result.err()
    );
    let info = result.unwrap();
    assert_eq!(info.target, PathBuf::from("/var"));
    assert!(info.staging.starts_with(PIVOT_STAGING_BASE));
    assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
    assert_eq!(info.upper, PathBuf::from("/mnt/hidden/var-upper"));
    assert_eq!(info.work, PathBuf::from("/mnt/hidden/var-work"));
    assert_eq!(info.lower, PathBuf::from("/var"));
    assert!(!info.is_ephemeral);
}

#[test]
fn test_pivot_overlay_mount_bind_fails_rolls_back_overlay() {
    let fs = MockFilesystem::new();
    setup_pivot_fs(
        &fs,
        "/home",
        "/mnt/hidden/home-upper",
        "/mnt/hidden/home-work",
    );
    fs.mock_set_mount_should_fail("/home", true);

    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/home")],
        Path::new("/mnt/hidden/home-upper"),
        Path::new("/mnt/hidden/home-work"),
        Path::new("/home"),
    );

    assert!(result.is_err(), "should fail when bind mount fails");
    let staging = PathBuf::from("/mnt/nails-pivot/home");
    assert!(
        !fs.is_mounted(&staging).unwrap_or(false),
        "staging overlay should be unmounted after rollback"
    );
}

#[test]
fn test_pivot_overlay_mount_root_target_fails() {
    let fs = MockFilesystem::new();
    let result = pivot_overlay_mount(
        &fs,
        &[Path::new("/")],
        Path::new("/mnt/hidden/root-upper"),
        Path::new("/mnt/hidden/root-work"),
        Path::new("/"),
    );
    assert!(result.is_err());
}

#[test]
fn test_pivot_overlay_mount_roundtrip_with_unmount() {
    let fs = MockFilesystem::new();
    setup_pivot_fs(&fs, "/etc", "/mnt/hidden/etc-upper", "/mnt/hidden/etc-work");

    let info = pivot_overlay_mount(
        &fs,
        &[Path::new("/etc")],
        Path::new("/mnt/hidden/etc-upper"),
        Path::new("/mnt/hidden/etc-work"),
        Path::new("/etc"),
    )
    .expect("mount should succeed");

    assert!(fs.is_mounted(&info.staging).unwrap_or(false));
    assert!(fs.is_mounted(&info.target).unwrap_or(false));

    let result = unmount_pivot_overlay(&fs, &info);
    assert!(result.is_ok(), "unmount should succeed: {:?}", result.err());
    assert!(!fs.path_exists(&info.staging).unwrap());
}

#[test]
fn test_unmount_pivot_overlay_ephemeral() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/run", true);
    fs.mock_set_path_exists("/mnt", true);

    let config = crate::config::EphemeralOverlayDir {
        path: PathBuf::from("/run"),
        tmpfs_upper_size: "512M".to_string(),
        tmpfs_work_size: "256M".to_string(),
    };

    let info = pivot_ephemeral_mount(&fs, &config, Path::new("/run"))
        .expect("ephemeral mount should succeed");

    assert!(info.is_ephemeral);

    let result = unmount_pivot_overlay(&fs, &info);
    assert!(
        result.is_ok(),
        "ephemeral unmount should succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_unmount_pivot_overlay_snapshot_lower() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot-work", true);
    fs.mock_set_path_exists("/mnt", true);

    let info = snapshot_pivot_overlay_mount(
        &fs,
        &[Path::new("/boot")],
        Path::new("/mnt/hidden/boot-upper"),
        Path::new("/mnt/hidden/boot-work"),
        Path::new("/boot"),
    )
    .expect("snapshot pivot should succeed");

    assert!(info.lower.to_string_lossy().ends_with("-snapshot"));

    let result = unmount_pivot_overlay(&fs, &info);
    assert!(
        result.is_ok(),
        "snapshot unmount should succeed: {:?}",
        result.err()
    );
    assert!(!fs.path_exists(&info.staging).unwrap());
    assert!(!fs.path_exists(&info.lower).unwrap());
}

#[test]
fn test_pivot_ephemeral_mount_success() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_exists("/run", true);
    fs.mock_set_path_exists("/mnt", true);

    let config = crate::config::EphemeralOverlayDir {
        path: PathBuf::from("/tmp"),
        tmpfs_upper_size: "2G".to_string(),
        tmpfs_work_size: "1G".to_string(),
    };

    let result = pivot_ephemeral_mount(&fs, &config, Path::new("/tmp"));
    assert!(
        result.is_ok(),
        "ephemeral mount should succeed: {:?}",
        result.err()
    );
    let info = result.unwrap();
    assert!(info.is_ephemeral);
    assert_eq!(info.target, PathBuf::from("/tmp"));
    assert!(info.upper.to_string_lossy().ends_with("-upper"));
    assert!(info.work.to_string_lossy().ends_with("-work"));
}

#[test]
fn test_pivot_ephemeral_mount_invalid_size_fails() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);

    let config = crate::config::EphemeralOverlayDir {
        path: PathBuf::from("/tmp"),
        tmpfs_upper_size: "notasize".to_string(),
        tmpfs_work_size: "1G".to_string(),
    };

    let result = pivot_ephemeral_mount(&fs, &config, Path::new("/tmp"));
    assert!(result.is_err(), "invalid size should fail");
}

#[test]
fn test_pivot_ephemeral_mount_root_path_fails() {
    let fs = MockFilesystem::new();
    let config = crate::config::EphemeralOverlayDir {
        path: PathBuf::from("/"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };
    let result = pivot_ephemeral_mount(&fs, &config, Path::new("/"));
    assert!(result.is_err());
}

#[test]
fn test_snapshot_pivot_success() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot-upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot-work", true);
    fs.mock_set_path_exists("/mnt", true);

    let result = snapshot_pivot_overlay_mount(
        &fs,
        &[Path::new("/boot")],
        Path::new("/mnt/hidden/boot-upper"),
        Path::new("/mnt/hidden/boot-work"),
        Path::new("/boot"),
    );

    assert!(
        result.is_ok(),
        "snapshot pivot should succeed: {:?}",
        result.err()
    );
    let info = result.unwrap();
    assert_eq!(info.target, PathBuf::from("/boot"));
    assert!(info.lower.to_string_lossy().ends_with("-snapshot"));
    assert!(!info.is_ephemeral);
}

#[test]
fn test_snapshot_pivot_copy_tree_failure_rolls_back() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_copy_tree_should_fail(Path::new("/boot"));

    let result = snapshot_pivot_overlay_mount(
        &fs,
        &[Path::new("/boot")],
        Path::new("/mnt/hidden/boot-upper"),
        Path::new("/mnt/hidden/boot-work"),
        Path::new("/boot"),
    );

    assert!(result.is_err(), "should fail when copy_tree fails");
}

#[test]
fn test_snapshot_pivot_root_target_fails() {
    let fs = MockFilesystem::new();
    let result = snapshot_pivot_overlay_mount(
        &fs,
        &[Path::new("/")],
        Path::new("/mnt/hidden/root-upper"),
        Path::new("/mnt/hidden/root-work"),
        Path::new("/"),
    );
    assert!(result.is_err());
}
