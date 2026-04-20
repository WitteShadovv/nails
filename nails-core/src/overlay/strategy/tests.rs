use super::*;

#[test]
fn test_fstype_supports_overlay_compatible() {
    assert!(fstype_supports_overlay("ext4"));
    assert!(fstype_supports_overlay("xfs"));
    assert!(fstype_supports_overlay("btrfs"));
    assert!(fstype_supports_overlay("tmpfs"));
    assert!(fstype_supports_overlay("overlay"));
}

#[test]
fn test_fstype_supports_overlay_incompatible() {
    assert!(!fstype_supports_overlay("vfat"));
    assert!(!fstype_supports_overlay("fat"));
    assert!(!fstype_supports_overlay("msdos"));
    assert!(!fstype_supports_overlay("exfat"));
    assert!(!fstype_supports_overlay("ntfs"));
    assert!(!fstype_supports_overlay("ntfs3"));
    assert!(!fstype_supports_overlay("fuse.ntfs-3g"));
}

fn setup_vfat_boot(fs: &crate::filesystem::MockFilesystem) {
    use std::path::Path;

    fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/boot-snapshot", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/boot", true);
}

#[test]
fn test_vfat_boot_uses_snapshot_pivot_bypassing_no_pivot() {
    use crate::filesystem::MockFilesystem;

    let fs = MockFilesystem::new();
    setup_vfat_boot(&fs);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        auto_accept_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[std::path::Path::new("/boot")],
        std::path::Path::new("/mnt/hidden/boot/.upper"),
        std::path::Path::new("/mnt/hidden/boot/.work"),
        std::path::Path::new("/boot"),
        &options,
    );

    assert!(
        result.is_ok(),
        "vfat target should use snapshot pivot: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().method, MountMethod::Pivot);
}

#[test]
fn test_exfat_target_uses_snapshot_pivot() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/boot"), "exfat");
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/boot-snapshot", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/boot", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/boot")],
        Path::new("/mnt/hidden/boot/.upper"),
        Path::new("/mnt/hidden/boot/.work"),
        Path::new("/boot"),
        &options,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Pivot);
}

#[test]
fn test_ext4_target_uses_direct_mount() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/mnt/hidden/home/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/home/.work", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/home")],
        Path::new("/mnt/hidden/home/.upper"),
        Path::new("/mnt/hidden/home/.work"),
        Path::new("/home"),
        &options,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_no_fstype_info_attempts_direct_mount() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/hidden/data/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/data/.work", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/hidden/data/.upper"),
        Path::new("/mnt/hidden/data/.work"),
        Path::new("/data"),
        &options,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_ntfs_target_uses_snapshot_pivot() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_filesystem_type(Path::new("/mnt/windows"), "ntfs3");
    fs.mock_set_path_exists("/mnt/windows", true);
    fs.mock_set_path_exists("/mnt/hidden/windows/.upper", true);
    fs.mock_set_path_exists("/mnt/hidden/windows/.work", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/windows-snapshot", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/windows", true);

    let options = OverlayStrategyOptions {
        allow_pivot: false,
        skip_process_detection: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/mnt/windows")],
        Path::new("/mnt/hidden/windows/.upper"),
        Path::new("/mnt/hidden/windows/.work"),
        Path::new("/mnt/windows"),
        &options,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Pivot);
}

#[test]
fn test_restart_services_after_failure_empty_list() {
    restart_services_after_failure(&[]);
}

#[test]
fn test_overlay_incompatible_fstypes_constant_not_empty() {
    assert!(!OVERLAY_INCOMPATIBLE_FSTYPES.is_empty());
    assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"vfat"));
    assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"ntfs3"));
}

#[test]
fn test_mount_overlay_with_strategy_direct_mount_succeeds_when_no_fstype() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);

    let options = super::OverlayStrategyOptions {
        skip_process_detection: true,
        allow_pivot: false,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().method, MountMethod::Direct);
}

#[test]
fn test_direct_mount_fatal_error_is_returned_without_pivot_fallback() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    fs.mock_set_mount_should_fail("/data", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: true,
        auto_accept_pivot: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Mock mount failure for testing"));
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_busy_direct_mount_without_pivot_returns_invalid_state() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    fs.mock_set_mount_should_fail("/data", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: false,
        auto_accept_pivot: false,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Mock mount failure for testing"));
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}

#[test]
fn test_busy_direct_mount_with_auto_accept_uses_pivot_fallback() {
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/data", true);
    fs.mock_set_path_exists("/mnt/upper", true);
    fs.mock_set_path_exists("/mnt/work", true);
    fs.mock_set_filesystem_type(Path::new("/data"), "ext4");
    fs.mock_set_mount_should_fail("/data", true);
    fs.mock_set_directory_creatable("/mnt/nails-pivot/data", true);

    let options = OverlayStrategyOptions {
        skip_process_detection: false,
        allow_pivot: true,
        auto_accept_pivot: true,
        ..Default::default()
    };

    let result = mount_overlay_with_strategy(
        &fs,
        &[Path::new("/data")],
        Path::new("/mnt/upper"),
        Path::new("/mnt/work"),
        Path::new("/data"),
        &options,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Mock mount failure for testing"));
        }
        other => panic!("expected OverlayError, got {other:?}"),
    }
}
