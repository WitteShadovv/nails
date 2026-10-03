use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;
use std::path::Path;

#[test]
fn test_space_check_struct_with_fields() {
    // Create SpaceCheck struct with minimum_space_mb and hidden_volume_root fields
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048);
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(check.minimum_space_mb, 2048);
}

#[test]
fn test_space_check_default_values() {
    // Default trait provides the base 500 MB floor and default path
    let check = SpaceCheck::default();
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(check.minimum_space_mb, 500);
}

#[test]
fn test_space_check_trait_metadata() {
    // Implements PreFlightCheck trait with name() and description()
    let check = SpaceCheck::default();

    assert_eq!(
        <SpaceCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "space"
    );
    assert_eq!(
        <SpaceCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Validates sufficient disk space is available for activation"
    );
}

#[test]
fn test_space_check_pass_plenty_of_space() {
    // Given 2GB available with the 500 MB floor, returns Pass
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(
        Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
        2 * 1024 * 1024 * 1024,
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("2.0 GB available"));
    assert!(result.message().contains("minimum required"));
}

#[test]
fn test_space_check_pass_exactly_at_minimum() {
    // Exactly at the floor (500 MB) -> Pass
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 500 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("500 MB available"));
    assert!(result.message().contains("1.0x minimum required"));
}

#[test]
fn test_space_check_pass_just_above_floor() {
    // 600 MB free with a 500 MB floor -> Pass (overlay-only sized activation)
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 600 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("600 MB available"));
}

#[test]
fn test_space_check_fail_below_floor() {
    // 400 MB free with a 500 MB floor -> hard Fail (no warn band)
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 400 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 400 MB available"));
    assert!(
        result
            .message()
            .contains("Free up at least 500 MB before activation")
    );
}

#[test]
fn test_space_check_fail_just_below_floor() {
    // Just below the floor (499 MB with a 500 MB floor) -> Fail, no warn tier
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 499 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 499 MB available"));
}

#[test]
fn test_space_check_fail_zero_space() {
    // Zero space -> Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 500 MB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 0);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 0 MB available"));
}

#[test]
fn test_space_check_custom_minimum() {
    // Custom minimum value works
    let fs = MockFilesystem::new();
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB floor

    fs.mock_set_free_space(
        Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
        3 * 1024 * 1024 * 1024,
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("3.0 GB available"));
}

#[test]
fn test_space_check_custom_minimum_fails_below() {
    // Custom floor: 1.5 GB free with a 2 GB floor -> Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB floor

    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1536 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("1.5 GB available"));
}

#[test]
fn test_space_check_bytes_to_mb_conversion() {
    // Helper function test
    assert_eq!(SpaceCheck::bytes_to_mb(1024 * 1024), 1);
    assert_eq!(SpaceCheck::bytes_to_mb(2 * 1024 * 1024 * 1024), 2048);
    assert_eq!(SpaceCheck::bytes_to_mb(512 * 1024 * 1024), 512);
}

#[test]
fn test_space_check_format_space_mb() {
    // Helper function test: values < 1024 MB show as MB
    assert_eq!(SpaceCheck::format_space(512), "512 MB");
    assert_eq!(SpaceCheck::format_space(800), "800 MB");
    assert_eq!(SpaceCheck::format_space(1023), "1023 MB");
}

#[test]
fn test_space_check_format_space_gb() {
    // Helper function test: values >= 1024 MB show as GB
    assert_eq!(SpaceCheck::format_space(1024), "1.0 GB");
    assert_eq!(SpaceCheck::format_space(2048), "2.0 GB");
    assert_eq!(SpaceCheck::format_space(1536), "1.5 GB");
}

#[test]
fn test_space_check_format_space_gb_rounding() {
    // Edge case: verify rounding behavior for precision
    assert_eq!(SpaceCheck::format_space(1025), "1.0 GB"); // Rounds to 1 decimal
    assert_eq!(SpaceCheck::format_space(1792), "1.8 GB"); // 1.75 rounded to 1.8
}

#[test]
fn test_space_check_format_space_large_values() {
    // Edge case: very large values (terabyte range)
    assert_eq!(SpaceCheck::format_space(1048576), "1024.0 GB"); // 1 TB
    assert_eq!(SpaceCheck::format_space(2097152), "2048.0 GB"); // 2 TB
}

#[test]
fn test_space_check_clone() {
    // Verify SpaceCheck is Clone
    let check = SpaceCheck::default();
    let cloned = check.clone();
    assert_eq!(check.hidden_volume_root, cloned.hidden_volume_root);
    assert_eq!(check.minimum_space_mb, cloned.minimum_space_mb);
}

#[test]
fn test_space_check_debug() {
    // Verify SpaceCheck is Debug
    let check = SpaceCheck::default();
    let debug = format!("{:?}", check);
    assert!(debug.contains("SpaceCheck"));
}

// OverlayDirs tests

#[test]
fn test_overlay_dirs_new_constructor() {
    let overlay = OverlayDirs::new(
        "home".to_string(),
        PathBuf::from("/home"),
        PathBuf::from("/mnt/hidden-volume/home"),
        PathBuf::from("/mnt/hidden-volume/.work/home"),
    );
    assert_eq!(overlay.name, "home");
    assert_eq!(overlay.lower, PathBuf::from("/home"));
    assert_eq!(overlay.upper, PathBuf::from("/mnt/hidden-volume/home"));
    assert_eq!(overlay.work, PathBuf::from("/mnt/hidden-volume/.work/home"));
}

#[test]
fn test_overlay_dirs_struct_fields() {
    let overlay = OverlayDirs::new(
        "etc".to_string(),
        PathBuf::from("/etc"),
        PathBuf::from("/hidden/etc"),
        PathBuf::from("/hidden/.work/etc"),
    );
    assert_eq!(overlay.name, "etc");
    assert_eq!(overlay.lower, PathBuf::from("/etc"));
    assert_eq!(overlay.upper, PathBuf::from("/hidden/etc"));
    assert_eq!(overlay.work, PathBuf::from("/hidden/.work/etc"));
}

#[test]
fn test_overlay_dirs_clone() {
    let overlay = OverlayDirs::new(
        "home".to_string(),
        PathBuf::from("/home"),
        PathBuf::from("/hidden/home"),
        PathBuf::from("/hidden/.work/home"),
    );
    let cloned = overlay.clone();
    assert_eq!(overlay, cloned);
}

#[test]
fn test_overlay_dirs_debug() {
    let overlay = OverlayDirs::new(
        "test".to_string(),
        PathBuf::from("/test"),
        PathBuf::from("/hidden/test"),
        PathBuf::from("/hidden/.work/test"),
    );
    let debug = format!("{:?}", overlay);
    assert!(debug.contains("OverlayDirs"));
}
