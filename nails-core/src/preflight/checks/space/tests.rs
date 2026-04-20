use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::MockFilesystem;
use std::path::Path;

#[test]
fn test_space_check_struct_with_fields() {
    // AC 1: Create SpaceCheck struct with minimum_space_mb and hidden_volume_path fields
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048);
    assert_eq!(
        check.hidden_volume_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(check.minimum_space_mb, 2048);
}

#[test]
fn test_space_check_default_values() {
    // AC 1: Default trait provides 1024 MB minimum and default path
    let check = SpaceCheck::default();
    assert_eq!(
        check.hidden_volume_path,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(check.minimum_space_mb, 1024);
}

#[test]
fn test_space_check_trait_metadata() {
    // AC 2: Implements PreFlightCheck trait with name() and description()
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
    // AC 3, 6: Given 2GB available with 1GB minimum, returns Pass with 2x multiplier
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 2GB available (2048 MB)
    fs.mock_set_free_space(
        Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
        2 * 1024 * 1024 * 1024,
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("2.0 GB available"));
    assert!(result.message().contains("2.0x minimum required"));
}

#[test]
fn test_space_check_pass_exactly_at_minimum() {
    // AC 6: Exactly at minimum (1024 MB) -> Pass
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up exactly 1GB available (1024 MB)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1024 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("1.0 GB available"));
    assert!(result.message().contains("1.0x minimum required"));
}

#[test]
fn test_space_check_warn_low_space() {
    // AC 4, 6: Given 800MB available with 1GB minimum, returns Warn
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 800MB available (between 512-1024 MB = warn range)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 800 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("800 MB available"));
    assert!(result.message().contains("below 1.0 GB recommended"));
    assert!(
        result
            .message()
            .contains("Activation may succeed but monitor space")
    );
}

#[test]
fn test_space_check_warn_at_50_percent_boundary() {
    // AC 6: At 50% boundary (512 MB with 1024 minimum) -> Warn
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up exactly 512MB available (50% of 1024 MB)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 512 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(result.message().contains("512 MB available"));
}

#[test]
fn test_space_check_fail_below_50_percent() {
    // AC 5, 6: Given 300MB available with 1GB minimum, returns Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 300MB available (< 512 MB = fail)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 300 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 300 MB available"));
    assert!(
        result
            .message()
            .contains("Free up at least 1.0 GB before activation")
    );
}

#[test]
fn test_space_check_fail_just_below_50_percent_boundary() {
    // AC 6: Just below 50% (511 MB with 1024 minimum) -> Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 511MB available (just below 512 MB threshold)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 511 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 511 MB available"));
}

#[test]
fn test_space_check_fail_critically_low() {
    // AC 6: Critically low space (10% of minimum) -> Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 100MB available (10% of 1024 MB)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 100 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 100 MB available"));
}

#[test]
fn test_space_check_fail_zero_space() {
    // AC 6: Zero space -> Fail
    let fs = MockFilesystem::new();
    let check = SpaceCheck::default(); // 1024 MB minimum

    // Set up 0 bytes available
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 0);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Only 0 MB available"));
}

#[test]
fn test_space_check_custom_minimum() {
    // AC 6: Custom minimum value works
    let fs = MockFilesystem::new();
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB minimum

    // Set up 3GB available
    fs.mock_set_free_space(
        Path::new(DEFAULT_HIDDEN_VOLUME_ROOT),
        3 * 1024 * 1024 * 1024,
    );

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("3.0 GB available"));
}

#[test]
fn test_space_check_custom_minimum_warn_threshold() {
    // AC 6: Custom minimum affects warn threshold (50% rule)
    let fs = MockFilesystem::new();
    let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 2048); // 2GB minimum

    // Set up 1.5GB available (between 1GB and 2GB = warn range)
    fs.mock_set_free_space(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1536 * 1024 * 1024);

    let result = check.run(&fs).unwrap();
    assert!(result.is_warn());
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
    assert_eq!(check.hidden_volume_path, cloned.hidden_volume_path);
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
