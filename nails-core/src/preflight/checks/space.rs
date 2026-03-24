//! Space pre-flight check
//!
//! Validates that sufficient disk space is available on the hidden volume.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, obfuscate};
use std::path::PathBuf;

/// Pre-flight check to validate sufficient disk space is available
///
/// # Security & Reliability
///
/// Activation requires disk space for:
/// - OverlayFS upper layers (modifications persist here)
/// - Temporary files during activation
/// - NixOS profile builds (lazy build pattern)
///
/// # Graduated Response System
///
/// Uses three-tier threshold system for nuanced feedback:
/// - **Pass** (>= minimum): Safe to proceed
/// - **Warn** (50-100% of minimum): Proceed with caution, monitor space
/// - **Fail** (< 50% of minimum): Blocked, insufficient space
///
/// # Default Thresholds
///
/// Default minimum: 1024 MB (1 GB)
/// - Pass: >= 1024 MB
/// - Warn: 512-1023 MB
/// - Fail: < 512 MB
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::preflight::{SpaceCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = SpaceCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), 1024);
///
/// // Simulate 2GB available
/// fs.mock_set_free_space(std::path::Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 2 * 1024 * 1024 * 1024);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct SpaceCheck {
    pub(crate) hidden_volume_path: PathBuf,
    pub(crate) minimum_space_mb: u64,
}

impl SpaceCheck {
    /// Create a new SpaceCheck with custom minimum space requirement
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to check for free space
    /// * `minimum_space_mb` - Minimum space required in megabytes
    pub fn new(hidden_volume_path: PathBuf, minimum_space_mb: u64) -> Self {
        Self {
            hidden_volume_path,
            minimum_space_mb,
        }
    }

    /// Convert bytes to megabytes
    ///
    /// Performs integer division, converting raw byte values to megabytes
    /// for threshold comparison and display.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Space in bytes
    ///
    /// # Returns
    ///
    /// Space value in megabytes (integer division)
    pub fn bytes_to_mb(bytes: u64) -> u64 {
        bytes / (1024 * 1024)
    }

    /// Format space value with appropriate unit (MB or GB)
    ///
    /// Converts raw megabyte values to human-readable format:
    /// - Values < 1024 MB → displayed as MB (e.g., "800 MB")
    /// - Values >= 1024 MB → displayed as GB with 1 decimal place (e.g., "1.5 GB")
    ///
    /// # Arguments
    ///
    /// * `mb` - Space in megabytes
    ///
    /// # Returns
    ///
    /// Formatted string with appropriate unit
    pub fn format_space(mb: u64) -> String {
        if mb >= 1024 {
            format!("{:.1} GB", mb as f64 / 1024.0)
        } else {
            format!("{} MB", mb)
        }
    }
}

impl Default for SpaceCheck {
    /// Create check with default hidden volume path and 1024 MB minimum
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from(obfuscate::hidden_volume_root()),
            minimum_space_mb: 1024, // 1 GB default
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SpaceCheck {
    fn name(&self) -> &'static str {
        "space"
    }

    fn description(&self) -> &'static str {
        "Validates sufficient disk space is available for activation"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Get available space in bytes
        let available_bytes = fs.get_free_space(&self.hidden_volume_path)?;
        let available_mb = Self::bytes_to_mb(available_bytes);
        let minimum_mb = self.minimum_space_mb;
        let warn_threshold = minimum_mb / 2; // 50% of minimum

        // Three-tier graduated response
        if available_mb >= minimum_mb {
            // PASS: >= minimum (safe to proceed)
            let ratio = ((available_mb as f64) / (minimum_mb as f64)).min(9999.9);
            Ok(CheckResult::Pass(format!(
                "{} available ({:.1}x minimum required)",
                Self::format_space(available_mb),
                ratio
            )))
        } else if available_mb >= warn_threshold {
            // WARN: 50-100% of minimum (proceed with caution)
            Ok(CheckResult::Warn(format!(
                "{} available (below {} recommended). Activation may succeed but monitor space.",
                Self::format_space(available_mb),
                Self::format_space(minimum_mb)
            )))
        } else {
            // FAIL: < 50% of minimum (blocked)
            Ok(CheckResult::Fail(format!(
                "Only {} available. Free up at least {} before activation.",
                Self::format_space(available_mb),
                Self::format_space(minimum_mb)
            )))
        }
    }
}

/// Configuration for a single overlay mount (lower, upper, work directories)
///
/// # OverlayFS Structure
///
/// OverlayFS requires three directory types:
/// - **Lower**: Read-only base layer (e.g., /home, /etc)
/// - **Upper**: Writable layer for changes (on hidden volume)
/// - **Work**: OverlayFS internal working directory (on hidden volume)
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::OverlayDirs;
/// use std::path::PathBuf;
///
/// let home_overlay = OverlayDirs::new(
///     "home".to_string(),
///     PathBuf::from("/home"),
///     PathBuf::from("/mnt/hidden-volume/home"),
///     PathBuf::from("/mnt/hidden-volume/.work/home"),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDirs {
    /// Name/identifier for this overlay (e.g., "home", "etc")
    pub name: String,
    /// Lower (read-only) directory - base layer
    pub lower: PathBuf,
    /// Upper (writable) directory - changes persist here
    pub upper: PathBuf,
    /// Work directory - OverlayFS metadata
    pub work: PathBuf,
}

impl OverlayDirs {
    /// Create a new OverlayDirs configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier for this overlay (e.g., "home", "etc")
    /// * `lower` - Read-only base layer path
    /// * `upper` - Writable overlay layer path
    /// * `work` - OverlayFS work directory path
    pub fn new(name: String, lower: PathBuf, upper: PathBuf, work: PathBuf) -> Self {
        Self {
            name,
            lower,
            upper,
            work,
        }
    }
}

#[cfg(test)]
mod tests {
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
}
