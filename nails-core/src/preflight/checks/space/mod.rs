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
/// use nails_core::preflight::{SpaceCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = SpaceCheck::new(PathBuf::from("/mnt/hidden-volume"), 1024);
///
/// // Simulate 2GB available
/// fs.mock_set_free_space(std::path::Path::new("/mnt/hidden-volume"), 2 * 1024 * 1024 * 1024);
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
    /// - Values < 1024 MB -> displayed as MB (e.g., "800 MB")
    /// - Values >= 1024 MB -> displayed as GB with 1 decimal place (e.g., "1.5 GB")
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
mod tests;
