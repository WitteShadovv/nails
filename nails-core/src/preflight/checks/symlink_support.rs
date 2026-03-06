//! Symlink support pre-flight check
//!
//! Validates that the hidden volume filesystem supports symbolic links.
//! FAT32 and exFAT volumes will fail this check.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, config::DEFAULT_HIDDEN_VOLUME_ROOT};
use std::path::PathBuf;

/// Pre-flight check that validates the hidden volume filesystem supports symbolic links
///
/// Creates a temporary probe symlink to detect filesystems (e.g. FAT32, exFAT)
/// that cannot host symlinks. Without this check, `stage_hidden_config_symlink`
/// fails with a cryptic "Operation not permitted" error.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::preflight::{SymlinkSupportCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = SymlinkSupportCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
///
/// // Mock supports symlinks by default
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct SymlinkSupportCheck {
    hidden_volume_path: PathBuf,
}

impl SymlinkSupportCheck {
    /// Create a new SymlinkSupportCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    pub fn new(hidden_volume_path: PathBuf) -> Self {
        Self { hidden_volume_path }
    }
}

impl Default for SymlinkSupportCheck {
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SymlinkSupportCheck {
    fn name(&self) -> &'static str {
        "symlink-support"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume filesystem supports symbolic links"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if !fs.supports_symlinks(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Filesystem at {} does not support symbolic links. \
                 The hidden volume must be formatted with a Linux filesystem (e.g. ext4). \
                 FAT32 and exFAT do not support symlinks.",
                self.hidden_volume_path.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Filesystem at {} supports symbolic links",
            self.hidden_volume_path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    #[test]
    fn test_symlink_support_check_default_path() {
        let check = SymlinkSupportCheck::default();
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn test_symlink_support_check_custom_path() {
        let custom_path = PathBuf::from("/custom/path");
        let check = SymlinkSupportCheck::new(custom_path.clone());
        assert_eq!(check.hidden_volume_path, custom_path);
    }

    #[test]
    fn test_symlink_support_check_trait_metadata() {
        let check = SymlinkSupportCheck::default();

        assert_eq!(
            <SymlinkSupportCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "symlink-support"
        );
        assert_eq!(
            <SymlinkSupportCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates hidden volume filesystem supports symbolic links"
        );
    }

    #[test]
    fn test_symlink_support_check_pass_when_supported() {
        let fs = MockFilesystem::new();
        let check = SymlinkSupportCheck::default();

        // MockFilesystem defaults to supporting symlinks
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("supports symbolic links"));
    }

    #[test]
    fn test_symlink_support_check_fail_when_not_supported() {
        let fs = MockFilesystem::new();
        let check = SymlinkSupportCheck::default();

        // Simulate FAT32/exFAT volume
        fs.mock_set_supports_symlinks(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("does not support symbolic links"));
        assert!(result.message().contains("ext4"));
        assert!(result.message().contains("FAT32"));
    }

    #[test]
    fn test_symlink_support_check_custom_path_works() {
        let fs = MockFilesystem::new();
        let custom_path = PathBuf::from("/custom/volume");
        let check = SymlinkSupportCheck::new(custom_path.clone());

        // Explicitly set support
        fs.mock_set_supports_symlinks(Path::new("/custom/volume"), true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("/custom/volume"));
    }

    #[test]
    fn test_symlink_support_check_clone() {
        let check = SymlinkSupportCheck::default();
        let cloned = check.clone();
        assert_eq!(check.hidden_volume_path, cloned.hidden_volume_path);
    }
}
