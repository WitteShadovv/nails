//! Hidden volume pre-flight check
//!
//! Validates that the hidden volume is mounted and writable before activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, config::get_default_hidden_volume_root};
use std::path::PathBuf;

/// Pre-flight check that validates the hidden volume is mounted and accessible
///
/// This check performs three-step validation:
/// 1. **Path Existence**: Hidden volume path must exist
/// 2. **Mount Status**: Path must be mounted (not just exist as an empty directory)
/// 3. **Write Permission**: Path must be writable to store overlay directories
///
/// # Failure Guidance
///
/// Each failure mode provides actionable guidance following UXR19 requirements:
/// - **Path not found**: Suggests mounting the hidden volume
/// - **Not mounted**: Provides cryptsetup command example
/// - **Not writable**: Suggests checking permissions
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{HiddenVolumeCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = HiddenVolumeCheck::new(PathBuf::from("/mnt/hidden-volume"));
///
/// // Set up mock state
/// fs.mock_set_path_exists("/mnt/hidden-volume", true);
/// fs.mock_set_mounted(std::path::Path::new("/mnt/hidden-volume"), true);
/// fs.mock_set_writable("/mnt/hidden-volume", true);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct HiddenVolumeCheck {
    hidden_volume_path: PathBuf,
}

impl HiddenVolumeCheck {
    /// Create a new HiddenVolumeCheck with a custom path
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    pub fn new(hidden_volume_path: PathBuf) -> Self {
        Self { hidden_volume_path }
    }
}

impl Default for HiddenVolumeCheck {
    /// Create check with default hidden volume path
    fn default() -> Self {
        Self {
            hidden_volume_path: PathBuf::from(get_default_hidden_volume_root()),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HiddenVolumeCheck {
    fn name(&self) -> &'static str {
        "hidden-volume"
    }

    fn description(&self) -> &'static str {
        "Validates hidden volume is mounted and writable"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Step 1: Check path exists
        if !fs.path_exists(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume not found at {}. Mount volume before activation.",
                self.hidden_volume_path.display()
            )));
        }

        // Step 2: Check path is mounted
        if !fs.is_mounted(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume at {} is not mounted. Mount the hidden LUKS volume to this path before activation.",
                self.hidden_volume_path.display()
            )));
        }

        // Step 3: Check path is writable
        if !fs.is_writable(&self.hidden_volume_path)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden volume at {} is not writable. Check permissions.",
                self.hidden_volume_path.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Hidden volume mounted at {}",
            self.hidden_volume_path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    #[test]
    fn test_hidden_volume_check_default_path() {
        let check = HiddenVolumeCheck::default();
        assert_eq!(
            check.hidden_volume_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn test_hidden_volume_check_custom_path() {
        let custom_path = PathBuf::from("/custom/path");
        let check = HiddenVolumeCheck::new(custom_path.clone());
        assert_eq!(check.hidden_volume_path, custom_path);
    }

    #[test]
    fn test_hidden_volume_check_trait_metadata() {
        let check = HiddenVolumeCheck::default();

        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "hidden-volume"
        );
        assert_eq!(
            <HiddenVolumeCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates hidden volume is mounted and writable"
        );
    }

    #[test]
    fn test_hidden_volume_check_pass_when_mounted_and_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Set up: volume exists, is mounted, and writable
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), true);
        fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert_eq!(
            result.message(),
            "Hidden volume mounted at /mnt/hidden-volume"
        );
    }

    #[test]
    fn test_hidden_volume_check_fail_when_path_does_not_exist() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume path does not exist
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(
            result
                .message()
                .contains("Hidden volume not found at /mnt/hidden-volume")
        );
        assert!(result.message().contains("Mount volume before activation"));
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_mounted() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume exists but is NOT mounted
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not mounted"));
        assert!(result.message().contains("Mount the hidden LUKS volume"));
    }

    #[test]
    fn test_hidden_volume_check_fail_when_not_writable() {
        let fs = MockFilesystem::new();
        let check = HiddenVolumeCheck::default();

        // Volume exists and is mounted but NOT writable
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_mounted(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), true);
        fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("is not writable"));
        assert!(result.message().contains("Check permissions"));
    }

    #[test]
    fn test_hidden_volume_check_custom_path_works() {
        let fs = MockFilesystem::new();
        let custom_path = PathBuf::from("/custom/volume");
        let check = HiddenVolumeCheck::new(custom_path.clone());

        // Set up custom path
        fs.mock_set_path_exists("/custom/volume", true);
        fs.mock_set_mounted(Path::new("/custom/volume"), true);
        fs.mock_set_writable("/custom/volume", true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("/custom/volume"));
    }

    #[test]
    fn test_hidden_volume_check_clone() {
        let check = HiddenVolumeCheck::default();
        let cloned = check.clone();
        assert_eq!(check.hidden_volume_path, cloned.hidden_volume_path);
    }
}
