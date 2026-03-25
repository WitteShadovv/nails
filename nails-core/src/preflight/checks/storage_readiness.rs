//! Storage readiness pre-flight check
//!
//! Unified pre-flight check that validates hidden storage directory structure
//! AND overlay directory accessibility in a single pass (Story 14.5).

use super::super::{CheckResult, PreFlightCheck};
use super::OverlayDirs;
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// Required directories in hidden storage (design.tex Section 4.3.5)
const REQUIRED_DIRS: &[&str] = &[
    "etc",        // Upper layer for /etc overlay
    "home",       // Upper layer for /home overlay
    "config",     // NAILS configuration (nails.toml)
    "nix",        // Hidden environment Nix configuration
    ".work/etc",  // OverlayFS work directory for /etc
    ".work/home", // OverlayFS work directory for /home
    ".work/nix",  // OverlayFS work directory for /nix
];

// Note: Additional work directories for overlays (e.g., .work/nix) are auto-created as needed

/// Unified pre-flight check that validates hidden storage directory structure
/// AND overlay directory accessibility in a single pass.
///
/// Replaces both `HiddenStorageStructureCheck` and `OverlayDirectoriesCheck`
/// with one comprehensive validation that provides a single coherent result.
///
/// # Validation Phases
///
/// 1. **Structure**: Required base directories exist on hidden volume
/// 2. **Auto-create**: Missing directories are created with 0o700 permissions
/// 3. **Overlay access**: Overlay lower/upper/work directories are accessible
///
/// # Required Directory Structure
///
/// ```text
/// /mnt/hidden-volume/
/// ├── etc/           # Upper layer for /etc overlay
/// ├── home/          # Upper layer for /home overlay
/// ├── nix/           # Upper layer for /nix overlay
/// ├── config/        # NAILS configuration (nails.toml)
/// └── .work/         # OverlayFS work directories
///     ├── etc/
///     ├── home/
///     └── nix/
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use nails_core::preflight::{StorageReadinessCheck, OverlayDirs, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let check = StorageReadinessCheck::new(
///     PathBuf::from("/mnt/hidden-volume"),
///     vec![OverlayDirs::new(
///         "home".to_string(),
///         PathBuf::from("/home"),
///         PathBuf::from("/mnt/hidden-volume/home"),
///         PathBuf::from("/mnt/hidden-volume/.work/home"),
///     )],
/// );
/// ```
#[derive(Debug, Clone)]
pub struct StorageReadinessCheck {
    hidden_volume_path: PathBuf,
    overlays: Vec<OverlayDirs>,
}

impl StorageReadinessCheck {
    /// Create a new StorageReadinessCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_path` - Path to the hidden volume mount point
    /// * `overlays` - Overlay directory configurations to validate
    pub fn new(hidden_volume_path: PathBuf, overlays: Vec<OverlayDirs>) -> Self {
        Self {
            hidden_volume_path,
            overlays,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StorageReadinessCheck {
    fn name(&self) -> &'static str {
        "storage-readiness"
    }

    fn description(&self) -> &'static str {
        "Validates hidden storage directories exist and are accessible"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut issues = Vec::new();

        // Phase 1: Check required directories exist on hidden volume
        let mut missing = Vec::new();
        for dir in REQUIRED_DIRS {
            let path = self.hidden_volume_path.join(dir);
            if !fs.path_exists(&path)? || !fs.is_directory(&path)? {
                missing.push(*dir);
            }
        }

        // Phase 2: Auto-create missing directories (Story 14.4)
        if !missing.is_empty() {
            let mut created = Vec::new();

            for dir in &missing {
                let path = self.hidden_volume_path.join(dir);
                match fs.create_directory(&path) {
                    Ok(()) => {
                        if let Err(e) = fs.set_permissions(&path, 0o700) {
                            issues.push(format!(
                                "Missing: {}/: failed to set permissions: {}",
                                dir, e
                            ));
                            continue;
                        }
                        tracing::info!(directory = %dir, "Created missing hidden storage directory");
                        created.push(format!("{}/", dir));
                    }
                    Err(e) => {
                        issues.push(format!("Missing: {}/: {}", dir, e));
                    }
                }
            }

            if !created.is_empty() {
                tracing::info!(directories = %created.join(", "), "Auto-created directories");
            }
        }

        // Phase 3: Validate overlay directories are accessible and auto-create if missing
        for overlay in &self.overlays {
            let mut lower_ok = true;
            // Lower must exist and be readable
            if !fs.path_exists(&overlay.lower)? {
                issues.push(format!(
                    "{} lower directory not found: {}",
                    overlay.name,
                    overlay.lower.display()
                ));
                lower_ok = false;
            } else if !fs.is_readable(&overlay.lower)? {
                issues.push(format!(
                    "{} lower directory not readable: {}",
                    overlay.name,
                    overlay.lower.display()
                ));
                lower_ok = false;
            }

            // Upper permissions should mirror lower directory permissions
            let desired_upper_mode = if lower_ok {
                match fs.get_permissions(&overlay.lower) {
                    Ok(mode) => Some(mode),
                    Err(e) => {
                        issues.push(format!(
                            "{} lower permissions unreadable: {}",
                            overlay.name, e
                        ));
                        None
                    }
                }
            } else {
                None
            };

            // Upper: auto-create if missing
            let mut upper_exists = fs.path_exists(&overlay.upper)?;
            if !upper_exists {
                match fs.create_directory(&overlay.upper) {
                    Ok(()) => {
                        upper_exists = true;
                        tracing::info!(
                            directory = %overlay.upper.display(),
                            overlay = %overlay.name,
                            "Created missing overlay upper directory"
                        );
                    }
                    Err(e) => {
                        issues.push(format!(
                            "{} upper directory not found: {}. Auto-create failed: {}",
                            overlay.name,
                            overlay.upper.display(),
                            e
                        ));
                    }
                }
            }

            if upper_exists {
                if let Some(mode) = desired_upper_mode
                    && let Err(e) = fs.set_permissions(&overlay.upper, mode)
                {
                    issues.push(format!(
                        "{} upper directory: failed to set permissions to match lower: {}",
                        overlay.name, e
                    ));
                }
                if !fs.is_writable(&overlay.upper)? {
                    issues.push(format!(
                        "Not writable: {} upper ({})",
                        overlay.name,
                        overlay.upper.display()
                    ));
                }
            }

            // Work: auto-create if missing
            let mut work_exists = fs.path_exists(&overlay.work)?;
            if !work_exists {
                match fs.create_directory(&overlay.work) {
                    Ok(()) => {
                        work_exists = true;
                        tracing::info!(
                            directory = %overlay.work.display(),
                            overlay = %overlay.name,
                            "Created missing overlay work directory"
                        );
                    }
                    Err(e) => {
                        issues.push(format!(
                            "{} work directory not found: {}. Auto-create failed: {}",
                            overlay.name,
                            overlay.work.display(),
                            e
                        ));
                    }
                }
            }

            if work_exists {
                if let Err(e) = fs.set_permissions(&overlay.work, 0o700) {
                    issues.push(format!(
                        "{} work directory: failed to set permissions: {}",
                        overlay.name, e
                    ));
                }
                if !fs.is_writable(&overlay.work)? {
                    issues.push(format!(
                        "Not writable: {} work ({})",
                        overlay.name,
                        overlay.work.display()
                    ));
                }
            }
        }

        if issues.is_empty() {
            Ok(CheckResult::Pass(
                "Hidden storage ready: all directories accessible".to_string(),
            ))
        } else {
            Ok(CheckResult::Fail(format!(
                "Storage not ready: {}",
                issues.join(". ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    /// Helper: create StorageReadinessCheck with no overlays
    fn make_check_no_overlays() -> StorageReadinessCheck {
        StorageReadinessCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), vec![])
    }

    /// Helper: create StorageReadinessCheck with home+etc overlays
    fn make_check_with_overlays() -> StorageReadinessCheck {
        StorageReadinessCheck::new(
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
            vec![
                OverlayDirs::new(
                    "home".to_string(),
                    PathBuf::from("/home"),
                    PathBuf::from("/mnt/hidden-volume/home"),
                    PathBuf::from("/mnt/hidden-volume/.work/home"),
                ),
                OverlayDirs::new(
                    "etc".to_string(),
                    PathBuf::from("/etc"),
                    PathBuf::from("/mnt/hidden-volume/etc"),
                    PathBuf::from("/mnt/hidden-volume/.work/etc"),
                ),
            ],
        )
    }

    /// Helper: set up all required directories on hidden volume
    fn setup_all_required_dirs(fs: &MockFilesystem) {
        for dir in &[
            "etc",
            "home",
            "config",
            "nix",
            ".work/etc",
            ".work/home",
            ".work/nix",
        ] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
            fs.mock_set_writable(&path, true);
        }
    }

    /// Helper: set up overlay lower directories
    fn setup_overlay_lower_dirs(fs: &MockFilesystem) {
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", true);
    }

    #[test]
    fn test_storage_readiness_trait_metadata() {
        let check = make_check_no_overlays();
        assert_eq!(
            <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "storage-readiness"
        );
        assert!(
            <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("directories exist and are accessible")
        );
    }

    #[test]
    fn test_storage_readiness_all_dirs_exist_no_overlays_pass() {
        // AC4: All dirs exist → Pass
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();
        setup_all_required_dirs(&fs);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("Hidden storage ready"));
    }

    #[test]
    fn test_storage_readiness_all_dirs_and_overlays_pass() {
        // AC1+AC4: All dirs exist + overlays accessible → single Pass
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(
            result
                .message()
                .contains("Hidden storage ready: all directories accessible")
        );
    }

    #[test]
    fn test_storage_readiness_sets_upper_permissions_from_lower() {
        // Upper permissions should mirror lower directory permissions
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        fs.set_permissions(Path::new("/home"), 0o750).unwrap();
        fs.set_permissions(Path::new("/etc"), 0o755).unwrap();

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());

        let home_upper = fs.mock_get_permissions(Path::new("/mnt/hidden-volume/home"));
        let etc_upper = fs.mock_get_permissions(Path::new("/mnt/hidden-volume/etc"));
        assert_eq!(home_upper, Some(0o750));
        assert_eq!(etc_upper, Some(0o755));
    }

    #[test]
    fn test_storage_readiness_missing_dir_autocreate_success() {
        // AC6: Auto-create missing dirs (integration from 14.4)
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        // Most dirs exist
        for dir in &[
            "home",
            "config",
            "nix",
            ".work/etc",
            ".work/home",
            ".work/nix",
        ] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        // etc/ is missing but creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", true);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());

        // Verify permissions set
        let perms = fs.mock_get_permissions(Path::new("/mnt/hidden-volume/etc"));
        assert_eq!(perms, Some(0o700));
    }

    #[test]
    fn test_storage_readiness_missing_dir_autocreate_fails() {
        // AC3: Creation failure → single Fail message
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &[
            "home",
            "config",
            "nix",
            ".work/etc",
            ".work/home",
            ".work/nix",
        ] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        fs.mock_set_path_exists("/mnt/hidden-volume/etc", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Storage not ready"));
        assert!(result.message().contains("etc/"));
    }

    #[test]
    fn test_storage_readiness_overlay_lower_missing_fail() {
        // AC3: Overlay lower missing → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);

        // /home exists, /etc does NOT
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc lower directory not found"));
    }

    #[test]
    fn test_storage_readiness_overlay_upper_not_writable_fail() {
        // AC3: Upper not writable → single Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: home upper is not writable
        fs.mock_set_writable("/mnt/hidden-volume/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Not writable: home upper"));
    }

    #[test]
    fn test_storage_readiness_overlay_work_not_writable_fail() {
        // AC3: Work not writable → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: etc work is not writable
        fs.mock_set_writable("/mnt/hidden-volume/.work/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("Not writable: etc work"));
    }

    #[test]
    fn test_storage_readiness_mixed_issues_single_fail() {
        // AC3: Mixed issues → single Fail message listing ALL problems
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();

        // config/ and nix/ missing and not creatable
        for dir in &["etc", "home", ".work/etc", ".work/home", ".work/nix"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
            fs.mock_set_writable(&path, true);
        }
        fs.mock_set_path_exists("/mnt/hidden-volume/config", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/config", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/nix", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/nix", false);

        // Lower dirs: /etc not readable
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        let msg = result.message();
        assert!(msg.contains("Storage not ready"), "msg: {}", msg);
        assert!(msg.contains("config/"), "missing config/: {}", msg);
        assert!(msg.contains("nix/"), "missing nix/: {}", msg);
        assert!(
            msg.contains("etc lower directory not readable"),
            "etc not readable: {}",
            msg
        );
    }

    #[test]
    fn test_storage_readiness_directory_is_file_triggers_autocreate() {
        // Directory exists but is a file → treated as missing, auto-create attempted
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &[
            "home",
            "config",
            "nix",
            ".work/etc",
            ".work/home",
            ".work/nix",
        ] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
            fs.mock_set_writable(&path, true);
        }

        // etc/ exists but is a file, not a directory
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "file");
        fs.mock_set_directory_creatable("/mnt/hidden-volume/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc/"));
    }

    #[test]
    fn test_storage_readiness_overlay_lower_not_readable_fail() {
        // Lower exists but not readable → Fail
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);

        fs.mock_set_path_exists("/home", true);
        fs.mock_set_readable("/home", true);
        fs.mock_set_path_exists("/etc", true);
        fs.mock_set_readable("/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(
            result
                .message()
                .contains("etc lower directory not readable")
        );
    }

    #[test]
    fn test_storage_readiness_overlay_upper_missing_fail() {
        // Upper directory missing → Fail (when not auto-creatable)
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: home upper does not exist and is NOT creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/home", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("home upper directory not found"));
    }

    #[test]
    fn test_storage_readiness_overlay_work_missing_fail() {
        // Work directory missing → Fail (when not auto-creatable)
        let fs = MockFilesystem::new();
        let check = make_check_with_overlays();
        setup_all_required_dirs(&fs);
        setup_overlay_lower_dirs(&fs);

        // Override: etc work does not exist and is NOT creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/.work/etc", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/.work/etc", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("etc work directory not found"));
    }

    #[test]
    fn test_storage_readiness_collect_all_overlay_errors() {
        // All overlay dirs missing → single Fail with all issues listed (when not creatable)
        let fs = MockFilesystem::new();
        let check = StorageReadinessCheck::new(
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
            vec![OverlayDirs::new(
                "home".to_string(),
                PathBuf::from("/home"),
                PathBuf::from("/mnt/hidden-volume/home"),
                PathBuf::from("/mnt/hidden-volume/.work/home"),
            )],
        );
        setup_all_required_dirs(&fs);

        // All overlay dirs missing and NOT creatable
        fs.mock_set_path_exists("/home", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/home", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/home", false);
        fs.mock_set_path_exists("/mnt/hidden-volume/.work/home", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/.work/home", false);

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("lower directory not found"));
        assert!(result.message().contains("upper directory not found"));
        assert!(result.message().contains("work directory not found"));
    }

    #[test]
    fn test_storage_readiness_multiple_missing_dirs_autocreate_partial() {
        // Multiple dirs missing: one creatable, one not → Fail with only the uncreatable
        let fs = MockFilesystem::new();
        let check = make_check_no_overlays();

        for dir in &["home", ".work/etc", ".work/home", ".work/nix"] {
            let path = format!("/mnt/hidden-volume/{}", dir);
            fs.mock_set_path_exists(&path, true);
            fs.mock_set_path_type(&path, "directory");
        }

        // config/ missing but creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/config", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/config", true);
        // nix/ missing and NOT creatable
        fs.mock_set_path_exists("/mnt/hidden-volume/nix", false);
        fs.mock_set_directory_creatable("/mnt/hidden-volume/nix", false);
        // etc/ exists
        fs.mock_set_path_exists("/mnt/hidden-volume/etc", true);
        fs.mock_set_path_type("/mnt/hidden-volume/etc", "directory");

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("nix/"));
        // config/ was auto-created, so should NOT be in the error
    }

    #[test]
    fn test_storage_readiness_clone() {
        let check = make_check_with_overlays();
        let cloned = check.clone();
        assert_eq!(format!("{:?}", check), format!("{:?}", cloned));
    }

    #[test]
    fn test_storage_readiness_debug() {
        let check = make_check_no_overlays();
        let debug = format!("{:?}", check);
        assert!(debug.contains("StorageReadinessCheck"));
    }
}
