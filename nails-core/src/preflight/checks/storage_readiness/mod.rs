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
    "config",     // NAILS configuration (nails.yaml)
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
/// ├── config/        # NAILS configuration (nails.yaml)
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
mod tests;
