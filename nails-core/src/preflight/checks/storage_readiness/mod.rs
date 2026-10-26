// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage readiness pre-flight check
//!
//! Unified pre-flight check that validates hidden storage directory structure
//! AND overlay directory accessibility in a single pass.

use super::super::{CheckResult, PreFlightCheck};
use super::OverlayDirs;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Required directories in hidden storage (design.tex Section 4.3.5)
const REQUIRED_DIRS: &[&str] = &[
    "root/upper", // Upper layer of the root overlay: the hidden system
    "root/work",  // Its overlayfs work directory
];

// Note: the layers of other overlaid decoy filesystems (root/mounts/…) are
// created at entry, once the fstab policy has decided which there are.

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
/// use std::path::{Path, PathBuf};
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
    hidden_volume_root: PathBuf,
    overlays: Vec<OverlayDirs>,
    /// When set, the check leaves the layout as it is: it never creates a
    /// missing directory or changes permissions, and reports what activation
    /// would create as a warning instead. Its write probe still makes and
    /// removes `.nails_write_test` in the upper and work directories that
    /// exist. `nails check` and activation both set it; the entry creates the
    /// layout itself once every check passed.
    read_only: bool,
}

impl StorageReadinessCheck {
    /// Create a new StorageReadinessCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_volume_root` - Path to the hidden volume mount point
    /// * `overlays` - Overlay directory configurations to validate
    pub fn new(hidden_volume_root: PathBuf, overlays: Vec<OverlayDirs>) -> Self {
        Self {
            hidden_volume_root,
            overlays,
            read_only: false,
        }
    }

    /// Make the check leave the layout as it is: it validates the layout
    /// without creating any missing directory or changing permissions, and its
    /// write probe still makes and removes `.nails_write_test`. Missing
    /// directories activation would auto-create are reported as a warning
    /// rather than a failure.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
}

impl StorageReadinessCheck {
    /// Phases 1 and 2: find required directories missing from the hidden volume
    /// and create them, or record them as pending when read-only.
    fn ensure_required_dirs<F: Filesystem>(
        &self,
        fs: &F,
        issues: &mut Vec<String>,
        pending: &mut Vec<(PathBuf, String)>,
    ) -> Result<()> {
        let mut missing = Vec::new();
        for dir in REQUIRED_DIRS {
            let path = self.hidden_volume_root.join(dir);
            if !fs.path_exists(&path)? || !fs.is_directory(&path)? {
                missing.push(*dir);
            }
        }

        // Phase 2: Auto-create missing directories, or record them
        // when read-only.
        if !missing.is_empty() {
            let mut created = Vec::new();

            for dir in &missing {
                if self.read_only {
                    pending.push((self.hidden_volume_root.join(dir), format!("{}/", dir)));
                    continue;
                }
                let path = self.hidden_volume_root.join(dir);
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
        Ok(())
    }

    /// Phase 3: the overlay lower must be readable, and its upper and work
    /// directories must exist and be writable (created unless read-only).
    fn check_overlay<F: Filesystem>(
        &self,
        fs: &F,
        overlay: &OverlayDirs,
        issues: &mut Vec<String>,
        pending: &mut Vec<(PathBuf, String)>,
    ) -> Result<()> {
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

        // Upper: auto-create if missing (or record it when read-only)
        let mut upper_exists = fs.path_exists(&overlay.upper)?;
        if !upper_exists {
            if self.read_only {
                pending.push((
                    overlay.upper.clone(),
                    format!("{} upper ({})", overlay.name, overlay.upper.display()),
                ));
            } else {
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
        }

        if upper_exists {
            if !self.read_only
                && let Some(mode) = desired_upper_mode
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

        // Work: auto-create if missing (or record it when read-only)
        let mut work_exists = fs.path_exists(&overlay.work)?;
        if !work_exists {
            if self.read_only {
                pending.push((
                    overlay.work.clone(),
                    format!("{} work ({})", overlay.name, overlay.work.display()),
                ));
            } else {
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
        }

        if work_exists {
            if !self.read_only
                && let Err(e) = fs.set_permissions(&overlay.work, 0o700)
            {
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
        Ok(())
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StorageReadinessCheck {
    fn name(&self) -> &'static str {
        "storage-readiness"
    }

    fn description(&self) -> &'static str {
        "Validates hidden storage directories exist and are accessible"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut issues = Vec::new();
        // Directories activation would auto-create. In read-only mode they are
        // reported here instead of being created, so a fresh-but-sound volume
        // warns rather than fails.
        let mut pending: Vec<(PathBuf, String)> = Vec::new();

        self.ensure_required_dirs(fs, &mut issues, &mut pending)?;
        for overlay in &self.overlays {
            self.check_overlay(fs, overlay, &mut issues, &mut pending)?;
        }
        // Each directory once, and the root overlay's upper apart: the entry
        // makes it itself, with the decoy root's mode and owner (an overlay's
        // root directory takes them from its upper), so a fresh volume
        // has none yet by design.
        let mut listed: Vec<PathBuf> = Vec::new();
        pending.retain(|(path, _)| {
            let first = !listed.contains(path);
            listed.push(path.clone());
            first
        });
        let root_upper = self
            .overlays
            .iter()
            .find(|overlay| overlay.lower == Path::new("/"))
            .map(|overlay| overlay.upper.clone());
        let (by_design, pending): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|(path, _)| Some(path) == root_upper.as_ref());
        let made_at_entry = (!by_design.is_empty()).then(|| {
            format!(
                "activation creates {} with the decoy root's mode and owner",
                by_design[0].0.display()
            )
        });

        if !issues.is_empty() {
            Ok(CheckResult::fail(format!(
                "Storage not ready: {}",
                issues.join(". ")
            )))
        } else if !pending.is_empty() {
            let mut message = format!(
                "Hidden storage usable; activation will create: {}",
                pending
                    .iter()
                    .map(|(_, label)| label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if let Some(note) = made_at_entry {
                message.push_str(&format!("; {note}"));
            }
            Ok(CheckResult::Warn(message))
        } else {
            Ok(CheckResult::Pass(match made_at_entry {
                Some(note) => format!("Hidden storage ready: {note}"),
                None => "Hidden storage ready: all directories accessible".to_string(),
            }))
        }
    }
}

#[cfg(test)]
mod tests;
