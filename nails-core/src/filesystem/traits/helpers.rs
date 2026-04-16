//! Helper functions for filesystem mount precondition checks.

use super::Filesystem;
use crate::{NailsError, Result};
use std::path::Path;

/// Verify all preconditions are met before mounting an overlay
///
/// Validates that all required directories exist and the target is not already
/// mounted. Provides specific error messages for each failure condition.
///
/// # Arguments
///
/// * `fs` - Filesystem trait object to use for checks
/// * `lower` - Lower directory path (must exist)
/// * `upper` - Upper directory path (must exist or be creatable)
/// * `work` - Work directory path (must exist or be creatable)
/// * `target` - Target mount point (must not be already overlay-mounted)
///
/// # "Creatable" Definition
///
/// A directory is considered "creatable" if its parent directory exists
/// and is writable. This check does NOT attempt to create the directory.
///
/// # Example
///
/// ```rust
/// use nails_core::filesystem::{verify_mount_preconditions, MockFilesystem};
/// use std::path::Path;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_path_exists("/", true);
/// fs.mock_set_path_exists("/mnt/hidden/upper", true);
/// fs.mock_set_path_exists("/mnt/hidden/work", true);
///
/// let result = verify_mount_preconditions(
///     &fs,
///     Path::new("/"),
///     Path::new("/mnt/hidden/upper"),
///     Path::new("/mnt/hidden/work"),
///     Path::new("/home")
/// );
/// assert!(result.is_ok());
/// ```
pub fn verify_mount_preconditions<F: Filesystem>(
    fs: &F,
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<()> {
    // Check lower directory exists
    if !fs.path_exists(lower)? {
        return Err(NailsError::OverlayError(format!(
            "Lower directory not found: {}",
            lower.display()
        )));
    }

    // Check upper directory exists or can be created
    if !fs.path_exists(upper)? {
        if let Some(parent) = upper.parent() {
            if !fs.path_exists(parent)? {
                return Err(NailsError::OverlayError(format!(
                    "Upper directory not found and parent doesn't exist: {}",
                    upper.display()
                )));
            }
            if !fs.is_writable(parent)? {
                return Err(NailsError::PermissionDenied(format!(
                    "Upper directory not found and parent not writable: {}",
                    upper.display()
                )));
            }
        } else {
            return Err(NailsError::OverlayError(format!(
                "Upper directory not found: {}",
                upper.display()
            )));
        }
    }

    // Check work directory exists or can be created
    if !fs.path_exists(work)? {
        if let Some(parent) = work.parent() {
            if !fs.path_exists(parent)? {
                return Err(NailsError::OverlayError(format!(
                    "Work directory not found and parent doesn't exist: {}",
                    work.display()
                )));
            }
            if !fs.is_writable(parent)? {
                return Err(NailsError::PermissionDenied(format!(
                    "Work directory not found and parent not writable: {}",
                    work.display()
                )));
            }
        } else {
            return Err(NailsError::OverlayError(format!(
                "Work directory not found: {}",
                work.display()
            )));
        }
    }

    // Check target not already overlay-mounted (block device mounts are OK)
    if fs.is_overlay_mounted(target)? {
        return Err(NailsError::AlreadyMounted {
            path: target.to_path_buf(),
        });
    }

    Ok(())
}
