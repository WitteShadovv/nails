//! Ephemeral overlay operations with tmpfs-backed layers
//!
//! Provides functions to mount and unmount ephemeral overlays where the
//! upper and work directories are stored in tmpfs (RAM) for forensic safety.

use crate::config::EphemeralOverlayDir;
use crate::{Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

use super::mount_info::EphemeralMountInfo;

/// Mount an ephemeral overlay with tmpfs-backed upper/work layers
///
/// Creates a complete ephemeral overlay mount:
/// 1. Creates tmpfs filesystems for upper and work directories
/// 2. Mounts overlay using tmpfs-backed layers
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `config` - Ephemeral overlay configuration
/// * `lower` - Read-only base layer path
///
/// # Returns
///
/// `Ok(EphemeralMountInfo)` with mount details on success.
///
/// # Errors
///
/// * `NailsError::OverlayError` - If any mount operation fails
/// * `NailsError::PermissionDenied` - If lacking privileges
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::mount_ephemeral_overlay;
/// use nails_core::config::EphemeralOverlayDir;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::{Path, PathBuf};
///
/// let fs = MockFilesystem::new();
/// let config = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
///
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_directory_creatable("/run/nails/var-upper", true);
/// fs.mock_set_directory_creatable("/run/nails/var-work", true);
///
/// let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();
/// assert_eq!(info.target, PathBuf::from("/var"));
/// ```
pub fn mount_ephemeral_overlay<F: Filesystem>(
    fs: &F,
    config: &EphemeralOverlayDir,
    lower: &Path,
) -> Result<EphemeralMountInfo> {
    let base = PathBuf::from("/run/nails");
    let dir_name = config
        .path
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid path: {}", config.path.display()))
        })?
        .to_string_lossy();

    let upper = base.join(format!("{}-upper", dir_name));
    let work = base.join(format!("{}-work", dir_name));

    // Step 1: Create directories
    fs.create_directory(&upper)?;
    fs.create_directory(&work)?;

    // Step 2: Mount tmpfs for upper
    fs.mount_tmpfs(&upper, &config.tmpfs_upper_size)?;

    // Step 3: Mount tmpfs for work
    fs.mount_tmpfs(&work, &config.tmpfs_work_size)?;

    // Step 4: Mount overlay using tmpfs upper/work
    fs.mount_overlay(&[lower], &upper, &work, &config.path)?;

    Ok(EphemeralMountInfo {
        target: config.path.clone(),
        upper,
        work,
        lower: lower.to_path_buf(),
    })
}

/// Unmount an ephemeral overlay and its tmpfs layers
///
/// Destroys all ephemeral data by unmounting in reverse order:
/// 1. Unmount overlay from target
/// 2. Unmount work tmpfs (destroys work metadata)
/// 3. Unmount upper tmpfs (destroys all ephemeral data)
/// 4. Clean up mount point directories
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `info` - Mount information from `mount_ephemeral_overlay`
///
/// # Forensic Safety
///
/// All data in tmpfs upper/work layers is destroyed immediately upon unmount.
/// No disk writes occur - data exists only in RAM.
///
/// # Errors
///
/// Returns `NailsError::UnmountError` if any unmount fails. Uses best-effort
/// cleanup to unmount as much as possible even if some operations fail.
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::{mount_ephemeral_overlay, unmount_ephemeral_overlay};
/// use nails_core::config::EphemeralOverlayDir;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::{Path, PathBuf};
///
/// let fs = MockFilesystem::new();
/// let config = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
///
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_directory_creatable("/run/nails/var-upper", true);
/// fs.mock_set_directory_creatable("/run/nails/var-work", true);
///
/// let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();
/// let result = unmount_ephemeral_overlay(&fs, &info);
/// assert!(result.is_ok());
/// ```
pub fn unmount_ephemeral_overlay<F: Filesystem>(fs: &F, info: &EphemeralMountInfo) -> Result<()> {
    let mut errors = Vec::new();

    // Step 1: Unmount overlay first (try graceful, then force)
    if let Err(_e) = fs.unmount(&info.target, false) {
        // Graceful unmount failed, try force
        if let Err(force_err) = fs.unmount(&info.target, true) {
            errors.push(format!("overlay {}: {}", info.target.display(), force_err));
        }
    }

    // Step 2: Unmount work tmpfs
    if let Err(e) = fs.unmount_tmpfs(&info.work) {
        errors.push(format!("work tmpfs {}: {}", info.work.display(), e));
    }

    // Step 3: Unmount upper tmpfs (this destroys all ephemeral data)
    if let Err(e) = fs.unmount_tmpfs(&info.upper) {
        errors.push(format!("upper tmpfs {}: {}", info.upper.display(), e));
    }

    // Step 4: Clean up mount point directories (best effort)
    // These directories were created during mount and should be removed after tmpfs unmount.
    // We use best-effort approach since the critical cleanup (tmpfs unmount) already happened.
    // Failures here don't compromise forensic safety - tmpfs data is already destroyed.
    //
    // Note: We use std::fs directly here since directory cleanup is a host filesystem
    // operation that happens after all mounts are unmounted. The Filesystem trait
    // is primarily for operations that need to be mocked during testing.
    let _ = std::fs::remove_dir(&info.work);
    let _ = std::fs::remove_dir(&info.upper);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(errors.join("; ")))
    }
}
