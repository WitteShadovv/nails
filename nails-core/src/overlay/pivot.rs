//! Pivot mount strategy for active directories
//!
//! Provides functions to mount overlays onto actively-used directories
//! using a two-step staging approach to work around kernel limitations.

use crate::config::EphemeralOverlayDir;
use crate::{Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

use super::mount_info::PivotMountInfo;

/// Default staging directory for pivot mounts
pub const PIVOT_STAGING_BASE: &str = "/mnt/nails-pivot";

/// Mount an overlay using the pivot strategy for active directories
///
/// This function enables overlaying directories like `/var` that are actively in use.
/// Direct overlay mount fails with EINVAL, so we use a two-step approach:
/// 1. Mount overlay to staging location (`/mnt/nails-pivot/var`)
/// 2. Bind mount staging to target (`/var`)
///
/// # Process Impact (Split View)
///
/// - **Existing processes:** Keep seeing original content (forensically beneficial)
/// - **New path resolutions:** See overlay content
/// - This split behavior is a SECURITY FEATURE - old processes can't see hidden data
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `lower` - Read-only base layer (typically the current `/var`)
/// * `upper` - Writeable upper layer (on hidden volume or tmpfs)
/// * `work` - Work directory for overlay metadata
/// * `target` - Final mount point (e.g., `/var`)
///
/// # Returns
///
/// `Ok(PivotMountInfo)` with mount details on success.
///
/// # Errors
///
/// * `NailsError::OverlayError` - If overlay or bind mount fails
/// * `NailsError::PermissionDenied` - If lacking root privileges
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::pivot_overlay_mount;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::Path;
///
/// let fs = MockFilesystem::new();
///
/// // Set up mock filesystem
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
/// fs.mock_set_path_exists("/mnt/hidden/var-work", true);
/// fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);
///
/// let info = pivot_overlay_mount(
///     &fs,
///     Path::new("/var"),           // lower
///     Path::new("/mnt/hidden/var-upper"),  // upper
///     Path::new("/mnt/hidden/var-work"),   // work
///     Path::new("/var"),           // target
/// ).unwrap();
///
/// assert_eq!(info.target, Path::new("/var"));
/// assert!(info.staging.starts_with("/mnt/nails-pivot"));
/// ```
pub fn pivot_overlay_mount<F: Filesystem>(
    fs: &F,
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<PivotMountInfo> {
    // Derive staging path from target
    let dir_name = target
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid target path: {}", target.display()))
        })?
        .to_string_lossy();
    let staging = PathBuf::from(PIVOT_STAGING_BASE).join(dir_name.as_ref());

    // Step 1: Create staging directory
    fs.create_directory(&staging)?;

    // Step 2: Mount overlay at staging location
    // This always succeeds because staging is not in active use
    fs.mount_overlay(lower, upper, work, &staging)?;

    // Step 3: Bind mount staging to target
    // This works even for active directories
    if let Err(e) = fs.bind_mount(&staging, target) {
        // Rollback: unmount the overlay from staging
        let _ = fs.unmount(&staging, true);
        return Err(e);
    }

    Ok(PivotMountInfo {
        target: target.to_path_buf(),
        staging,
        upper: upper.to_path_buf(),
        work: work.to_path_buf(),
        lower: lower.to_path_buf(),
        is_ephemeral: false, // Caller can set this based on upper/work type
    })
}

/// Mount an ephemeral pivot overlay with tmpfs-backed upper/work layers
///
/// Combines the pivot mount strategy with tmpfs-backed layers for directories
/// like `/var` that need ephemeral storage.
///
/// # Mount Sequence
///
/// 1. Create tmpfs at upper path
/// 2. Create tmpfs at work path
/// 3. Mount overlay to staging
/// 4. Bind mount staging to target
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `config` - Ephemeral overlay configuration with tmpfs sizes
/// * `lower` - Read-only base layer path
///
/// # Returns
///
/// `Ok(PivotMountInfo)` with `is_ephemeral = true`.
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::pivot_ephemeral_mount;
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
/// fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);
///
/// let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();
/// assert!(info.is_ephemeral);
/// ```
pub fn pivot_ephemeral_mount<F: Filesystem>(
    fs: &F,
    config: &EphemeralOverlayDir,
    lower: &Path,
) -> Result<PivotMountInfo> {
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
    if let Err(e) = fs.mount_tmpfs(&work, &config.tmpfs_work_size) {
        // Rollback: unmount upper tmpfs
        let _ = fs.unmount_tmpfs(&upper);
        return Err(e);
    }

    // Step 4: Pivot mount overlay to target
    match pivot_overlay_mount(fs, lower, &upper, &work, &config.path) {
        Ok(mut info) => {
            info.is_ephemeral = true;
            Ok(info)
        }
        Err(e) => {
            // Rollback: unmount tmpfs layers
            let _ = fs.unmount_tmpfs(&work);
            let _ = fs.unmount_tmpfs(&upper);
            Err(e)
        }
    }
}

/// Unmount a pivot overlay
///
/// Unmounts in reverse order:
/// 1. Unmount bind mount from target
/// 2. Unmount overlay from staging
/// 3. Remove staging directory
/// 4. If ephemeral, unmount tmpfs layers
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `info` - Mount information from `pivot_overlay_mount` or `pivot_ephemeral_mount`
///
/// # Forensic Safety
///
/// For ephemeral mounts, all data in tmpfs layers is destroyed immediately.
///
/// # Errors
///
/// Uses best-effort cleanup - attempts all unmounts even if some fail.
/// Returns combined error if any operations fail.
pub fn unmount_pivot_overlay<F: Filesystem>(fs: &F, info: &PivotMountInfo) -> Result<()> {
    let mut errors = Vec::new();

    // Step 1: Unmount bind mount from target
    if let Err(e) = fs.unmount_bind(&info.target) {
        errors.push(format!("bind mount {}: {}", info.target.display(), e));
    }

    // Step 2: Unmount overlay from staging (try graceful, then force)
    if let Err(_e) = fs.unmount(&info.staging, false) {
        // Graceful unmount failed, try force
        if let Err(force_err) = fs.unmount(&info.staging, true) {
            errors.push(format!("overlay {}: {}", info.staging.display(), force_err));
        }
    }

    // Step 3: Remove staging directory (best effort)
    let _ = std::fs::remove_dir(&info.staging);

    // Step 4: If ephemeral, unmount tmpfs layers
    if info.is_ephemeral {
        if let Err(e) = fs.unmount_tmpfs(&info.work) {
            errors.push(format!("work tmpfs {}: {}", info.work.display(), e));
        }
        if let Err(e) = fs.unmount_tmpfs(&info.upper) {
            errors.push(format!("upper tmpfs {}: {}", info.upper.display(), e));
        }
        // Clean up tmpfs directories (best effort)
        let _ = std::fs::remove_dir(&info.work);
        let _ = std::fs::remove_dir(&info.upper);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(errors.join("; ")))
    }
}
