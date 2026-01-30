//! Overlay filesystem operations for extended overlay strategy
//!
//! This module provides operations for mounting and unmounting ephemeral overlays
//! with tmpfs-backed upper layers (Story 4.11).
//!
//! # Forensic Rationale (Thesis Section 4.3.6)
//!
//! The extended overlay strategy provides defense-in-depth against forensic analysis:
//! - **Persistent overlays** (home/etc): Data on hidden encrypted storage
//! - **Ephemeral overlays** (var/tmp): Data in RAM, destroyed on unmount
//! - Different threat models for different data types
//!
//! # Example
//!
//! ```rust
//! use nails_core::overlay::{mount_ephemeral_overlay, EphemeralMountInfo};
//! use nails_core::config::EphemeralOverlayDir;
//! use nails_core::filesystem::MockFilesystem;
//! use std::path::{Path, PathBuf};
//!
//! let fs = MockFilesystem::new();
//! let config = EphemeralOverlayDir {
//!     path: PathBuf::from("/var"),
//!     tmpfs_upper_size: "1G".to_string(),
//!     tmpfs_work_size: "512M".to_string(),
//! };
//!
//! // Set up mock filesystem state
//! fs.mock_set_path_exists("/var", true);
//! fs.mock_set_directory_creatable("/run/nails/var-upper", true);
//! fs.mock_set_directory_creatable("/run/nails/var-work", true);
//!
//! let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
//! assert!(result.is_ok());
//! ```

use crate::config::EphemeralOverlayDir;
use crate::filesystem::Filesystem;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Information about a mounted ephemeral overlay
///
/// Tracks all paths involved in an ephemeral overlay mount for cleanup.
///
/// # Fields
///
/// * `target` - Mount point where overlay appears (e.g., "/var")
/// * `upper` - Tmpfs-backed upper layer (e.g., "/run/nails/var-upper")
/// * `work` - Tmpfs-backed work directory (e.g., "/run/nails/var-work")
/// * `lower` - Read-only base layer (e.g., "/var")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralMountInfo {
    /// Target mount point
    pub target: PathBuf,

    /// Tmpfs-backed upper layer
    pub upper: PathBuf,

    /// Tmpfs-backed work directory
    pub work: PathBuf,

    /// Read-only base layer
    pub lower: PathBuf,
}

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
    fs.mount_overlay(lower, &upper, &work, &config.path)?;

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

    // Step 1: Unmount overlay first
    if let Err(e) = fs.unmount(&info.target, false) {
        errors.push(format!("overlay {}: {}", info.target.display(), e));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    // ========== EphemeralMountInfo Tests ==========

    #[test]
    fn test_ephemeral_mount_info_creation() {
        let info = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
        assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
        assert_eq!(info.lower, PathBuf::from("/var"));
    }

    #[test]
    fn test_ephemeral_mount_info_clone() {
        let info1 = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        let info2 = info1.clone();
        assert_eq!(info1, info2);
    }

    // ========== mount_ephemeral_overlay Tests ==========

    #[test]
    fn test_mount_ephemeral_overlay_success() {
        // AC2: Creates tmpfs mounts and overlay
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        // Set up mock filesystem
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
        assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
        assert_eq!(info.lower, PathBuf::from("/var"));

        // Verify tmpfs mounts created
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

        // Verify overlay mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
    }

    #[test]
    fn test_mount_ephemeral_overlay_creates_directories() {
        // AC2: Creates upper and work directories
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        // Directories don't exist yet
        assert!(!fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.path_exists(Path::new("/run/nails/var-work")).unwrap());

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_ok());

        // Directories were created
        assert!(fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.path_exists(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    fn test_mount_ephemeral_overlay_validates_sizes() {
        // AC1: Size validation via tmpfs mount
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "invalid".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_ephemeral_overlay_multiple_directories() {
        // AC2: Can mount multiple ephemeral overlays
        let fs = MockFilesystem::new();

        let config_var = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        let config_tmp = EphemeralOverlayDir {
            path: PathBuf::from("/tmp"),
            tmpfs_upper_size: "512M".to_string(),
            tmpfs_work_size: "256M".to_string(),
        };

        // Set up mock filesystem for both
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/run/nails/tmp-upper", true);
        fs.mock_set_directory_creatable("/run/nails/tmp-work", true);

        // Mount first ephemeral overlay
        let result_var = mount_ephemeral_overlay(&fs, &config_var, Path::new("/var"));
        assert!(result_var.is_ok());

        // Mount second ephemeral overlay
        let result_tmp = mount_ephemeral_overlay(&fs, &config_tmp, Path::new("/tmp"));
        assert!(result_tmp.is_ok());

        // Both should be mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
    }

    // ========== unmount_ephemeral_overlay Tests ==========

    #[test]
    fn test_unmount_ephemeral_overlay_success() {
        // AC5: Unmounts overlay and tmpfs in correct order
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

        // Unmount
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());

        // Verify all unmounted
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    fn test_unmount_ephemeral_overlay_best_effort() {
        // AC5: Best-effort unmount continues even if some fail
        let fs = MockFilesystem::new();
        let info = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        // No mounts exist, but unmount should still succeed (idempotent)
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unmount_ephemeral_overlay_full_cycle() {
        // AC4, AC5: Full mount/write/unmount cycle
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        // Mount
        let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

        // Simulate writes to /var (would go to tmpfs upper in real system)
        // In mock, just verify mount exists
        assert!(fs.is_mounted(Path::new("/var")).unwrap());

        // Unmount destroys tmpfs data
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());

        // No artifacts remain
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    }
}
