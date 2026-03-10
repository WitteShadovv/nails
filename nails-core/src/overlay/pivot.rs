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
/// * `lower` - Read-only base layers (first is primary, rest are extra lower layers)
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
///     &[Path::new("/var")],           // lower
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
    lower: &[&Path],
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
        lower: lower[0].to_path_buf(),
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
    match pivot_overlay_mount(fs, &[lower], &upper, &work, &config.path) {
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

/// Mount an overlay using the snapshot pivot strategy for overlay-incompatible filesystems
///
/// Some filesystems (vfat, exfat, ntfs) cannot serve as overlayfs lower layers because
/// they lack required POSIX semantics (d_type, xattrs). This function works around the
/// limitation by:
///
/// 1. Creating a tmpfs "snapshot" and copying the target contents into it
/// 2. Using the tmpfs snapshot as the overlay lower layer
/// 3. Mounting the overlay to a staging directory
/// 4. Bind mounting the staging directory over the original target
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `lower` - Original lower layers (on overlay-incompatible filesystem)
/// * `upper` - Upper layer directory (on hidden volume)
/// * `work` - Work directory for overlay
/// * `target` - Target directory to overlay (e.g., `/boot`)
///
/// # Returns
///
/// `Ok(PivotMountInfo)` with `lower` set to the snapshot tmpfs path.
///
/// # Rollback
///
/// On failure at any step, all previous steps are rolled back.
pub fn snapshot_pivot_overlay_mount<F: Filesystem>(
    fs: &F,
    _lower: &[&Path],
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<PivotMountInfo> {
    let dir_name = target
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid target path: {}", target.display()))
        })?
        .to_string_lossy();

    // Step 1: Create snapshot tmpfs directory
    let snapshot_path = PathBuf::from(PIVOT_STAGING_BASE).join(format!("{}-snapshot", dir_name));
    fs.create_directory(&snapshot_path)?;

    // Step 2: Mount tmpfs at snapshot location
    if let Err(e) = fs.mount_tmpfs(&snapshot_path, "1G") {
        let _ = std::fs::remove_dir(&snapshot_path);
        return Err(e);
    }

    // Step 3: Copy target contents into snapshot tmpfs
    if let Err(e) = fs.copy_tree(target, &snapshot_path) {
        let _ = fs.unmount_tmpfs(&snapshot_path);
        let _ = std::fs::remove_dir(&snapshot_path);
        return Err(e);
    }

    // Step 4: Create staging directory
    let staging = PathBuf::from(PIVOT_STAGING_BASE).join(dir_name.as_ref());
    if let Err(e) = fs.create_directory(&staging) {
        let _ = fs.unmount_tmpfs(&snapshot_path);
        let _ = std::fs::remove_dir(&snapshot_path);
        return Err(e);
    }

    // Step 5: Mount overlay with snapshot as lower layer
    if let Err(e) = fs.mount_overlay(&[snapshot_path.as_path()], upper, work, &staging) {
        let _ = std::fs::remove_dir(&staging);
        let _ = fs.unmount_tmpfs(&snapshot_path);
        let _ = std::fs::remove_dir(&snapshot_path);
        return Err(e);
    }

    // Step 6: Bind mount staging to target
    if let Err(e) = fs.bind_mount(&staging, target) {
        let _ = fs.unmount(&staging, true);
        let _ = std::fs::remove_dir(&staging);
        let _ = fs.unmount_tmpfs(&snapshot_path);
        let _ = std::fs::remove_dir(&snapshot_path);
        return Err(e);
    }

    Ok(PivotMountInfo {
        target: target.to_path_buf(),
        staging,
        upper: upper.to_path_buf(),
        work: work.to_path_buf(),
        lower: snapshot_path,
        is_ephemeral: false,
    })
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

    // Step 3.5: If snapshot pivot, unmount and remove the snapshot tmpfs
    // Snapshot pivots have their lower dir under PIVOT_STAGING_BASE ending with "-snapshot"
    if info.lower.starts_with(PIVOT_STAGING_BASE)
        && info
            .lower
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with("-snapshot"))
    {
        if let Err(e) = fs.unmount_tmpfs(&info.lower) {
            errors.push(format!("snapshot tmpfs {}: {}", info.lower.display(), e));
        }
        let _ = std::fs::remove_dir(&info.lower);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// Helper: set up MockFilesystem so pivot_overlay_mount can succeed for a given target.
    /// - `lower_path`: the lower directory (must exist)
    /// - `upper_path`: the upper directory (must exist)
    /// - `work_path`: the work directory (must exist)
    ///   The staging dir is auto-created under PIVOT_STAGING_BASE.
    fn setup_pivot_fs(fs: &MockFilesystem, lower: &str, upper: &str, work: &str) {
        fs.mock_set_path_exists(lower, true);
        fs.mock_set_path_exists(upper, true);
        fs.mock_set_path_exists(work, true);
        // create_directory("/mnt/nails-pivot/{name}") needs grandparent /mnt to exist+be writable
        fs.mock_set_path_exists("/mnt", true);
    }

    // ── pivot_overlay_mount ────────────────────────────────────────────────────

    #[test]
    fn test_pivot_overlay_mount_success() {
        let fs = MockFilesystem::new();
        setup_pivot_fs(&fs, "/var", "/mnt/hidden/var-upper", "/mnt/hidden/var-work");

        let result = pivot_overlay_mount(
            &fs,
            &[Path::new("/var")],
            Path::new("/mnt/hidden/var-upper"),
            Path::new("/mnt/hidden/var-work"),
            Path::new("/var"),
        );

        assert!(
            result.is_ok(),
            "pivot_overlay_mount should succeed: {:?}",
            result.err()
        );
        let info = result.unwrap();
        assert_eq!(info.target, PathBuf::from("/var"));
        assert!(info.staging.starts_with(PIVOT_STAGING_BASE));
        assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
        assert_eq!(info.upper, PathBuf::from("/mnt/hidden/var-upper"));
        assert_eq!(info.work, PathBuf::from("/mnt/hidden/var-work"));
        assert_eq!(info.lower, PathBuf::from("/var"));
        assert!(!info.is_ephemeral);
    }

    #[test]
    fn test_pivot_overlay_mount_bind_fails_rolls_back_overlay() {
        let fs = MockFilesystem::new();
        setup_pivot_fs(
            &fs,
            "/home",
            "/mnt/hidden/home-upper",
            "/mnt/hidden/home-work",
        );
        // Make bind mount to /home fail
        fs.mock_set_mount_should_fail("/home", true);

        let result = pivot_overlay_mount(
            &fs,
            &[Path::new("/home")],
            Path::new("/mnt/hidden/home-upper"),
            Path::new("/mnt/hidden/home-work"),
            Path::new("/home"),
        );

        assert!(result.is_err(), "should fail when bind mount fails");
        // Verify staging overlay was unmounted as part of rollback
        let staging = PathBuf::from("/mnt/nails-pivot/home");
        assert!(
            !fs.is_mounted(&staging).unwrap_or(false),
            "staging overlay should be unmounted after rollback"
        );
    }

    #[test]
    fn test_pivot_overlay_mount_root_target_fails() {
        // Target with no file_name component (e.g., "/") should fail
        let fs = MockFilesystem::new();
        let result = pivot_overlay_mount(
            &fs,
            &[Path::new("/")],
            Path::new("/mnt/hidden/root-upper"),
            Path::new("/mnt/hidden/root-work"),
            Path::new("/"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pivot_overlay_mount_roundtrip_with_unmount() {
        let fs = MockFilesystem::new();
        setup_pivot_fs(&fs, "/etc", "/mnt/hidden/etc-upper", "/mnt/hidden/etc-work");

        let info = pivot_overlay_mount(
            &fs,
            &[Path::new("/etc")],
            Path::new("/mnt/hidden/etc-upper"),
            Path::new("/mnt/hidden/etc-work"),
            Path::new("/etc"),
        )
        .expect("mount should succeed");

        // Verify overlay is mounted at staging
        assert!(fs.is_mounted(&info.staging).unwrap_or(false));
        // Verify bind mount is registered (target is "mounted")
        assert!(fs.is_mounted(&info.target).unwrap_or(false));

        // Now unmount
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(result.is_ok(), "unmount should succeed: {:?}", result.err());
    }

    // ── unmount_pivot_overlay ──────────────────────────────────────────────────

    #[test]
    fn test_unmount_pivot_overlay_ephemeral() {
        let fs = MockFilesystem::new();
        // For ephemeral, the lower must exist; upper/work are created by mount_tmpfs
        fs.mock_set_path_exists("/run", true);
        // /mnt must exist+be writable for staging dir creation under /mnt/nails-pivot/
        fs.mock_set_path_exists("/mnt", true);

        let config = crate::config::EphemeralOverlayDir {
            path: PathBuf::from("/run"),
            tmpfs_upper_size: "512M".to_string(),
            tmpfs_work_size: "256M".to_string(),
        };

        let info = pivot_ephemeral_mount(&fs, &config, Path::new("/run"))
            .expect("ephemeral mount should succeed");

        assert!(info.is_ephemeral);

        // Unmount
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(
            result.is_ok(),
            "ephemeral unmount should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_unmount_pivot_overlay_snapshot_lower() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/boot", true);
        fs.mock_set_path_exists("/mnt/hidden/boot-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/boot-work", true);
        // /mnt must be writable for staging/snapshot dirs under /mnt/nails-pivot/
        fs.mock_set_path_exists("/mnt", true);

        let info = snapshot_pivot_overlay_mount(
            &fs,
            &[Path::new("/boot")],
            Path::new("/mnt/hidden/boot-upper"),
            Path::new("/mnt/hidden/boot-work"),
            Path::new("/boot"),
        )
        .expect("snapshot pivot should succeed");

        // lower should be the snapshot tmpfs path
        assert!(info.lower.to_string_lossy().ends_with("-snapshot"));

        // Unmount snapshot pivot
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(
            result.is_ok(),
            "snapshot unmount should succeed: {:?}",
            result.err()
        );
    }

    // ── pivot_ephemeral_mount ──────────────────────────────────────────────────

    #[test]
    fn test_pivot_ephemeral_mount_success() {
        let fs = MockFilesystem::new();
        // lower path must exist; upper/work dirs are created via mount_tmpfs
        fs.mock_set_path_exists("/tmp", true);
        // /run must exist+be writable for upper/work dirs under /run/nails/
        fs.mock_set_path_exists("/run", true);
        // /mnt must exist+be writable for staging dir under /mnt/nails-pivot/
        fs.mock_set_path_exists("/mnt", true);

        let config = crate::config::EphemeralOverlayDir {
            path: PathBuf::from("/tmp"),
            tmpfs_upper_size: "2G".to_string(),
            tmpfs_work_size: "1G".to_string(),
        };

        let result = pivot_ephemeral_mount(&fs, &config, Path::new("/tmp"));
        assert!(
            result.is_ok(),
            "ephemeral mount should succeed: {:?}",
            result.err()
        );
        let info = result.unwrap();
        assert!(info.is_ephemeral);
        assert_eq!(info.target, PathBuf::from("/tmp"));
        assert!(info.upper.to_string_lossy().ends_with("-upper"));
        assert!(info.work.to_string_lossy().ends_with("-work"));
    }

    #[test]
    fn test_pivot_ephemeral_mount_invalid_size_fails() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp", true);

        let config = crate::config::EphemeralOverlayDir {
            path: PathBuf::from("/tmp"),
            tmpfs_upper_size: "notasize".to_string(),
            tmpfs_work_size: "1G".to_string(),
        };

        let result = pivot_ephemeral_mount(&fs, &config, Path::new("/tmp"));
        assert!(result.is_err(), "invalid size should fail");
    }

    #[test]
    fn test_pivot_ephemeral_mount_root_path_fails() {
        let fs = MockFilesystem::new();
        let config = crate::config::EphemeralOverlayDir {
            path: PathBuf::from("/"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };
        let result = pivot_ephemeral_mount(&fs, &config, Path::new("/"));
        assert!(result.is_err());
    }

    // ── snapshot_pivot_overlay_mount ───────────────────────────────────────────

    #[test]
    fn test_snapshot_pivot_success() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/boot", true);
        fs.mock_set_path_exists("/mnt/hidden/boot-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/boot-work", true);
        // /mnt must be writable for snapshot/staging dirs under /mnt/nails-pivot/
        fs.mock_set_path_exists("/mnt", true);

        let result = snapshot_pivot_overlay_mount(
            &fs,
            &[Path::new("/boot")],
            Path::new("/mnt/hidden/boot-upper"),
            Path::new("/mnt/hidden/boot-work"),
            Path::new("/boot"),
        );

        assert!(
            result.is_ok(),
            "snapshot pivot should succeed: {:?}",
            result.err()
        );
        let info = result.unwrap();
        assert_eq!(info.target, PathBuf::from("/boot"));
        assert!(info.lower.to_string_lossy().ends_with("-snapshot"));
        assert!(!info.is_ephemeral);
    }

    #[test]
    fn test_snapshot_pivot_copy_tree_failure_rolls_back() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/boot", true);
        // Make copy_tree fail
        fs.mock_set_copy_tree_should_fail(Path::new("/boot"));

        let result = snapshot_pivot_overlay_mount(
            &fs,
            &[Path::new("/boot")],
            Path::new("/mnt/hidden/boot-upper"),
            Path::new("/mnt/hidden/boot-work"),
            Path::new("/boot"),
        );

        assert!(result.is_err(), "should fail when copy_tree fails");
    }

    #[test]
    fn test_snapshot_pivot_root_target_fails() {
        let fs = MockFilesystem::new();
        let result = snapshot_pivot_overlay_mount(
            &fs,
            &[Path::new("/")],
            Path::new("/mnt/hidden/root-upper"),
            Path::new("/mnt/hidden/root-work"),
            Path::new("/"),
        );
        assert!(result.is_err());
    }
}
