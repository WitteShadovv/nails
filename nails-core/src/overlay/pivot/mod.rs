// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pivot mount strategy for active directories
//!
//! Provides functions to mount overlays onto actively-used directories
//! using a two-step staging approach to work around kernel limitations.

use crate::config::EphemeralOverlayDir;
use crate::{Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

use super::mount_info::PivotMountInfo;

#[cfg(test)]
mod tests;

/// Staging directory base for pivot mounts.
///
/// This lives on `/run` (a tmpfs that is always overlay-excluded and can never
/// be un-excluded, see `config::dynamic`), not on the decoy root. An earlier
/// design staged under `/mnt/nails-pivot`; because `/mnt` is overlay-excluded it
/// sat on the persistent decoy filesystem, so every activation created staging
/// and snapshot directories there that survived teardown and a reboot — a
/// standing forensic trace on the decoy disk. Staging on the `/run` tmpfs keeps
/// the same overlay-exclusion property while making the scaffolding volatile:
/// it is gone on power-off and never reaches the decoy disk image. The old decoy
/// path stays in the artifact registry so `verify` still flags a leftover from a
/// prior build.
pub const PIVOT_STAGING_BASE: &str = "/run/nails-pivot";

/// Upper bound on a snapshot tmpfs, so an overlay-incompatible target can never
/// request an unbounded amount of RAM. Shared with the overlay-compatibility
/// preflight check, which fails any target measuring larger than this.
pub const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 1_073_741_824;

/// Floor for a snapshot tmpfs, so a near-empty target still yields a usable
/// filesystem (overlayfs copy-up and the snapshot copy both need a little room).
const MIN_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

/// Derive the snapshot tmpfs size (in bytes) from the measured size of the
/// target directory.
///
/// The old code hard-coded `"1G"` for every snapshot regardless of how small the
/// target was, pinning a gigabyte of RAM for a 50 MB ESP. Instead, size the
/// tmpfs from the actual content plus headroom for filesystem overhead and the
/// copy itself, with a floor so a tiny target still mounts and a ceiling so an
/// unexpectedly large one cannot exhaust RAM.
pub(crate) fn snapshot_tmpfs_bytes(measured: u64) -> u64 {
    // 25% headroom plus the floor as a fixed slack allowance.
    let with_headroom = measured
        .saturating_add(measured / 4)
        .saturating_add(MIN_SNAPSHOT_BYTES);
    with_headroom.clamp(MIN_SNAPSHOT_BYTES, DEFAULT_MAX_SNAPSHOT_BYTES)
}

fn cleanup_empty_directory<F: Filesystem>(fs: &F, path: &Path) {
    let _ = fs.remove_directory(path);
}

/// Mount an overlay using the pivot strategy for active directories
///
/// A busy directory does not block an overlay mount, so this is not a workaround
/// for a mount that cannot otherwise happen. It is the fallback used when a direct
/// mount is rejected for another reason: the overlay is mounted on a staging path
/// and bind-mounted over the target in two steps:
/// 1. Mount overlay to staging location (`/run/nails-pivot/var`)
/// 2. Bind mount staging to target (`/var`)
///
/// # Process Impact (Split View)
///
/// - **Existing processes:** keep resolving the directory handle they opened
///   before the mount, so they keep reading *and writing* the original decoy
///   content underneath the overlay.
/// - **New path resolutions:** see the overlay content.
/// - This split view is a RISK, not a benefit: a pre-existing writer leaks hidden-
///   session activity back into the decoy lower tree. The same split affects
///   pre-existing processes under a direct mount too, so the mount method itself
///   carries no security guarantee — the leak is in the surviving writers.
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
/// fs.mock_set_directory_creatable("/run/nails-pivot/var", true);
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
/// assert!(info.staging.starts_with("/run/nails-pivot"));
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
/// 1. Mount a shared tmpfs backing directory
/// 2. Create `upper` and `work` beneath it
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
/// fs.mock_set_directory_creatable("/run/nails-pivot/var", true);
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

    let backing = base.join(format!("{}-ephemeral", dir_name));
    let upper = backing.join("upper");
    let work = backing.join("work");

    // Step 1: Mount a shared tmpfs backing directory
    fs.create_directory(&backing)?;

    fs.mount_tmpfs(&backing, &config.tmpfs_upper_size)?;

    // Step 2: Create upper/work directories inside the tmpfs
    if let Err(e) = fs.create_directory(&upper) {
        let _ = fs.unmount_tmpfs(&backing);
        cleanup_empty_directory(fs, &backing);
        return Err(e);
    }

    if let Err(e) = fs.create_directory(&work) {
        let _ = fs.remove_directory(&upper);
        let _ = fs.unmount_tmpfs(&backing);
        cleanup_empty_directory(fs, &backing);
        return Err(e);
    }

    // Step 3: Pivot mount overlay to target
    match pivot_overlay_mount(fs, &[lower], &upper, &work, &config.path) {
        Ok(mut info) => {
            info.is_ephemeral = true;
            Ok(info)
        }
        Err(e) => {
            // Rollback: unmount shared tmpfs backing
            let _ = fs.remove_directory(&work);
            let _ = fs.remove_directory(&upper);
            let _ = fs.unmount_tmpfs(&backing);
            cleanup_empty_directory(fs, &backing);
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

    // Measure the target so the snapshot tmpfs is sized from its real content
    // plus headroom, rather than pinning a fixed gigabyte of RAM.
    let measured = fs.get_directory_size(target)?;
    let snapshot_size = snapshot_tmpfs_bytes(measured).to_string();

    // Step 1: Create snapshot tmpfs directory
    let snapshot_path = PathBuf::from(PIVOT_STAGING_BASE).join(format!("{}-snapshot", dir_name));
    fs.create_directory(&snapshot_path)?;

    // Step 2: Mount tmpfs at snapshot location
    if let Err(e) = fs.mount_tmpfs(&snapshot_path, &snapshot_size) {
        cleanup_empty_directory(fs, &snapshot_path);
        return Err(e);
    }

    // Step 3: Copy target contents into snapshot tmpfs
    if let Err(e) = fs.copy_tree(target, &snapshot_path) {
        let _ = fs.unmount_tmpfs(&snapshot_path);
        cleanup_empty_directory(fs, &snapshot_path);
        return Err(e);
    }

    // Step 4: Create staging directory
    let staging = PathBuf::from(PIVOT_STAGING_BASE).join(dir_name.as_ref());
    if let Err(e) = fs.create_directory(&staging) {
        let _ = fs.unmount_tmpfs(&snapshot_path);
        cleanup_empty_directory(fs, &snapshot_path);
        return Err(e);
    }

    // Step 5: Mount overlay with snapshot as lower layer
    if let Err(e) = fs.mount_overlay(&[snapshot_path.as_path()], upper, work, &staging) {
        cleanup_empty_directory(fs, &staging);
        let _ = fs.unmount_tmpfs(&snapshot_path);
        cleanup_empty_directory(fs, &snapshot_path);
        return Err(e);
    }

    // Step 6: Bind mount staging to target
    if let Err(e) = fs.bind_mount(&staging, target) {
        let _ = fs.unmount(&staging, true);
        cleanup_empty_directory(fs, &staging);
        let _ = fs.unmount_tmpfs(&snapshot_path);
        cleanup_empty_directory(fs, &snapshot_path);
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
    cleanup_empty_directory(fs, &info.staging);

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
        cleanup_empty_directory(fs, &info.lower);
    }

    // Step 4: If ephemeral, remove upper/work and unmount shared tmpfs backing
    if info.is_ephemeral {
        let Some(backing) = info.upper.parent() else {
            errors.push(format!(
                "invalid ephemeral upper path: {}",
                info.upper.display()
            ));
            return Err(NailsError::OverlayError(errors.join("; ")));
        };

        cleanup_empty_directory(fs, &info.work);
        cleanup_empty_directory(fs, &info.upper);
        if let Err(e) = fs.unmount_tmpfs(backing) {
            errors.push(format!("ephemeral tmpfs {}: {}", backing.display(), e));
        }
        cleanup_empty_directory(fs, backing);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(errors.join("; ")))
    }
}
