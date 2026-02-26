//! RAII Mount Tracker for Automatic Rollback
//!
//! This module provides the MountTracker type, which implements the RAII
//! (Resource Acquisition Is Initialization) pattern for overlay mount management.
//!
//! # Architecture
//!
//! - **LIFO Ordering**: Mounts are tracked in a Vec<MountInfo> and unmounted in reverse
//! - **Best-Effort Rollback**: Continues unmounting even if individual unmounts fail
//! - **RAII Pattern**: Automatic rollback on drop if not committed
//! - **Graceful unmount first**: Tries graceful unmount (force=false) before forcing
//! - **Mount Type Aware**: Handles both persistent and ephemeral (tmpfs-backed) overlays

use crate::{Filesystem, NailsError, Result};
use std::path::PathBuf;

/// Type of mount being tracked
///
/// Distinguishes between persistent overlays (backed by hidden storage)
/// and ephemeral overlays (backed by tmpfs RAM storage).
///
/// (Story 4.11: Extended Overlay Strategy)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountType {
    /// Persistent overlay: lower from system, upper/work on hidden storage
    ///
    /// Used for /home and /etc - changes persist across reboots
    Persistent,

    /// Ephemeral overlay: lower from system, upper/work on tmpfs (RAM)
    ///
    /// Used for /var, /tmp, /srv, /opt - changes destroyed on unmount
    /// Provides forensic safety even if system is seized while running
    Ephemeral,
}

/// Information about a tracked mount
///
/// Contains metadata needed to properly unmount both the overlay
/// and any associated tmpfs filesystems.
///
/// (Story 4.11: Extended Overlay Strategy)
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Type of mount (persistent or ephemeral)
    pub mount_type: MountType,
    /// Target path where the overlay is mounted
    pub target: PathBuf,
    /// Tmpfs mount paths that must be unmounted after overlay
    ///
    /// For persistent mounts: empty
    /// For ephemeral mounts: [upper_path, work_path]
    pub tmpfs_paths: Vec<PathBuf>,
}

impl MountInfo {
    /// Create a new persistent mount info
    pub fn persistent(target: PathBuf) -> Self {
        Self {
            mount_type: MountType::Persistent,
            target,
            tmpfs_paths: Vec::new(),
        }
    }

    /// Create a new ephemeral mount info with tmpfs paths
    pub fn ephemeral(target: PathBuf, tmpfs_paths: Vec<PathBuf>) -> Self {
        Self {
            mount_type: MountType::Ephemeral,
            target,
            tmpfs_paths,
        }
    }
}

/// RAII mount tracker for automatic rollback on failure
///
/// Tracks mounted overlays in LIFO order and provides automatic rollback
/// if the MountTracker is dropped without being committed.
///
/// # Architecture
///
/// - **LIFO Ordering**: Mounts are tracked in a `Vec<MountInfo>` and unmounted in reverse
/// - **Best-Effort Rollback**: Continues unmounting even if individual unmounts fail
/// - **RAII Pattern**: Automatic rollback on drop if not committed
/// - **Graceful unmount first**: Tries graceful unmount (force=false) before forcing
/// - **Mount Type Aware**: Handles both persistent and ephemeral (tmpfs-backed) overlays
///
/// # Example
///
/// ```no_run
/// use nails_core::{MockFilesystem, MountTracker, MountInfo};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let mut tracker = MountTracker::new(&fs);
///
/// // Track successful persistent mounts
/// tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
/// tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));
///
/// // Track ephemeral mount with tmpfs paths
/// tracker.push_mount(MountInfo::ephemeral(
///     PathBuf::from("/var"),
///     vec![PathBuf::from("/run/nails/var/upper"), PathBuf::from("/run/nails/var/work")]
/// ));
///
/// // Commit to prevent rollback
/// tracker.commit();
///
/// // If not committed, tracker will automatically rollback on drop
/// ```
pub struct MountTracker<'a, F: Filesystem> {
    /// List of successfully mounted overlays (LIFO order)
    pub mounted: Vec<MountInfo>,
    /// Filesystem reference for unmount operations
    filesystem: &'a F,
    /// Whether mounts have been committed (prevents rollback on drop)
    pub committed: bool,
}

impl<'a, F: Filesystem> MountTracker<'a, F> {
    /// Create a new MountTracker
    ///
    /// # Arguments
    ///
    /// - `filesystem`: Reference to filesystem for unmount operations
    ///
    /// # Returns
    ///
    /// New MountTracker instance with empty mount list
    pub fn new(filesystem: &'a F) -> Self {
        Self {
            mounted: Vec::new(),
            filesystem,
            committed: false,
        }
    }

    /// Track a successful mount
    ///
    /// Adds the mount info to the tracked list for potential rollback.
    ///
    /// # Arguments
    ///
    /// - `mount_info`: Information about the successfully mounted overlay
    pub fn push_mount(&mut self, mount_info: MountInfo) {
        self.mounted.push(mount_info);
    }

    /// Commit mounts to prevent automatic rollback
    ///
    /// Mark the tracker as committed, preventing automatic rollback
    /// when the tracker is dropped.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Rollback all mounts in reverse order (LIFO) with graceful unmount first
    ///
    /// Unmounts all tracked overlays in reverse order (last mounted, first unmounted).
    /// Uses best-effort approach: continues unmounting even if some fail.
    /// Tries graceful unmount (force=false) first, then force unmount if that fails.
    ///
    /// For ephemeral mounts, also unmounts associated tmpfs filesystems after
    /// unmounting the overlay (cascade unmount).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all unmounts succeed
    /// - `Err(NailsError)` with aggregate errors if any unmounts fail
    ///
    /// # Best-Effort Behavior
    ///
    /// Even if this method returns an error, it will have attempted to unmount
    /// all tracked paths. The error contains details of all failures.
    ///
    /// (Story 4.11: Extended Overlay Strategy with tmpfs cleanup)
    pub fn rollback_all(&mut self) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // LIFO: unmount in reverse order
        for mount_info in self.mounted.iter().rev() {
            let path = &mount_info.target;
            let mount_type_str = match mount_info.mount_type {
                MountType::Persistent => "persistent",
                MountType::Ephemeral => "ephemeral",
            };

            tracing::info!(
                path = %path.display(),
                mount_type = mount_type_str,
                phase = "rollback",
                "Unmounting overlay"
            );

            // Try graceful unmount first (Epic 4.2 requirement)
            if let Err(e) = self.filesystem.unmount(path, false) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    attempt = "graceful",
                    "Unmount failed, trying force unmount"
                );

                // If graceful fails, try force unmount
                if let Err(force_err) = self.filesystem.unmount(path, true) {
                    let msg = format!(
                        "Failed to unmount {} (graceful and force both failed): {}",
                        path.display(),
                        force_err
                    );
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    errors.push(msg); // Collect error but continue (best-effort)
                } else {
                    tracing::info!(
                        path = %path.display(),
                        method = "force",
                        "Unmount succeeded"
                    );
                }
            } else {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Unmount succeeded"
                );
            }

            // For ephemeral mounts, also unmount tmpfs filesystems (cascade)
            if mount_info.mount_type == MountType::Ephemeral {
                for tmpfs_path in &mount_info.tmpfs_paths {
                    tracing::info!(
                        path = %tmpfs_path.display(),
                        filesystem_type = "tmpfs",
                        "Unmounting tmpfs"
                    );

                    if let Err(e) = self.filesystem.unmount_tmpfs(tmpfs_path) {
                        let msg =
                            format!("Failed to unmount tmpfs at {}: {}", tmpfs_path.display(), e);
                        tracing::warn!(
                            path = %tmpfs_path.display(),
                            error = %e,
                            filesystem_type = "tmpfs",
                            "Tmpfs unmount failed"
                        );
                        errors.push(msg); // Collect error but continue (best-effort)
                    } else {
                        tracing::info!(
                            path = %tmpfs_path.display(),
                            filesystem_type = "tmpfs",
                            "Tmpfs unmounted"
                        );
                    }
                }
            }
        }

        self.mounted.clear();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NailsError::OverlayError(format!(
                "Rollback completed with errors: {}",
                errors.join("; ")
            )))
        }
    }
}

/// Automatic rollback on drop (RAII pattern)
///
/// If the MountTracker is dropped without being committed,
/// it will automatically attempt to rollback all mounts.
impl<'a, F: Filesystem> Drop for MountTracker<'a, F> {
    fn drop(&mut self) {
        if !self.committed && !self.mounted.is_empty() {
            tracing::warn!(
                mount_count = self.mounted.len(),
                committed = false,
                "MountTracker dropped without commit, rolling back"
            );
            let _ = self.rollback_all();
        }
    }
}
