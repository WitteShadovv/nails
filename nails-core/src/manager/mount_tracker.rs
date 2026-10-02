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

    /// Take ownership of the tracked mounts, leaving the tracker empty.
    ///
    /// Used by the activation flow to move the mount list into an
    /// activation-scope rollback guard once the mount phase completes. The
    /// emptied tracker's `Drop` then becomes inert, so removing the old
    /// `commit()` call no longer risks a spurious rollback on the success path.
    pub fn take_mounts(&mut self) -> Vec<MountInfo> {
        std::mem::take(&mut self.mounted)
    }

    /// Roll back all tracked mounts in reverse (LIFO) order, best-effort.
    ///
    /// Delegates to [`rollback_mounts`](crate::manager::activation::rollback::rollback_mounts),
    /// the single unmount routine shared with the activation-scope guard: it
    /// tries a graceful unmount before forcing, cascades ephemeral tmpfs
    /// teardown, and continues past individual failures. The tracker is emptied
    /// so a later drop is a no-op.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if every tracked mount came down.
    /// - `Err(NailsError::OverlayError)` listing the targets that did not, after
    ///   attempting all of them.
    ///
    /// (Story 4.11: Extended Overlay Strategy with tmpfs cleanup)
    pub fn rollback_all(&mut self) -> Result<()> {
        let remaining =
            crate::manager::activation::rollback::rollback_mounts(self.filesystem, &self.mounted);
        self.mounted.clear();

        if remaining.is_empty() {
            Ok(())
        } else {
            let detail = remaining
                .iter()
                .map(|path| format!("Failed to unmount {}", path.display()))
                .collect::<Vec<_>>()
                .join("; ");
            Err(NailsError::OverlayError(format!(
                "Rollback completed with errors: {}",
                detail
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use std::path::Path;

    #[test]
    fn take_mounts_empties_tracker_so_drop_is_inert() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));

        let taken = tracker.take_mounts();
        assert_eq!(taken.len(), 1);
        assert!(tracker.mounted.is_empty());

        // The tracker is uncommitted, but take_mounts emptied it, so its drop
        // must not roll back the overlay the caller now owns.
        drop(tracker);
        assert!(
            fs.is_mounted(Path::new("/home")).unwrap(),
            "/home must stay mounted after an emptied tracker is dropped"
        );
    }

    #[test]
    fn rollback_all_reports_targets_it_could_not_unmount() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
        fs.mock_set_unmount_should_fail("/etc", true);

        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
        tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

        let err = tracker
            .rollback_all()
            .expect_err("rollback should report /etc");
        let msg = err.to_string();
        assert!(
            msg.contains("/etc") && msg.contains("Failed to unmount"),
            "got: {msg}"
        );
        // Best-effort: /home still came down.
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
    }
}
