//! Mount information structures for overlay filesystems
//!
//! Provides data structures to track ephemeral and pivot overlay mounts.

use std::path::PathBuf;

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

/// Information about a pivot-mounted overlay
///
/// Tracks all paths involved in a pivot overlay mount for cleanup.
/// Used when mounting overlays onto active directories like `/var`.
///
/// # Pivot Mount Strategy
///
/// Direct overlay mount onto `/var` fails with EINVAL because the directory
/// is actively in use. The pivot strategy works around this:
/// 1. Mount overlay to staging location (e.g., `/mnt/nails-pivot/var`)
/// 2. Bind mount staging to target (e.g., `/var`)
///
/// This creates a "split view":
/// - Existing processes with open FDs see original content
/// - New path resolutions see overlay content
///
/// # Fields
///
/// * `target` - Final mount point (e.g., "/var")
/// * `staging` - Intermediate staging location (e.g., "/mnt/nails-pivot/var")
/// * `upper` - Upper layer path
/// * `work` - Work directory path
/// * `lower` - Read-only base layer
/// * `is_ephemeral` - If true, upper/work are tmpfs-backed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivotMountInfo {
    /// Final mount point where overlay appears
    pub target: PathBuf,

    /// Staging location where overlay is initially mounted
    pub staging: PathBuf,

    /// Upper layer path (may be on hidden volume or tmpfs)
    pub upper: PathBuf,

    /// Work directory path
    pub work: PathBuf,

    /// Read-only base layer
    pub lower: PathBuf,

    /// Whether upper/work are tmpfs-backed (ephemeral)
    pub is_ephemeral: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_pivot_mount_info_creation() {
        let info = PivotMountInfo {
            target: PathBuf::from("/var"),
            staging: PathBuf::from("/mnt/nails-pivot/var"),
            upper: PathBuf::from("/mnt/hidden/var-upper"),
            work: PathBuf::from("/mnt/hidden/var-work"),
            lower: PathBuf::from("/var"),
            is_ephemeral: false,
        };
        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
        assert!(!info.is_ephemeral);
    }

    #[test]
    fn test_ephemeral_mount_info_clone() {
        let info = EphemeralMountInfo {
            target: PathBuf::from("/tmp"),
            upper: PathBuf::from("/run/nails/tmp-upper"),
            work: PathBuf::from("/run/nails/tmp-work"),
            lower: PathBuf::from("/tmp"),
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_pivot_mount_info_ephemeral_flag() {
        let ephemeral = PivotMountInfo {
            target: PathBuf::from("/var"),
            staging: PathBuf::from("/mnt/nails-pivot/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
            is_ephemeral: true,
        };
        assert!(ephemeral.is_ephemeral);

        let persistent = PivotMountInfo {
            target: PathBuf::from("/home"),
            staging: PathBuf::from("/mnt/nails-pivot/home"),
            upper: PathBuf::from("/mnt/hidden/home-upper"),
            work: PathBuf::from("/mnt/hidden/home-work"),
            lower: PathBuf::from("/home"),
            is_ephemeral: false,
        };
        assert!(!persistent.is_ephemeral);
    }
}
