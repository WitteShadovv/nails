//! Mount metadata tracking for overlay filesystem operations

use std::path::PathBuf;

/// Mount metadata for tracking overlay mount operations
///
/// Used by MockFilesystem to track which overlays are mounted and when.
/// This enables comprehensive testing of mount/unmount sequences.
///
/// # Fields
///
/// * `lower` - Read-only base layer path
/// * `upper` - Writeable upper layer path
/// * `work` - Work directory path for overlay metadata
/// * `target` - Mount point where overlay appears
/// * `mounted_at` - Timestamp when mount occurred (UTC)
///
/// # Dependencies
///
/// Requires `chrono` crate for timestamp functionality.
///
/// # Example
///
/// ```rust
/// use nails_core::filesystem::MountInfo;
/// use std::path::PathBuf;
/// use chrono::Utc;
///
/// let info = MountInfo {
///     lower: PathBuf::from("/"),
///     upper: PathBuf::from("/mnt/hidden/upper"),
///     work: PathBuf::from("/mnt/hidden/work"),
///     target: PathBuf::from("/home"),
///     mounted_at: Utc::now(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub target: PathBuf,
    pub mounted_at: chrono::DateTime<chrono::Utc>,
}
