//! Mount metadata tracking for overlay filesystem operations

use std::path::PathBuf;

/// Mount metadata for tracking overlay mount operations
///
/// Used by MockFilesystem to track which overlays are mounted and when, and
/// returned by [`Filesystem::get_mount_info`](crate::Filesystem::get_mount_info)
/// for a live overlay.
///
/// # Fields
///
/// * `lowers` - Read-only base layers, in overlayfs stacking order (first
///   element is the primary lower). Every layer is kept, so an overlay mounted
///   with several extra lower layers round-trips faithfully through both the real
///   and the mock filesystem instead of collapsing to a single layer.
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
///     lowers: vec![PathBuf::from("/")],
///     upper: PathBuf::from("/mnt/hidden/upper"),
///     work: PathBuf::from("/mnt/hidden/work"),
///     target: PathBuf::from("/home"),
///     mounted_at: Utc::now(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub lowers: Vec<PathBuf>,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub target: PathBuf,
    pub mounted_at: chrono::DateTime<chrono::Utc>,
}

impl MountInfo {
    /// The primary (first) lower layer, when the overlay has at least one.
    ///
    /// Callers that only care about the base layer — a snapshot pivot checking
    /// whether its lower lives under the staging base, status reporting the
    /// backing layer — read this instead of indexing `lowers` directly.
    pub fn primary_lower(&self) -> Option<&std::path::Path> {
        self.lowers.first().map(PathBuf::as_path)
    }
}
