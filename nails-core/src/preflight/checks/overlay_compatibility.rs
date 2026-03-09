//! Overlay compatibility pre-flight check
//!
//! Validates that:
//! 1. Overlay-incompatible filesystem targets (vfat, exfat, ntfs) are small enough
//!    to be snapshot-pivoted into RAM.
//! 2. Upper layer directories don't have `trusted.overlay.opaque` xattrs that would
//!    hide lower-layer contents after a previous activation cycle.

use super::super::{CheckResult, PreFlightCheck};
use crate::overlay::OVERLAY_INCOMPATIBLE_FSTYPES;
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// Default maximum snapshot size: 1 GB
const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 1_073_741_824;

/// Pre-flight check for overlay compatibility issues
///
/// Detects two classes of problems:
///
/// 1. **Incompatible filesystems**: Targets on vfat/exfat/ntfs that need snapshot pivot.
///    Warns if small enough, fails if too large for RAM.
///
/// 2. **Opaque upper-layer directories**: Upper directories marked opaque from a previous
///    activation cycle. These are auto-fixed (xattr stripped) and a warning is emitted.
pub struct OverlayCompatibilityCheck {
    overlay_targets: Vec<PathBuf>,
    hidden_volume_root: PathBuf,
    max_snapshot_bytes: u64,
}

impl OverlayCompatibilityCheck {
    /// Create a new OverlayCompatibilityCheck
    pub fn new(overlay_targets: Vec<PathBuf>, hidden_volume_root: PathBuf) -> Self {
        Self {
            overlay_targets,
            hidden_volume_root,
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
        }
    }
}

/// Format bytes as a human-readable string (e.g., "156 MB", "2.3 GB")
fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;

    if bytes >= GB {
        let gb = bytes as f64 / GB as f64;
        format!("{:.1} GB", gb)
    } else {
        let mb = bytes as f64 / MB as f64;
        format!("{:.0} MB", mb)
    }
}

impl<F: Filesystem> PreFlightCheck<F> for OverlayCompatibilityCheck {
    fn name(&self) -> &'static str {
        "overlay-compatibility"
    }

    fn description(&self) -> &'static str {
        "Validates overlay compatibility and upper-layer health"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut warnings = Vec::new();

        // Check 1: Overlay-incompatible filesystems (vfat, exfat, ntfs)
        for target in &self.overlay_targets {
            let fstype = fs.get_filesystem_type(target)?;

            let is_incompatible = fstype
                .as_deref()
                .is_some_and(|ft| OVERLAY_INCOMPATIBLE_FSTYPES.contains(&ft));

            if !is_incompatible {
                continue;
            }

            let fstype_str = fstype.as_deref().unwrap_or("unknown");
            let size = fs.get_directory_size(target)?;

            if size > self.max_snapshot_bytes {
                return Ok(CheckResult::Fail(format!(
                    "Cannot overlay {} ({}, {}): exceeds {} snapshot limit. \
                     Add {} to overlay_exclusions.",
                    target.display(),
                    fstype_str,
                    format_bytes(size),
                    format_bytes(self.max_snapshot_bytes),
                    target.display(),
                )));
            }

            warnings.push(format!(
                "{} ({}, {}) will use snapshot pivot (copies to RAM)",
                target.display(),
                fstype_str,
                format_bytes(size),
            ));
        }

        // Check 2: Opaque upper-layer directories
        // These hide lower-layer contents and are a common source of broken overlays.
        // Auto-fix by stripping the xattr, then warn.
        for target in &self.overlay_targets {
            let dir_name = match target.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };
            let upper = self.hidden_volume_root.join(&dir_name);

            let stripped = crate::overlay::opaque::strip_opaque_xattrs(&upper);
            if stripped > 0 {
                warnings.push(format!(
                    "Fixed {} opaque dir(s) in upper layer for {} \
                     (previous activation left stale overlay markers)",
                    stripped,
                    target.display(),
                ));
            }
        }

        if warnings.is_empty() {
            Ok(CheckResult::Pass(
                "All overlay targets are compatible, no opaque dirs found".into(),
            ))
        } else {
            Ok(CheckResult::Warn(warnings.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    #[test]
    fn test_pass_no_incompatible_targets() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
        fs.mock_set_filesystem_type(Path::new("/etc"), "ext4");

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            PathBuf::from("/mnt/hidden"),
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    #[test]
    fn test_pass_no_fstype_info() {
        let fs = MockFilesystem::new();

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/data")],
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    #[test]
    fn test_warn_vfat_under_limit() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_directory_size(Path::new("/boot"), 156 * 1_048_576); // 156 MB

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/boot")],
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_warn(), "Expected Warn, got: {:?}", result);
        assert!(result.message().contains("/boot"));
        assert!(result.message().contains("vfat"));
        assert!(result.message().contains("snapshot pivot"));
    }

    #[test]
    fn test_fail_vfat_over_limit() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_directory_size(Path::new("/boot"), 2_500_000_000); // ~2.3 GB

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/boot")],
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail(), "Expected Fail, got: {:?}", result);
        assert!(result.message().contains("/boot"));
        assert!(result.message().contains("overlay_exclusions"));
    }

    #[test]
    fn test_mixed_compatible_and_incompatible() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_directory_size(Path::new("/boot"), 100 * 1_048_576); // 100 MB

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/home"), PathBuf::from("/boot")],
            PathBuf::from("/mnt/hidden"),
        );

        let result = check.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("/boot"));
    }

    #[test]
    fn test_metadata() {
        let check = OverlayCompatibilityCheck::new(vec![], PathBuf::from("/mnt/hidden"));
        assert_eq!(
            <OverlayCompatibilityCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "overlay-compatibility"
        );
    }
}
