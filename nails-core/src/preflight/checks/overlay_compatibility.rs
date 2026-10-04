// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Overlay compatibility pre-flight check
//!
//! Validates that:
//! 1. Overlay-incompatible filesystem targets (vfat, exfat, ntfs) are small enough
//!    to be snapshot-pivoted into RAM.
//! 2. NAILS-managed upper directories don't carry a `trusted.overlay.opaque`
//!    xattr that would hide lower-layer contents after a previous activation
//!    cycle. This check only reports such markers; the mount step clears them,
//!    so preflight and `--dry-run` make no writes.

use super::super::{CheckResult, PreFlightCheck};
use crate::overlay::{DEFAULT_MAX_SNAPSHOT_BYTES, OVERLAY_INCOMPATIBLE_FSTYPES};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Pre-flight check for overlay compatibility issues
///
/// Detects two classes of problems:
///
/// 1. **Incompatible filesystems**: Targets on vfat/exfat/ntfs that need snapshot pivot.
///    Warns if small enough, fails if too large for RAM.
///
/// 2. **Opaque managed directories**: NAILS-managed upper directories (currently
///    `/etc/nixos`) marked opaque from a previous activation cycle. These are
///    reported as a warning only; the mount step clears them, so this check
///    never writes.
pub struct OverlayCompatibilityCheck {
    persistent_overlay_targets: Vec<PathBuf>,
    hidden_volume_root: PathBuf,
    max_snapshot_bytes: u64,
    /// Xattr name probed for opaque markers. Production uses the real overlay
    /// marker; tests override it with a `user.*` name they can set unprivileged.
    opaque_xattr: &'static str,
}

impl OverlayCompatibilityCheck {
    /// Create a new OverlayCompatibilityCheck
    pub fn new(persistent_overlay_targets: Vec<PathBuf>, hidden_volume_root: PathBuf) -> Self {
        Self {
            persistent_overlay_targets,
            hidden_volume_root,
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
            opaque_xattr: crate::overlay::opaque::OPAQUE_XATTR,
        }
    }

    /// Override the probed xattr name (test seam for unprivileged `user.*`
    /// markers).
    #[cfg(test)]
    fn with_opaque_xattr(mut self, name: &'static str) -> Self {
        self.opaque_xattr = name;
        self
    }
}

/// Remediation for a failed size probe on `target`.
///
/// `du` fails with `Permission denied` when run unprivileged against a tree it
/// cannot traverse (e.g. `/boot`), so an unprivileged run is told to re-run as
/// root rather than being left with a raw command error; either way the target
/// can instead be excluded from overlaying.
fn size_probe_remediation(target: &Path) -> String {
    if nix::unistd::geteuid().is_root() {
        format!(
            "Ensure {} is readable, or add it to overlay_exclusions in nails.toml.",
            target.display()
        )
    } else {
        format!(
            "Run as root for this check (measuring {} needs full read access), \
             or add it to overlay_exclusions in nails.toml.",
            target.display()
        )
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

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let mut warnings = Vec::new();

        // Check 1: Overlay-incompatible filesystems (vfat, exfat, ntfs)
        for target in &self.persistent_overlay_targets {
            let fstype = fs.get_filesystem_type(target)?;

            let is_incompatible = fstype
                .as_deref()
                .is_some_and(|ft| OVERLAY_INCOMPATIBLE_FSTYPES.contains(&ft));

            if !is_incompatible {
                continue;
            }

            let fstype_str = fstype.as_deref().unwrap_or("unknown");
            let size = match fs.get_directory_size(target) {
                Ok(size) => size,
                // A raw `du: Permission denied` here is useless to the operator.
                // Turn it into an actionable failure that names the target and
                // says how to clear it.
                Err(e) => {
                    return Ok(CheckResult::fail_with(
                        format!(
                            "cannot measure {} ({}) to decide whether it fits a RAM snapshot: {}",
                            target.display(),
                            fstype_str,
                            e
                        ),
                        size_probe_remediation(target),
                    ));
                }
            };

            if size > self.max_snapshot_bytes {
                return Ok(CheckResult::fail(format!(
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

        // Check 2: Opaque markers on NAILS-managed directories.
        // These hide lower-layer contents (e.g. the lower flake.nix under
        // /etc/nixos) and are a common source of broken overlays. This is a
        // read-only report: the mount step clears the marker, so preflight and
        // --dry-run never write to the hidden volume.
        for target in &self.persistent_overlay_targets {
            let dir_name = match target.file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => continue,
            };
            let upper = self.hidden_volume_root.join(&dir_name);

            let marked = crate::overlay::opaque::report_managed_opaque_named(
                &upper,
                target,
                self.opaque_xattr,
            );
            if !marked.is_empty() {
                let paths = marked
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                warnings.push(format!(
                    "Stale overlay opaque marker on {} for {} \
                     (a previous activation left it; the mount step will clear it)",
                    paths,
                    target.display(),
                ));
            }
        }

        // Check 3: Submounts nested under overlay targets. A parent overlay hides
        // any filesystem mounted beneath it, so each hidden submount is listed with
        // the plan activation will apply: a read-only re-attach over the overlay
        // (snap squashfs, an ESP, tmpfs) or its own nested overlay with the upper on
        // the hidden volume (a writable, decoy-backed partition). Read-only report;
        // no mounts happen here.
        for target in &self.persistent_overlay_targets {
            for submount in fs.find_submounts(target)? {
                match submount {
                    crate::filesystem::Submount::Reattach {
                        mount_point,
                        fstype,
                        read_only,
                    } => warnings.push(format!(
                        "{} ({}) under {} will be re-attached {} over the overlay",
                        mount_point.display(),
                        fstype,
                        target.display(),
                        if read_only { "read-only" } else { "writable" },
                    )),
                    crate::filesystem::Submount::NestedOverlay {
                        mount_point,
                        fstype,
                    } => warnings.push(format!(
                        "{} ({}) under {} will get its own nested overlay (writes land on the hidden volume)",
                        mount_point.display(),
                        fstype,
                        target.display(),
                    )),
                    // Extra-lower binds are folded into the overlay's lower stack
                    // and stay visible without a re-attach, so they are not listed.
                    crate::filesystem::Submount::ExtraLower { .. } => {}
                }
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
    use rustix::fs::XattrFlags;
    use std::path::Path;

    /// `user.*` marker so the test can set it without root (`trusted.*` needs
    /// CAP_SYS_ADMIN). Production probes the real overlay marker.
    const TEST_XATTR: &str = "user.nails.test.opaque";

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
    fn test_lists_reattach_and_nested_submounts() {
        use crate::filesystem::Submount;
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/snap"), "ext4");
        fs.mock_set_filesystem_type(Path::new("/var"), "ext4");
        fs.mock_set_submounts(
            Path::new("/snap"),
            vec![Submount::Reattach {
                mount_point: PathBuf::from("/snap/firefox/1234"),
                fstype: "squashfs".to_string(),
                read_only: true,
            }],
        );
        fs.mock_set_submounts(
            Path::new("/var"),
            vec![Submount::NestedOverlay {
                mount_point: PathBuf::from("/var/log"),
                fstype: "ext4".to_string(),
            }],
        );

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/snap"), PathBuf::from("/var")],
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();

        assert!(result.is_warn(), "Expected Warn, got: {:?}", result);
        let message = result.message();
        assert!(message.contains("/snap/firefox/1234"));
        assert!(message.contains("re-attached read-only"));
        assert!(message.contains("/var/log"));
        assert!(message.contains("nested overlay"));
    }

    #[test]
    fn test_extra_lower_submounts_are_not_listed() {
        use crate::filesystem::Submount;
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/etc"), "ext4");
        fs.mock_set_submounts(
            Path::new("/etc"),
            vec![Submount::ExtraLower {
                mount_point: PathBuf::from("/etc/nixos"),
                source: PathBuf::from("/persist/etc/nixos"),
            }],
        );

        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/etc")],
            PathBuf::from("/mnt/hidden"),
        );
        let result = check.run(&fs).unwrap();
        assert!(
            result.is_pass(),
            "extra-lower binds must not warn: {result:?}"
        );
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
    fn test_opaque_marker_reported_not_stripped() {
        // A real hidden root so Check 2 exercises the actual syscalls.
        let hidden = tempfile::tempdir().unwrap();
        let managed = hidden.path().join("etc").join("nixos");
        std::fs::create_dir_all(&managed).unwrap();

        // Self-skip when the temp filesystem rejects user.* xattrs.
        if rustix::fs::lsetxattr(&managed, TEST_XATTR, b"y", XattrFlags::empty()).is_err() {
            return;
        }

        let fs = MockFilesystem::new();
        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/etc")],
            hidden.path().to_path_buf(),
        )
        .with_opaque_xattr(TEST_XATTR);

        let result = check.run(&fs).unwrap();

        // The marker is reported as a warning that names the managed path...
        assert!(result.is_warn(), "Expected Warn, got: {:?}", result);
        assert!(result.message().contains("/etc"));
        assert!(result.message().contains(&managed.display().to_string()));

        // ...but the check is read-only: the marker is still present afterwards.
        let mut probe: [u8; 0] = [];
        assert!(
            rustix::fs::lgetxattr(&managed, TEST_XATTR, &mut probe[..]).is_ok(),
            "Check 2 must not strip the marker"
        );
    }

    #[test]
    fn test_no_opaque_marker_passes() {
        let hidden = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(hidden.path().join("etc").join("nixos")).unwrap();

        let fs = MockFilesystem::new();
        let check = OverlayCompatibilityCheck::new(
            vec![PathBuf::from("/etc")],
            hidden.path().to_path_buf(),
        )
        .with_opaque_xattr(TEST_XATTR);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "Expected Pass, got: {:?}", result);
    }

    #[test]
    fn size_probe_remediation_is_actionable() {
        let remediation = size_probe_remediation(Path::new("/boot"));
        // Always names the target and the way to exclude it, regardless of euid.
        assert!(remediation.contains("/boot"), "{remediation}");
        assert!(remediation.contains("overlay_exclusions"), "{remediation}");
        // Unprivileged (the usual CI case): the operator is pointed at root so a
        // raw `du: Permission denied` never surfaces unexplained.
        if !nix::unistd::geteuid().is_root() {
            assert!(
                remediation.contains("Run as root for this check"),
                "{remediation}"
            );
        }
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
