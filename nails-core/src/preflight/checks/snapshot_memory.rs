//! Snapshot memory pre-flight check
//!
//! Overlay-incompatible targets (vfat/exfat/ntfs, in practice the ESP or
//! `/boot`) are snapshotted into a tmpfs during activation. That content lives in
//! RAM for the whole hidden session, and swap is disabled, so a large snapshot on
//! a low-memory host can push the system into memory pressure or an OOM kill.
//!
//! This check estimates the RAM the snapshots would consume and compares it to
//! `MemAvailable`. It only ever warns: sizing is best-effort and the operator may
//! know the host can cope, so it must never block activation on its own.

use super::super::{CheckResult, PreFlightCheck};
use crate::overlay::{OVERLAY_INCOMPATIBLE_FSTYPES, snapshot_tmpfs_bytes};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Headroom to leave free after the snapshots are resident, so the estimate
/// warns before RAM is actually exhausted rather than at the exact boundary.
const SAFETY_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

/// Pre-flight check that estimated snapshot tmpfs usage fits in available RAM.
pub struct SnapshotMemoryCheck {
    persistent_overlay_targets: Vec<PathBuf>,
}

impl SnapshotMemoryCheck {
    /// Create a new `SnapshotMemoryCheck` over the persistent overlay targets.
    pub fn new(persistent_overlay_targets: Vec<PathBuf>) -> Self {
        Self {
            persistent_overlay_targets,
        }
    }
}

/// Parse `MemAvailable` (in bytes) from the contents of `/proc/meminfo`.
///
/// The line is of the form `MemAvailable:   12345678 kB`. Returns `None` if the
/// field is absent or unparseable, so the caller can degrade to a pass.
fn parse_mem_available_bytes(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return Some(kib.saturating_mul(1024));
    }
    None
}

/// Format bytes as a rough human-readable string (e.g. "156 MB", "2.3 GB").
fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{:.0} MB", bytes as f64 / MB as f64)
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SnapshotMemoryCheck {
    fn name(&self) -> &'static str {
        "snapshot-memory"
    }

    fn description(&self) -> &'static str {
        "Checks available RAM against estimated snapshot tmpfs usage"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Sum the RAM the snapshot tmpfs filesystems would occupy, sized the same
        // way the mount step sizes them (measured content plus headroom).
        let mut estimate: u64 = 0;
        for target in &self.persistent_overlay_targets {
            let fstype = fs.get_filesystem_type(target)?;
            let incompatible = fstype
                .as_deref()
                .is_some_and(|ft| OVERLAY_INCOMPATIBLE_FSTYPES.contains(&ft));
            if !incompatible {
                continue;
            }
            let measured = fs.get_directory_size(target)?;
            estimate = estimate.saturating_add(snapshot_tmpfs_bytes(measured));
        }

        if estimate == 0 {
            return Ok(CheckResult::Pass(
                "No snapshot pivots required; no snapshot RAM needed".into(),
            ));
        }

        // Best-effort: if MemAvailable cannot be read or parsed, do not block or
        // noise. The estimate is advisory only.
        let available = match fs.read_file_content(Path::new("/proc/meminfo")) {
            Ok(meminfo) => match parse_mem_available_bytes(&meminfo) {
                Some(bytes) => bytes,
                None => {
                    return Ok(CheckResult::Pass(
                        "Could not read MemAvailable; skipping snapshot memory estimate".into(),
                    ));
                }
            },
            Err(_) => {
                return Ok(CheckResult::Pass(
                    "Could not read /proc/meminfo; skipping snapshot memory estimate".into(),
                ));
            }
        };

        if estimate.saturating_add(SAFETY_MARGIN_BYTES) > available {
            Ok(CheckResult::Warn(format!(
                "Snapshot tmpfs needs ~{} but only {} RAM is available (swap is off); \
                 the hidden session may hit memory pressure. Consider excluding large \
                 overlay-incompatible targets.",
                format_bytes(estimate),
                format_bytes(available),
            )))
        } else {
            Ok(CheckResult::Pass(format!(
                "Snapshot tmpfs estimate ~{} fits within {} available RAM",
                format_bytes(estimate),
                format_bytes(available),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// `/proc/meminfo` fixture with the given MemAvailable in MiB.
    fn meminfo_with_available_mib(mib: u64) -> String {
        format!(
            "MemTotal:       16000000 kB\n\
             MemFree:         1000000 kB\n\
             MemAvailable:   {} kB\n\
             Buffers:          200000 kB\n",
            mib * 1024
        )
    }

    #[test]
    fn parses_mem_available() {
        let info = meminfo_with_available_mib(512);
        assert_eq!(parse_mem_available_bytes(&info), Some(512 * 1024 * 1024));
    }

    #[test]
    fn parse_returns_none_without_field() {
        assert_eq!(parse_mem_available_bytes("MemTotal: 16000000 kB\n"), None);
    }

    #[test]
    fn passes_when_no_incompatible_targets() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
        fs.mock_set_filesystem_type(Path::new("/etc"), "ext4");

        let check = SnapshotMemoryCheck::new(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "got: {:?}", result);
    }

    #[test]
    fn passes_when_snapshot_fits_in_available_ram() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_directory_size(Path::new("/boot"), 120 * 1_048_576); // 120 MiB
        fs.mock_set_file_content("/proc/meminfo", &meminfo_with_available_mib(4096));

        let check = SnapshotMemoryCheck::new(vec![PathBuf::from("/boot")]);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "got: {:?}", result);
        assert!(result.message().contains("fits"));
    }

    #[test]
    fn warns_when_snapshot_would_not_fit() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        // A large ESP measuring ~900 MiB against a low-memory host.
        fs.mock_set_directory_size(Path::new("/boot"), 900 * 1_048_576);
        fs.mock_set_file_content("/proc/meminfo", &meminfo_with_available_mib(512));

        let check = SnapshotMemoryCheck::new(vec![PathBuf::from("/boot")]);
        let result = check.run(&fs).unwrap();
        assert!(result.is_warn(), "got: {:?}", result);
        assert!(result.message().contains("memory pressure"));
    }

    #[test]
    fn passes_when_meminfo_unreadable() {
        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_directory_size(Path::new("/boot"), 120 * 1_048_576);
        // No /proc/meminfo content set, so read_file_content errors.

        let check = SnapshotMemoryCheck::new(vec![PathBuf::from("/boot")]);
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "got: {:?}", result);
    }

    #[test]
    fn test_metadata() {
        let check = SnapshotMemoryCheck::new(vec![]);
        assert_eq!(
            <SnapshotMemoryCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "snapshot-memory"
        );
    }
}
