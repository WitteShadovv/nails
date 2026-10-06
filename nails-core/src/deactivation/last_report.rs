// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Post-deactivation self-check report written to the hidden volume.
//!
//! A standard deactivation tears the hidden session down and reboots into the
//! decoy. Just before that reboot — once the decoy configuration is restored and
//! the overlays are unmounted, while the hidden volume is still attached and
//! writable — it records a verify-style summary of the teardown at
//! `<hidden-root>/reports/last-deactivation.json`. The next `nails status` reads
//! it back (when the hidden volume is attached) so the operator can see how the
//! last session ended.
//!
//! The report only ever lands on the hidden volume, through the symlink- and
//! traversal-safe hidden-file API; nothing is written to the decoy. It is torn
//! down with the volume, so recording it leaves no decoy-side trace.

use crate::verify::{Finding, Severity, VerifyStatus};
use crate::{DeactivationReport, Filesystem, Result, SystemState};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Schema version for the on-disk report, bumped when the shape changes.
pub const LAST_DEACTIVATION_SCHEMA_VERSION: u32 = 1;

/// Subdirectory under the hidden root that holds activation and deactivation
/// reports. Shares the directory the pre-activation residue baseline uses.
pub const LAST_DEACTIVATION_REPORT_DIR: &str = "reports";

/// File name of the last-deactivation self-check under
/// [`LAST_DEACTIVATION_REPORT_DIR`]. A fixed name so the next `status` can find
/// it without scanning.
pub const LAST_DEACTIVATION_REPORT_FILE: &str = "last-deactivation.json";

/// The outcome of the teardown the report describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivationOutcome {
    /// Final system state after the teardown (`Inactive` on a clean run).
    pub final_state: String,
    /// Whether the teardown returned the system to a clean Inactive state.
    pub successful: bool,
    /// Whether the teardown was a no-op because the system was already inactive.
    pub was_already_inactive: bool,
    /// Whether only a full reboot is a complete remedy (teardown did not reboot).
    pub reboot_recommended: bool,
}

/// A verify-style self-check of the last standard deactivation, written to the
/// hidden volume before the reboot and surfaced by the next `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastDeactivationReport {
    /// Report schema version, so a reader can tell how to interpret the file.
    pub schema_version: u32,
    /// When the teardown finished, as an RFC 3339 / ISO 8601 UTC timestamp.
    pub generated_at: String,
    /// Overall verify-style verdict derived from the findings below.
    pub status: VerifyStatus,
    /// Total wall-clock time the teardown took, in milliseconds.
    pub duration_ms: u64,
    /// Structured outcome (final state, success, reboot guidance).
    pub outcome: DeactivationOutcome,
    /// Overlays that were unmounted during the teardown.
    pub unmounted_overlays: Vec<String>,
    /// Overlays whose unmount failed after both graceful and forced attempts.
    pub failed_overlays: Vec<String>,
    /// NAILS mounts still live after every target was attempted.
    pub remaining_mounts: Vec<String>,
    /// Verify-style findings describing anything the teardown left behind.
    pub findings: Vec<Finding>,
}

impl LastDeactivationReport {
    /// Build the report from a completed [`DeactivationReport`].
    ///
    /// Translates the teardown accounting into verify-style findings: a mount or
    /// overlay still live is Critical, a forced detach or an incomplete history
    /// edit is a Warning, and a clean teardown records a single Info note. The
    /// overall [`status`](Self::status) is the worst severity present.
    pub fn from_report(report: &DeactivationReport, generated_at: impl Into<String>) -> Self {
        let mut findings = Vec::new();

        for overlay in &report.failed_overlays {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!("Overlay could not be unmounted during teardown: {overlay}"),
                )
                .with_fix_guidance("Run 'nails recover' to finish the teardown"),
            );
        }

        for mount in &report.remaining_mounts {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!("NAILS mount still live after teardown: {}", mount.display()),
                )
                .with_fix_guidance("Run 'nails recover' or 'nails emergency' to tear it down"),
            );
        }

        for overlay in &report.force_detached_overlays {
            findings.push(Finding::new(
                Severity::Warn,
                "mount",
                format!("Overlay only came down after a forced detach: {overlay}"),
            ));
        }

        for warning in &report.post_unmount_cleanup.warnings {
            findings.push(Finding::new(
                Severity::Warn,
                "cleanup",
                format!("Post-unmount cleanup warning: {warning}"),
            ));
        }

        if report.history_truncation_verified == Some(false) {
            findings.push(
                Finding::new(
                    Severity::Warn,
                    "file",
                    "History truncation incomplete: a decoy history file still carries content",
                )
                .with_fix_guidance("Review decoy shell history before handing over the machine"),
            );
        }

        let status = if findings.iter().any(|f| f.severity == Severity::Critical) {
            VerifyStatus::Critical
        } else if findings.iter().any(|f| f.severity == Severity::Warn) {
            VerifyStatus::Warning
        } else {
            VerifyStatus::Secure
        };

        if findings.is_empty() {
            findings.push(Finding::new(
                Severity::Info,
                "state",
                "Deactivation completed cleanly; teardown found no residual NAILS mounts",
            ));
        }

        let successful = report.final_state == SystemState::Inactive;

        Self {
            schema_version: LAST_DEACTIVATION_SCHEMA_VERSION,
            generated_at: generated_at.into(),
            status,
            duration_ms: report.duration.as_millis() as u64,
            outcome: DeactivationOutcome {
                final_state: format!("{:?}", report.final_state),
                successful,
                was_already_inactive: report.was_already_inactive,
                reboot_recommended: report.reboot_recommended,
            },
            unmounted_overlays: report.unmounted_overlays.clone(),
            failed_overlays: report.failed_overlays.clone(),
            remaining_mounts: report
                .remaining_mounts
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            findings,
        }
    }

    /// The relative path, under the hidden root, that the report is written to.
    fn relative_path() -> PathBuf {
        Path::new(LAST_DEACTIVATION_REPORT_DIR).join(LAST_DEACTIVATION_REPORT_FILE)
    }

    /// The absolute path of the report on the given hidden volume root.
    pub fn path_on(hidden_root: &Path) -> PathBuf {
        hidden_root.join(Self::relative_path())
    }
}

/// Write the last-deactivation report to the hidden volume.
///
/// The report lands at
/// `<hidden_root>/reports/last-deactivation.json`, created through the symlink-
/// and traversal-safe hidden-directory API so a planted symlink under the hidden
/// root cannot redirect the write off the volume. Returns the absolute path the
/// report was written to.
pub fn write_last_deactivation_report<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
    report: &LastDeactivationReport,
) -> Result<PathBuf> {
    fs.create_hidden_dir_all(hidden_root, Path::new(LAST_DEACTIVATION_REPORT_DIR))?;

    let relative = LastDeactivationReport::relative_path();
    // LastDeactivationReport is plain data, so serialization cannot realistically
    // fail; surface any error as I/O rather than inventing a bespoke variant.
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    fs.write_hidden_file_atomic(hidden_root, &relative, &json, 0o600)?;

    Ok(LastDeactivationReport::path_on(hidden_root))
}

/// Read the last-deactivation report back from the hidden volume, if present.
///
/// Best-effort: a missing file, an unreadable one, or malformed JSON all yield
/// `None` so `status` stays read-only and never fails on a stale or absent
/// report. The caller is expected to gate this on the hidden volume being
/// attached.
pub fn read_last_deactivation_report<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
) -> Option<LastDeactivationReport> {
    let path = LastDeactivationReport::path_on(hidden_root);
    let content = fs.read_file_content(&path).ok()?;
    serde_json::from_str(&content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CleanupReport;
    use crate::MockFilesystem;
    use crate::deactivation::PostUnmountCleanupReport;
    use std::time::Duration;

    fn clean_report() -> DeactivationReport {
        DeactivationReport {
            cleanup_report: CleanupReport::default(),
            unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
            failed_overlays: Vec::new(),
            remaining_mounts: Vec::new(),
            duration: Duration::from_millis(1234),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
            post_unmount_cleanup: PostUnmountCleanupReport::default(),
            force_detached_overlays: Vec::new(),
            page_cache_dropped: false,
            history_truncation_verified: None,
            runtime_journal_scrubbed: true,
            reboot_recommended: false,
        }
    }

    fn writable_hidden_root(fs: &MockFilesystem, root: &str) {
        fs.mock_set_path_exists(root, true);
        fs.mock_set_writable(root, true);
    }

    #[test]
    fn clean_teardown_is_secure_with_an_info_note() {
        let built = LastDeactivationReport::from_report(&clean_report(), "2026-10-06T00:00:00Z");
        assert_eq!(built.status, VerifyStatus::Secure);
        assert!(built.outcome.successful);
        assert_eq!(built.duration_ms, 1234);
        assert_eq!(built.unmounted_overlays, vec!["/home", "/etc"]);
        assert_eq!(built.findings.len(), 1);
        assert_eq!(built.findings[0].severity, Severity::Info);
    }

    #[test]
    fn remaining_mount_is_critical() {
        let mut report = clean_report();
        report.remaining_mounts = vec![PathBuf::from("/home")];
        report.final_state = SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "unmount failed".into(),
            remaining_mounts: vec![PathBuf::from("/home")],
        };
        let built = LastDeactivationReport::from_report(&report, "2026-10-06T00:00:00Z");
        assert_eq!(built.status, VerifyStatus::Critical);
        assert!(!built.outcome.successful);
        assert!(
            built
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.message.contains("/home"))
        );
    }

    #[test]
    fn forced_detach_is_a_warning() {
        let mut report = clean_report();
        report.force_detached_overlays = vec!["/etc".to_string()];
        let built = LastDeactivationReport::from_report(&report, "2026-10-06T00:00:00Z");
        assert_eq!(built.status, VerifyStatus::Warning);
    }

    #[test]
    fn write_then_read_round_trips_under_reports_dir() {
        let fs = MockFilesystem::new();
        let hidden_root = Path::new("/mnt/hidden");
        writable_hidden_root(&fs, "/mnt/hidden");

        let built = LastDeactivationReport::from_report(&clean_report(), "2026-10-06T00:00:00Z");
        let path = write_last_deactivation_report(&fs, hidden_root, &built)
            .expect("writing the report should succeed");
        assert!(path.ends_with("reports/last-deactivation.json"));

        let written = fs
            .get_written_content(&path)
            .expect("the report file must have been written");
        // Make the written content readable back through the filesystem.
        fs.mock_set_file_content(path.to_str().unwrap(), &written);

        let read = read_last_deactivation_report(&fs, hidden_root)
            .expect("the report must read back and parse");
        assert_eq!(read, built);
    }

    #[test]
    fn read_missing_report_is_none() {
        let fs = MockFilesystem::new();
        assert!(read_last_deactivation_report(&fs, Path::new("/mnt/hidden")).is_none());
    }
}
