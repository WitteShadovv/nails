// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-activation decoy residue report.
//!
//! `nails activate` runs the read-only decoy residue scan *before* it mounts any
//! overlay and records the result on the hidden volume. The report is a snapshot
//! of what the decoy looked like at the moment the hidden session began: if a
//! later examination finds a trace, the operator can tell from this baseline
//! whether it predated the session or was left by it. The scan only reads the
//! decoy; it never writes to it. The report itself is written to the hidden root
//! (`<hidden-root>/reports/`), which is torn down with the session, so recording
//! the baseline leaves nothing on the decoy.

use super::{VerifyResult, VerifyStatus};
use crate::{Filesystem, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Schema version for the on-disk residue report, bumped when the shape changes.
pub const RESIDUE_REPORT_SCHEMA_VERSION: u32 = 1;

/// Subdirectory under the hidden root that holds activation reports.
pub const RESIDUE_REPORT_DIR: &str = "reports";

/// The serialized residue report written under `<hidden-root>/reports/`.
#[derive(Debug, Clone, Serialize)]
pub struct ResidueReport<'a> {
    /// Report schema version, so a reader can tell how to interpret the file.
    pub schema_version: u32,
    /// When the scan ran, as an RFC 3339 / ISO 8601 UTC timestamp.
    pub generated_at: &'a str,
    /// The read-only decoy scan result captured before overlays were mounted.
    pub result: &'a VerifyResult,
}

/// What the caller needs to report the written report to the operator.
#[derive(Debug, Clone)]
pub struct ResidueReportSummary {
    /// Absolute path of the written report on the hidden volume.
    pub path: PathBuf,
    /// Overall status of the pre-activation scan.
    pub status: VerifyStatus,
    /// Number of findings the scan recorded.
    pub finding_count: usize,
}

/// Build a filename-safe report name from an ISO 8601 timestamp.
///
/// Colons and other characters an ISO timestamp can carry are not portable in a
/// filename, so they are folded to `-`; the result stays sortable.
fn report_filename(generated_at: &str) -> String {
    let safe: String = generated_at
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("activation-residue-{safe}.json")
}

/// Write the pre-activation decoy residue report to the hidden volume.
///
/// The `result` is the outcome of a read-only decoy scan (a [`super::Verifier`]
/// run against the live host before any overlay is mounted). The report lands at
/// `<hidden_root>/reports/activation-residue-<timestamp>.json`, created through
/// the symlink- and traversal-safe hidden-directory API so a planted symlink
/// under the hidden root cannot redirect the write.
pub fn write_activation_residue_report<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
    result: &VerifyResult,
    generated_at: &str,
) -> Result<ResidueReportSummary> {
    fs.create_hidden_dir_all(hidden_root, Path::new(RESIDUE_REPORT_DIR))?;

    let relative = Path::new(RESIDUE_REPORT_DIR).join(report_filename(generated_at));
    let path = hidden_root.join(&relative);

    let report = ResidueReport {
        schema_version: RESIDUE_REPORT_SCHEMA_VERSION,
        generated_at,
        result,
    };
    // VerifyResult is plain data, so serialization cannot realistically fail;
    // surface any error as I/O rather than inventing a bespoke variant.
    let json = serde_json::to_string_pretty(&report).map_err(std::io::Error::other)?;

    // Write the report through the symlink- and traversal-safe hidden-file API at
    // operator-only mode, so a symlink planted at the report name under the hidden
    // root cannot redirect the write off the volume. The absolute `path` is kept
    // only to report the location back to the operator.
    fs.write_hidden_file_atomic(hidden_root, &relative, &json, 0o600)?;

    Ok(ResidueReportSummary {
        path,
        status: result.status,
        finding_count: result.findings.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use crate::verify::types::{Finding, ScanDepth, Severity};

    fn secure_result() -> VerifyResult {
        VerifyResult::secure(ScanDepth::Standard)
    }

    fn planted_result() -> VerifyResult {
        let findings = vec![Finding::new(
            Severity::Critical,
            "file",
            "planted indicator on the decoy",
        )];
        VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Standard)
    }

    fn writable_hidden_root(fs: &MockFilesystem, root: &str) {
        fs.mock_set_path_exists(root, true);
        fs.mock_set_writable(root, true);
    }

    #[test]
    fn writes_report_under_hidden_reports_dir() {
        let fs = MockFilesystem::new();
        let hidden_root = Path::new("/mnt/usb");
        writable_hidden_root(&fs, "/mnt/usb");

        let result = secure_result();
        let summary =
            write_activation_residue_report(&fs, hidden_root, &result, "2026-10-04T12:00:00Z")
                .expect("report write should succeed");

        assert!(
            summary
                .path
                .starts_with(hidden_root.join(RESIDUE_REPORT_DIR)),
            "report must live under <hidden-root>/reports/, got {}",
            summary.path.display()
        );
        assert_eq!(summary.status, VerifyStatus::Secure);
        assert_eq!(summary.finding_count, 0);

        let contents = fs
            .get_written_content(&summary.path)
            .expect("the report file must have been written");
        assert!(contents.contains("\"schema_version\""));
        assert!(contents.contains("\"Secure\""));
    }

    #[test]
    fn report_records_planted_findings() {
        let fs = MockFilesystem::new();
        let hidden_root = Path::new("/mnt/usb");
        writable_hidden_root(&fs, "/mnt/usb");

        let result = planted_result();
        let summary =
            write_activation_residue_report(&fs, hidden_root, &result, "2026-10-04T12:00:00Z")
                .expect("report write should succeed");

        assert_eq!(summary.status, VerifyStatus::Critical);
        assert_eq!(summary.finding_count, 1);

        let contents = fs
            .get_written_content(&summary.path)
            .expect("the report file must have been written");
        assert!(contents.contains("planted indicator on the decoy"));
        assert!(contents.contains("\"Critical\""));
    }

    #[test]
    fn filename_is_sortable_and_safe() {
        let name = report_filename("2026-10-04T12:00:00Z");
        assert!(name.starts_with("activation-residue-"));
        assert!(name.ends_with(".json"));
        assert!(
            !name.contains(':'),
            "colons are not portable in filenames: {name}"
        );
    }
}
