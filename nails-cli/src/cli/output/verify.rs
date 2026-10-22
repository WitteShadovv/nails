// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the verify command

use nails_core::output::{Mark, Style, Tone};
use nails_core::{
    ExaminerReport, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus,
};
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, EnvelopePrint};
use crate::cli::output::exit::ExitStatus;

/// The `data` payload for `verify --json`.
///
/// Separate from `nails_core::VerifyResult` so the wire enums render in
/// `snake_case` (`secure`, `warn`, `deep`) rather than the library's internal
/// `PascalCase`.
#[derive(Debug, Serialize)]
pub struct VerifyData {
    status: VerifyStatusJson,
    findings: Vec<FindingJson>,
    scan_depth: ScanDepthJson,
    config_aware: bool,
    config_paths_checked: usize,
    checks_run: usize,
    areas_not_checked: Vec<String>,
    state_file_status: StateFileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    examiner: Option<ExaminerJson>,
}

/// The examiner audit on the wire: setup traces grouped by conclusion.
#[derive(Debug, Serialize)]
struct ExaminerJson {
    groups: Vec<ExaminerGroupJson>,
    not_checked: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExaminerGroupJson {
    conclusion: String,
    findings: Vec<ExaminerFindingJson>,
}

#[derive(Debug, Serialize)]
struct ExaminerFindingJson {
    catalog_id: String,
    severity: SeverityJson,
    location: String,
    evidence: String,
}

fn severity_json(severity: Severity) -> SeverityJson {
    match severity {
        Severity::Info => SeverityJson::Info,
        Severity::Warn => SeverityJson::Warn,
        Severity::Critical => SeverityJson::Critical,
    }
}

impl ExaminerJson {
    fn from_report(report: &ExaminerReport) -> Self {
        Self {
            groups: report
                .groups
                .iter()
                .map(|group| ExaminerGroupJson {
                    conclusion: group.conclusion.to_string(),
                    findings: group
                        .findings
                        .iter()
                        .map(|finding| ExaminerFindingJson {
                            catalog_id: finding.catalog_id.to_string(),
                            severity: severity_json(finding.severity),
                            location: finding.location.clone(),
                            evidence: finding.evidence.clone(),
                        })
                        .collect(),
                })
                .collect(),
            not_checked: report.not_checked.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerifyStatusJson {
    Secure,
    Warning,
    Critical,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScanDepthJson {
    Standard,
    Deep,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SeverityJson {
    Info,
    Warn,
    Critical,
}

#[derive(Debug, Serialize)]
struct FindingJson {
    severity: SeverityJson,
    category: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix_guidance: Option<String>,
}

impl VerifyData {
    /// Build the wire payload from a verification result.
    pub fn from_result(result: &VerifyResult) -> Self {
        Self {
            status: match result.status {
                VerifyStatus::Secure => VerifyStatusJson::Secure,
                VerifyStatus::Warning => VerifyStatusJson::Warning,
                VerifyStatus::Critical => VerifyStatusJson::Critical,
            },
            findings: result
                .findings
                .iter()
                .map(|finding| FindingJson {
                    severity: severity_json(finding.severity),
                    category: finding.category.clone(),
                    message: finding.message.clone(),
                    fix_guidance: finding.fix_guidance.clone(),
                })
                .collect(),
            scan_depth: match result.scan_depth {
                ScanDepth::Standard => ScanDepthJson::Standard,
                ScanDepth::Deep => ScanDepthJson::Deep,
            },
            config_aware: result.config_aware,
            config_paths_checked: result.config_paths_checked,
            checks_run: result.checks_run,
            areas_not_checked: result.areas_not_checked.clone(),
            state_file_status: result.state_file_status.clone(),
            examiner: result.examiner.as_ref().map(ExaminerJson::from_report),
        }
    }
}

/// Print the verification result as one envelope on stdout. `ok` follows the
/// scan's own exit code: a secure scan is ok, a warning (10) or a critical
/// finding (11) is not.
pub fn print_verify_json(result: &VerifyResult) {
    let ok = verify_exit_status(result.status).is_success();
    Envelope::outcome("verify", ok, VerifyData::from_result(result)).print();
}

/// The exit status for a verification outcome: a warning and a critical finding
/// are distinguishable from each other and from an ordinary failure.
pub fn verify_exit_status(status: VerifyStatus) -> ExitStatus {
    match status {
        VerifyStatus::Secure => ExitStatus::Ok,
        VerifyStatus::Warning => ExitStatus::VerifyWarning,
        VerifyStatus::Critical => ExitStatus::VerifyCritical,
    }
}

/// The headline of the human report: the verdict and, on a warning or a
/// critical result, how many findings it found, in the right number.
fn header_line(result: &VerifyResult, style: Style) -> String {
    use nails_core::VerifyStatus;

    let depth = match result.scan_depth {
        nails_core::ScanDepth::Standard => "standard",
        nails_core::ScanDepth::Deep => "deep",
    };
    match result.status {
        VerifyStatus::Secure => style.paint_bold(
            format_args!(
                "{} No known artifacts found ({} checks, {depth} scan). This is not proof of absence.",
                style.glyph(Mark::Pass),
                result.checks_run,
            ),
            Tone::Green,
        ),
        VerifyStatus::Warning => style.paint_bold(
            format_args!(
                "{} WARNING: Found {}",
                style.glyph(Mark::Warn),
                super::count_noun(
                    attention_count(result),
                    "potential issue",
                    "potential issues"
                )
            ),
            Tone::Yellow,
        ),
        VerifyStatus::Critical => style.paint_bold(
            format_args!(
                "{} CRITICAL: Found {} requiring attention",
                style.glyph(Mark::Fail),
                super::count_noun(attention_count(result), "artifact", "artifacts")
            ),
            Tone::Red,
        ),
    }
}

/// Print verification results in human-readable format
///
/// Marks come from the shared table and colour/ASCII follow `style` (the
/// stdout style from the resolved output settings).
pub fn print_verify_result(result: &VerifyResult, style: Style) {
    use nails_core::Severity;

    println!("{}", header_line(result, style));

    if let nails_core::ScanDepth::Deep = result.scan_depth {
        println!(
            "{}",
            style.paint("Deep scan enabled - comprehensive validation", Tone::Dim)
        );
    }

    if let Some(summary) = config_scan_summary(result) {
        println!("{}", summary);
    }

    if let Some(summary) = state_file_status_summary(result) {
        println!("{}", summary);
    }

    if !result.findings.is_empty() {
        println!();
        for finding in &result.findings {
            let severity = match finding.severity {
                Severity::Info => style.paint("[INFO]", Tone::Blue),
                Severity::Warn => style.paint("[WARN]", Tone::Yellow),
                Severity::Critical => style.paint("[CRIT]", Tone::Red),
            };

            println!("{} [{}] {}", severity, finding.category, finding.message);

            if let Some(ref guidance) = finding.fix_guidance {
                println!(
                    "  {} {}",
                    style.glyph(Mark::Arrow),
                    style.paint(guidance, Tone::Dim)
                );
            }
        }
    }

    if let Some(report) = &result.examiner {
        print_examiner_report(report, style);
    }

    if !result.areas_not_checked.is_empty() {
        println!();
        println!("{}", style.paint("Not checked by this run:", Tone::Dim));
        for area in &result.areas_not_checked {
            println!(
                "  {} {}",
                style.glyph(Mark::Arrow),
                style.paint(area, Tone::Dim)
            );
        }
    }
}

/// The findings the header counts: warnings and critical ones. Notes (INFO)
/// are listed below it but are not issues, so a run with three notes and one
/// warning reports one.
fn attention_count(result: &VerifyResult) -> usize {
    result
        .findings
        .iter()
        .filter(|finding| finding.severity != Severity::Info)
        .count()
}

/// Print the examiner audit: one heading per conclusion, then its traces.
fn print_examiner_report(report: &ExaminerReport, style: Style) {
    println!();
    if report.groups.is_empty() {
        println!(
            "{}",
            style.marked(
                Mark::Pass,
                "Examiner's view: no setup traces found (report only; nothing was changed)"
            )
        );
        return;
    }
    println!(
        "{}",
        style.paint_bold(
            format_args!(
                "Examiner's view: {} (report only; nothing was changed)",
                super::count_noun(report.finding_count(), "setup trace", "setup traces")
            ),
            Tone::Yellow,
        )
    );
    for group in &report.groups {
        println!("  {} {}", style.glyph(Mark::Warn), group.conclusion);
        for finding in &group.findings {
            println!(
                "    {} {}: {} [{}]",
                style.glyph(Mark::Arrow),
                finding.location,
                finding.evidence,
                finding.catalog_id
            );
        }
    }
}

pub(crate) fn config_scan_summary(result: &VerifyResult) -> Option<String> {
    result.config_aware.then(|| {
        format!(
            "Config-aware scan: checked {} paths from config",
            result.config_paths_checked
        )
    })
}

pub(crate) fn state_file_status_summary(result: &VerifyResult) -> Option<String> {
    match &result.state_file_status {
        StateFileStatus::NotChecked => None,
        StateFileStatus::Missing { path } => {
            Some(format!("State file status: missing at {}", path.display()))
        }
        StateFileStatus::Present { path, state } => Some(format!(
            "State file status: present at {} ({})",
            path.display(),
            state
        )),
        StateFileStatus::Error { path, message } => Some(format!(
            "State file status: error at {} ({})",
            path.display(),
            message
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
    use std::path::PathBuf;

    #[test]
    fn the_headline_puts_a_single_finding_in_the_singular() {
        let plain = Style::default();
        let one = |status, severity| {
            VerifyResult::new(
                status,
                vec![Finding::new(severity, "file", "x")],
                ScanDepth::Standard,
            )
        };

        assert_eq!(
            header_line(&one(VerifyStatus::Warning, Severity::Warn), plain),
            "\u{26a0} WARNING: Found 1 potential issue"
        );
        assert_eq!(
            header_line(&one(VerifyStatus::Critical, Severity::Critical), plain),
            "\u{2717} CRITICAL: Found 1 artifact requiring attention"
        );
        let two = VerifyResult::new(
            VerifyStatus::Warning,
            vec![
                Finding::new(Severity::Warn, "file", "x"),
                Finding::new(Severity::Warn, "file", "y"),
            ],
            ScanDepth::Standard,
        );
        assert_eq!(
            header_line(&two, plain),
            "\u{26a0} WARNING: Found 2 potential issues"
        );
    }

    #[test]
    fn test_print_verify_result_secure_status() {
        // Test that secure status prints correctly
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        // This will print to stdout - we're testing it doesn't panic and covers the code path
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_warning_status() {
        // Test warning status with findings
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete the file"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_critical_status() {
        // Test critical status with findings
        let findings = vec![
            Finding::new(Severity::Critical, "mount", "Overlay mount found"),
            Finding::new(Severity::Warn, "file", "Artifact file found"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_deep_scan() {
        // Test deep scan depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Deep);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_all_severity_levels() {
        // Test all severity levels in findings
        let findings = vec![
            Finding::new(Severity::Info, "memory", "RAM keeps the session's data"),
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete artifact"),
            Finding::new(Severity::Critical, "mount", "Overlay mounted")
                .with_fix_guidance("Run nails deactivate"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_finding_without_fix_guidance() {
        // Test finding without fix guidance (None path)
        let findings = vec![Finding::new(
            Severity::Info,
            "memory",
            "RAM keeps the session's data",
        )];
        let result = VerifyResult::new(VerifyStatus::Secure, findings, ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_empty_findings() {
        // Test with empty findings array
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_multiple_findings_same_category() {
        // Test multiple findings in same category
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact 1").with_fix_guidance("Delete file 1"),
            Finding::new(Severity::Warn, "file", "Artifact 2").with_fix_guidance("Delete file 2"),
            Finding::new(Severity::Warn, "file", "Artifact 3"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_standard_scan_no_depth_message() {
        // Test that standard scan doesn't print depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_warning_with_single_finding() {
        // Edge case: warning status with exactly 1 finding
        let findings = vec![Finding::new(Severity::Warn, "test", "Single warning")];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn test_print_verify_result_critical_with_many_findings() {
        // Edge case: critical status with many findings
        let findings: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    Severity::Critical,
                    format!("category{}", i),
                    format!("Finding {}", i),
                )
                .with_fix_guidance(format!("Fix {}", i))
            })
            .collect();
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result, Style::default());
    }

    #[test]
    fn the_header_counts_warnings_and_critical_findings_but_not_notes() {
        let findings = vec![
            Finding::new(
                Severity::Info,
                "session",
                "verify runs inside the hidden session",
            ),
            Finding::new(Severity::Info, "memory", "RAM keeps the session's data"),
            Finding::new(Severity::Warn, "file", "NAILS-related file found"),
            Finding::new(Severity::Critical, "memory", "Swap can leak memory"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        assert_eq!(attention_count(&result), 2);
        assert_eq!(
            header_line(&result, Style::default()),
            "\u{2717} CRITICAL: Found 2 artifacts requiring attention"
        );

        let notes_only = VerifyResult::new(
            VerifyStatus::Secure,
            vec![Finding::new(
                Severity::Info,
                "memory",
                "RAM keeps the session's data",
            )],
            ScanDepth::Standard,
        );
        assert_eq!(attention_count(&notes_only), 0);
    }

    #[test]
    fn test_config_scan_summary_uses_requested_phrase() {
        let result = VerifyResult::new_config_aware(
            VerifyStatus::Secure,
            vec![],
            ScanDepth::Standard,
            4,
            StateFileStatus::Missing {
                path: PathBuf::from("/mnt/hidden/state.json"),
            },
        );

        assert_eq!(
            config_scan_summary(&result).as_deref(),
            Some("Config-aware scan: checked 4 paths from config")
        );
    }

    #[test]
    fn test_state_file_status_summary_for_missing_file() {
        let result = VerifyResult::new_config_aware(
            VerifyStatus::Secure,
            vec![],
            ScanDepth::Standard,
            4,
            StateFileStatus::Missing {
                path: PathBuf::from("/mnt/hidden/state.json"),
            },
        );

        assert_eq!(
            state_file_status_summary(&result).as_deref(),
            Some("State file status: missing at /mnt/hidden/state.json")
        );
    }

    #[test]
    fn test_state_file_status_summary_for_present_file() {
        let result = VerifyResult::new_config_aware(
            VerifyStatus::Warning,
            vec![],
            ScanDepth::Standard,
            4,
            StateFileStatus::Present {
                path: PathBuf::from("/mnt/hidden/state.json"),
                state: "INACTIVE".to_string(),
            },
        );

        assert_eq!(
            state_file_status_summary(&result).as_deref(),
            Some("State file status: present at /mnt/hidden/state.json (INACTIVE)")
        );
    }
}
