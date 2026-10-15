// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rendering for the read-only `check`/`doctor` command.
//!
//! One typed [`CheckReport`] carries the whole readiness picture: the pre-flight
//! check results plus the effective configuration, the overlay targets, how the
//! decoy filesystems would be handled and which NixOS profile would be built. The report
//! renders either as a human summary or as one JSON [`Envelope`](super::envelope::Envelope),
//! so the two outputs can never describe different things.

use serde::Serialize;

use nails_core::CheckResult;
use nails_core::output::{Mark, Style};

use super::envelope::Envelope;

mod inherited;
pub use inherited::{InheritedEntry, InheritedSummary};

/// The command name used in the JSON envelope and in error reports.
pub const COMMAND: &str = "check";

/// One pre-flight check result as it appears in the report.
#[derive(Debug, Serialize)]
pub struct CheckRow {
    /// The check's stable kebab-case identifier.
    pub name: String,
    /// `"pass"`, `"warn"`, `"fail"` or `"skipped"`.
    pub status: &'static str,
    /// The check's human-readable message.
    pub message: String,
    /// What to do about a failure, when the check says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl CheckRow {
    /// Build a row from a registry result.
    pub fn from_result(name: String, result: &CheckResult) -> Self {
        let (status, message, remediation) = match result {
            CheckResult::Pass(msg) => ("pass", msg.clone(), None),
            CheckResult::Warn(msg) => ("warn", msg.clone(), None),
            CheckResult::Fail {
                message,
                remediation,
            } => ("fail", message.clone(), remediation.clone()),
            CheckResult::Skipped(reason) => ("skipped", reason.clone(), None),
        };
        Self {
            name,
            status,
            message,
            remediation,
        }
    }

    fn mark(&self) -> Mark {
        match self.status {
            "pass" => Mark::Pass,
            "warn" => Mark::Warn,
            "skipped" => Mark::Neutral,
            _ => Mark::Fail,
        }
    }
}

/// Tally of the check outcomes.
#[derive(Debug, Serialize)]
pub struct CheckSummary {
    /// Checks that passed.
    pub passed: usize,
    /// Checks that warned.
    pub warnings: usize,
    /// Checks that failed.
    pub failed: usize,
    /// Checks skipped because a prerequisite (the hidden volume) was absent.
    #[serde(default)]
    pub skipped: usize,
}

/// The effective configuration the checks ran against.
#[derive(Debug, Serialize)]
pub struct ConfigSummary {
    /// The configuration file consulted, if any.
    pub config_file: Option<String>,
    /// Hidden volume root.
    pub hidden_volume_root: String,
    /// State file path.
    pub state_file: String,
    /// Log directory.
    pub log_path: String,
    /// Persona mode: `"shared-home"` or `"fresh-home"`.
    pub persona_mode: &'static str,
    /// Minimum free space required to activate, in MB.
    pub minimum_space_mb: u64,
}

/// Which NixOS profile activation would build and switch to.
#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    /// `"overlay-only"`, `"flake"`, `"legacy"`, `"refused"` (the decoy's own
    /// flake, which activation does not build) or `"none"`.
    pub mode: &'static str,
    /// A human description of the selected target, if any.
    pub detail: Option<String>,
}

/// The full readiness report.
#[derive(Debug, Serialize)]
pub struct CheckReport {
    /// True when no check failed.
    pub ready: bool,
    /// The pre-flight check results, in execution order.
    pub checks: Vec<CheckRow>,
    /// Tally of the outcomes.
    pub summary: CheckSummary,
    /// The effective configuration.
    pub config: ConfigSummary,
    /// What happens to each decoy filesystem in the hidden root.
    pub filesystems: Vec<String>,
    /// Which NixOS profile would be built.
    pub profile: ProfileSummary,
    /// The decoy persona state the hidden session would inherit.
    pub inherited: InheritedSummary,
    /// Why the attach gate refused the hidden root, with its code
    /// (`not_separate_volume`, `root_covered` or `storage_unjudged`); the
    /// hidden-volume row reports the same failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<super::envelope::ErrorBody>,
}

impl CheckReport {
    /// Build the summary tally and `ready` flag from the rows.
    pub fn finalize(
        checks: Vec<CheckRow>,
        config: ConfigSummary,
        filesystems: Vec<String>,
        profile: ProfileSummary,
        inherited: InheritedSummary,
    ) -> Self {
        let mut summary = CheckSummary {
            passed: 0,
            warnings: 0,
            failed: 0,
            skipped: 0,
        };
        for row in &checks {
            match row.status {
                "pass" => summary.passed += 1,
                "warn" => summary.warnings += 1,
                "skipped" => summary.skipped += 1,
                _ => summary.failed += 1,
            }
        }
        Self {
            refusal: None,
            ready: summary.failed == 0,
            checks,
            summary,
            config,
            filesystems,
            profile,
            inherited,
        }
    }
}

/// Print the readiness report as one JSON envelope on stdout.
pub fn print_check_json(report: &CheckReport) {
    Envelope::success(COMMAND, report).print();
}

/// Print the readiness report for people.
pub fn print_check_human(report: &CheckReport, style: Style) {
    if style.ascii {
        println!("=======================================");
        println!("  NAILS Readiness Check");
        println!("=======================================");
    } else {
        println!("╭─────────────────────────────────────╮");
        println!("│  NAILS Readiness Check              │");
        println!("╰─────────────────────────────────────╯");
    }
    println!();

    println!("Pre-flight checks:");
    for row in &report.checks {
        println!("  {} {}: {}", style.mark(row.mark()), row.name, row.message);
        if let Some(remediation) = &row.remediation {
            let mut lines = remediation.lines();
            if let Some(first) = lines.next() {
                println!("      {}", style.marked(Mark::Arrow, first));
            }
            for line in lines {
                println!("        {line}");
            }
        }
    }
    println!();

    println!("Effective configuration:");
    if let Some(path) = &report.config.config_file {
        println!("  config file:        {path}");
    } else {
        println!("  config file:        (built-in defaults)");
    }
    println!("  hidden volume root: {}", report.config.hidden_volume_root);
    println!("  state file:         {}", report.config.state_file);
    println!("  log directory:      {}", report.config.log_path);
    println!("  persona mode:       {}", report.config.persona_mode);
    println!(
        "  minimum free space: {} MB",
        report.config.minimum_space_mb
    );
    println!();

    println!("Decoy filesystems in the hidden root:");
    if report.filesystems.is_empty() {
        println!("  {} only the root (overlaid)", style.mark(Mark::Bullet));
    } else {
        for line in &report.filesystems {
            println!("  {} {line}", style.mark(Mark::Bullet));
        }
    }
    println!();

    println!("Session:");
    println!(
        "  {} activation soft-reboots into the hidden root: every program closes and you are logged out",
        style.mark(Mark::Info)
    );
    println!();

    println!("NixOS profile:");
    match &report.profile.detail {
        Some(detail) => println!("  {} {detail}", style.mark(Mark::Info)),
        None => println!("  {} no profile switch", style.mark(Mark::Info)),
    }
    println!();

    println!("Inherited decoy state:");
    for line in inherited::inherited_lines(&report.inherited, report.config.persona_mode, style) {
        println!("  {line}");
    }
    println!();

    println!("{}", summary_line(report, style));
}

/// The verdict that ends the report, with the tally (`1 warning`, `2 warnings`).
fn summary_line(report: &CheckReport, style: Style) -> String {
    let (mark, verdict) = if report.ready {
        (Mark::Pass, "Ready to activate")
    } else {
        (Mark::Fail, "Not ready: resolve the failing checks above")
    };
    let skipped_suffix = if report.summary.skipped > 0 {
        format!(", {} skipped", report.summary.skipped)
    } else {
        String::new()
    };
    format!(
        "{}  ({} passed, {}, {} failed{skipped_suffix})",
        style.marked(mark, verdict),
        report.summary.passed,
        super::count_noun(report.summary.warnings, "warning", "warnings"),
        report.summary.failed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<CheckRow> {
        vec![
            CheckRow::from_result("a".into(), &CheckResult::Pass("ok".into())),
            CheckRow::from_result("b".into(), &CheckResult::Warn("careful".into())),
        ]
    }

    fn report(rows: Vec<CheckRow>) -> CheckReport {
        CheckReport::finalize(
            rows,
            ConfigSummary {
                config_file: None,
                hidden_volume_root: "/mnt/vault".into(),
                state_file: "/mnt/vault/state.json".into(),
                log_path: "/mnt/vault/logs".into(),
                persona_mode: "shared-home",
                minimum_space_mb: 100,
            },
            vec!["/home: overlaid".into()],
            ProfileSummary {
                mode: "none",
                detail: None,
            },
            InheritedSummary {
                inspected: true,
                entries: vec![InheritedEntry {
                    name: "dropbox".into(),
                    source: "user-autostart",
                    remote_linked: true,
                    maskable: true,
                    origin: "added",
                    status: "review",
                }],
                remote_linked: vec!["dropbox".into()],
                unmatched_masks: Vec::new(),
            },
        )
    }

    #[test]
    fn finalize_counts_outcomes_and_sets_ready() {
        let report = report(rows());
        assert!(report.ready);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.summary.failed, 0);
    }

    #[test]
    fn the_summary_line_puts_a_single_warning_in_the_singular() {
        let style = Style {
            ascii: true,
            ..Style::default()
        };
        assert_eq!(
            summary_line(&report(rows()), style),
            "[PASS] Ready to activate  (1 passed, 1 warning, 0 failed)"
        );

        let mut rows = rows();
        rows.push(CheckRow::from_result(
            "c".into(),
            &CheckResult::Warn("again".into()),
        ));
        rows.push(CheckRow::from_result(
            "d".into(),
            &CheckResult::fail("boom".to_string()),
        ));
        rows.push(CheckRow::from_result(
            "e".into(),
            &CheckResult::Skipped("no volume".into()),
        ));
        assert_eq!(
            summary_line(&report(rows), style),
            "[FAIL] Not ready: resolve the failing checks above  \
             (1 passed, 2 warnings, 1 failed, 1 skipped)"
        );
    }

    #[test]
    fn a_failing_check_marks_the_report_not_ready() {
        let mut rows = rows();
        rows.push(CheckRow::from_result(
            "c".into(),
            &CheckResult::fail("boom".to_string()),
        ));
        let report = report(rows);
        assert!(!report.ready);
        assert_eq!(report.summary.failed, 1);
    }

    #[test]
    fn json_envelope_carries_checks_and_summary() {
        let report = report(rows());
        let line = Envelope::success(COMMAND, &report).to_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["command"], "check");
        assert_eq!(value["data"]["ready"], true);
        assert_eq!(value["data"]["checks"][0]["name"], "a");
        assert_eq!(value["data"]["checks"][0]["status"], "pass");
        assert_eq!(value["data"]["summary"]["warnings"], 1);
    }

    #[test]
    fn json_envelope_carries_inherited_inventory() {
        let report = report(rows());
        let line = Envelope::success(COMMAND, &report).to_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["data"]["inherited"]["inspected"], true);
        assert_eq!(value["data"]["inherited"]["entries"][0]["name"], "dropbox");
        assert_eq!(
            value["data"]["inherited"]["entries"][0]["source"],
            "user-autostart"
        );
        assert_eq!(
            value["data"]["inherited"]["entries"][0]["remote_linked"],
            true
        );
        assert_eq!(value["data"]["inherited"]["remote_linked"][0], "dropbox");
        assert_eq!(value["data"]["inherited"]["entries"][0]["origin"], "added");
        assert_eq!(value["data"]["inherited"]["entries"][0]["status"], "review");
    }

    #[test]
    fn not_inspected_summary_is_empty() {
        let summary = InheritedSummary::not_inspected();
        assert!(!summary.inspected);
        assert!(summary.entries.is_empty());
        assert!(summary.remote_linked.is_empty());
    }
}
