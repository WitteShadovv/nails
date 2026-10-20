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

use super::envelope::{Envelope, EnvelopePrint};

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

impl ProfileSummary {
    /// The line `check` prints for it.
    pub fn line(&self) -> &str {
        self.detail
            .as_deref()
            .unwrap_or("no hidden NixOS build target")
    }
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
    for line in human_lines(report, style) {
        println!("{line}");
    }
}

/// The lines of the readiness report for people.
fn human_lines(report: &CheckReport, style: Style) -> Vec<String> {
    let mut out = Vec::new();
    if style.ascii {
        out.push("=======================================".to_string());
        out.push("  NAILS Readiness Check".to_string());
        out.push("=======================================".to_string());
    } else {
        out.push("╭─────────────────────────────────────╮".to_string());
        out.push("│  NAILS Readiness Check              │".to_string());
        out.push("╰─────────────────────────────────────╯".to_string());
    }
    out.push(String::new());

    out.push("Pre-flight checks:".to_string());
    for row in &report.checks {
        out.push(format!(
            "  {} {}: {}",
            style.mark(row.mark()),
            row.name,
            row.message
        ));
        if let Some(remediation) = &row.remediation {
            let mut lines = remediation.lines();
            if let Some(first) = lines.next() {
                out.push(format!("      {}", style.marked(Mark::Arrow, first)));
            }
            for line in lines {
                out.push(format!("        {line}"));
            }
        }
    }
    out.push(String::new());

    out.push("Effective configuration:".to_string());
    out.push(match &report.config.config_file {
        Some(path) => format!("  config file:        {path}"),
        None => "  config file:        (built-in defaults)".to_string(),
    });
    out.push(format!(
        "  hidden volume root: {}",
        report.config.hidden_volume_root
    ));
    out.push(format!(
        "  state file:         {}",
        report.config.state_file
    ));
    out.push(format!("  log directory:      {}", report.config.log_path));
    out.push(format!(
        "  persona mode:       {}",
        report.config.persona_mode
    ));
    out.push(format!(
        "  minimum free space: {} MB",
        report.config.minimum_space_mb
    ));
    out.push(String::new());

    out.push("Decoy filesystems in the hidden root:".to_string());
    if report.filesystems.is_empty() {
        out.push(format!(
            "  {} only the root (overlaid)",
            style.mark(Mark::Bullet)
        ));
    } else {
        for line in &report.filesystems {
            out.push(format!("  {} {line}", style.mark(Mark::Bullet)));
        }
    }
    out.push(String::new());

    out.push("Session:".to_string());
    out.push(format!(
        "  {} activation soft-reboots into the hidden root: every program closes and you are logged out",
        style.mark(Mark::Info)
    ));
    out.push(String::new());

    out.push("NixOS profile:".to_string());
    out.push(format!(
        "  {} {}",
        style.mark(Mark::Info),
        report.profile.line()
    ));
    out.push(String::new());

    out.push("Inherited decoy state:".to_string());
    for line in inherited::inherited_lines(&report.inherited, report.config.persona_mode, style) {
        out.push(format!("  {line}"));
    }
    out.push(String::new());

    out.push(summary_line(report, style));
    out
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
mod tests;
