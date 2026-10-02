//! Rendering for the read-only `check`/`doctor` command.
//!
//! One typed [`CheckReport`] carries the whole readiness picture: the pre-flight
//! check results plus the effective configuration, the overlay targets, how the
//! session would be handled and which NixOS profile would be built. The report
//! renders either as a human summary or as one JSON [`Envelope`](super::envelope::Envelope),
//! so the two outputs can never describe different things.

use serde::Serialize;

use nails_core::CheckResult;
use nails_core::output::{Mark, Style};

use super::envelope::Envelope;

/// The command name used in the JSON envelope and in error reports.
pub const COMMAND: &str = "check";

/// One pre-flight check result as it appears in the report.
#[derive(Debug, Serialize)]
pub struct CheckRow {
    /// The check's stable kebab-case identifier.
    pub name: String,
    /// `"pass"`, `"warn"` or `"fail"`.
    pub status: &'static str,
    /// The check's human-readable message.
    pub message: String,
}

impl CheckRow {
    /// Build a row from a registry result.
    pub fn from_result(name: String, result: &CheckResult) -> Self {
        let (status, message) = match result {
            CheckResult::Pass(msg) => ("pass", msg.clone()),
            CheckResult::Warn(msg) => ("warn", msg.clone()),
            CheckResult::Fail(msg) => ("fail", msg.clone()),
        };
        Self {
            name,
            status,
            message,
        }
    }

    fn mark(&self) -> Mark {
        match self.status {
            "pass" => Mark::Pass,
            "warn" => Mark::Warn,
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
    /// `"auto"` or `"explicit"`.
    pub overlay_mode: &'static str,
    /// Minimum free space required to activate, in MB.
    pub minimum_space_mb: u64,
}

/// How the graphical session would be handled at activation.
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    /// The detected session kind, or `"unknown"` when detection failed.
    pub kind: &'static str,
    /// The display manager that would be restarted, if any.
    pub display_manager: Option<String>,
    /// Whether activation would end the graphical session.
    pub would_terminate: bool,
}

/// Which NixOS profile activation would build and switch to.
#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    /// `"overlay-only"`, `"flake"`, `"legacy"` or `"none"`.
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
    /// The overlay targets that would be mounted.
    pub overlay_targets: Vec<String>,
    /// How the session would be handled.
    pub session: SessionSummary,
    /// Which NixOS profile would be built.
    pub profile: ProfileSummary,
}

impl CheckReport {
    /// Build the summary tally and `ready` flag from the rows.
    pub fn finalize(
        checks: Vec<CheckRow>,
        config: ConfigSummary,
        overlay_targets: Vec<String>,
        session: SessionSummary,
        profile: ProfileSummary,
    ) -> Self {
        let mut summary = CheckSummary {
            passed: 0,
            warnings: 0,
            failed: 0,
        };
        for row in &checks {
            match row.status {
                "pass" => summary.passed += 1,
                "warn" => summary.warnings += 1,
                _ => summary.failed += 1,
            }
        }
        Self {
            ready: summary.failed == 0,
            checks,
            summary,
            config,
            overlay_targets,
            session,
            profile,
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
    println!("  overlay mode:       {}", report.config.overlay_mode);
    println!(
        "  minimum free space: {} MB",
        report.config.minimum_space_mb
    );
    println!();

    println!("Overlay targets:");
    if report.overlay_targets.is_empty() {
        println!("  {} none resolved", style.mark(Mark::Warn));
    } else {
        for target in &report.overlay_targets {
            println!("  {} {target}", style.mark(Mark::Bullet));
        }
    }
    println!();

    println!("Session handling:");
    println!("  detected session:   {}", report.session.kind);
    if let Some(dm) = &report.session.display_manager {
        println!("  display manager:    {dm}");
    }
    println!(
        "  activation would:   {}",
        if report.session.would_terminate {
            "end the graphical session"
        } else {
            "keep the current session"
        }
    );
    println!();

    println!("NixOS profile:");
    match &report.profile.detail {
        Some(detail) => println!("  {} {detail}", style.mark(Mark::Info)),
        None => println!("  {} no profile switch", style.mark(Mark::Info)),
    }
    println!();

    let (mark, verdict) = if report.ready {
        (Mark::Pass, "Ready to activate".to_string())
    } else {
        (
            Mark::Fail,
            "Not ready: resolve the failing checks above".to_string(),
        )
    };
    println!(
        "{}  ({} passed, {} warnings, {} failed)",
        style.marked(mark, verdict),
        report.summary.passed,
        report.summary.warnings,
        report.summary.failed
    );
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
                overlay_mode: "auto",
                minimum_space_mb: 100,
            },
            vec!["/home".into()],
            SessionSummary {
                kind: "tty",
                display_manager: None,
                would_terminate: false,
            },
            ProfileSummary {
                mode: "none",
                detail: None,
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
    fn a_failing_check_marks_the_report_not_ready() {
        let mut rows = rows();
        rows.push(CheckRow::from_result(
            "c".into(),
            &CheckResult::Fail("boom".into()),
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
}
