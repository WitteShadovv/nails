// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rendering for the read-only `check` command.
//!
//! One typed [`CheckReport`] carries the whole readiness picture: the pre-flight
//! check results plus the effective configuration, the overlay targets, how the
//! decoy filesystems would be handled and which NixOS profile would be built. The report
//! renders either as a human summary or as one JSON [`Envelope`](super::envelope::Envelope),
//! so the two outputs can never describe different things.

use nails_core::app::readiness::{CheckRow, ReadinessReport};
use nails_core::output::{Mark, Style};

use super::envelope::{Envelope, EnvelopePrint};

mod inherited;
pub use inherited::inherited_lines;

/// The command name used in the JSON envelope and in error reports.
pub const COMMAND: &str = "check";

/// The output mark for a check row's status.
fn row_mark(row: &CheckRow) -> Mark {
    match row.status {
        "pass" => Mark::Pass,
        "warn" => Mark::Warn,
        "skipped" => Mark::Neutral,
        _ => Mark::Fail,
    }
}

/// Print the readiness report as one JSON envelope on stdout. `ok` is whether
/// the host is ready: a refused check (exit 4) reads as not ok.
pub fn print_check_json(report: &ReadinessReport) {
    Envelope::outcome(COMMAND, report.ready, report).print();
}

/// Print the readiness report for people.
pub fn print_check_human(report: &ReadinessReport, style: Style) {
    for line in human_lines(report, style) {
        println!("{line}");
    }
}

/// The lines of the readiness report for people.
fn human_lines(report: &ReadinessReport, style: Style) -> Vec<String> {
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
            style.mark(row_mark(row)),
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

    // The NixOS-profile section is shown on NixOS, and on any host where the
    // operator configured a real NixOS build target (an explicit flake or a
    // legacy configuration). A plain Debian, Ubuntu, Fedora or Arch host builds
    // no NixOS profile, so the section is hidden there rather than printing a
    // "no hidden NixOS build target" line that does not apply.
    if report.nixos_host || matches!(report.profile.mode, "flake" | "legacy") {
        out.push("NixOS profile:".to_string());
        out.push(format!(
            "  {} {}",
            style.mark(Mark::Info),
            report.profile.line()
        ));
        out.push(String::new());
    }

    out.push("Inherited decoy state:".to_string());
    for line in inherited::inherited_lines(&report.inherited, report.config.persona_mode, style) {
        out.push(format!("  {line}"));
    }
    out.push(String::new());

    out.push(summary_line(report, style));
    out
}

/// The verdict that ends the report, with the tally (`1 warning`, `2 warnings`).
fn summary_line(report: &ReadinessReport, style: Style) -> String {
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
