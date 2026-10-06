// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use nails_core::SystemState;
use nails_core::output::{Mark, Style};

use super::{config_file_label, read_recent_logs};
use crate::cli::output::dto::system_state_label;

/// Format a byte count with binary units (KiB/MiB/GiB), one decimal place above
/// bytes. Used for the hidden-volume usage line.
pub(super) fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// The hidden-volume usage line, or `None` when the figures are unavailable
/// (a failed `statvfs`), so the renderer simply omits it rather than guessing.
pub(super) fn hidden_volume_line(report: &nails_core::status::StatusReport) -> Option<String> {
    match (
        report.hidden_root_total,
        report.hidden_root_used,
        report.hidden_root_available,
    ) {
        (Some(total), Some(used), Some(available)) => Some(format!(
            "Hidden volume:      {} used of {} ({} free)",
            format_bytes(used),
            format_bytes(total),
            format_bytes(available),
        )),
        _ => None,
    }
}

/// Human-readable state label, reporting "Unknown" when the state file could not
/// be read or trusted rather than claiming the safe default is the real state.
fn state_label(report: &nails_core::status::StatusReport) -> &'static str {
    if report.load_outcome.is_unknown() {
        "Unknown"
    } else {
        system_state_label(&report.state)
    }
}

/// The security-posture lines: the kernel-truth posture and its remediation,
/// followed — when writers were left on the decoy at activation — by
/// `NOT OPTIMAL: N writers still on the decoy` and one line per writer, so the
/// operator sees exactly what is leaking even while the posture stays ACTIVE.
pub(super) fn posture_lines(
    report: &nails_core::status::StatusReport,
    style: Style,
) -> Vec<String> {
    let mut lines = vec![format!(
        "Security Posture:   {}",
        report
            .posture
            .render_with_mark(style, report.posture_mark())
    )];
    if let Some(remediation) = report.posture.remediation() {
        lines.push(format!("  {}", style.marked(Mark::Arrow, remediation)));
    }

    // A persistent decoy keeps a durable log of the hidden session on the decoy
    // disk, so an otherwise-clean ACTIVE posture is not fully secure. Surface it
    // with a warning line (the posture mark is downgraded above) rather than
    // reading as secure. Only relevant while the hidden environment is active:
    // on a decoy or already-dangerous posture there is no clean pass to qualify.
    if report.decoy_persistent && report.posture == nails_core::status::Posture::Active {
        lines.push(format!(
            "  {}",
            style.marked(
                Mark::Warn,
                "PERSISTENT DECOY: the decoy keeps a durable log/audit store; \
                 hidden-session metadata lands on the decoy disk",
            )
        ));
        lines.push(format!(
            "  {}",
            style.marked(
                Mark::Arrow,
                "Set journald Storage=volatile and stop rsyslog/syslog-ng/auditd, \
                 or re-run with --accept-persistent-decoy to accept the risk",
            )
        ));
    }

    let writers = report.decoy_writers();
    if !writers.is_empty() {
        lines.push(format!(
            "  {}",
            style.marked(
                Mark::Warn,
                format_args!(
                    "NOT OPTIMAL: {}",
                    nails_core::decoy_writers_headline(writers.len())
                ),
            )
        ));
        lines.extend(
            writers
                .iter()
                .map(|writer| format!("    {}", style.marked(Mark::Bullet, writer))),
        );
        lines.push(format!(
            "    {}",
            style.paint(
                "Recorded at activation: what these write lands on the decoy disk. \
                 Close or restart them to stop it.",
                nails_core::output::Tone::Dim,
            )
        ));
    }
    lines
}

/// The lines describing an activation still in flight: the phase and elapsed
/// time, then the phase detail when the progress record carries one. Empty when
/// no activation is running.
pub(super) fn activation_in_flight_lines(
    report: &nails_core::status::StatusReport,
    style: Style,
) -> Vec<String> {
    let Some(flight) = report.activation_in_flight.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![format!(
        "Activation:         in progress: {}",
        flight.summary()
    )];
    if let Some(detail) = flight.progress.as_ref().and_then(|p| p.detail.as_deref()) {
        lines.push(format!("  {}", style.marked(Mark::Arrow, detail)));
    }
    lines
}

/// The last-activation line, or `None` before the first successful activation.
pub(super) fn last_activation_line(report: &nails_core::status::StatusReport) -> Option<String> {
    report.last_activation.as_ref().map(|last| {
        format!(
            "Last activation:    took {} (finished {})",
            nails_core::timing::format_elapsed(std::time::Duration::from_millis(last.duration_ms)),
            last.finished_at.format("%Y-%m-%d %H:%M:%S UTC")
        )
    })
}

/// The undelivered-results block: how many result notifications never reached
/// the operator, one line per title, and why when `notify-send` was missing.
/// Empty when everything was delivered.
pub(super) fn undelivered_lines(
    report: &nails_core::status::StatusReport,
    style: Style,
) -> Vec<String> {
    let pending = &report.undelivered_notifications;
    if pending.is_empty() && !report.notify_send_missing {
        return Vec::new();
    }
    let mut lines = vec![format!("Undelivered notifications: {}", pending.len())];
    lines.extend(
        pending
            .iter()
            .map(|n| format!("  {}", style.marked(Mark::Bullet, &n.title))),
    );
    if report.notify_send_missing {
        lines.push(format!(
            "  {}",
            style.marked(
                Mark::Warn,
                "notify-send was not found in the session, so desktop notifications \
                 could not be shown; install libnotify in the hidden configuration",
            )
        ));
    }
    lines
}

/// Print the status report header: box drawing, or an ASCII rule.
pub fn print_status_header(style: Style) {
    if style.ascii {
        println!("=======================================");
        println!("  NAILS Status Report");
        println!("=======================================");
    } else {
        println!("╭─────────────────────────────────────╮");
        println!("│  NAILS Status Report                │");
        println!("╰─────────────────────────────────────╯");
    }
    println!();
}

/// Print the status report for people.
///
/// One renderer serves colour, no-colour and ASCII output: `style` (the stdout
/// style from the resolved output settings) decides marks, colour and box
/// drawing. `details` adds resolved paths and overlay mount information.
pub fn print_status_human(
    report: &nails_core::status::StatusReport,
    details: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
    log_path: &std::path::Path,
    style: Style,
) {
    print_status_header(style);

    println!("State:              {}", state_label(report));
    for line in activation_in_flight_lines(report, style) {
        println!("{line}");
    }
    for line in posture_lines(report, style) {
        println!("{line}");
    }
    if !report.remaining_mounts.is_empty() {
        println!("Live NAILS mounts:");
        for mount in &report.remaining_mounts {
            println!(
                "  {}",
                style.marked(Mark::Fail, format_args!("{}", mount.display()))
            );
        }
    }
    println!("Persona mode:       {}", report.persona_mode.as_str());
    if report.persona_mode == nails_core::config::PersonaMode::SharedHome {
        println!(
            "  {}",
            style.marked(
                Mark::Warn,
                format_args!(
                    "shared-home: the hidden session uses the decoy home; its accounts and \
                     secrets are live"
                ),
            )
        );
    }

    if let SystemState::Active { .. } = report.state {
        if let Some(activated_at) = report.activated_at {
            println!(
                "Activated at:       {}",
                activated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if !report.formatted_uptime.is_empty() {
            println!("Uptime:             {}", report.formatted_uptime);
        }

        println!();

        if !report.overlay_mount_statuses.is_empty() {
            println!("Overlays:");
            for status in &report.overlay_mount_statuses {
                let line = if status.owned {
                    style.marked(
                        Mark::Pass,
                        format_args!("{} (verified NAILS overlay)", status.path.display()),
                    )
                } else {
                    style.marked(
                        Mark::Fail,
                        format_args!("{} (NOT a NAILS overlay)", status.path.display()),
                    )
                };
                println!("  {line}");
            }
        }

        if let Some(ref toplevel) = report.hidden_toplevel {
            println!();
            println!("Hidden system:      {}", toplevel);
        }

        // A hidden NixOS configuration that did not apply on the last activation
        // is reported as a warning: the overlays are up, but the declarative
        // configuration is NOT in force.
        if let Some(ref warning) = report.last_switch_warning {
            println!();
            println!(
                "  {}",
                style.marked(
                    Mark::Warn,
                    format_args!("hidden configuration NOT applied ({warning})"),
                )
            );
        }
    } else if let SystemState::Inactive = report.state {
        println!();
        println!("Run 'nails activate' to mount hidden environment");
    }

    if let Some(line) = last_activation_line(report) {
        println!();
        println!("{line}");
    }

    let undelivered = undelivered_lines(report, style);
    if !undelivered.is_empty() {
        println!();
        for line in undelivered {
            println!("{line}");
        }
    }

    if let Some(line) = hidden_volume_line(report) {
        println!();
        println!("{line}");
    }

    if let Some(ref last) = report.last_deactivation {
        print_last_deactivation_summary(last, style);
    }

    if details && matches!(report.state, SystemState::Active { .. }) {
        println!();
        println!("Details:");
        println!("  Config file:        {}", config_file_label(config_path));
        println!("  State file:         {}", state_path.display());
        println!();

        if let Some(ref overlay_details) = report.overlay_details {
            println!("  Overlay Mount Details:");
            for (mount_path, info) in overlay_details.iter() {
                println!();
                println!("    Mount:     {}", mount_path.display());
                println!("    Lower:     {}", info.lower_dir.display());
                println!("    Upper:     {}", info.upper_dir.display());
                println!("    Work:      {}", info.work_dir.display());
                println!(
                    "    Mounted:   {}",
                    info.mounted_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }
    }

    if details && matches!(report.state, SystemState::Inactive) {
        use nails_core::LoadOutcome;

        println!();
        println!("Details:");
        println!("  Config file:        {}", config_file_label(config_path));
        println!("  Hidden volume root: {}", hidden_volume_root.display());
        println!("  State file:         {}", state_path.display());
        println!("  Log path:           {}", log_path.display());
        match &report.load_outcome {
            LoadOutcome::Loaded => println!("  State loaded:       normal"),
            LoadOutcome::Missing => println!("  State loaded:       fresh default (no file)"),
            LoadOutcome::Unreadable => {
                println!("  State loaded:       unreadable (state unknown, using defaults)")
            }
            LoadOutcome::Corrupt => {
                println!("  State loaded:       corrupt (state unknown, using defaults)")
            }
        }
    }

    if !report.opsec_reminders.is_empty() {
        println!();
        for reminder in &report.opsec_reminders {
            println!("{}", reminder.render(style));
        }
    }

    // Recent logs are noise on a clean decoy, so show them only with --details or
    // when the posture warrants a look (active or degraded). `read_recent_logs`
    // already returns the newest entries in chronological order.
    let show_logs = details
        || matches!(
            report.posture,
            nails_core::status::Posture::Active | nails_core::status::Posture::Degraded
        );
    if show_logs && let Some(logs) = read_recent_logs(log_path, report.activated_at, details, style)
    {
        println!();
        println!("Recent Logs:");
        for log in &logs {
            println!("  {}", log);
        }
    }
}

/// Render a concise summary of the last standard deactivation's self-check.
///
/// Shows the overall verdict, when it ran and the outcome, and lists any
/// non-informational findings so an operator can see at a glance whether the
/// previous session tore down cleanly. The full detail is available in
/// `status --json`.
fn print_last_deactivation_summary(report: &nails_core::LastDeactivationReport, style: Style) {
    use nails_core::{Severity, VerifyStatus};

    let (mark, verdict) = match report.status {
        VerifyStatus::Secure => (Mark::Pass, "clean"),
        VerifyStatus::Warning => (Mark::Warn, "warnings"),
        VerifyStatus::Critical => (Mark::Fail, "critical findings"),
    };

    println!();
    println!(
        "Last deactivation:  {}",
        style.marked(mark, format_args!("{verdict} ({})", report.generated_at))
    );

    for finding in &report.findings {
        let finding_mark = match finding.severity {
            Severity::Info => continue,
            Severity::Warn => Mark::Warn,
            Severity::Critical => Mark::Fail,
        };
        println!(
            "  {}",
            style.marked(finding_mark, format_args!("{}", finding.message))
        );
    }
}
