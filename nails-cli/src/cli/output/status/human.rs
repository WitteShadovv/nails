// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, TimeZone, Utc};
use nails_core::output::{Mark, Style};
use nails_core::status::{Posture, StatusReport};

use super::{config_file_label, read_recent_logs};
use crate::cli::output::dto::system_state_label;

/// Print the status header box.
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

/// `instant` in `zone` with its offset from UTC, as `status` shows a time:
/// `2026-10-14 21:41:59 +02:00`. In the local zone that is the time the desktop
/// clock shows; the JSON output and the files on the volume keep UTC.
pub(super) fn stamp<Tz: TimeZone>(instant: DateTime<Utc>, zone: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    instant
        .with_timezone(zone)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

/// The lines of the human status report (without the header and logs), with
/// the times in `zone`.
pub(super) fn status_lines<Tz: TimeZone>(
    report: &StatusReport,
    details: bool,
    style: Style,
    zone: &Tz,
) -> Vec<String>
where
    Tz::Offset: std::fmt::Display,
{
    let mut out = Vec::new();
    out.push(format!(
        "Security Posture:   {}",
        report.posture.render(style)
    ));
    if let Some(reason) = &report.reason {
        out.push(format!("  {reason}"));
    }
    if let Some(remediation) = &report.remediation {
        out.push(format!("  {}", style.marked(Mark::Arrow, remediation)));
    }
    out.push(format!(
        "State:              {} (recorded)",
        system_state_label(&report.state)
    ));
    if let Some(entered) = report.entered_at {
        out.push(format!("Entered:            {}", stamp(entered, zone)));
    }
    if let Some(uptime) = report.uptime {
        out.push(format!(
            "Uptime:             {}",
            nails_core::status::format_uptime(uptime)
        ));
    }
    if let Some(system) = &report.hidden_system {
        out.push(format!("Hidden system:      {system}"));
    }
    if report.posture == Posture::Active || details {
        for mount in &report.policy_mounts {
            out.push(format!(
                "  {} {} ({})",
                style.mark(Mark::Bullet),
                mount.target.display(),
                mount.kind
            ));
        }
        if !report.masked_units.is_empty() {
            out.push(format!(
                "Masked decoy units: {}",
                report.masked_units.join(", ")
            ));
        }
    }
    out.push(format!(
        "Hidden volume:      {} ({})",
        report.hidden_root.display(),
        if report.hidden_root_mounted {
            "mounted"
        } else {
            "not mounted"
        }
    ));
    if let Some(reason) = &report.accepted_decoy_storage {
        out.push(format!(
            "  {} --allow-decoy-storage: {reason}; {}",
            style.mark(Mark::Warn),
            nails_core::hidden_root::refusal::OVERRIDE_CONSEQUENCE
        ));
    }
    if let Some(cover) = &report.hidden_root_covered_by {
        out.push(format!(
            "  {} {} is mounted over it: files saved there go to that disk \
             (`sudo umount {}` takes it off)",
            style.mark(Mark::Warn),
            cover.source,
            cover.mount_point.display()
        ));
    }
    if report.decoy_persistent && report.posture != Posture::Active {
        out.push(style.marked(
            Mark::Warn,
            "The decoy keeps a persistent journal or syslog: the soft-reboots are recorded on its disk",
        ));
    }
    if let Some(last) = &report.last_activation {
        out.push(format!(
            "Last activation:    took {} (finished {})",
            nails_core::timing::format_duration(std::time::Duration::from_millis(last.duration_ms)),
            stamp(last.finished_at, zone)
        ));
    }
    for reminder in &report.opsec_reminders {
        out.push(reminder.render(style));
    }
    out
}

/// Print the status report for people. `details` adds the resolved paths, the
/// policy mounts on every posture and the recent log lines.
pub fn print_status_human(
    report: &StatusReport,
    details: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
    log_path: &std::path::Path,
    style: Style,
) {
    print_status_header(style);
    for line in status_lines(report, details, style, &chrono::Local) {
        println!("{line}");
    }
    if details {
        println!();
        println!("Details:");
        println!("  Config file:        {}", config_file_label(config_path));
        println!("  Hidden volume root: {}", hidden_volume_root.display());
        println!("  State file:         {}", state_path.display());
        println!("  Log path:           {}", log_path.display());
        println!(
            "  State loaded:       {}",
            match report.state_source {
                "loaded" => "normal",
                "missing" => "fresh default (no file)",
                "unreadable" => "unreadable (state unknown, using defaults)",
                _ => "corrupt (state unknown, using defaults)",
            }
        );
        if let Some(logs) =
            read_recent_logs(log_path, report.entered_at, false, style, &chrono::Local)
        {
            println!();
            println!("Recent log lines:");
            for line in logs {
                println!("  {line}");
            }
        }
    }
}
