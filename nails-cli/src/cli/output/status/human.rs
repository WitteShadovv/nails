use nails_core::SystemState;
use nails_core::output::{Mark, Style};

use super::{config_file_label, read_recent_logs};
use crate::cli::output::dto::system_state_label;

/// Human-readable state label, reporting "Unknown" when the state file could not
/// be read or trusted rather than claiming the safe default is the real state.
fn state_label(report: &nails_core::status::StatusReport) -> &'static str {
    if report.load_outcome.is_unknown() {
        "Unknown"
    } else {
        system_state_label(&report.state)
    }
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
    println!(
        "Security Posture:   {}",
        report.security_posture().render(style)
    );

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
                let line = if status.actually_mounted {
                    style.marked(
                        Mark::Pass,
                        format_args!("{} (mounted)", status.path.display()),
                    )
                } else {
                    style.marked(
                        Mark::Fail,
                        format_args!("{} (NOT mounted)", status.path.display()),
                    )
                };
                println!("  {line}");
            }
        }

        if let Some(ref generation) = report.nixos_generation {
            println!();
            println!("NixOS Generation:   {}", generation);
        }
    } else if let SystemState::Inactive = report.state {
        println!();
        println!("Run 'nails activate' to mount hidden environment");
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

    if let Some(logs) = read_recent_logs(log_path, report.activated_at, details, style) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}
