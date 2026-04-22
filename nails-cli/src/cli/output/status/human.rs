use nails_core::SystemState;

use super::read_recent_logs;

pub fn print_status_human(
    report: &nails_core::status::StatusReport,
    verbose: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
    log_path: &std::path::Path,
) {
    if nails_core::is_color_disabled() {
        print_status_no_color(
            report,
            verbose,
            config_path,
            state_path,
            hidden_volume_root,
            log_path,
        );
        return;
    }

    println!("╭─────────────────────────────────────╮");
    println!("│  NAILS Status Report                │");
    println!("╰─────────────────────────────────────╯");
    println!();

    println!("State:              {:?}", report.state);

    let posture = report.security_posture();
    println!("Security Posture:   {}", posture);

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
                if status.actually_mounted {
                    println!("  ✓ {} (mounted)", status.path.display());
                } else {
                    println!("  ✗ {} (NOT mounted)", status.path.display());
                }
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

    if verbose && matches!(report.state, SystemState::Active { .. }) {
        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
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

    if verbose && matches!(report.state, SystemState::Inactive) {
        use nails_core::LoadOutcome;

        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
        println!("  Hidden volume root: {}", hidden_volume_root.display());
        println!("  State file:         {}", state_path.display());
        println!("  Log path:           {}", log_path.display());
        match &report.load_outcome {
            LoadOutcome::FreshDefault => println!("  State loaded:       fresh default (no file)"),
            LoadOutcome::Normal => println!("  State loaded:       normal"),
            LoadOutcome::Migrated { from_version } => {
                println!("  State loaded:       migrated from v{}", from_version)
            }
            LoadOutcome::RecoveredFromCorruption => {
                println!("  State loaded:       recovered from corruption (using defaults)")
            }
        }
    }

    if !report.opsec_reminders.is_empty() {
        println!();
        for reminder in &report.opsec_reminders {
            println!("{}", reminder);
        }
    }

    if let Some(logs) = read_recent_logs(log_path, report.activated_at, verbose, true) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}

fn print_status_no_color(
    report: &nails_core::status::StatusReport,
    verbose: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
    log_path: &std::path::Path,
) {
    println!("╭─────────────────────────────────────╮");
    println!("│  NAILS Status Report                │");
    println!("╰─────────────────────────────────────╯");
    println!();

    println!("State:              {:?}", report.state);

    let posture = report.security_posture();
    println!(
        "Security Posture:   {} {}: {}",
        match posture {
            nails_core::SecurityPosture::Secure => "🟢",
            nails_core::SecurityPosture::Warning => "🟡",
            nails_core::SecurityPosture::Decoy => "🔴",
            nails_core::SecurityPosture::Critical => "🔴",
        },
        match posture {
            nails_core::SecurityPosture::Secure => "SECURE",
            nails_core::SecurityPosture::Warning => "WARNING",
            nails_core::SecurityPosture::Decoy => "DECOY",
            nails_core::SecurityPosture::Critical => "CRITICAL",
        },
        match posture {
            nails_core::SecurityPosture::Secure => "Hidden environment active, overlays verified",
            nails_core::SecurityPosture::Warning =>
                "System in transitional state - wait for completion",
            nails_core::SecurityPosture::Decoy => "Decoy system - no sensitive data accessible",
            nails_core::SecurityPosture::Critical =>
                "Emergency deactivation occurred - reboot recommended",
        }
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
                if status.actually_mounted {
                    println!("  ✓ {} (mounted)", status.path.display());
                } else {
                    println!("  ✗ {} (NOT mounted)", status.path.display());
                }
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

    if verbose && matches!(report.state, SystemState::Active { .. }) {
        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
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

    if verbose && matches!(report.state, SystemState::Inactive) {
        use nails_core::LoadOutcome;

        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
        println!("  Hidden volume root: {}", hidden_volume_root.display());
        println!("  State file:         {}", state_path.display());
        println!("  Log path:           {}", log_path.display());
        match &report.load_outcome {
            LoadOutcome::FreshDefault => println!("  State loaded:       fresh default (no file)"),
            LoadOutcome::Normal => println!("  State loaded:       normal"),
            LoadOutcome::Migrated { from_version } => {
                println!("  State loaded:       migrated from v{}", from_version)
            }
            LoadOutcome::RecoveredFromCorruption => {
                println!("  State loaded:       recovered from corruption (using defaults)")
            }
        }
    }

    if !report.opsec_reminders.is_empty() {
        println!();
        for reminder in &report.opsec_reminders {
            println!("{}", reminder);
        }
    }

    if let Some(logs) = read_recent_logs(log_path, report.activated_at, verbose, false) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}
