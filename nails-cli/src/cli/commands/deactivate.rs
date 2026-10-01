//! Deactivate command handler

use std::path::Path;

use nails_core::output::Mark;

use crate::cli::args::DeactivateArgs;
use crate::cli::detach::maybe_detach_for_deactivation;
use crate::cli::output::OutputSettings;

/// Execute the deactivate command
///
/// Deactivate and return to decoy state (unmount + cleanup).
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `deactivate` arguments
/// * `config_override` - Optional config file path override
///
/// # Returns
///
/// Never returns - exits with code 0 on success, 1 on deactivation failure, 2 on safety guard
/// or detach failures. A missing or invalid config is logged as a warning and defaults are used.
pub fn execute(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    config_override: Option<&Path>,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    use nails_core::{NailsManager, RealFilesystem};

    let json = settings.is_json();
    let verbosity = settings.verbosity;

    // A broken or missing config must never block returning to the decoy.
    let mut config = super::load_config_or_defaults(config_override).into_config();

    // Apply --no-clear-history CLI override
    if args.no_clear_history {
        config.clear_history = false;
    }

    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        eprintln!("{}", msg);
        std::process::exit(2);
    }

    let state_path = config.state_file_path.clone();
    // Retained for the state lock after detach, since `config` and the clone
    // above are moved into the manager below.
    let lock_state_path = state_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let mut manager = NailsManager::new(filesystem, config, state_path);
    manager.set_verbosity(verbosity);

    if let Err(e) = maybe_detach_for_deactivation() {
        if !json {
            eprintln!("Error: {}", e);
        } else {
            eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
        }
        std::process::exit(2);
    }

    // Take the exclusive state lock after any detach, so a concurrent operation
    // fails fast instead of racing this teardown.
    let _state_lock = super::acquire_state_lock_or_exit(&lock_state_path);

    // Run quick deactivation (restore symlink + reboot)
    match manager.deactivate() {
        Ok(()) => {
            // Success - system will reboot
            if !json {
                println!(
                    "{}",
                    settings
                        .stdout_style()
                        .marked(Mark::Pass, "System configuration restored")
                );
                println!("  Rebooting to decoy environment...");
                eprintln!();
                for line in deactivate_recovery_guidance(settings) {
                    eprintln!("{line}");
                }
            } else {
                println!("{}", deactivate_success_json());
            }
            // Note: Reboot command was already issued, this code may not execute
            std::process::exit(0);
        }
        Err(e) => {
            if !json {
                eprintln!(
                    "{}",
                    settings
                        .stderr_style()
                        .marked(Mark::Fail, format_args!("Deactivation failed: {e}"))
                );
            } else {
                eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
            }
            std::process::exit(1);
        }
    }
}

/// Build the JSON success response for deactivation
fn deactivate_success_json() -> String {
    r#"{"status":"success","message":"Rebooting to decoy configuration","recovery_guidance":["Dismount hidden volume","Reboot to ensure clean state"]}"#.to_string()
}

/// Recovery guidance printed to stderr after deactivation; the first line
/// carries the shared warning mark in the stderr style.
const DEACTIVATE_RECOVERY_GUIDANCE: &[&str] = &[
    "Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

fn deactivate_recovery_guidance(settings: &OutputSettings) -> Vec<String> {
    let mut lines: Vec<String> = DEACTIVATE_RECOVERY_GUIDANCE
        .iter()
        .map(|line| line.to_string())
        .collect();
    lines[0] = settings.stderr_style().marked(Mark::Warn, &lines[0]);
    lines
}

#[cfg(test)]
mod tests;
