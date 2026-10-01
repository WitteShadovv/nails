//! Deactivate command handler

use std::path::PathBuf;

use crate::cli::detach::maybe_detach_for_deactivation;

/// Execute the deactivate command
///
/// Deactivate and return to decoy state (unmount + cleanup).
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `no_clear_history` - Skip shell history cleanup
/// * `quiet` - Suppress output except errors
/// * `verbose` - Verbosity level (0 = normal, 1 = verbose, 2+ = debug)
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
///
/// # Returns
///
/// Never returns - exits with code 0 on success, 1 on deactivation failure, 2 on safety guard
/// or detach failures. A missing or invalid config is logged as a warning and defaults are used.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    config_override: Option<PathBuf>,
    no_clear_history: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    use nails_core::{NailsManager, RealFilesystem, Verbosity};
    use std::sync::{Arc, Mutex};

    // Configure color output
    nails_core::set_plain_mode(plain);
    nails_core::set_color_enabled(
        !(plain
            || no_color
            || std::env::var("NO_COLOR").is_ok()
            || std::env::var(nails_core::constants::ENV_NO_COLOR).is_ok()),
    );

    // Convert CLI flags to Verbosity enum
    let verbosity = if quiet {
        Verbosity::Quiet
    } else {
        match verbose {
            0 => Verbosity::Normal,
            1 => Verbosity::Verbose,
            _ => Verbosity::Debug,
        }
    };

    // A broken or missing config must never block returning to the decoy.
    let mut config = super::load_config_or_defaults(config_override.as_deref()).into_config();

    // Apply --no-clear-history CLI override
    if no_clear_history {
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
    let manager = Arc::new(Mutex::new(NailsManager::new(
        filesystem, config, state_path,
    )));
    super::lock_manager_or_exit(&manager, "setting deactivation verbosity")
        .set_verbosity(verbosity);

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
    match NailsManager::deactivate(Arc::clone(&manager)) {
        Ok(()) => {
            // Success - system will reboot
            if !json {
                let success_prefix = if plain { "[PASS]" } else { "✓" };
                println!("{success_prefix} System configuration restored");
                println!("  Rebooting to decoy environment...");
                eprintln!();
                for line in deactivate_recovery_guidance(plain) {
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
                let error_prefix = if plain { "[FAIL]" } else { "✗" };
                eprintln!("{error_prefix} Deactivation failed: {}", e);
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

/// Recovery guidance lines for human-readable deactivation output
const DEACTIVATE_RECOVERY_GUIDANCE: &[&str] = &[
    "⚠ Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

const DEACTIVATE_RECOVERY_GUIDANCE_PLAIN: &[&str] = &[
    "[WARN] Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

fn deactivate_recovery_guidance(plain: bool) -> &'static [&'static str] {
    if plain {
        DEACTIVATE_RECOVERY_GUIDANCE_PLAIN
    } else {
        DEACTIVATE_RECOVERY_GUIDANCE
    }
}

#[cfg(test)]
mod tests;
