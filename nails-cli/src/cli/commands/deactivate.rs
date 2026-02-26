//! Deactivate command handler

use std::path::PathBuf;

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
/// Never returns - exits with code 0 on success, 1 on failure
pub fn execute(
    config_override: Option<PathBuf>,
    _no_clear_history: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
) -> ! {
    use nails_core::{Config, NailsManager, RealFilesystem, Verbosity};
    use std::sync::{Arc, Mutex};

    // Configure color output
    if no_color || plain || std::env::var("NO_COLOR").is_ok() {
        nails_core::set_plain_mode(true);
    }

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

    // Load configuration
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let config = Config::load_or_default(&config_path).unwrap_or_else(|_| Config::test_default());
    let state_path = config.state_file_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let manager = Arc::new(Mutex::new(NailsManager::new(
        filesystem, config, state_path,
    )));
    manager.lock().unwrap().set_verbosity(verbosity);

    // Run quick deactivation (restore symlink + reboot)
    match NailsManager::deactivate(Arc::clone(&manager)) {
        Ok(()) => {
            // Success - system will reboot
            if !json {
                println!("✓ System configuration restored");
                println!("  Rebooting to decoy environment...");
            } else {
                println!(
                    "{{\"status\":\"success\",\"message\":\"Rebooting to decoy configuration\"}}"
                );
            }
            // Note: Reboot command was already issued, this code may not execute
            std::process::exit(0);
        }
        Err(e) => {
            if !json {
                eprintln!("✗ Deactivation failed: {}", e);
            } else {
                eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
            }
            std::process::exit(1);
        }
    }
}
