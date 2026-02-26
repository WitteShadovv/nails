//! Emergency command handler

use std::path::PathBuf;

/// Execute the emergency command
///
/// Rapid deactivation with countdown.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `no_countdown` - Skip the 3-second countdown (proceed immediately)
/// * `quiet` - Suppress output except final result
/// * `verbose` - Verbosity level (0 = normal, 1 = verbose, 2+ = debug)
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
///
/// # Returns
///
/// Never returns - exits with code 0 on success, 1 on failure, 2 on safety guard
#[allow(clippy::too_many_arguments)]
pub fn execute(
    config_override: Option<PathBuf>,
    _no_countdown: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    use nails_core::{Config, NailsManager, RealFilesystem, Verbosity, emergency_deactivate};
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

    // Load config
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());
    let config = Config::load_or_default(&config_path).unwrap_or_else(|_| Config::test_default());

    // TEST SAFETY GUARD
    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        eprintln!("{}", msg);
        std::process::exit(2);
    }

    let state_path = config.state_file_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let manager = Arc::new(Mutex::new(NailsManager::new(
        filesystem, config, state_path,
    )));
    manager.lock().unwrap().set_verbosity(verbosity);

    // Run emergency deactivation
    match emergency_deactivate(Arc::clone(&manager)) {
        Ok(()) => {
            if !json {
                println!("✓ Emergency deactivation complete");
                println!("  System returned to decoy configuration");
            } else {
                println!(
                    "{{\"status\":\"success\",\"message\":\"Emergency deactivation complete\"}}"
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            if !json {
                eprintln!("✗ Emergency deactivation failed: {}", e);
            } else {
                eprintln!("{{\"status\":\"error\",\"message\":\"{}\"}}", e);
            }
            std::process::exit(1);
        }
    }
}
