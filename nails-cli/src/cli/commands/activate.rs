//! Activate command handler
//!
//! This module contains the standalone handler for the `activate` command, which:
//! - Loads configuration with CLI overrides
//! - Runs pre-flight checks (unless skipped)
//! - Optionally detaches to a background service when killing GUI sessions
//! - Activates the hidden NixOS environment (mounts overlayfs, switches profiles)
//! - Configures shell instrumentation for the active state
//!
//! The handler is extracted from the main CLI dispatch logic to improve modularity
//! and testability.

use crate::cli::detach::maybe_detach_for_session_kill;
use crate::cli::output;

use nails_core::{
    ActivateOptions, CliOverrides, Config, Filesystem, NailsManager, NixOSBuilder, RealFilesystem,
    Verbosity,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Execute the activate command
///
/// # Parameters
///
/// - `no_preflight`: Skip pre-flight checks (DANGEROUS - expert use only)
/// - `quiet`: Quiet mode, only show final result
/// - `verbose`: Verbosity level (0 = normal, 1 = verbose, 2+ = debug)
/// - `json`: Output results in JSON format
/// - `no_color`: Disable colored output
/// - `plain`: ASCII-only output (no Unicode symbols)
/// - `no_clear_history`: Skip clearing shell history on deactivation
/// - `no_kill_session`: Do not kill graphical session (interactive mode)
/// - `accept_pivot_risks`: Accept pivot mount fallback for any volume (degraded security)
/// - `interactive`: Prompt for confirmations instead of auto-accepting
/// - `nixos_flake`: Optional NixOS flake reference (e.g., /etc/nixos#hostname)
/// - `config_override`: Optional path to configuration file
/// - `check_real_ops`: Safety guard callback to verify real operations are allowed
///
/// # Returns
///
/// This function never returns normally - it always exits the process with an
/// appropriate exit code (0 for success, 1 for activation failure, 2 for errors).
#[allow(clippy::too_many_arguments)]
pub fn execute(
    no_preflight: bool,
    quiet: bool,
    verbose: u8,
    json: bool,
    no_color: bool,
    plain: bool,
    no_clear_history: bool,
    no_kill_session: bool,
    accept_pivot_risks: bool,
    interactive: bool,
    nixos_flake: Option<String>,
    overlay_only: bool,
    config_override: Option<std::path::PathBuf>,
    check_real_ops: impl Fn(&std::path::Path) -> Result<(), String>,
) -> ! {
    // Configure color output (must be done before any colored output)
    // Story 14.7: Integrate output module with NO_COLOR/--no-color/--plain support
    // Note: set_plain_mode() already handles colored::control::set_override()
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
            _ => Verbosity::Debug, // 2+ maps to Debug
        }
    };

    // Apply defaults: kill_session, yes, and no_pivot are enabled by default
    // Users must explicitly disable them with --no-kill-session, --interactive, or --accept-pivot-risks
    let kill_session = !no_kill_session; // Default true unless explicitly disabled
    let yes = !interactive; // Default true unless explicitly disabled
    let no_pivot = !accept_pivot_risks; // Default true unless explicitly disabled

    // Build ActivateOptions from CLI flags
    let mut options = ActivateOptions {
        kill_session,
        accept_pivot_risks,
        no_pivot,
        yes,
        quiet,
        verbosity: verbose,
        json,
        no_color,
        overlay_only,
        skip_process_detection_override: None, // Use default test behavior
        session_kill_confirmed: false,
        pre_activation_cleanup: true, // Default to running pre-activation cleanup
    };

    if options.kill_session {
        if !options.yes {
            eprintln!("Error: --kill-session is non-interactive after detach; use --yes");
            std::process::exit(2);
        }
        if !options.accept_pivot_risks && !options.no_pivot {
            eprintln!(
                "Error: --kill-session requires --accept-pivot-risks or --no-pivot to avoid prompts"
            );
            std::process::exit(2);
        }
    }

    // Validate options (check for conflicting flags)
    if let Err(e) = options.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(2);
    }

    // Build CLI overrides from parsed arguments (Story 10.3)
    let cli_overrides = CliOverrides {
        preflight_checks: if no_preflight { Some(false) } else { None },
        clear_history: if no_clear_history { Some(false) } else { None },
        verbosity: if quiet {
            Some("quiet".to_string())
        } else if verbose >= 2 {
            Some("debug".to_string())
        } else if verbose == 1 {
            Some("info".to_string()) // AC4: -v maps to "info"
        } else {
            None // Use config file or default
        },
        color_output: if no_color { Some(false) } else { None },
        nixos_flake,
        ..Default::default()
    };

    // Load config with CLI overrides (Story 10.3, updated in Story 14.1)
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());

    let config = Config::from_file_and_cli(&config_path, &cli_overrides).unwrap_or_else(|e| {
        eprintln!("Error loading config: {}", e);
        std::process::exit(2);
    });

    // TEST SAFETY GUARD (Layer 1): Check if real operations are allowed
    if let Err(msg) = check_real_ops(&config.hidden_volume_root) {
        eprintln!("{}", msg);
        std::process::exit(2);
    }

    let state_path = config.state_file_path.clone();

    // Create NailsManager with real filesystem (enable NixOS switching when flake is present)
    let filesystem = RealFilesystem;
    let nails_profile = std::path::PathBuf::from("/nix/var/nix/profiles/nails-system");

    let manager = if overlay_only {
        // --overlay-only: skip NixOS builder creation entirely
        tracing::info!("Overlay-only mode: skipping NixOS profile switch");
        Arc::new(Mutex::new(NailsManager::new(
            filesystem, config, state_path,
        )))
    } else if let Some(ref flake_ref) = config.nixos_flake {
        // Explicit flake reference from --flake flag or config nixos_flake
        // Skip auto-discovery and use the provided reference directly
        tracing::info!(
            flake_ref = %flake_ref,
            "Using explicit NixOS flake reference"
        );
        let builder = NixOSBuilder::new_with_flake_ref(flake_ref.clone(), nails_profile);
        Arc::new(Mutex::new(NailsManager::with_nixos(
            filesystem, config, state_path, builder,
        )))
    } else {
        // Auto-discovery cascade: hidden volume → /etc/nixos → legacy → no NixOS
        let nixos_flake_dir = config.hidden_volume_root.join("nixos");
        let nixos_flake = nixos_flake_dir.join("flake.nix");
        let etc_flake = std::path::PathBuf::from("/etc/nixos/flake.nix");
        let legacy_config = std::path::PathBuf::from("/etc/nixos/configuration.nix");
        let system_profile = std::path::PathBuf::from("/nix/var/nix/profiles/system");
        if nixos_flake.exists() {
            let builder = NixOSBuilder::new(nixos_flake_dir, nails_profile);
            Arc::new(Mutex::new(NailsManager::with_nixos(
                filesystem, config, state_path, builder,
            )))
        } else if etc_flake.exists() {
            let builder = NixOSBuilder::new(std::path::PathBuf::from("/etc/nixos"), nails_profile);
            Arc::new(Mutex::new(NailsManager::with_nixos(
                filesystem, config, state_path, builder,
            )))
        } else if legacy_config.exists() || system_profile.exists() {
            let builder = NixOSBuilder::new_legacy(legacy_config, nails_profile);
            Arc::new(Mutex::new(NailsManager::with_nixos(
                filesystem, config, state_path, builder,
            )))
        } else {
            Arc::new(Mutex::new(NailsManager::new(
                filesystem, config, state_path,
            )))
        }
    };

    // Set verbosity level
    manager.lock().unwrap().set_verbosity(verbosity);

    // If kill-session, run preflight before detaching so output stays visible.
    let mut skip_preflight = no_preflight;
    if options.kill_session && !no_preflight {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Running pre-flight checks before session kill...");
        }

        // Probe symlink support before staging (catches FAT32/exFAT early)
        {
            let mgr = manager.lock().unwrap();
            match mgr
                .filesystem()
                .supports_symlinks(&mgr.config().hidden_volume_root)
            {
                Ok(false) => {
                    let msg = format!(
                        "Filesystem at {} does not support symbolic links. \
                         The hidden volume must be formatted with a Linux filesystem (e.g. ext4). \
                         FAT32 and exFAT do not support symlinks.",
                        mgr.config().hidden_volume_root.display()
                    );
                    eprintln!("Error: {}", msg);
                    std::process::exit(2);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Could not probe symlink support; continuing");
                }
                Ok(true) => {}
            }
        }

        {
            let mgr = manager.lock().unwrap();
            if let Err(e) = nails_core::stage_hidden_config_symlink(
                mgr.filesystem(),
                &mgr.config().hidden_volume_root,
            ) {
                tracing::error!(
                    error = %e,
                    "Failed to stage hidden config symlink before pre-flight checks"
                );
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }

        {
            let mgr = manager.lock().unwrap();
            if let Err(e) = mgr.run_preflight_checks(overlay_only) {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }

        skip_preflight = true;
    }

    // Detach if we're about to kill the GUI session so the worker survives it
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut session_ctx = None;
    if options.kill_session
        && let Ok(ctx) = nails_core::detect_session_context()
        && ctx.kind == nails_core::SessionKind::GraphicalUser
    {
        session_ctx = Some(ctx);
    }

    if options.kill_session
        && !options.session_kill_confirmed
        && let Some(ref ctx) = session_ctx
    {
        if let Err(e) = nails_core::prompt_session_kill_confirmation(ctx, options.yes) {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
        options.session_kill_confirmed = true;
    }

    if let Err(e) = maybe_detach_for_session_kill(kill_session, &argv, session_ctx.as_ref()) {
        eprintln!("Error: {}", e);
        std::process::exit(2);
    }

    // Run activation with options and measure duration
    let start = Instant::now();
    let result = NailsManager::activate_with_options(manager.clone(), options, skip_preflight);
    let duration = start.elapsed().as_secs_f64();

    // If activation succeeded, set up shell instrumentation (non-critical)
    let shell_setup_result = if result.is_ok() {
        use nails_core::ShellInstrumentation;
        let mgr = manager.lock().unwrap();
        let shell = ShellInstrumentation::new(nails_core::RealFilesystem, mgr.config().clone());
        // shell_setup() never returns Err, only Ok(Some) or Ok(None)
        shell.shell_setup().ok().flatten()
    } else {
        None
    };

    // Output results based on flags
    if json {
        output::print_activate_json(&result, duration, &manager, shell_setup_result.as_ref());
    } else {
        output::print_activate_human(
            &result,
            duration,
            &manager,
            shell_setup_result.as_ref(),
            quiet,
        );
    }

    // Return appropriate exit code
    match result {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}
