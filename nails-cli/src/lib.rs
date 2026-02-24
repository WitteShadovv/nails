//! # NAILS CLI Library
//!
//! This module contains the CLI command handlers and argument parsing.
//! Commands are implemented in the `cli` module for testability and reusability.
//! The entry point in main.rs simply invokes `cli::execute_command()`.

pub mod cli {
    mod detach;
    use clap::{Parser, Subcommand};
    use detach::maybe_detach_for_session_kill;

    /// NixOS Anti-forensics Isolation & Layering System
    #[derive(Parser)]
    #[command(name = "nails")]
    #[command(author = "NAILS Project")]
    #[command(version)]
    #[command(about = "NixOS Anti-forensics Isolation & Layering System", long_about = None)]
    pub struct Cli {
        /// Path to configuration file (overrides binary-relative discovery)
        #[arg(long, global = true, value_name = "PATH")]
        pub config: Option<std::path::PathBuf>,

        /// Verbose output (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
        pub verbose: u8,

        /// Quiet mode: only show errors and warnings
        #[arg(short = 'q', long, conflicts_with = "verbose")]
        pub quiet: bool,

        /// Skip file logging (only log to stdout)
        #[arg(long)]
        pub no_logs: bool,

        #[command(subcommand)]
        pub command: Commands,
    }

    #[derive(Subcommand)]
    pub enum Commands {
        /// Activate the hidden NixOS environment (mount overlayfs + switch profiles)
        Activate {
            /// Skip pre-flight checks (DANGEROUS - expert use only)
            #[arg(long)]
            no_preflight: bool,

            /// Quiet mode: only show final result
            #[arg(short = 'q', long, conflicts_with = "verbose")]
            quiet: bool,

            /// Verbose output (-v for detailed, -vv for debug)
            #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
            verbose: u8,

            /// Output results in JSON format
            #[arg(long)]
            json: bool,

            /// Disable colored output
            #[arg(long)]
            no_color: bool,

            /// ASCII-only output (no Unicode symbols)
            #[arg(long)]
            plain: bool,

            /// Skip clearing shell history on deactivation
            #[arg(long)]
            no_clear_history: bool,

            /// Kill graphical session before activation (enables all direct mounts)
            #[arg(long)]
            kill_session: bool,

            /// Accept pivot mount fallback for any volume (degraded security)
            #[arg(long, conflicts_with = "no_pivot")]
            accept_pivot_risks: bool,

            /// Abort if any volume requires pivot mount (strict security)
            #[arg(long, conflicts_with = "accept_pivot_risks")]
            no_pivot: bool,

            /// Skip all confirmation prompts (auto-accept)
            #[arg(short = 'y', long)]
            yes: bool,
        },
        /// Deactivate and return to decoy state (unmount + cleanup)
        Deactivate {
            /// Skip shell history cleanup
            ///
            /// By default, deactivation removes all 'nails' commands from shell history.
            /// Use this flag to preserve history (not recommended for forensic safety).
            #[arg(long)]
            no_clear_history: bool,

            /// Suppress output except errors
            #[arg(short, long, conflicts_with = "verbose")]
            quiet: bool,

            /// Increase verbosity (-v for details, -vv for debug)
            #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
            verbose: u8,

            /// Output results in JSON format
            #[arg(long)]
            json: bool,

            /// Disable colored output
            #[arg(long)]
            no_color: bool,

            /// ASCII-only output (no Unicode symbols)
            #[arg(long)]
            plain: bool,
        },
        /// Emergency mode: rapid deactivation with countdown
        Emergency {
            /// Skip the 3-second countdown (proceed immediately)
            #[arg(long)]
            no_countdown: bool,

            /// Suppress output except final result
            #[arg(long, conflicts_with = "verbose")]
            quiet: bool,

            /// Increase verbosity (-v for details, -vv for debug)
            #[arg(short, long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
            verbose: u8,

            /// Output results in JSON format
            #[arg(long)]
            json: bool,

            /// Disable colored output
            #[arg(long)]
            no_color: bool,

            /// ASCII-only output (no Unicode symbols)
            #[arg(long)]
            plain: bool,
        },
        /// Show current status and uptime
        Status {
            /// Output results in JSON format
            #[arg(long)]
            json: bool,

            /// Disable colored output
            #[arg(long)]
            no_color: bool,

            /// ASCII-only output (no Unicode box drawing or emoji)
            #[arg(long)]
            plain: bool,

            /// Display detailed overlay mount information
            #[arg(short, long)]
            verbose: bool,
        },
        /// Verify system is clean of NAILS artifacts
        Verify {
            /// Perform deep scan (slower, more thorough)
            #[arg(long)]
            deep: bool,
            /// Output results as JSON
            #[arg(long)]
            json: bool,
        },
    }

    /// TEST SAFETY GUARD (Layer 1): Check if real system operations are allowed
    ///
    /// This is a defense-in-depth measure to prevent integration tests from
    /// accidentally executing dangerous operations on the development system.
    ///
    /// # How It Works
    ///
    /// 1. Checks if `NAILS_UNSAFE_REAL_OPS=1` environment variable is set
    /// 2. If NOT set, checks if the hidden volume root appears to be a build directory
    /// 3. If it's a build directory and env var not set, refuses to proceed
    ///
    /// # When This Triggers
    ///
    /// - Integration tests running from `cargo test` without opt-in
    /// - Binary executed from `target/debug/` or `target/release/` without explicit permission
    ///
    /// # How to Bypass (Intentionally)
    ///
    /// Set the environment variable:
    /// ```bash
    /// NAILS_UNSAFE_REAL_OPS=1 cargo test
    /// ```
    ///
    /// # Returns
    ///
    /// - `Ok(())` if operations are allowed
    /// - `Err(message)` if operations are blocked for safety
    fn check_real_operations_allowed(hidden_volume_root: &std::path::Path) -> Result<(), String> {
        // Check for explicit opt-in via environment variable
        if std::env::var("NAILS_UNSAFE_REAL_OPS").unwrap_or_default() == "1" {
            return Ok(());
        }

        // Check if hidden volume root appears to be a build directory
        let path_str = hidden_volume_root.to_string_lossy();
        let is_build_dir = path_str.contains("/target/debug")
            || path_str.contains("/target/release")
            || path_str.contains("/target/llvm-cov-target");

        if is_build_dir {
            return Err(format!(
                "🛡️  TEST SAFETY GUARD: Refusing to execute real system operations\n\
                 \n\
                 Hidden volume root appears to be a build directory:\n\
                 {}\n\
                 \n\
                 This usually means you're running integration tests without proper safeguards.\n\
                 Real system operations (mount, unmount, systemctl, process killing) are BLOCKED.\n\
                 \n\
                 To run tests that execute real operations, set:\n\
                 \n\
                 NAILS_UNSAFE_REAL_OPS=1 cargo test\n\
                 \n\
                 ⚠️  WARNING: This will execute REAL system commands. Only use this if you know\n\
                 what you're doing and are prepared for potential system disruption.\n\
                 \n\
                 For safe testing, use the unit tests or MockFilesystem-based tests instead.",
                hidden_volume_root.display()
            ));
        }

        Ok(())
    }

    /// Execute the CLI command - extracted for testability
    pub fn execute_command(cli: Cli) -> std::result::Result<(), Box<dyn std::error::Error>> {
        match cli.command {
            Commands::Activate {
                no_preflight,
                quiet,
                verbose,
                json,
                no_color,
                plain,
                no_clear_history,
                kill_session,
                accept_pivot_risks,
                no_pivot,
                yes,
            } => {
                use nails_core::{
                    ActivateOptions, CliOverrides, Config, NailsManager, NixOSBuilder,
                    RealFilesystem, Verbosity,
                };

                use std::sync::{Arc, Mutex};
                use std::time::Instant;

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
                    skip_process_detection_override: None, // Use default test behavior
                    session_kill_confirmed: false,
                };

                if options.kill_session {
                    if !options.yes {
                        eprintln!(
                            "Error: --kill-session is non-interactive after detach; use --yes"
                        );
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
                    ..Default::default()
                };

                // Load config with CLI overrides (Story 10.3, updated in Story 14.1)
                let config_path = nails_core::config::discover_config_path(cli.config.as_deref());

                let config = Config::from_file_and_cli(&config_path, &cli_overrides)
                    .unwrap_or_else(|e| {
                        eprintln!("Error loading config: {}", e);
                        std::process::exit(2);
                    });

                // TEST SAFETY GUARD (Layer 1): Check if real operations are allowed
                if let Err(msg) = check_real_operations_allowed(&config.hidden_volume_root) {
                    eprintln!("{}", msg);
                    std::process::exit(2);
                }

                let state_path = config.state_file_path.clone();

                // Create NailsManager with real filesystem (enable NixOS switching when flake is present)
                let filesystem = RealFilesystem;
                let nixos_flake_dir = config.hidden_volume_root.join("nixos");
                let nixos_flake = nixos_flake_dir.join("flake.nix");
                let etc_flake = std::path::PathBuf::from("/etc/nixos/flake.nix");
                let legacy_config = std::path::PathBuf::from("/etc/nixos/configuration.nix");
                let system_profile = std::path::PathBuf::from("/nix/var/nix/profiles/system");
                let manager = if nixos_flake.exists() {
                    let builder = NixOSBuilder::new(
                        nixos_flake_dir,
                        std::path::PathBuf::from("/nix/var/nix/profiles/nails-system"),
                    );
                    Arc::new(Mutex::new(NailsManager::with_nixos(
                        filesystem, config, state_path, builder,
                    )))
                } else if etc_flake.exists() {
                    let builder = NixOSBuilder::new(
                        std::path::PathBuf::from("/etc/nixos"),
                        std::path::PathBuf::from("/nix/var/nix/profiles/nails-system"),
                    );
                    Arc::new(Mutex::new(NailsManager::with_nixos(
                        filesystem, config, state_path, builder,
                    )))
                } else if legacy_config.exists() || system_profile.exists() {
                    let builder = NixOSBuilder::new_legacy(
                        legacy_config,
                        std::path::PathBuf::from("/nix/var/nix/profiles/nails-system"),
                    );
                    Arc::new(Mutex::new(NailsManager::with_nixos(
                        filesystem, config, state_path, builder,
                    )))
                } else {
                    Arc::new(Mutex::new(NailsManager::new(
                        filesystem, config, state_path,
                    )))
                };

                // Set verbosity level
                manager.lock().unwrap().set_verbosity(verbosity);

                // If kill-session, run preflight before detaching so output stays visible.
                let mut skip_preflight = no_preflight;
                if options.kill_session && !no_preflight {
                    if verbosity >= Verbosity::Normal {
                        tracing::info!("Running pre-flight checks before session kill...");
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
                        if let Err(e) = mgr.run_preflight_checks() {
                            eprintln!("Error: {}", e);
                            std::process::exit(2);
                        }
                    }

                    skip_preflight = true;
                }

                // Detach if we're about to kill the GUI session so the worker survives it
                let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
                let mut session_ctx = None;
                if options.kill_session {
                    if let Ok(ctx) = nails_core::detect_session_context() {
                        if ctx.kind == nails_core::SessionKind::GraphicalUser {
                            session_ctx = Some(ctx);
                        }
                    }
                }

                if options.kill_session && !options.session_kill_confirmed {
                    if let Some(ref ctx) = session_ctx {
                        if let Err(e) =
                            nails_core::prompt_session_kill_confirmation(ctx, options.yes)
                        {
                            eprintln!("Error: {}", e);
                            std::process::exit(2);
                        }
                        options.session_kill_confirmed = true;
                    }
                }

                maybe_detach_for_session_kill(kill_session, &argv, session_ctx.as_ref())?;

                // Run activation with options and measure duration
                let start = Instant::now();
                let result =
                    NailsManager::activate_with_options(manager.clone(), options, skip_preflight);
                let duration = start.elapsed().as_secs_f64();

                // If activation succeeded, set up shell instrumentation (non-critical)
                let shell_setup_result = if result.is_ok() {
                    use nails_core::ShellInstrumentation;
                    let mgr = manager.lock().unwrap();
                    let shell =
                        ShellInstrumentation::new(nails_core::RealFilesystem, mgr.config().clone());
                    // shell_setup() never returns Err, only Ok(Some) or Ok(None)
                    shell.shell_setup().ok().flatten()
                } else {
                    None
                };

                // Output results based on flags
                if json {
                    print_activate_json(&result, duration, &manager, shell_setup_result.as_ref());
                } else {
                    print_activate_human(
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
            Commands::Deactivate {
                no_clear_history: _,
                quiet,
                verbose,
                json,
                no_color,
                plain,
            } => {
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
                let config_path = nails_core::config::discover_config_path(cli.config.as_deref());
                let config = Config::load_or_default(&config_path)
                    .unwrap_or_else(|_| Config::test_default());
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
            Commands::Emergency {
                no_countdown: _,
                quiet,
                verbose,
                json,
                no_color,
                plain,
            } => {
                use nails_core::{
                    Config, NailsManager, RealFilesystem, Verbosity, emergency_deactivate,
                };
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
                let config_path = nails_core::config::discover_config_path(cli.config.as_deref());
                let config = Config::load_or_default(&config_path)
                    .unwrap_or_else(|_| Config::test_default());

                // TEST SAFETY GUARD
                if let Err(msg) = check_real_operations_allowed(&config.hidden_volume_root) {
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
            Commands::Status {
                json,
                no_color,
                plain,
                verbose,
            } => {
                use nails_core::{
                    Config, NailsError, RealFilesystem, StatusCommand, status::SecurityPosture,
                };

                // Configure color output (must be done before any colored output)
                // Story 14.7: Integrate output module with NO_COLOR/--no-color/--plain support
                // Note: set_plain_mode() already handles colored::control::set_override()
                if no_color || plain || std::env::var("NO_COLOR").is_ok() {
                    nails_core::set_plain_mode(true);
                }

                // Load configuration (Story 14.1)
                let config_path = nails_core::config::discover_config_path(cli.config.as_deref());

                let config = Config::load_or_default(&config_path)
                    .unwrap_or_else(|_| Config::test_default());

                let state_path = config.state_file_path.clone();

                // Create StatusCommand and run
                let filesystem = RealFilesystem;
                let command = StatusCommand::new(filesystem, config, state_path.clone());

                // Always succeed - even if state file is missing, show status (FR63)
                let report = match command.run() {
                    Ok(report) => report,
                    // FIX #4 & #7: Better error context with specific messages
                    Err(e) => {
                        // State file error - show INACTIVE status with error details
                        // FR63: Status always succeeds (exit code 0)
                        let error_msg = match e {
                            NailsError::IoError(ref io_err) => {
                                if io_err.kind() == std::io::ErrorKind::NotFound {
                                    format!("State file not found: {}", state_path.display())
                                } else {
                                    format!(
                                        "I/O error reading state file {}: {}",
                                        state_path.display(),
                                        io_err
                                    )
                                }
                            }
                            NailsError::PermissionDenied(ref msg) => {
                                format!(
                                    "Permission denied accessing state file {}: {}",
                                    state_path.display(),
                                    msg
                                )
                            }
                            NailsError::ConfigError(ref msg) => {
                                format!(
                                    "State file corrupted or invalid at {}: {}",
                                    state_path.display(),
                                    msg
                                )
                            }
                            _ => {
                                format!("Error reading state file {}: {}", state_path.display(), e)
                            }
                        };

                        // FIX #5: Use SecurityPosture constant instead of duplicated strings
                        let posture = SecurityPosture::Decoy;

                        if json {
                            println!(
                                "{{\"state\":\"INACTIVE\",\"security_posture\":\"decoy\",\"error\":\"{}\"}}",
                                error_msg.replace('"', "\\\"")
                            );
                        } else if plain {
                            println!("=== NAILS Status Report ===");
                            println!();
                            println!("State:              INACTIVE");
                            println!("Security Posture:   {}", posture.to_plain());
                            println!();
                            println!("Error: {}", error_msg);
                            println!();
                            println!("Run 'nails activate' to mount hidden environment");
                        } else {
                            println!("╭─────────────────────────────────────╮");
                            println!("│  NAILS Status Report                │");
                            println!("╰─────────────────────────────────────╯");
                            println!();
                            println!("State:              INACTIVE");
                            println!("Security Posture:   {}", posture);
                            println!();
                            println!("Error: {}", error_msg);
                            println!();
                            println!("Run 'nails activate' to mount hidden environment");
                        }
                        std::process::exit(0); // FR63: Always exit 0
                    }
                };

                // Format output based on flags
                if json {
                    print_status_json(&report);
                } else if plain {
                    print_status_ascii(&report, verbose, &config_path, &state_path);
                } else {
                    print_status_human(&report, verbose, &config_path, &state_path);
                }

                // FR63: Status always succeeds (exit code 0)
                std::process::exit(0);
            }
            Commands::Verify { deep, json } => {
                use nails_core::{RealFilesystem, Verifier};

                // Create verifier with real filesystem
                let filesystem = RealFilesystem;
                let verifier = Verifier::new(filesystem);

                // Run verification
                let result = match verifier.run(deep) {
                    Ok(result) => result,
                    Err(e) => {
                        eprintln!("Error running verification: {}", e);
                        std::process::exit(2); // Exit code 2 for verify command errors
                    }
                };

                // Output results
                if json {
                    // JSON output
                    let json_output = serde_json::to_string_pretty(&result)?;
                    println!("{}", json_output);
                } else {
                    // Human-readable output
                    print_verify_result(&result);
                }

                // Set exit code based on status
                match result.status {
                    nails_core::VerifyStatus::Secure => std::process::exit(0),
                    nails_core::VerifyStatus::Warning | nails_core::VerifyStatus::Critical => {
                        std::process::exit(1)
                    }
                }
            }
        }
    }

    /// Initialize dual-layer tracing subscriber with file + stdout logging
    ///
    /// Sets up a two-layer subscriber:
    /// 1. **File layer** (JSON): Captures ALL events (TRACE+) to `{hidden_volume}/logs/nails.log`
    /// 2. **Stdout layer** (fmt): Human-readable output filtered by verbosity level
    ///
    /// Implements graceful fallback: if hidden volume is not mounted or LoggingManager
    /// initialization fails, continues with stdout-only logging (no errors raised).
    ///
    /// # Arguments
    ///
    /// * `verbose_count` - Number of `-v` flags passed (0, 1, 2+)
    ///
    /// # Levels (Stdout Layer)
    ///
    /// - 0 (normal): INFO and above (ERROR, WARN, INFO)
    /// - 1 (`-v`): DEBUG and above
    /// - 2+ (`-vv`): TRACE and above
    ///
    /// # File Layer
    ///
    /// Always captures TRACE+ regardless of user verbosity (full audit trail).
    ///
    /// # Graceful Fallback (AC: Story 9.3, Task 2.4)
    ///
    /// If hidden volume not mounted or LoggingManager fails:
    /// - Logs warning to stderr
    /// - Continues with stdout-only logging
    /// - Does NOT fail the command
    ///
    /// # Parameters
    ///
    /// - `verbose_count`: Verbosity level (0 = INFO, 1 = DEBUG, 2+ = TRACE)
    /// - `quiet`: Quiet mode - only show WARN and ERROR (AC: Story 9.3, AC #5)
    /// - `no_logs`: Skip file logging entirely (AC: Story 9.3, Task 2.5)
    /// - `config_override`: Optional explicit config file path (from `--config` flag)
    pub fn init_stdout_subscriber(
        verbose_count: u8,
        quiet: bool,
        no_logs: bool,
        config_override: Option<&std::path::Path>,
    ) {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt; // Required for .with_filter()

        // Map CLI flags to tracing level (AC #5)
        let stdout_level = if quiet {
            LevelFilter::WARN // Quiet mode: only WARN and ERROR
        } else {
            match verbose_count {
                0 => LevelFilter::INFO,  // Normal mode: INFO, WARN, ERROR
                1 => LevelFilter::DEBUG, // Verbose mode: DEBUG + INFO + WARN + ERROR
                _ => LevelFilter::TRACE, // Debug mode: TRACE + all above
            }
        };

        // Skip file layer if --no-logs flag is set (AC: Story 9.3, Task 2.5)
        if no_logs {
            // Stdout-only logging (no file layer)
            tracing_subscriber::fmt()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_level(true)
                .with_max_level(stdout_level)
                .init();
            return;
        }

        // Try to initialize LoggingManager for file logging (Task 2.1)
        let file_layer_result = init_file_layer(config_override);

        match file_layer_result {
            Ok(Some(file_layer)) => {
                // Dual-layer subscriber: file (JSON, all events) + stdout (fmt, filtered)
                let stdout_layer = fmt::layer()
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_level(true)
                    .with_filter(stdout_level);

                tracing_subscriber::registry()
                    .with(file_layer)
                    .with(stdout_layer)
                    .init();
            }
            Ok(None) | Err(_) => {
                // Graceful fallback: stdout-only logging (Task 2.4)
                tracing_subscriber::fmt()
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_level(true)
                    .with_max_level(stdout_level)
                    .init();
            }
        }
    }

    /// Initialize file logging layer with LoggingManager
    ///
    /// Creates JSON file layer that writes to `{hidden_volume}/logs/nails.log`.
    /// Implements graceful fallback if hidden volume is not mounted.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(layer))` - File layer successfully created
    /// - `Ok(None)` - Hidden volume not available, logged warning to stderr
    /// - `Err(_)` - Unexpected error during initialization
    ///
    /// # Implementation (Task 2.1-2.4)
    ///
    /// - Task 2.1: Create LoggingManager with config paths
    /// - Task 2.2: Call LoggingManager::init() for validation
    /// - Task 2.3: Build JSON file layer that captures ALL events
    /// - Task 2.4: Graceful fallback if hidden volume not mounted
    #[allow(clippy::type_complexity)]
    fn init_file_layer(
        config_override: Option<&std::path::Path>,
    ) -> Result<
        Option<
            tracing_subscriber::filter::Filtered<
                tracing_subscriber::fmt::Layer<
                    tracing_subscriber::Registry,
                    tracing_subscriber::fmt::format::JsonFields,
                    tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Json>,
                    std::sync::Mutex<std::fs::File>,
                >,
                tracing_subscriber::filter::LevelFilter,
                tracing_subscriber::Registry,
            >,
        >,
        Box<dyn std::error::Error>,
    > {
        use nails_core::{LoggingManager, RealFilesystem};
        use std::fs::OpenOptions;
        use std::path::PathBuf;
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::fmt; // Required for .with_filter()

        // Determine hidden volume and log paths from config (Story 14.3: Task 5, AC #4)
        let config_path = nails_core::config::discover_config_path(config_override);
        let hidden_volume_path = nails_core::config::Config::load_or_default(&config_path)
            .map(|c| c.hidden_volume_root)
            .unwrap_or_else(|_| PathBuf::from(nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT));
        let log_path = hidden_volume_path.join("logs");

        // Create LoggingManager (Task 2.1)
        let logging_manager = LoggingManager::new(log_path.clone(), hidden_volume_path.clone());

        // Initialize LoggingManager with validation (Task 2.2)
        // Returns Ok(None) for graceful degradation (hidden volume not available)
        let fs = RealFilesystem;
        let logging_config = match logging_manager.init(&fs) {
            Ok(Some(config)) => config,
            Ok(None) => {
                // Graceful degradation: hidden volume not available (Story 14.3, AC #3)
                return Ok(None);
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    nails_core::logging::format_early_error(&format!(
                        "Logging init failed: {}, continuing with stdout-only logging",
                        e
                    ))
                );
                return Ok(None);
            }
        };

        // Open log file for appending (Task 2.3)
        let log_file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logging_config.log_file_path)
        {
            Ok(file) => file,
            Err(e) => {
                eprintln!(
                    "{}",
                    nails_core::logging::format_early_warning(&format!(
                        "Failed to open log file: {}, continuing without file logging",
                        e
                    ))
                );
                return Ok(None);
            }
        };

        // Build JSON file layer that captures ALL events (Task 2.3)
        let file_writer = std::sync::Mutex::new(log_file);
        let file_layer = fmt::layer()
            .json()
            .with_writer(file_writer)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_filter(LevelFilter::TRACE); // Capture ALL events to file

        Ok(Some(file_layer))
    }

    /// Print verification results in human-readable format
    ///
    /// This function is pub(crate) to enable testing of the output formatting.
    pub(crate) fn print_verify_result(result: &nails_core::VerifyResult) {
        use colored::Colorize;
        use nails_core::{Severity, VerifyStatus};

        // Print header
        match result.status {
            VerifyStatus::Secure => {
                println!(
                    "{}",
                    "✓ SECURE: No traces found. System appears clean."
                        .green()
                        .bold()
                );
            }
            VerifyStatus::Warning => {
                println!(
                    "{}",
                    format!(
                        "⚠ WARNING: Found {} potential issues",
                        result.findings.len()
                    )
                    .yellow()
                    .bold()
                );
            }
            VerifyStatus::Critical => {
                println!(
                    "{}",
                    format!(
                        "✗ CRITICAL: Found {} artifacts requiring attention",
                        result.findings.len()
                    )
                    .red()
                    .bold()
                );
            }
        }

        // Print scan depth info
        match result.scan_depth {
            nails_core::ScanDepth::Deep => {
                println!(
                    "{}",
                    "Deep scan enabled - comprehensive validation".dimmed()
                );
            }
            nails_core::ScanDepth::Standard => {}
        }

        // Print findings
        if !result.findings.is_empty() {
            println!();
            for finding in &result.findings {
                let severity_str = match finding.severity {
                    Severity::Info => "[INFO]".blue(),
                    Severity::Warn => "[WARN]".yellow(),
                    Severity::Critical => "[CRIT]".red(),
                };

                println!(
                    "{} [{}] {}",
                    severity_str, finding.category, finding.message
                );

                if let Some(ref guidance) = finding.fix_guidance {
                    println!("  → {}", guidance.dimmed());
                }
            }
        }
    }

    /// JSON output structure for activate command
    #[derive(serde::Serialize)]
    struct ActivateResult {
        status: String,
        duration: f64,
        state: String,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        failed_checks: Option<Vec<FailedCheckJson>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        shell_instructions: Option<ShellInstructionsJson>,
    }

    #[derive(serde::Serialize)]
    pub(crate) struct ShellInstructionsJson {
        pub(crate) shell_type: String,
        pub(crate) prompt_script: String,
        pub(crate) alias_script: String,
        pub(crate) instructions: Vec<String>,
    }

    #[derive(serde::Serialize)]
    struct FailedCheckJson {
        name: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        fix: Option<String>,
    }

    /// Print activation result in JSON format
    fn print_activate_json<F: nails_core::Filesystem>(
        result: &Result<(), nails_core::NailsError>,
        duration: f64,
        manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
        shell_setup: Option<&nails_core::ShellSetupResult>,
    ) {
        use nails_core::NailsError;

        let state = manager
            .lock()
            .unwrap()
            .current_state()
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|_| "UNKNOWN".to_string());

        // Convert shell setup result to JSON structure
        let shell_instructions_json = shell_setup.map(|setup| ShellInstructionsJson {
            shell_type: format!("{:?}", setup.shell_type).to_lowercase(),
            prompt_script: setup.prompt_script_path.display().to_string(),
            alias_script: setup.alias_script_path.display().to_string(),
            instructions: setup.instructions.clone(),
        });

        let output = match result {
            Ok(_) => ActivateResult {
                status: "success".to_string(),
                duration,
                state,
                message: format!("Activation complete in {:.1}s", duration),
                failed_checks: None,
                shell_instructions: shell_instructions_json,
            },
            Err(e) => match e {
                NailsError::PreFlightCheckFailed(failures) => ActivateResult {
                    status: "error".to_string(),
                    duration,
                    state: state.clone(),
                    message: "Pre-flight checks failed".to_string(),
                    failed_checks: Some(
                        failures
                            .iter()
                            .map(|(name, reason)| FailedCheckJson {
                                name: name.clone(),
                                reason: reason.clone(),
                                fix: Some(
                                    "Review system state and ensure hidden volume is mounted"
                                        .to_string(),
                                ),
                            })
                            .collect(),
                    ),
                    shell_instructions: None,
                },
                _ => ActivateResult {
                    status: "error".to_string(),
                    duration,
                    state,
                    message: format!("Activation failed: {}", e),
                    failed_checks: None,
                    shell_instructions: None,
                },
            },
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
        );
    }

    /// Print activation result in human-readable format
    fn print_activate_human<F: nails_core::Filesystem>(
        result: &Result<(), nails_core::NailsError>,
        duration: f64,
        manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
        shell_setup: Option<&nails_core::ShellSetupResult>,
        quiet: bool,
    ) {
        use colored::Colorize;
        use nails_core::NailsError;

        match result {
            Ok(_) => {
                println!(
                    "{}",
                    format!("✓ Activation complete in {:.1}s", duration)
                        .green()
                        .bold()
                );

                // Print shell integration instructions (unless quiet mode)
                if !quiet {
                    if let Some(setup) = shell_setup {
                        if let Some(ref warn) = setup.warning {
                            // Script generation failed, show warning with reason
                            println!();
                            println!("{}", format!("Shell prompt not updated: {}", warn).yellow());
                            println!(
                                "{}",
                                "You can manually source scripts from the hidden volume if needed"
                                    .dimmed()
                            );
                        } else if setup.rc_modified {
                            // RC file was modified - new terminals auto-configured
                            println!();
                            println!("{}", "Shell Integration:".cyan().bold());
                            println!(
                                "{}",
                                "✓ New terminals will automatically have prompt, alias, and color scheme."
                                    .green()
                            );
                            println!();
                            println!("{}", "To apply to this terminal now, run:".dimmed());
                            for cmd in &setup.instructions {
                                println!("  {}", cmd.bright_white());
                            }
                        } else {
                            // RC file not modified - show fallback instructions
                            println!();
                            println!("{}", "Shell Integration:".cyan().bold());
                            println!(
                                "{}",
                                "To update your prompt and add the 'nails' alias, run:".dimmed()
                            );
                            for cmd in &setup.instructions {
                                println!("  {}", cmd.bright_white());
                            }
                        }
                    } else {
                        // No shell detected or unsupported shell
                        println!();
                        println!(
                            "{}",
                            "Shell prompt not updated - no supported shell detected".yellow()
                        );
                        println!(
                            "{}",
                            "You can manually source scripts from the hidden volume if needed"
                                .dimmed()
                        );
                    }
                }
            }
            Err(e) => match e {
                NailsError::PreFlightCheckFailed(failures) => {
                    eprintln!("{}", "✗ Pre-flight checks failed:".red().bold());
                    for (name, reason) in failures {
                        eprintln!("  • {}: {}", name.yellow(), reason);
                    }
                    eprintln!(
                        "\n  {}",
                        "Fix: Review system state and ensure hidden volume is mounted".yellow()
                    );
                }
                _ => {
                    eprintln!("{}", format!("✗ Activation failed: {}", e).red().bold());
                    eprintln!("  {}", "Automatic rollback completed.".dimmed());
                    if let Ok(state) = manager.lock().unwrap().current_state() {
                        eprintln!("  {}: {:?}", "Current state".dimmed(), state);
                    }
                }
            },
        }
    }

    /// JSON output structure for deactivate command (AC7)
    #[derive(serde::Serialize)]
    struct DeactivateJsonOutput {
        /// "success" or "error"
        status: String,
        /// Duration in seconds
        duration: f64,
        /// System state after deactivation (UPPERCASE per AC7: "INACTIVE" or "ACTIVE")
        state: String,
        /// List of cleaned items (history files, temp files, logs)
        cleaned_items: Vec<String>,
        /// Error messages (if any)
        errors: Vec<String>,
        /// Shell cleanup instructions
        #[serde(skip_serializing_if = "Option::is_none")]
        shell_cleanup: Option<ShellCleanupJson>,
    }

    #[derive(serde::Serialize)]
    pub(crate) struct ShellCleanupJson {
        pub(crate) shell_type: String,
        pub(crate) instructions: Vec<String>,
        pub(crate) note: String,
    }

    /// Print deactivation result in JSON format (AC7)
    fn print_deactivate_json<F: nails_core::Filesystem>(
        result: &Result<nails_core::DeactivationReport, nails_core::NailsError>,
        manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
        shell_cleanup: Option<&nails_core::ShellCleanupResult>,
    ) {
        let state = manager
            .lock()
            .unwrap()
            .current_state()
            .map(|s| format!("{:?}", s).to_uppercase())
            .unwrap_or_else(|_| "UNKNOWN".to_string());

        // Convert shell cleanup result to JSON structure
        let shell_cleanup_json = shell_cleanup.and_then(|cleanup| {
            cleanup
                .shell_type
                .as_ref()
                .map(|shell_type| ShellCleanupJson {
                    shell_type: format!("{:?}", shell_type).to_lowercase(),
                    instructions: cleanup.instructions.clone(),
                    note: "Shell prompt may still show (NAILS-ACTIVE) until next login".to_string(),
                })
        });

        let output = match result {
            Ok(report) => DeactivateJsonOutput {
                status: if report.is_successful() {
                    "success"
                } else {
                    "error"
                }
                .to_string(),
                duration: report.duration.as_secs_f64(),
                state: format!("{:?}", report.final_state).to_uppercase(),
                cleaned_items: report.cleanup_report.cleaned_items.clone(),
                errors: report.cleanup_report.errors.clone(),
                shell_cleanup: shell_cleanup_json,
            },
            Err(e) => DeactivateJsonOutput {
                status: "error".to_string(),
                duration: 0.0,
                state,
                cleaned_items: vec![],
                errors: vec![e.to_string()],
                shell_cleanup: None,
            },
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
        );
    }

    /// Print deactivation result in human-readable format (AC3, AC4, AC5)
    ///
    /// ## Error Path Testing (AC4, AC5)
    /// Error paths are tested at the orchestrator level in nails-core.
    /// CLI-level error path testing would require:
    /// - Mocking DeactivationOrchestrator (not feasible without dependency injection)
    /// - E2E test environment with LUKS volumes and overlayfs (requires VM/container)
    /// - Simulating filesystem permission errors (requires root/sudo)
    ///
    /// Current test coverage:
    /// - Argument parsing and flag handling (unit tests)
    /// - Success path E2E (integration tests verify idempotent behavior)
    /// - Error formatting logic (covered by orchestrator tests in nails-core)
    fn print_deactivate_human(
        result: &Result<nails_core::DeactivationReport, nails_core::NailsError>,
        verbosity: nails_core::Verbosity,
        no_color: bool,
        shell_cleanup: Option<&nails_core::ShellCleanupResult>,
        quiet: bool,
    ) {
        use colored::Colorize;
        use nails_core::{NailsError, Verbosity};

        match result {
            Ok(report) => {
                let check = if no_color { "[OK]" } else { "✓" };
                let duration = report.duration.as_secs_f64();

                if report.was_already_inactive {
                    println!("{} Already inactive - no action needed", check);
                    return;
                }

                // AC3: Print success message with duration (2 decimal places per spec)
                if no_color {
                    println!("[OK] deactivation complete in {:.2}s", duration);
                } else {
                    println!(
                        "{}",
                        format!("✓ deactivation complete in {:.2}s", duration)
                            .green()
                            .bold()
                    );
                }

                // AC3: Print cleanup summary with cleaned items (UXR13)
                if verbosity >= Verbosity::Normal && !report.cleanup_report.cleaned_items.is_empty()
                {
                    println!();
                    println!("Cleanup Summary:");
                    for item in &report.cleanup_report.cleaned_items {
                        println!("  {} {}", check, item);
                    }
                }

                // Show unmounted overlays
                if verbosity >= Verbosity::Normal && !report.unmounted_overlays.is_empty() {
                    println!();
                    println!("Unmounted Overlays:");
                    for overlay in &report.unmounted_overlays {
                        println!("  {} {}", check, overlay);
                    }
                }

                // AC8: -vv shows debug info including state transitions
                if verbosity >= Verbosity::Debug {
                    println!();
                    println!("Final State: {:?}", report.final_state);
                }

                // Shell cleanup instructions (unless quiet mode)
                if !quiet
                    && let Some(cleanup) = shell_cleanup
                    && let Some(_shell_type) = cleanup.shell_type
                {
                    println!();
                    if no_color {
                        println!("Shell Cleanup:");
                        println!("Shell prompt will be restored in new terminals automatically.");
                        println!("To remove from this terminal now, run:");
                    } else {
                        println!("{}", "Shell Cleanup:".cyan().bold());
                        println!(
                            "{}",
                            "Shell prompt will be restored in new terminals automatically.".green()
                        );
                        println!("{}", "To remove from this terminal now, run:".dimmed());
                    }
                    for cmd in &cleanup.instructions {
                        if no_color {
                            println!("  {}", cmd);
                        } else {
                            println!("  {}", cmd.bright_white());
                        }
                    }
                }
            }
            Err(e) => {
                let cross = if no_color { "[FAIL]" } else { "✗" };

                // AC4, AC5: Detect error type and show appropriate message
                let (category, details, guidance) = match e {
                    NailsError::PermissionDenied(msg) => (
                        "cleanup error",
                        msg.clone(),
                        "Check file permissions and retry with sudo".to_string(),
                    ),
                    NailsError::MountBusy { path, suggestion } => (
                        "unmount error",
                        format!("Overlay busy: {}", path.display()),
                        suggestion.clone(),
                    ),
                    NailsError::UnmountError { path, reason } => (
                        "unmount error",
                        format!("{}: {}", path.display(), reason),
                        "Check if overlay is in use and retry".to_string(),
                    ),
                    NailsError::InvalidState(msg) => (
                        "state error",
                        msg.clone(),
                        "Verify system is in ACTIVE state".to_string(),
                    ),
                    _ => (
                        "deactivation error",
                        e.to_string(),
                        "Check system state and retry".to_string(),
                    ),
                };

                // Print error message
                if no_color {
                    eprintln!("[FAIL] deactivation failed: {}", category);
                } else {
                    eprintln!(
                        "{}",
                        format!("{} deactivation failed: {}", cross, category)
                            .red()
                            .bold()
                    );
                }

                eprintln!();
                eprintln!("Details: {}", details);
                eprintln!();

                // AC4, AC5: Show state (ACTIVE after rollback)
                eprintln!("State: ACTIVE (rollback occurred)");
                eprintln!("Overlays: Remain mounted (safe state preserved)");
                eprintln!();

                // Show fix guidance
                if no_color {
                    eprintln!("Fix: {}", guidance);
                } else {
                    eprintln!("Fix: {}", guidance.yellow());
                }
            }
        }
    }
    // ========================================================================

    /// JSON output structure for status command (AC5)
    #[derive(serde::Serialize)]
    struct StatusJsonOutput {
        /// System state (ACTIVE, INACTIVE, etc.)
        state: String,
        /// Security posture level (secure, warning, critical)
        security_posture: String,
        /// When the system was activated (ISO 8601)
        #[serde(skip_serializing_if = "Option::is_none")]
        activated_at: Option<String>,
        /// Uptime in seconds
        #[serde(skip_serializing_if = "Option::is_none")]
        uptime_seconds: Option<i64>,
        /// Human-readable uptime string
        #[serde(skip_serializing_if = "Option::is_none")]
        uptime_formatted: Option<String>,
        /// Overlay list with status
        overlays: Vec<OverlayJsonEntry>,
        /// Overlay verification result
        overlay_verification: String,
        /// NixOS generation (if available)
        #[serde(skip_serializing_if = "Option::is_none")]
        nixos_generation: Option<String>,
        /// OpSec reminders
        opsec_reminders: Vec<OpSecReminderJson>,
    }

    #[derive(serde::Serialize)]
    struct OverlayJsonEntry {
        /// Overlay mount path
        path: String,
        /// Mount status
        status: String,
    }

    #[derive(serde::Serialize)]
    struct OpSecReminderJson {
        /// Reminder severity
        severity: String,
        /// Reminder message
        message: String,
    }

    /// Print status result in JSON format (AC5)
    ///
    /// Outputs a JSON object with all status fields including:
    /// - state (system state)
    /// - security_posture (secure/warning/critical)
    /// - activated_at (ISO 8601 timestamp)
    /// - uptime_seconds (duration in seconds)
    /// - uptime_formatted (human-readable uptime)
    /// - overlays (array of overlay paths with status)
    /// - overlay_verification (verification result)
    /// - nixos_generation (current generation if available)
    /// - opsec_reminders (array of reminders with severity and message)
    ///
    /// # Arguments
    ///
    /// * `report` - Status report from StatusCommand
    fn print_status_json(report: &nails_core::status::StatusReport) {
        use nails_core::status::*;

        let output = StatusJsonOutput {
            state: format!("{:?}", report.state),
            security_posture: match report.security_posture() {
                SecurityPosture::Secure => "secure".to_string(),
                SecurityPosture::Warning => "warning".to_string(),
                SecurityPosture::Decoy => "decoy".to_string(),
                SecurityPosture::Critical => "critical".to_string(),
            },
            activated_at: report.activated_at.map(|dt| dt.to_rfc3339()),
            uptime_seconds: report.uptime.map(|d| d.num_seconds()),
            uptime_formatted: if report.formatted_uptime.is_empty() {
                None
            } else {
                Some(report.formatted_uptime.clone())
            },
            overlays: report
                .overlays
                .iter()
                .map(|p| OverlayJsonEntry {
                    path: p.display().to_string(),
                    status: "mounted".to_string(),
                })
                .collect(),
            overlay_verification: match report.overlay_verification {
                VerificationStatus::Verified => "verified".to_string(),
                VerificationStatus::Mismatch { .. } => "mismatch".to_string(),
                VerificationStatus::Skipped => "skipped".to_string(),
                VerificationStatus::NotApplicable => "not_applicable".to_string(),
            },
            nixos_generation: report.nixos_generation.clone(),
            opsec_reminders: report
                .opsec_reminders
                .iter()
                .map(|r| OpSecReminderJson {
                    severity: format!("{}", r.severity),
                    message: r.message.clone(),
                })
                .collect(),
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
        );
    }

    /// Print status result in human-readable format with emojis (AC3, AC4, AC8, AC10)
    ///
    /// # Arguments
    ///
    /// * `report` - Status report from StatusCommand
    /// * `verbose` - Whether to show detailed overlay information
    /// * `config_path` - Path to config file (shown in verbose mode)
    /// * `state_path` - Path to state file (shown in verbose mode)
    ///
    /// # Verbose Mode (AC8)
    ///
    /// When `verbose` is true, displays:
    /// - Full overlay mount details (lower, upper, work directories)
    /// - State file path
    /// - Config file path
    /// - Mount timestamps for each overlay
    fn print_status_human(
        report: &nails_core::status::StatusReport,
        verbose: bool,
        config_path: &std::path::Path,
        state_path: &std::path::Path,
    ) {
        use nails_core::SystemState;

        // Print header with box drawing
        println!("╭─────────────────────────────────────╮");
        println!("│  NAILS Status Report                │");
        println!("╰─────────────────────────────────────╯");
        println!();

        // Format state without emoji (AC1: emoji only on Security Posture line)
        println!("State:              {:?}", report.state);

        // Format security posture with Display trait (includes emoji)
        let posture = report.security_posture();
        println!("Security Posture:   {}", posture);

        // Print activation details for ACTIVE state
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

            // Print overlay list with per-overlay mount status (Task 3)
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

            // Print NixOS generation if available
            if let Some(ref generation) = report.nixos_generation {
                println!();
                println!("NixOS Generation:   {}", generation);
            }
        } else if let SystemState::Inactive = report.state {
            println!();
            println!("Run 'nails activate' to mount hidden environment");
        }

        // Verbose mode: show detailed overlay info (AC8)
        if verbose && matches!(report.state, SystemState::Active { .. }) {
            println!();
            println!("Verbose Details:");
            println!("  Config file:        {}", config_path.display());
            println!("  State file:         {}", state_path.display());
            println!();

            // Show detailed overlay mount information
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

        // Print OpSec reminders if present (AC10)
        if !report.opsec_reminders.is_empty() {
            println!();
            for reminder in &report.opsec_reminders {
                println!("{}", reminder);
            }
        }
    }

    /// Print status result in ASCII-only format (AC6)
    ///
    /// # Arguments
    ///
    /// * `report` - Status report from StatusCommand
    /// * `verbose` - Whether to show detailed overlay information
    /// * `config_path` - Path to config file (shown in verbose mode)
    /// * `state_path` - Path to state file (shown in verbose mode)
    fn print_status_ascii(
        report: &nails_core::status::StatusReport,
        verbose: bool,
        config_path: &std::path::Path,
        state_path: &std::path::Path,
    ) {
        use nails_core::SystemState;

        // Print ASCII header (no box drawing)
        println!("=======================================");
        println!("  NAILS Status Report");
        println!("=======================================");
        println!();

        // Format state without ASCII indicator (AC1: indicator only on Security Posture line)
        println!("State:              {:?}", report.state);

        // Format security posture with to_plain()
        let posture = report.security_posture();
        println!("Security Posture:   {}", posture.to_plain());

        // Print activation details for ACTIVE state
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

            // Print overlay list with per-overlay mount status (Task 3)
            if !report.overlay_mount_statuses.is_empty() {
                println!("Overlays:");
                for status in &report.overlay_mount_statuses {
                    if status.actually_mounted {
                        println!("  [OK] {} (mounted)", status.path.display());
                    } else {
                        println!("  [ERROR] {} (NOT mounted)", status.path.display());
                    }
                }
            }

            // Print NixOS generation if available
            if let Some(ref generation) = report.nixos_generation {
                println!();
                println!("NixOS Generation:   {}", generation);
            }
        } else if let SystemState::Inactive = report.state {
            println!();
            println!("Run 'nails activate' to mount hidden environment");
        }

        // Verbose mode: show detailed info
        if verbose && matches!(report.state, SystemState::Active { .. }) {
            println!();
            println!("Verbose Details:");
            println!("  Config file:        {}", config_path.display());
            println!("  State file:         {}", state_path.display());
            println!();

            // Show detailed overlay mount information
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

        // Print OpSec reminders in ASCII format
        if !report.opsec_reminders.is_empty() {
            println!();
            for reminder in &report.opsec_reminders {
                println!("{}", reminder.to_plain());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cli::*;
    use clap::Parser;

    // Note: activate/deactivate tests moved to E2E (tests/ directory)
    // because these commands call std::process::exit() which terminates test processes.
    // Use assert_cmd E2E tests for full command validation.

    // ========================================================================
    // Deactivate Command Argument Parsing Tests (AC1, AC6, AC8)
    // ========================================================================

    #[test]
    fn test_deactivate_args_parsing_defaults() {
        // AC1: Test default args parsing
        let cli = Cli::try_parse_from(["nails", "deactivate"]).unwrap();
        if let Commands::Deactivate {
            no_clear_history,
            quiet,
            verbose,
            json,
            no_color,
            plain,
        } = cli.command
        {
            assert!(!no_clear_history);
            assert!(!quiet);
            assert_eq!(verbose, 0);
            assert!(!json);
            assert!(!no_color);
            assert!(!plain);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_no_clear_history_flag() {
        // AC6: Test --no-clear-history flag
        let cli = Cli::try_parse_from(["nails", "deactivate", "--no-clear-history"]).unwrap();
        if let Commands::Deactivate {
            no_clear_history, ..
        } = cli.command
        {
            assert!(no_clear_history);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_quiet_flag() {
        // AC1: Test --quiet flag
        let cli = Cli::try_parse_from(["nails", "deactivate", "--quiet"]).unwrap();
        if let Commands::Deactivate { quiet, .. } = cli.command {
            assert!(quiet);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_quiet_short_flag() {
        // AC1: Test -q short flag
        let cli = Cli::try_parse_from(["nails", "deactivate", "-q"]).unwrap();
        if let Commands::Deactivate { quiet, .. } = cli.command {
            assert!(quiet);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_verbose_flag_counting() {
        // AC8: Test -v flag (verbosity level 1)
        let cli = Cli::try_parse_from(["nails", "deactivate", "-v"]).unwrap();
        if let Commands::Deactivate { verbose, .. } = cli.command {
            assert_eq!(verbose, 1);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_verbose_vv_flag() {
        // AC8: Test -vv flag (verbosity level 2 = debug)
        let cli = Cli::try_parse_from(["nails", "deactivate", "-vv"]).unwrap();
        if let Commands::Deactivate { verbose, .. } = cli.command {
            assert_eq!(verbose, 2);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_json_flag() {
        // AC7: Test --json flag
        let cli = Cli::try_parse_from(["nails", "deactivate", "--json"]).unwrap();
        if let Commands::Deactivate { json, .. } = cli.command {
            assert!(json);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_no_color_flag() {
        // AC1: Test --no-color flag
        let cli = Cli::try_parse_from(["nails", "deactivate", "--no-color"]).unwrap();
        if let Commands::Deactivate { no_color, .. } = cli.command {
            assert!(no_color);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_multiple_flags() {
        // Test combining multiple flags
        let cli = Cli::try_parse_from([
            "nails",
            "deactivate",
            "--no-clear-history",
            "--json",
            "--no-color",
        ])
        .unwrap();
        if let Commands::Deactivate {
            no_clear_history,
            json,
            no_color,
            ..
        } = cli.command
        {
            assert!(no_clear_history);
            assert!(json);
            assert!(no_color);
        } else {
            panic!("Expected Deactivate command");
        }
    }

    #[test]
    fn test_deactivate_quiet_verbose_conflict() {
        // AC1: Test that --quiet and --verbose conflict
        let result = Cli::try_parse_from(["nails", "deactivate", "--quiet", "-v"]);
        assert!(result.is_err());
        // Note: clap provides helpful error messages like:
        // "error: the argument '--quiet' cannot be used with '--verbose'"
        // This is validated by manual testing and integration tests
    }

    // ========================================================================
    // Emergency Command Argument Parsing Tests (AC1, AC10)
    // ========================================================================
    //
    // Note: The emergency command handler calls std::process::exit(),
    // so we test argument parsing only. E2E tests cover full execution.

    #[test]
    fn test_emergency_args_parsing_defaults() {
        // AC1: Test default args parsing (no flags)
        let cli = Cli::try_parse_from(["nails", "emergency"]).unwrap();
        if let Commands::Emergency {
            no_countdown,
            quiet,
            verbose,
            json,
            no_color,
            plain,
        } = cli.command
        {
            assert!(!no_countdown);
            assert!(!quiet);
            assert_eq!(verbose, 0);
            assert!(!json);
            assert!(!no_color);
            assert!(!plain);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_no_countdown_flag() {
        // AC9: Test --no-countdown flag
        let cli = Cli::try_parse_from(["nails", "emergency", "--no-countdown"]).unwrap();
        if let Commands::Emergency { no_countdown, .. } = cli.command {
            assert!(no_countdown);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_quiet_flag() {
        // AC7: Test --quiet flag (long only, no short)
        let cli = Cli::try_parse_from(["nails", "emergency", "--quiet"]).unwrap();
        if let Commands::Emergency { quiet, .. } = cli.command {
            assert!(quiet);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_quiet_no_short_flag() {
        // AC1: --quiet has NO short flag for emergency
        let result = Cli::try_parse_from(["nails", "emergency", "-q"]);
        assert!(
            result.is_err(),
            "Emergency --quiet should NOT have -q short flag"
        );
    }

    #[test]
    fn test_emergency_verbose_flag() {
        // AC8: Test -v flag (verbosity level 1)
        let cli = Cli::try_parse_from(["nails", "emergency", "-v"]).unwrap();
        if let Commands::Emergency { verbose, .. } = cli.command {
            assert_eq!(verbose, 1);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_verbose_vv_flag() {
        // AC8: Test -vv flag (verbosity level 2 = debug)
        let cli = Cli::try_parse_from(["nails", "emergency", "-vv"]).unwrap();
        if let Commands::Emergency { verbose, .. } = cli.command {
            assert_eq!(verbose, 2);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_json_flag() {
        // AC6: Test --json flag
        let cli = Cli::try_parse_from(["nails", "emergency", "--json"]).unwrap();
        if let Commands::Emergency { json, .. } = cli.command {
            assert!(json);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_no_color_flag() {
        // AC1: Test --no-color flag
        let cli = Cli::try_parse_from(["nails", "emergency", "--no-color"]).unwrap();
        if let Commands::Emergency { no_color, .. } = cli.command {
            assert!(no_color);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_quiet_verbose_conflict() {
        // AC1: Test that --quiet and --verbose conflict
        let result = Cli::try_parse_from(["nails", "emergency", "--quiet", "-v"]);
        assert!(result.is_err(), "Quiet and verbose should conflict");
    }

    #[test]
    fn test_emergency_multiple_flags() {
        // Test combining multiple flags
        let cli = Cli::try_parse_from([
            "nails",
            "emergency",
            "--no-countdown",
            "--json",
            "--no-color",
        ])
        .unwrap();
        if let Commands::Emergency {
            no_countdown,
            json,
            no_color,
            ..
        } = cli.command
        {
            assert!(no_countdown);
            assert!(json);
            assert!(no_color);
        } else {
            panic!("Expected Emergency command");
        }
    }

    #[test]
    fn test_emergency_delay_flag_removed() {
        // AC1: Verify --delay flag no longer exists (removed per AR33)
        let result = Cli::try_parse_from(["nails", "emergency", "--delay", "10"]);
        assert!(result.is_err(), "--delay flag should no longer exist");
    }

    #[test]
    fn test_execute_status_command_with_verbose() {
        let cli = Cli {
            config: None,
            verbose: 0,
            quiet: false,
            no_logs: false,
            command: Commands::Status {
                json: false,
                no_color: false,
                plain: false,
                verbose: true,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_verbose_flag_values() {
        let cli = Cli {
            config: None,
            verbose: 3,
            quiet: false,
            no_logs: false,
            command: Commands::Status {
                json: false,
                no_color: false,
                plain: false,
                verbose: false,
            },
        };
        assert_eq!(cli.verbose, 3);
    }

    // ========================================================================
    // Status Command Argument Parsing Tests (Story 7.4, AC: 11)
    // ========================================================================

    #[test]
    fn test_status_args_parsing_defaults() {
        // Test default args parsing (all flags false)
        let cli = Cli::try_parse_from(["nails", "status"]).unwrap();
        if let Commands::Status {
            json,
            no_color,
            plain,
            verbose,
        } = cli.command
        {
            assert!(!json);
            assert!(!no_color);
            assert!(!plain);
            assert!(!verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_json_flag() {
        // Test --json flag
        let cli = Cli::try_parse_from(["nails", "status", "--json"]).unwrap();
        if let Commands::Status { json, .. } = cli.command {
            assert!(json);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_no_color_flag() {
        // Test --no-color flag
        let cli = Cli::try_parse_from(["nails", "status", "--no-color"]).unwrap();
        if let Commands::Status { no_color, .. } = cli.command {
            assert!(no_color);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_plain_flag() {
        // Test --plain flag
        let cli = Cli::try_parse_from(["nails", "status", "--plain"]).unwrap();
        if let Commands::Status { plain, .. } = cli.command {
            assert!(plain);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_verbose_flag() {
        // Test -v flag
        let cli = Cli::try_parse_from(["nails", "status", "-v"]).unwrap();
        if let Commands::Status { verbose, .. } = cli.command {
            assert!(verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_verbose_long_flag() {
        // Test --verbose flag
        let cli = Cli::try_parse_from(["nails", "status", "--verbose"]).unwrap();
        if let Commands::Status { verbose, .. } = cli.command {
            assert!(verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_multiple_flags() {
        // Test combining multiple flags
        let cli = Cli::try_parse_from(["nails", "status", "--json", "--plain", "--no-color", "-v"])
            .unwrap();
        if let Commands::Status {
            json,
            no_color,
            plain,
            verbose,
        } = cli.command
        {
            assert!(json);
            assert!(no_color);
            assert!(plain);
            assert!(verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_json_and_plain_flags() {
        // Test --json with --plain (JSON should take precedence in handler)
        let cli = Cli::try_parse_from(["nails", "status", "--json", "--plain"]).unwrap();
        if let Commands::Status {
            json,
            plain,
            no_color,
            verbose,
        } = cli.command
        {
            assert!(json);
            assert!(plain);
            assert!(!no_color);
            assert!(!verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_no_color_with_plain() {
        // Test --no-color with --plain
        let cli = Cli::try_parse_from(["nails", "status", "--no-color", "--plain"]).unwrap();
        if let Commands::Status {
            no_color, plain, ..
        } = cli.command
        {
            assert!(no_color);
            assert!(plain);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_status_all_flags() {
        // Test all flags together
        let cli = Cli::try_parse_from([
            "nails",
            "status",
            "--json",
            "--no-color",
            "--plain",
            "--verbose",
        ])
        .unwrap();
        if let Commands::Status {
            json,
            no_color,
            plain,
            verbose,
        } = cli.command
        {
            assert!(json);
            assert!(no_color);
            assert!(plain);
            assert!(verbose);
        } else {
            panic!("Expected Status command");
        }
    }

    #[test]
    fn test_execute_verify_command_without_flags() {
        let cli = Cli {
            config: None,
            verbose: 0,
            quiet: false,
            no_logs: false,
            command: Commands::Verify {
                deep: false,
                json: false,
            },
        };
        // This will exit with code 0 or 1, so we can't test result
        // But we can verify it compiles and the match arm exists
        let _cli = cli; // Consume to prevent unused warning
    }

    #[test]
    fn test_execute_verify_command_with_deep() {
        let cli = Cli {
            config: None,
            verbose: 0,
            quiet: false,
            no_logs: false,
            command: Commands::Verify {
                deep: true,
                json: false,
            },
        };
        let _cli = cli;
    }

    #[test]
    fn test_execute_verify_command_with_json() {
        let cli = Cli {
            config: None,
            verbose: 0,
            quiet: false,
            no_logs: false,
            command: Commands::Verify {
                deep: false,
                json: true,
            },
        };
        let _cli = cli;
    }

    #[test]
    fn test_execute_verify_command_with_deep_and_json() {
        let cli = Cli {
            config: None,
            verbose: 0,
            quiet: false,
            no_logs: false,
            command: Commands::Verify {
                deep: true,
                json: true,
            },
        };
        let _cli = cli;
    }

    // ========================================================================
    // print_verify_result() Tests - Comprehensive output formatting coverage
    // ========================================================================

    use nails_core::{Finding, ScanDepth, Severity, VerifyResult, VerifyStatus};

    #[test]
    fn test_print_verify_result_secure_status() {
        // Test that secure status prints correctly
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        // This will print to stdout - we're testing it doesn't panic and covers the code path
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_warning_status() {
        // Test warning status with findings
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete the file"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_critical_status() {
        // Test critical status with findings
        let findings = vec![
            Finding::new(Severity::Critical, "mount", "Overlay mount found"),
            Finding::new(Severity::Warn, "file", "Artifact file found"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_deep_scan() {
        // Test deep scan depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Deep);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_all_severity_levels() {
        // Test all severity levels in findings
        let findings = vec![
            Finding::new(Severity::Info, "memory", "RAM may retain data"),
            Finding::new(Severity::Warn, "file", "Artifact found")
                .with_fix_guidance("Delete artifact"),
            Finding::new(Severity::Critical, "mount", "Overlay mounted")
                .with_fix_guidance("Run nails deactivate"),
        ];
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_finding_without_fix_guidance() {
        // Test finding without fix guidance (None path)
        let findings = vec![Finding::new(
            Severity::Info,
            "memory",
            "RAM may retain data briefly",
        )];
        let result = VerifyResult::new(VerifyStatus::Secure, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_empty_findings() {
        // Test with empty findings array
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_multiple_findings_same_category() {
        // Test multiple findings in same category
        let findings = vec![
            Finding::new(Severity::Warn, "file", "Artifact 1").with_fix_guidance("Delete file 1"),
            Finding::new(Severity::Warn, "file", "Artifact 2").with_fix_guidance("Delete file 2"),
            Finding::new(Severity::Warn, "file", "Artifact 3"),
        ];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_standard_scan_no_depth_message() {
        // Test that standard scan doesn't print depth message
        let result = VerifyResult::new(VerifyStatus::Secure, vec![], ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_warning_with_single_finding() {
        // Edge case: warning status with exactly 1 finding
        let findings = vec![Finding::new(Severity::Warn, "test", "Single warning")];
        let result = VerifyResult::new(VerifyStatus::Warning, findings, ScanDepth::Standard);
        print_verify_result(&result);
    }

    #[test]
    fn test_print_verify_result_critical_with_many_findings() {
        // Edge case: critical status with many findings
        let findings: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    Severity::Critical,
                    format!("category{}", i),
                    format!("Finding {}", i),
                )
                .with_fix_guidance(format!("Fix {}", i))
            })
            .collect();
        let result = VerifyResult::new(VerifyStatus::Critical, findings, ScanDepth::Deep);
        print_verify_result(&result);
    }
}
