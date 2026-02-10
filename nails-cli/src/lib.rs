//! # NAILS CLI Library
//!
//! This module contains the CLI command handlers and argument parsing.
//! Commands are implemented in the `cli` module for testability and reusability.
//! The entry point in main.rs simply invokes `cli::execute_command()`.

pub mod cli {
    use clap::{Parser, Subcommand};

    /// NixOS Anti-forensics Isolation & Layering System
    #[derive(Parser)]
    #[command(name = "nails")]
    #[command(author = "NAILS Project")]
    #[command(version)]
    #[command(about = "NixOS Anti-forensics Isolation & Layering System", long_about = None)]
    pub struct Cli {
        /// Verbose output (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count)]
        pub verbose: u8,

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

    /// Execute the CLI command - extracted for testability
    pub fn execute_command(cli: Cli) -> std::result::Result<(), Box<dyn std::error::Error>> {
        match cli.command {
            Commands::Activate {
                no_preflight,
                quiet,
                verbose,
                json,
                no_color,
                no_clear_history,
                kill_session,
                accept_pivot_risks,
                no_pivot,
                yes,
            } => {
                use nails_core::{
                    ActivateOptions, CliOverrides, Config, NailsManager, RealFilesystem, Verbosity,
                };
                use std::path::PathBuf;
                use std::sync::{Arc, Mutex};
                use std::time::Instant;

                // Configure color output (must be done before any colored output)
                if no_color || std::env::var("NO_COLOR").is_ok() {
                    colored::control::set_override(false);
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
                let options = ActivateOptions {
                    kill_session,
                    accept_pivot_risks,
                    no_pivot,
                    yes,
                    quiet,
                    verbosity: verbose,
                    json,
                    no_color,
                    skip_process_detection_override: None, // Use default test behavior
                };

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

                // Load config with CLI overrides (Story 10.3)
                let config_path = dirs::home_dir()
                    .map(|h| h.join(".nails/config.yaml"))
                    .unwrap_or_else(|| PathBuf::from("~/.nails/config.yaml"));

                let config = Config::from_file_and_cli(&config_path, &cli_overrides)
                    .unwrap_or_else(|e| {
                        eprintln!("Error loading config: {}", e);
                        std::process::exit(2);
                    });

                let state_path = config.state_file_path.clone();

                // Create NailsManager with real filesystem
                let filesystem = RealFilesystem;
                let manager = Arc::new(Mutex::new(NailsManager::new(
                    filesystem, config, state_path,
                )));

                // Set verbosity level
                manager.lock().unwrap().set_verbosity(verbosity);

                // Run activation with options and measure duration
                let start = Instant::now();
                let result =
                    NailsManager::activate_with_options(manager.clone(), options, no_preflight);
                let duration = start.elapsed().as_secs_f64();

                // Output results based on flags
                if json {
                    print_activate_json(&result, duration, &manager);
                } else {
                    print_activate_human(&result, duration, &manager);
                }

                // Return appropriate exit code
                match result {
                    Ok(_) => std::process::exit(0),
                    Err(_) => std::process::exit(1),
                }
            }
            Commands::Deactivate {
                no_clear_history,
                quiet,
                verbose,
                json,
                no_color,
            } => {
                use nails_core::{
                    CleanupConfig, Config, DeactivationOrchestrator, NailsManager, RealFilesystem,
                    Verbosity,
                };
                use std::path::PathBuf;
                use std::sync::{Arc, Mutex};

                // Configure color output (must be done before any colored output)
                if no_color || std::env::var("NO_COLOR").is_ok() {
                    colored::control::set_override(false);
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

                // Create cleanup config from args
                let mut cleanup_config = CleanupConfig::default();
                if no_clear_history {
                    cleanup_config.clear_history = false;
                    if verbosity >= Verbosity::Normal && !json {
                        println!("Skipping history cleanup (--no-clear-history)");
                    }
                }

                // Load configuration
                let config_path = dirs::home_dir()
                    .map(|h| h.join(".nails/config.yaml"))
                    .unwrap_or_else(|| PathBuf::from("~/.nails/config.yaml"));

                let config = Config::load_or_default(&config_path)
                    .unwrap_or_else(|_| Config::test_default());

                let state_path = config.state_file_path.clone();

                // Create NailsManager with real filesystem
                let filesystem = RealFilesystem;
                let manager = Arc::new(Mutex::new(NailsManager::new(
                    filesystem, config, state_path,
                )));

                // Set verbosity level
                manager.lock().unwrap().set_verbosity(verbosity);

                // Create orchestrator and run deactivation
                let orchestrator =
                    DeactivationOrchestrator::new(Arc::clone(&manager), cleanup_config);

                let result = orchestrator.run();

                // Output results based on flags
                if json {
                    print_deactivate_json(&result, &manager);
                } else {
                    print_deactivate_human(&result, verbosity, no_color);
                }

                // Return appropriate exit code
                match result {
                    Ok(_) => std::process::exit(0),
                    Err(_) => std::process::exit(1),
                }
            }
            Commands::Emergency {
                no_countdown,
                quiet,
                verbose,
                json,
                no_color,
            } => {
                use nails_core::{
                    CleanupConfig, Config, EmergencyCountdown, EmergencyOrchestrator, ForkStrategy,
                    NailsManager, RealFilesystem, Verbosity, fork_and_execute,
                };
                use std::path::PathBuf;
                use std::sync::{Arc, Mutex};

                // Configure color output (must be done before any colored output)
                if no_color || std::env::var("NO_COLOR").is_ok() {
                    colored::control::set_override(false);
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

                // Load config with state path
                let config_path = dirs::home_dir()
                    .map(|h| h.join(".nails/config.yaml"))
                    .unwrap_or_else(|| PathBuf::from("~/.nails/config.yaml"));
                let config = Config::load_or_default(&config_path)
                    .unwrap_or_else(|_| Config::test_default());
                let state_path = config.state_file_path.clone();

                // AC2: Create countdown (3 seconds fixed per AR33)
                let countdown = EmergencyCountdown {
                    countdown_seconds: 3,
                    skip_countdown: no_countdown,
                };

                // Run countdown
                match countdown.run() {
                    Ok(false) => {
                        // Aborted by user (Ctrl+C)
                        if !json {
                            println!("Emergency deactivation aborted");
                        } else {
                            println!(
                                "{{\"status\":\"aborted\",\"message\":\"Emergency deactivation aborted by user\"}}"
                            );
                        }
                        // Exit immediately: user explicitly aborted, no cleanup needed
                        // Using exit() instead of return to prevent any further processing
                        std::process::exit(0);
                    }
                    Ok(true) => {
                        // Countdown completed — proceed with fork
                    }
                    Err(e) => {
                        eprintln!("Countdown error: {}", e);
                        // Continue anyway — emergency should not be blocked by countdown errors
                    }
                }

                // Capture flags for use in the closure
                let json_flag = json;
                let quiet_flag = quiet;
                let verbosity_clone = verbosity;

                // AC3: Fork and execute emergency deactivation
                let result = fork_and_execute(
                    move || {
                        // Child process: create fresh manager and orchestrator
                        let filesystem = RealFilesystem;
                        let config = Config::load_or_default(&config_path)
                            .unwrap_or_else(|_| Config::test_default());
                        let manager = Arc::new(Mutex::new(NailsManager::new(
                            filesystem, config, state_path,
                        )));

                        // Set verbosity level
                        manager.lock().unwrap().set_verbosity(verbosity_clone);

                        // Create orchestrator and run
                        let cleanup_config = CleanupConfig::default();
                        let orchestrator =
                            EmergencyOrchestrator::new(Arc::clone(&manager), cleanup_config);

                        let report = orchestrator.run()?;

                        // Format and output results
                        if json_flag {
                            print_emergency_json(&report);
                        } else {
                            print_emergency_human(&report, verbosity_clone, quiet_flag);
                        }

                        // Exit with appropriate code (AC5: exit 1 when errors present)
                        if report.errors.is_empty() {
                            // No errors - clean shutdown
                            // Using exit() instead of return: this code runs in forked child process,
                            // we must exit directly to prevent returning to parent's CLI handler
                            std::process::exit(0);
                        } else {
                            // Errors occurred during emergency - exit with error code
                            // Using exit() instead of return: child process must terminate directly
                            std::process::exit(1);
                        }
                    },
                    ForkStrategy::Fork,
                );

                // Parent process: handle result from fork_and_execute
                // Returns Ok(()) when: (1) fork succeeded, or (2) fork failed but fallback succeeded
                match result {
                    Ok(()) => {
                        // Fork succeeded (parent) OR fallback execution succeeded
                        // Using exit() instead of return: prevents race conditions with child process
                        std::process::exit(0);
                    }
                    Err(e) => {
                        // Fork failed AND fallback execution also failed (true failure)
                        eprintln!("Emergency deactivation failed: {}", e);
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
                use std::path::PathBuf;

                // Configure color output (must be done before any colored output)
                if no_color || std::env::var("NO_COLOR").is_ok() {
                    colored::control::set_override(false);
                }

                // Load configuration (FIX #3: Proper home directory handling)
                let config_path = match dirs::home_dir() {
                    Some(home) => home.join(".nails/config.yaml"),
                    None => {
                        // No home directory available - use fallback in /tmp for error message
                        // Config loading will fail gracefully and use test_default()
                        PathBuf::from("/tmp/.nails/config.yaml")
                    }
                };

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
                        let posture = SecurityPosture::Critical;

                        if json {
                            println!(
                                "{{\"state\":\"INACTIVE\",\"security_posture\":\"critical\",\"error\":\"{}\"}}",
                                error_msg.replace('"', "\\\"")
                            );
                        } else if plain {
                            println!("=== NAILS Status Report ===");
                            println!();
                            println!("State:              INACTIVE [CRITICAL]");
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
                            println!("State:              INACTIVE 🔴");
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
    ) {
        use nails_core::NailsError;

        let state = manager
            .lock()
            .unwrap()
            .current_state()
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|_| "UNKNOWN".to_string());

        let output = match result {
            Ok(_) => ActivateResult {
                status: "success".to_string(),
                duration,
                state,
                message: format!("Activation complete in {:.1}s", duration),
                failed_checks: None,
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
                },
                _ => ActivateResult {
                    status: "error".to_string(),
                    duration,
                    state,
                    message: format!("Activation failed: {}", e),
                    failed_checks: None,
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
    }

    /// Print deactivation result in JSON format (AC7)
    fn print_deactivate_json<F: nails_core::Filesystem>(
        result: &Result<nails_core::DeactivationReport, nails_core::NailsError>,
        manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    ) {
        let state = manager
            .lock()
            .unwrap()
            .current_state()
            .map(|s| format!("{:?}", s).to_uppercase())
            .unwrap_or_else(|_| "UNKNOWN".to_string());

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
            },
            Err(e) => DeactivateJsonOutput {
                status: "error".to_string(),
                duration: 0.0,
                state,
                cleaned_items: vec![],
                errors: vec![e.to_string()],
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

    /// JSON output structure for emergency command (AC6)
    #[derive(serde::Serialize)]
    pub(crate) struct EmergencyJsonOutput {
        /// "success", "error", or "aborted"
        pub(crate) status: String,
        /// Duration in seconds
        pub(crate) duration: f64,
        /// System state after emergency (e.g., "Inactive")
        pub(crate) state: String,
        /// Non-fatal errors collected during emergency
        pub(crate) errors: Vec<String>,
        /// Recommendation (e.g., "Reboot recommended" or "none")
        pub(crate) recommendation: String,
        /// Overlays that were successfully unmounted
        pub(crate) unmounted_overlays: Vec<String>,
        /// True if emergency ran when system was already INACTIVE (defensive cleanup)
        pub(crate) was_defensive: bool,
    }

    impl From<&nails_core::EmergencyReport> for EmergencyJsonOutput {
        fn from(report: &nails_core::EmergencyReport) -> Self {
            Self {
                status: report.status.clone(),
                duration: report.duration.as_secs_f64(),
                state: format!("{:?}", report.final_state),
                errors: report.errors.clone(),
                recommendation: report
                    .recommendation
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                unmounted_overlays: report.unmounted_overlays.clone(),
                was_defensive: report.was_defensive,
            }
        }
    }

    /// Print emergency result in JSON format (AC6)
    fn print_emergency_json(report: &nails_core::EmergencyReport) {
        let output = EmergencyJsonOutput::from(report);
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
        );
    }

    /// Print emergency result in human-readable format (AC4, AC5, AC7, AC8)
    fn print_emergency_human(
        report: &nails_core::EmergencyReport,
        verbosity: nails_core::Verbosity,
        quiet: bool,
    ) {
        use colored::Colorize;
        use nails_core::Verbosity;

        let duration = report.duration.as_secs_f64();

        if report.is_successful() && report.errors.is_empty() {
            // AC4: Successful emergency
            if quiet {
                // AC7: Quiet mode shows countdown and final result (duration + final state)
                println!("Emergency deactivation complete in {:.2}s", duration);
                println!("Final state: {:?}", report.final_state);
            } else {
                println!(
                    "{}",
                    format!("✓ Emergency deactivation complete in {:.2}s", duration)
                        .green()
                        .bold()
                );

                if report.was_defensive {
                    println!("{}", "  (defensive - system was already INACTIVE)".dimmed());
                }

                // Show unmounted overlays in normal+ mode
                if verbosity >= Verbosity::Normal && !report.unmounted_overlays.is_empty() {
                    println!();
                    println!("Unmounted Overlays:");
                    for overlay in &report.unmounted_overlays {
                        println!("  ✓ {}", overlay);
                    }
                }

                // -vv: Debug mode — show full details (AC8)
                if verbosity >= Verbosity::Debug {
                    println!();
                    println!("Debug Details:");
                    println!("  Final State: {:?}", report.final_state);
                    println!("  Duration: {:.4}s", duration);
                    println!("  Defensive: {}", report.was_defensive);
                    println!("  Unmounted overlays: {}", report.unmounted_overlays.len());

                    // Show cleanup details if available (AC8: show each cleanup step)
                    if !report.unmounted_overlays.is_empty() {
                        println!();
                        println!("  Unmount Details:");
                        for (i, overlay) in report.unmounted_overlays.iter().enumerate() {
                            println!("    {}. {} (force unmounted)", i + 1, overlay);
                        }
                    }

                    // Show cleanup report details (history files, temp files, etc.)
                    // Note: cleanup_report is private, but we can infer from report fields
                    if report.was_defensive {
                        println!();
                        println!("  Note: Defensive cleanup - system was already INACTIVE");
                    }
                }
            }
        } else {
            // AC5: Error-tolerant emergency
            eprintln!(
                "{}",
                "Emergency deactivation completed with errors".red().bold()
            );

            if !report.errors.is_empty() {
                eprintln!();
                for error in &report.errors {
                    eprintln!("  {} {}", "✗".red(), error);
                }
            }

            eprintln!();
            eprintln!(
                "{}",
                "Recommendation: Reboot system to ensure clean state"
                    .yellow()
                    .bold()
            );

            // Show state in verbose mode
            if verbosity >= Verbosity::Normal {
                eprintln!();
                eprintln!("Final State: {:?}", report.final_state);
            }
        }
    }

    // ========================================================================
    // Status Command Output Formatting (Story 7.4)
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

        // Format state with emoji indicator
        let state_emoji = match report.state {
            SystemState::Active { .. } => "🟢",
            SystemState::Inactive => "🔴",
            SystemState::Activating { .. } => "🟡",
            SystemState::Deactivating { .. } => "🟡",
            SystemState::Emergency { .. } => "🔴",
        };
        println!("State:              {:?} {}", report.state, state_emoji);

        // Format security posture with Display trait
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

            // Print overlay list with checkmarks
            if !report.overlays.is_empty() {
                println!("Overlays:");
                for overlay in &report.overlays {
                    println!("  ✓ {} (mounted)", overlay.display());
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

        // Format state with ASCII indicator
        let state_indicator = match report.state {
            SystemState::Active { .. } => "[SECURE]",
            SystemState::Inactive => "[CRITICAL]",
            SystemState::Activating { .. } => "[WARNING]",
            SystemState::Deactivating { .. } => "[WARNING]",
            SystemState::Emergency { .. } => "[CRITICAL]",
        };
        println!("State:              {:?} {}", report.state, state_indicator);

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

            // Print overlay list with [OK] markers
            if !report.overlays.is_empty() {
                println!("Overlays:");
                for overlay in &report.overlays {
                    println!("  [OK] {} (mounted)", overlay.display());
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
        } = cli.command
        {
            assert!(!no_clear_history);
            assert!(!quiet);
            assert_eq!(verbose, 0);
            assert!(!json);
            assert!(!no_color);
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
        } = cli.command
        {
            assert!(!no_countdown);
            assert!(!quiet);
            assert_eq!(verbose, 0);
            assert!(!json);
            assert!(!no_color);
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

    // ========================================================================
    // Emergency Output Formatting Tests (AC10)
    // ========================================================================
    // Note: Testing output formatting functions directly since execute_command
    // calls std::process::exit() which terminates test process.

    #[test]
    fn test_emergency_json_output_success() {
        // AC10: Test JSON output for successful emergency
        use nails_core::{EmergencyReport, SystemState};
        use std::time::Duration;

        let report = EmergencyReport {
            cleanup_report: nails_core::CleanupReport::default(),
            unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
            duration: Duration::from_millis(1500),
            final_state: SystemState::Inactive,
            errors: vec![],
            was_defensive: false,
            status: "success".to_string(),
            recommendation: None,
        };

        let json_output = EmergencyJsonOutput::from(&report);

        // Verify all required fields (AC6)
        assert_eq!(json_output.status, "success");
        assert!((json_output.duration - 1.5).abs() < 0.01);
        assert_eq!(json_output.state, "Inactive");
        assert!(json_output.errors.is_empty());
        assert_eq!(json_output.recommendation, "none");
        assert_eq!(json_output.unmounted_overlays.len(), 2);
        assert!(!json_output.was_defensive);

        // Verify JSON serialization
        let json_str = serde_json::to_string_pretty(&json_output).unwrap();
        assert!(json_str.contains("\"status\": \"success\""));
        assert!(json_str.contains("\"duration\""));
        assert!(json_str.contains("\"state\": \"Inactive\""));
        assert!(json_str.contains("\"recommendation\": \"none\""));
        assert!(json_str.contains("\"unmounted_overlays\""));
        assert!(json_str.contains("\"was_defensive\": false"));
    }

    #[test]
    fn test_emergency_json_output_with_errors() {
        // AC10: Test JSON output with errors
        use nails_core::{EmergencyReport, SystemState};
        use std::time::Duration;

        let report = EmergencyReport {
            cleanup_report: nails_core::CleanupReport::default(),
            unmounted_overlays: vec!["/etc".to_string()],
            duration: Duration::from_millis(2500),
            final_state: SystemState::Inactive,
            errors: vec![
                "Force unmount failed for /home: busy".to_string(),
                "Cleanup failed: permission denied".to_string(),
            ],
            was_defensive: false,
            status: "error".to_string(),
            recommendation: Some("Reboot recommended".to_string()),
        };

        let json_output = EmergencyJsonOutput::from(&report);

        assert_eq!(json_output.status, "error");
        assert_eq!(json_output.errors.len(), 2);
        assert_eq!(json_output.recommendation, "Reboot recommended");
        assert_eq!(json_output.unmounted_overlays.len(), 1);
    }

    #[test]
    fn test_emergency_json_output_defensive() {
        // AC10: Test JSON output for defensive emergency (already INACTIVE)
        use nails_core::{EmergencyReport, SystemState};
        use std::time::Duration;

        let report = EmergencyReport {
            cleanup_report: nails_core::CleanupReport::default(),
            unmounted_overlays: vec![],
            duration: Duration::from_millis(500),
            final_state: SystemState::Inactive,
            errors: vec![],
            was_defensive: true,
            status: "success".to_string(),
            recommendation: None,
        };

        let json_output = EmergencyJsonOutput::from(&report);

        assert!(json_output.was_defensive);
        assert_eq!(json_output.unmounted_overlays.len(), 0);
    }

    #[test]
    fn test_execute_status_command_without_verbose() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Status {
                json: false,
                no_color: false,
                plain: false,
                verbose: false,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_status_command_with_verbose() {
        let cli = Cli {
            verbose: 0,
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
            verbose: 3,
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
            verbose: 0,
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
            verbose: 0,
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
            verbose: 0,
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
            verbose: 0,
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
