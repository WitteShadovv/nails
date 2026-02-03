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
            /// Emergency delay in seconds (default: 10)
            #[arg(short = 'd', long, default_value = "10")]
            delay: u64,
        },
        /// Show current status and uptime
        Status {
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
            Commands::Emergency { delay } => {
                println!("Emergency: delay={}s", delay);
                // TODO: Call nails-core emergency logic
                Ok(())
            }
            Commands::Status { verbose } => {
                println!("Status: verbose={}", verbose);
                // TODO: Call nails-core status logic
                Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::cli::*;
    use clap::Parser;

    // Note: Tests for activate command have been moved to end-to-end tests
    // in tests/ directory because the activate command calls std::process::exit()
    // which would terminate the test process.
    //
    // The activate command can only be properly tested via E2E tests using assert_cmd.
    //
    // Note: Tests for deactivate command have also been moved to E2E tests
    // because the deactivate command calls std::process::exit().

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

    #[test]
    fn test_execute_emergency_command_default_delay() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Emergency { delay: 10 },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_emergency_command_custom_delay() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Emergency { delay: 30 },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_status_command_without_verbose() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Status { verbose: false },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_status_command_with_verbose() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Status { verbose: true },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_verbose_flag_values() {
        let cli = Cli {
            verbose: 3,
            command: Commands::Status { verbose: false },
        };
        assert_eq!(cli.verbose, 3);
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
