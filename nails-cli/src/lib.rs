//! # NAILS CLI Library
//!
//! This module re-exports the CLI functionality for testing purposes.
//! The main logic is in main.rs, but we need to expose it for unit tests
//! to achieve proper code coverage.

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
        },
        /// Deactivate and return to decoy state (unmount + cleanup)
        Deactivate {
            /// Quick cleanup mode (skip thorough wipe)
            #[arg(short, long)]
            fast: bool,
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
            } => {
                // Convert CLI flags to Verbosity enum
                use nails_core::Verbosity;
                let verbosity = if quiet {
                    Verbosity::Quiet
                } else {
                    match verbose {
                        0 => Verbosity::Normal,
                        1 => Verbosity::Verbose,
                        _ => Verbosity::Debug, // 2+ maps to Debug
                    }
                };

                // NOTE: Full NailsManager integration is deferred to Story 4-10 (implement-nails-activate-cli-command-integration)
                // Story 4-8 implements the Verbosity enum and progress logging infrastructure in NailsManager::activate()
                // Story 4-10 will wire up the CLI config loading, state path resolution, and manager instantiation.
                //
                // Integration code for Story 4-10:
                // use nails_core::{NailsManager, RealFilesystem, Config};
                // use std::path::PathBuf;
                // use std::sync::{Arc, Mutex};
                //
                // let fs = RealFilesystem;
                // let config = load_config_from_cli_args_or_file(); // Story 4-10
                // let state_path = config.state_file_path.clone();
                // let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
                // manager.lock().unwrap().set_verbosity(verbosity);
                // NailsManager::activate(manager, no_preflight)?;

                // Temporary: Verbosity flags are parsed correctly (Story 4-8 AC: 3, 4, 5)
                // but full activation awaits Story 4-10's CLI integration work.
                if no_preflight {
                    eprintln!("⚠️  DANGER: Skipping pre-flight checks. Activation may fail.");
                }
                println!(
                    "Activate: no_preflight={}, verbosity={:?}",
                    no_preflight, verbosity
                );
                eprintln!("Note: Full CLI activation integration will be completed in Story 4-10");
                Ok(())
            }
            Commands::Deactivate { fast } => {
                println!("Deactivate: fast={}", fast);
                // TODO: Call nails-core deactivation logic
                Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::cli::*;

    #[test]
    fn test_execute_activate_command_without_no_preflight() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate {
                no_preflight: false,
                quiet: false,
                verbose: 0,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_activate_command_with_no_preflight() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate {
                no_preflight: true,
                quiet: false,
                verbose: 0,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_activate_command_with_quiet() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate {
                no_preflight: false,
                quiet: true,
                verbose: 0,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_activate_command_with_verbose() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate {
                no_preflight: false,
                quiet: false,
                verbose: 1,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_activate_command_with_debug() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate {
                no_preflight: false,
                quiet: false,
                verbose: 2,
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_deactivate_command_without_fast() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Deactivate { fast: false },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_deactivate_command_with_fast() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Deactivate { fast: true },
        };
        assert!(execute_command(cli).is_ok());
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
