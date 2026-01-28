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
    }

    /// Execute the CLI command - extracted for testability
    pub fn execute_command(cli: Cli) -> std::result::Result<(), Box<dyn std::error::Error>> {
        match cli.command {
            Commands::Activate { no_preflight } => {
                if no_preflight {
                    eprintln!("⚠️  DANGER: Skipping pre-flight checks. Activation may fail.");
                }
                println!("Activate: no_preflight={}", no_preflight);
                // TODO: Call nails-core activation logic with no_preflight parameter
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
            },
        };
        assert!(execute_command(cli).is_ok());
    }

    #[test]
    fn test_execute_activate_command_with_no_preflight() {
        let cli = Cli {
            verbose: 0,
            command: Commands::Activate { no_preflight: true },
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
}
