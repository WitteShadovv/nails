//! # NAILS CLI
//!
//! Command-line interface for NixOS Anti-forensics Isolation & Layering System.
//!
//! This crate is responsible ONLY for:
//! - Argument parsing via clap
//! - CLI exit codes
//! - User-facing error messages
//!
//! ALL business logic is delegated to nails-core for testability.

use clap::{Parser, Subcommand};

/// NixOS Anti-forensics Isolation & Layering System
#[derive(Parser)]
#[command(name = "nails")]
#[command(author = "NAILS Project")]
#[command(version)]  // clap's "cargo" feature auto-reads version from Cargo.toml
#[command(about = "NixOS Anti-forensics Isolation & Layering System", long_about = None)]
struct Cli {
    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Activate the hidden NixOS environment (mount overlayfs + switch profiles)
    Activate {
        /// Force activation even if preflight checks fail
        #[arg(short, long)]
        force: bool,
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

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Activate { force } => {
            println!("Activate: force={}", force);
            // TODO: Call nails-core activation logic
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
