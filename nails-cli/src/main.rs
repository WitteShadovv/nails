//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for NixOS Anti-forensics Isolation & Layering System.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use clap::Parser;
use nails::cli::{Cli, execute_command};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Parse CLI args to extract verbosity BEFORE initializing tracing
    let cli = Cli::parse();

    // Initialize tracing subscriber with verbosity-aware filtering
    // Story 9.3: Wire verbosity flags to tracing subscriber (AC #5)
    nails::cli::init_stdout_subscriber(cli.verbose, cli.quiet, cli.no_logs, cli.config.as_deref());

    execute_command(cli)
}
