//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for NixOS Anti-forensics Isolation & Layering System.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use clap::Parser;
use nails::cli::{Cli, execute_command};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for structured logging
    // The verbosity level will be controlled per-command via NailsManager::set_verbosity()
    // For now, we use a default INFO level. In the future, this could be configured
    // by a global --verbose flag passed to the CLI struct.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    execute_command(cli)
}
