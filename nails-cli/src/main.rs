//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for NixOS Anti-forensics Isolation & Layering System.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use clap::Parser;
use nails::cli::{Cli, execute_command};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    execute_command(cli)
}
