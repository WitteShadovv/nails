//! # NAILS CLI Library
//!
//! This module contains the CLI command handlers and argument parsing.
//! Commands are implemented in the `cli` module for testability and reusability.
//! The entry point in main.rs simply invokes `cli::execute_command()`.

pub mod cli;
