// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS CLI Library
//!
//! This module contains the CLI command handlers and argument parsing.
//! Commands are implemented in the `cli` module for testability and reusability.
//! The entry point in main.rs simply invokes `cli::execute_command()`.

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

/// Serializes the tests that redirect the process's real stdout (fd 1) to
/// capture a printer's output. It is shared across every test module in this
/// crate, so an `activate` capture and an `emergency` capture can never hold the
/// redirection at the same time and clobber each other's fd 1.
#[cfg(test)]
pub(crate) static STDOUT_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod cli;
